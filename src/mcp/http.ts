import * as http from "node:http";
import * as crypto from "node:crypto";
import { buildVaultFromConfig } from "../core/config.js";
import type { PromptRedactConfig, SecretVault } from "../types.js";
import { PACKAGE_NAME, PACKAGE_VERSION } from "../version.js";
import { modernHttpStatus, validateModernHttpHeaders } from "./http-headers.js";
import type { JsonRpcId, JsonRpcResponse } from "./protocol.js";
import { createServer } from "./run.js";
import type { McpServer } from "./server.js";
import { buildTools } from "./tools.js";

export interface HttpTransportOptions {
  cwd: string;
  host?: string;
  port?: number;
  token?: string | null;
  allowedOrigins?: readonly string[];
  maxBodyBytes?: number;
  /**
   * Legacy SSE clients (EventSource) cannot set Authorization headers. Allow a
   * ?token= query parameter only when explicitly enabled; URLs leak into logs.
   */
  allowQueryToken?: boolean;
  noConfig?: boolean;
  config?: PromptRedactConfig;
  vault?: SecretVault;
  log?: (line: string) => void;
}

export interface HttpTransport {
  url: string;
  port: number;
  host: string;
  token: string | null;
  close(): Promise<void>;
}

export interface McpHttpHandlerOptions {
  cwd: string;
  token: string | null;
  allowedOrigins?: readonly string[];
  maxBodyBytes?: number;
  allowQueryToken?: boolean;
  noConfig?: boolean;
  config?: PromptRedactConfig;
  vault?: SecretVault;
  log?: (line: string) => void;
  onRequest?: (method: string) => void;
  onRefused?: () => void;
  onRateLimited?: () => void;
}

export interface McpHttpHandler {
  readonly toolCount: number;
  handle(request: http.IncomingMessage, response: http.ServerResponse): boolean;
  close(): Promise<void>;
}

const DEFAULT_PORT = 4791;
const DEFAULT_MAX_BODY = 2 * 1024 * 1024;
const RATE_LIMIT = 60;
const RATE_WINDOW_MS = 10_000;
const MAX_IN_FLIGHT = 4;
const MAX_SESSION_ENTRIES = 64;
const SESSION_TTL_MS = 30 * 60 * 1000;
const MAX_SSE_SESSIONS = 64;
const MAX_RATE_WINDOWS = 1024;

export function generateToken(): string {
  return crypto.randomBytes(24).toString("base64url");
}

function parseBearerToken(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1].trim() : null;
}

function isLoopbackOrigin(origin: string): boolean {
  try {
    const url = new URL(origin);
    if (url.protocol !== "http:" && url.protocol !== "https:") return false;
    const host = url.hostname;
    return host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";
  } catch {
    return false;
  }
}

function timingSafeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function sessionHeader(request: http.IncomingMessage): string {
  const header = request.headers["mcp-session-id"];
  return typeof header === "string" ? header.trim() : "";
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isToolCall(message: unknown): boolean {
  return isObject(message) && message.method === "tools/call";
}

function methodOf(message: unknown): string | null {
  return isObject(message) && typeof message.method === "string" ? message.method : null;
}

export function createMcpHttpHandler(options: McpHttpHandlerOptions): McpHttpHandler {
  const log = options.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  const token = options.token;
  const maxBody = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const allowQueryToken = options.allowQueryToken === true;
  const extraOrigins = options.allowedOrigins ?? [];
  const built = buildVaultFromConfig(options.cwd, {
    config: options.config,
    noConfig: options.noConfig,
    source: "mcp",
  });
  const sharedVault = options.vault ?? built.vault;
  const resolvedConfig = options.config ?? built.config;
  const modernCancellationsByClient = new Map<string, Map<JsonRpcId, Set<() => void>>>();
  const cancellationMapFor = (clientKey: string): Map<JsonRpcId, Set<() => void>> => {
    let existing = modernCancellationsByClient.get(clientKey);
    if (existing !== undefined) return existing;
    if (modernCancellationsByClient.size >= 64) {
      const oldest = modernCancellationsByClient.keys().next().value;
      if (oldest !== undefined) modernCancellationsByClient.delete(oldest);
    }
    existing = new Map<JsonRpcId, Set<() => void>>();
    modernCancellationsByClient.set(clientKey, existing);
    return existing;
  };
  const createMcp = (sharedCancellations?: Map<JsonRpcId, Set<() => void>>): McpServer =>
    createServer({
      cwd: options.cwd,
      vault: sharedVault,
      config: resolvedConfig,
      log,
      ...(sharedCancellations ? { cancellations: sharedCancellations } : {}),
      ...(options.noConfig === true ? { noConfig: true } : {}),
    });
  const toolCount = buildTools().length;

  const mcpSessions = new Map<
    string,
    { server: McpServer; lastSeen: number; socket: object; anonKey: string }
  >();
  const socketServers = new WeakMap<object, { server: McpServer; anonKey: string }>();
  const anonymousServers = new Map<string, McpServer>();
  const sseSessions = new Map<
    string,
    { write: (payload: string) => void; end: () => void; server: McpServer }
  >();
  const rateWindows = new Map<string, { count: number; resetAt: number }>();
  let inFlight = 0;

  const newSessionId = (): string => crypto.randomBytes(12).toString("hex");

  const evictSessionBindings = (entry: {
    server: McpServer;
    socket: object;
    anonKey: string;
  }): void => {
    const onSock = socketServers.get(entry.socket);
    if (onSock !== undefined && onSock.server === entry.server) {
      socketServers.delete(entry.socket);
    }
    if (anonymousServers.get(entry.anonKey) === entry.server) {
      anonymousServers.delete(entry.anonKey);
    }
  };

  const pruneSessions = (now: number): void => {
    for (const [id, entry] of mcpSessions) {
      if (now - entry.lastSeen > SESSION_TTL_MS) {
        mcpSessions.delete(id);
        evictSessionBindings(entry);
      }
    }
  };

  const rememberSession = (
    id: string,
    server: McpServer,
    now: number,
    socket: object,
    anonKey: string
  ): void => {
    pruneSessions(now);
    if (!mcpSessions.has(id) && mcpSessions.size >= MAX_SESSION_ENTRIES) {
      let oldestId: string | null = null;
      let oldestSeen = Infinity;
      for (const [candidate, entry] of mcpSessions) {
        if (entry.lastSeen < oldestSeen) {
          oldestSeen = entry.lastSeen;
          oldestId = candidate;
        }
      }
      if (oldestId !== null) {
        const evicted = mcpSessions.get(oldestId);
        mcpSessions.delete(oldestId);
        if (evicted) evictSessionBindings(evicted);
      }
    }
    mcpSessions.set(id, { server, lastSeen: now, socket, anonKey });
  };

  const anonymousKey = (request: http.IncomingMessage): string => {
    const userAgent =
      typeof request.headers["user-agent"] === "string" ? request.headers["user-agent"] : "";
    return `${request.socket.remoteAddress ?? "unknown"}\0${userAgent}`;
  };
  const rememberAnonymous = (key: string, server: McpServer): void => {
    if (anonymousServers.size >= 64 && !anonymousServers.has(key)) {
      const oldest = anonymousServers.keys().next().value;
      if (oldest !== undefined) anonymousServers.delete(oldest);
    }
    anonymousServers.set(key, server);
  };
  const fallbackServer = (request: http.IncomingMessage): McpServer => {
    const fallbackKey = anonymousKey(request);
    const onSocket = socketServers.get(request.socket);
    if (onSocket !== undefined && onSocket.anonKey === fallbackKey) {
      return onSocket.server;
    }
    let fallback = anonymousServers.get(fallbackKey);
    if (fallback === undefined) {
      fallback = createMcp(cancellationMapFor(fallbackKey));
      rememberAnonymous(fallbackKey, fallback);
    }
    socketServers.set(request.socket, { server: fallback, anonKey: fallbackKey });
    return fallback;
  };
  const allowedOrigin = (origin: string | undefined): string | null => {
    if (origin === undefined) return null;
    if (isLoopbackOrigin(origin)) return origin;
    return extraOrigins.includes(origin) ? origin : null;
  };

  const tokenAccepted = (
    request: http.IncomingMessage,
    url: URL,
    allowQuery: boolean
  ): boolean => {
    if (token === null) return true;
    const presented = parseBearerToken(request.headers.authorization);
    if (presented !== null && timingSafeEqual(presented, token)) return true;
    if (!allowQuery) return false;
    const fromQuery = url.searchParams.get("token");
    return fromQuery !== null && timingSafeEqual(fromQuery, token);
  };

  const rememberRateWindow = (remote: string, now: number, cost = 1): void => {
    if (!rateWindows.has(remote) && rateWindows.size >= MAX_RATE_WINDOWS) {
      for (const [key, value] of rateWindows) if (value.resetAt <= now) rateWindows.delete(key);
      while (rateWindows.size >= MAX_RATE_WINDOWS) {
        const oldest = rateWindows.keys().next().value;
        if (oldest === undefined) break;
        rateWindows.delete(oldest);
      }
    }
    rateWindows.set(remote, { count: cost, resetAt: now + RATE_WINDOW_MS });
  };

  const rateLimited = (request: http.IncomingMessage, cost = 1): boolean => {
    const remote = request.socket.remoteAddress ?? "unknown";
    const now = Date.now();
    const window = rateWindows.get(remote);
    if (window === undefined || window.resetAt <= now) {
      rememberRateWindow(remote, now, cost);
      return cost > RATE_LIMIT;
    }
    if (window.count + cost > RATE_LIMIT) return true;
    window.count += cost;
    return false;
  };

  const send = (
    response: http.ServerResponse,
    status: number,
    body: unknown,
    cors: Record<string, string>,
    extra: Record<string, string> = {}
  ): void => {
    if (response.headersSent || response.writableEnded) return;
    const text = typeof body === "string" ? body : JSON.stringify(body);
    const headers: Record<string, string> = {
      ...cors,
      "content-type":
        typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8",
      "content-length": String(Buffer.byteLength(text, "utf8")),
      "x-content-type-options": "nosniff",
      ...extra,
    };
    if (status >= 400 && status < 500 && status !== 429) options.onRefused?.();
    try {
      response.writeHead(status, headers);
      response.end(text);
    } catch {
      return;
    }
  };

  const corsFor = (
    request: http.IncomingMessage,
    response: http.ServerResponse
  ): Record<string, string> | null => {
    const origin = typeof request.headers.origin === "string" ? request.headers.origin : undefined;
    const allowed = allowedOrigin(origin);
    if (origin !== undefined && allowed === null) {
      send(response, 403, { error: "origin not allowed" }, {});
      return null;
    }
    if (allowed === null) return {};
    return {
      "access-control-allow-origin": allowed,
      vary: "origin",
      "access-control-allow-headers":
        "authorization, content-type, mcp-protocol-version, mcp-session-id, mcp-method, mcp-name",
      "access-control-expose-headers": "mcp-session-id",
      "access-control-allow-methods": "POST, GET, OPTIONS, DELETE",
      "access-control-max-age": "600",
    };
  };

  const unauthorized = (
    response: http.ServerResponse,
    cors: Record<string, string>
  ): void => {
    send(response, 401, { error: "unauthorized" }, cors, {
      "www-authenticate": 'Bearer realm="prompt-redact"',
    });
  };

  const tooMany = (response: http.ServerResponse, cors: Record<string, string>): void => {
    options.onRateLimited?.();
    send(response, 429, { error: "too many requests" }, cors, { "retry-after": "10" });
  };

  const busyResponse = (id: unknown): JsonRpcResponse => ({
    jsonrpc: "2.0",
    id: typeof id === "string" || typeof id === "number" || id === null ? id : null,
    error: {
      code: -32001,
      message: "server busy: too many tool calls are already in flight",
    },
  });

  const acquireToolSlot = (): boolean => {
    if (inFlight >= MAX_IN_FLIGHT) return false;
    inFlight += 1;
    return true;
  };
  const releaseToolSlot = (): void => {
    if (inFlight > 0) inFlight -= 1;
  };

  const readJsonBody = (
    request: http.IncomingMessage,
    response: http.ServerResponse,
    cors: Record<string, string>,
    onBody: (message: unknown) => void
  ): void => {
    let received = 0;
    let tooLarge = false;
    let drained = 0;
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => {
      if (tooLarge) {
        drained += chunk.length;
        if (drained > maxBody) request.destroy();
        return;
      }
      received += chunk.length;
      if (received > maxBody) {
        tooLarge = true;
        chunks.length = 0;
        send(response, 413, { error: "request body too large", limit: maxBody }, cors, {
          connection: "close",
        });
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (tooLarge) return;
      let message: unknown;
      try {
        message = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch (error) {
        send(
          response,
          400,
          { jsonrpc: "2.0", id: null, error: { code: -32700, message: `Parse error: ${(error as Error).message}` } },
          cors
        );
        return;
      }
      onBody(message);
    });
    request.on("error", () => {
      try {
        response.destroy();
      } catch {
        return;
      }
    });
  };

  const handleSse = (
    request: http.IncomingMessage,
    response: http.ServerResponse,
    url: URL,
    cors: Record<string, string>
  ): void => {
    if (!tokenAccepted(request, url, allowQueryToken)) {
      unauthorized(response, cors);
      return;
    }
    if (rateLimited(request)) {
      tooMany(response, cors);
      return;
    }
    if (sseSessions.size >= MAX_SSE_SESSIONS) {
      send(response, 503, { error: "too many open SSE sessions" }, cors, { "retry-after": "10" });
      return;
    }
    const id = crypto.randomBytes(12).toString("hex");
    const streamCors = {
      ...cors,
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    };
    response.writeHead(200, streamCors);
    const write = (payload: string): void => {
      try {
        response.write(payload);
      } catch {
        return;
      }
    };
    const heartbeat = setInterval(() => write(": ping\n\n"), 15_000);
    if (typeof heartbeat.unref === "function") heartbeat.unref();
    const cleanup = (): void => {
      clearInterval(heartbeat);
      sseSessions.delete(id);
    };
    sseSessions.set(id, {
      write,
      end: () => {
        clearInterval(heartbeat);
        try {
          response.end();
        } catch {
          return;
        }
      },
      server: createMcp(),
    });
    request.on("close", cleanup);
    response.on("close", cleanup);
    write(`event: endpoint\ndata: /messages?sessionId=${id}\n\n`);
  };

  const handleMessages = (
    request: http.IncomingMessage,
    response: http.ServerResponse,
    url: URL,
    cors: Record<string, string>
  ): void => {
    if (!tokenAccepted(request, url, allowQueryToken)) {
      unauthorized(response, cors);
      return;
    }
    if (rateLimited(request)) {
      tooMany(response, cors);
      return;
    }
    const id = url.searchParams.get("sessionId") ?? "";
    const stream = sseSessions.get(id);
    if (stream === undefined) {
      send(response, 404, { error: "unknown sessionId; open GET /sse first" }, cors);
      return;
    }
    readJsonBody(request, response, cors, (message) => {
      const gated = isToolCall(message);
      if (gated && !acquireToolSlot()) {
        const answer = busyResponse(isObject(message) ? message.id : null);
        stream.write(`event: message\ndata: ${JSON.stringify(answer)}\n\n`);
        send(response, 202, "", cors);
        return;
      }
      void (async () => {
        try {
          const answer = await stream.server.handle(message);
          if (answer !== null) stream.write(`event: message\ndata: ${JSON.stringify(answer)}\n\n`);
        } finally {
          if (gated) releaseToolSlot();
        }
        send(response, 202, "", cors);
      })().catch((error: unknown) => {
        log(`mcp/http: ${(error as Error).message}`);
        send(response, 500, { jsonrpc: "2.0", id: null, error: { code: -32603, message: "Internal error" } }, cors);
      });
    });
  };

  const handleMcp = (
    request: http.IncomingMessage,
    response: http.ServerResponse,
    cors: Record<string, string>
  ): void => {
    if (!tokenAccepted(request, new URL(request.url ?? "/", "http://localhost"), false)) {
      unauthorized(response, cors);
      return;
    }
    if (rateLimited(request)) {
      tooMany(response, cors);
      return;
    }

    if (request.method === "DELETE") {
      const supplied = sessionHeader(request);
      if (supplied === "") {
        send(response, 400, { error: "DELETE /mcp requires mcp-session-id" }, cors);
        return;
      }
      const now = Date.now();
      pruneSessions(now);
      const existing = mcpSessions.get(supplied);
      if (existing === undefined) {
        send(response, 404, { error: "unknown mcp-session-id" }, cors);
        return;
      }
      mcpSessions.delete(supplied);
      evictSessionBindings(existing);
      send(response, 204, "", cors);
      return;
    }

    if (request.method !== "POST") {
      send(response, 405, { error: "method not allowed" }, cors, { allow: "POST, DELETE, OPTIONS" });
      return;
    }

    readJsonBody(request, response, cors, (message) => {
      const batch = Array.isArray(message) ? message : [message];
      if (batch.length === 0) {
        send(
          response,
          400,
          { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request: empty batch" } },
          cors
        );
        return;
      }
      if (batch.length > 100) {
        send(response, 400, { error: "JSON-RPC batch is limited to 100 messages" }, cors);
        return;
      }
      const headers = validateModernHttpHeaders(request, message);
      if (headers.error !== undefined) {
        send(response, 400, headers.error, cors);
        return;
      }
      const modern = headers.modern;
      if (batch.length > 1 && rateLimited(request, batch.length - 1)) {
        tooMany(response, cors);
        return;
      }

      const supplied = sessionHeader(request);
      let server: McpServer;
      let responseSession = "";
      const initializeInBatch = batch.some((item) => methodOf(item) === "initialize");
      if (initializeInBatch && !modern) {
        if (batch.length !== 1 || supplied !== "") {
          send(response, 400, { error: "initialize must be sent alone, without mcp-session-id" }, cors);
          return;
        }
        server = createMcp();
        const anonKey = anonymousKey(request);
        socketServers.set(request.socket, { server, anonKey });
        rememberAnonymous(anonKey, server);
        responseSession = newSessionId();
        rememberSession(responseSession, server, Date.now(), request.socket, anonKey);
      } else if (modern) {
        server = createMcp(cancellationMapFor(anonymousKey(request)));
      } else if (supplied !== "") {
        const now = Date.now();
        pruneSessions(now);
        const existing = mcpSessions.get(supplied);
        if (existing === undefined) {
          send(response, 404, { error: "unknown mcp-session-id" }, cors);
          return;
        }
        existing.lastSeen = now;
        server = existing.server;
        responseSession = supplied;
      } else {
        server = fallbackServer(request);
      }

      const sessionHeaders =
        responseSession === "" ? cors : { ...cors, "mcp-session-id": responseSession };
      const answers: JsonRpcResponse[] = [];
      void (async () => {
        for (const item of batch) {
          const gated = isToolCall(item);
          if (gated && !acquireToolSlot()) {
            answers.push(busyResponse(isObject(item) ? item.id : null));
            continue;
          }
          try {
            const answer = await server.handle(item);
            if (answer !== null) answers.push(answer);
          } finally {
            if (gated) releaseToolSlot();
          }
        }
        if (answers.length === 0) {
          send(response, 202, "", sessionHeaders);
          return;
        }
        const status = modern ? modernHttpStatus(answers[0]) : 200;
        send(response, status, Array.isArray(message) ? answers : answers[0], sessionHeaders);
      })().catch((error: unknown) => {
        log(`mcp/http: ${(error as Error).message}`);
        send(response, 500, { jsonrpc: "2.0", id: null, error: { code: -32603, message: "Internal error" } }, cors);
      });
    });
  };

  return {
    toolCount,
    handle(request: http.IncomingMessage, response: http.ServerResponse): boolean {
      let url: URL;
      try {
        url = new URL(request.url ?? "/", "http://localhost");
      } catch {
        return false;
      }
      if (url.pathname !== "/mcp" && url.pathname !== "/sse" && url.pathname !== "/messages") {
        return false;
      }
      request.on("error", () => {
        if (!response.destroyed) response.destroy();
      });
      response.on("error", () => {
        if (!response.destroyed) response.destroy();
      });
      options.onRequest?.(request.method ?? "UNKNOWN");
      const cors = corsFor(request, response);
      if (cors === null) return true;
      if (request.method === "OPTIONS") {
        send(response, 204, "", cors);
        return true;
      }
      if (url.pathname === "/sse") {
        if (request.method !== "GET") {
          send(response, 405, { error: "method not allowed" }, cors, { allow: "GET, OPTIONS" });
          return true;
        }
        handleSse(request, response, url, cors);
        return true;
      }
      if (url.pathname === "/messages") {
        if (request.method !== "POST") {
          send(response, 405, { error: "method not allowed" }, cors, { allow: "POST, OPTIONS" });
          return true;
        }
        handleMessages(request, response, url, cors);
        return true;
      }
      handleMcp(request, response, cors);
      return true;
    },
    async close(): Promise<void> {
      for (const [, session] of sseSessions) {
        try {
          session.end();
        } catch {
          continue;
        }
      }
      sseSessions.clear();
      mcpSessions.clear();
      anonymousServers.clear();
      modernCancellationsByClient.clear();
      rateWindows.clear();
    },
  };
}

export async function startHttpTransport(options: HttpTransportOptions): Promise<HttpTransport> {
  const rawHost = options.host ?? "127.0.0.1";
  const host = rawHost.startsWith("[") && rawHost.endsWith("]") ? rawHost.slice(1, -1) : rawHost;
  const port = options.port ?? DEFAULT_PORT;
  const log = options.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  const token = options.token === undefined ? generateToken() : options.token;
  if (token === null && host !== "127.0.0.1" && host !== "localhost" && host !== "::1") {
    throw new Error(
      `Refusing to serve ${rawHost} without a token: a non-loopback server must require Authorization.`
    );
  }

  const metrics = {
    requests: 0,
    byMethod: new Map<string, number>(),
    refused: 0,
    rateLimited: 0,
    started: Date.now(),
  };
  const noteRequest = (method: string): void => {
    metrics.requests += 1;
    metrics.byMethod.set(method, (metrics.byMethod.get(method) ?? 0) + 1);
  };
  const mcp = createMcpHttpHandler({
    cwd: options.cwd,
    token,
    ...(options.allowedOrigins === undefined ? {} : { allowedOrigins: options.allowedOrigins }),
    ...(options.maxBodyBytes === undefined ? {} : { maxBodyBytes: options.maxBodyBytes }),
    ...(options.allowQueryToken === undefined ? {} : { allowQueryToken: options.allowQueryToken }),
    ...(options.noConfig === true ? { noConfig: true } : {}),
    ...(options.config === undefined ? {} : { config: options.config }),
    ...(options.vault === undefined ? {} : { vault: options.vault }),
    log,
    onRequest: noteRequest,
    onRefused: () => {
      metrics.refused += 1;
    },
    onRateLimited: () => {
      metrics.rateLimited += 1;
    },
  });
  const toolCount = mcp.toolCount;

  const httpServer = http.createServer((request, response) => {
    if (mcp.handle(request, response)) return;
    noteRequest(request.method ?? "UNKNOWN");

    let responseSent = false;
    const send = (status: number, body: unknown, extra: Record<string, string> = {}): void => {
      if (responseSent) return;
      responseSent = true;
      const text = typeof body === "string" ? body : JSON.stringify(body);
      if (status >= 400 && status < 500 && status !== 429) metrics.refused += 1;
      response.writeHead(status, {
        "content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json",
        "content-length": String(Buffer.byteLength(text, "utf8")),
        "x-content-type-options": "nosniff",
        ...extra,
      });
      response.end(text);
    };

    if (request.method === "GET" && request.url === "/healthz") {
      send(200, {
        ok: true,
        name: PACKAGE_NAME,
        version: PACKAGE_VERSION,
        tools: toolCount,
        uptimeMs: Date.now() - metrics.started,
      });
      return;
    }

    send(404, { error: "not found" });
  });

  httpServer.on("clientError", (_error, socket) => {
    if (socket.writable) {
      socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    } else {
      socket.destroy();
    }
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(port, host, () => {
      httpServer.removeListener("error", reject);
      resolve();
    });
  });

  const addr = httpServer.address();
  const actualPort = typeof addr === "object" && addr !== null ? addr.port : port;
  const display = host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host;
  const urlHost = display.includes(":") ? `[${display}]` : display;

  return {
    url: `http://${urlHost}:${actualPort}`,
    port: actualPort,
    host: display,
    token,
    close: async () => {
      await mcp.close();
      httpServer.closeAllConnections();
      await new Promise<void>((resolve) => {
        httpServer.close(() => resolve());
      });
    },
  };
}
