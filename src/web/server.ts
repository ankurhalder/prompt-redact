import * as http from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { buildVaultFromConfig } from "../core/config.js";
import { createSseRehydrationTransform } from "../core/sse.js";
import { VaultCapacityError } from "../core/vault.js";
import { createMcpHttpHandler } from "../mcp/http.js";
import type { PromptRedactConfig, SecretVault } from "../types.js";
import { PACKAGE_NAME, PACKAGE_VERSION } from "../version.js";
import { SERVE_PAGE } from "./ui.js";

export interface ServeOptions {
  cwd: string;
  host?: string;
  port?: number;
  token?: string | null;
  allowedOrigins?: readonly string[];
  noConfig?: boolean;
  config?: PromptRedactConfig;
  log?: (line: string) => void;
}

export interface ServeHandle {
  url: string;
  host: string;
  port: number;
  token: string | null;
  close(): Promise<void>;
}

const DEFAULT_PORT = 4788;
const MAX_BODY = 256 * 1024;

function isLoopbackOrigin(origin: string): boolean {
  try {
    const url = new URL(origin);
    if (url.protocol !== "http:" && url.protocol !== "https:") return false;
    return ["localhost", "127.0.0.1", "[::1]", "::1"].includes(url.hostname);
  } catch {
    return false;
  }
}

function parseBearer(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1].trim() : null;
}

export async function startWebServer(options: ServeOptions): Promise<ServeHandle> {
  const rawHost = options.host ?? "127.0.0.1";
  const host = rawHost.startsWith("[") && rawHost.endsWith("]") ? rawHost.slice(1, -1) : rawHost;
  const port = options.port ?? DEFAULT_PORT;
  const log = options.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  const token = options.token === undefined ? randomBytes(18).toString("base64url") : options.token;
  if (token === null && !["127.0.0.1", "localhost", "::1"].includes(host)) {
    throw new Error(`Refusing to serve ${rawHost} without a token.`);
  }

  const mcpBuilt = buildVaultFromConfig(options.cwd, {
    config: options.config,
    noConfig: options.noConfig,
    source: "mcp",
  });
  const playgroundBuilt = buildVaultFromConfig(options.cwd, {
    config: mcpBuilt.config,
    noConfig: options.noConfig,
    source: "serve",
  });
  const playgroundVault: SecretVault = playgroundBuilt.vault;

  const mcp = createMcpHttpHandler({
    cwd: options.cwd,
    token,
    config: mcpBuilt.config,
    vault: mcpBuilt.vault,
    ...(options.allowedOrigins === undefined ? {} : { allowedOrigins: options.allowedOrigins }),
    ...(options.noConfig === true ? { noConfig: true } : {}),
    log,
  });

  const authorized = (request: http.IncomingMessage): boolean => {
    if (token === null) return true;
    const presented = parseBearer(request.headers.authorization);
    if (presented === null) return false;
    const given = Buffer.from(presented, "utf8");
    const expected = Buffer.from(token, "utf8");
    return given.length === expected.length && timingSafeEqual(given, expected);
  };

  const readJson = (
    request: http.IncomingMessage,
    response: http.ServerResponse,
    onDone: (body: Record<string, unknown>) => void,
    onError: (status: number, message: string, headers?: Record<string, string>) => void
  ): void => {
    const chunks: Buffer[] = [];
    let received = 0;
    let failed = false;
    let drained = 0;
    request.on("data", (chunk: Buffer) => {
      if (failed) {
        drained += chunk.length;
        if (drained > MAX_BODY) request.destroy();
        return;
      }
      received += chunk.length;
      if (received > MAX_BODY) {
        failed = true;
        chunks.length = 0;
        onError(413, "request body too large", { connection: "close" });
        return;
      }
      chunks.push(chunk);
    });
    request.on("error", () => {
      if (!response.writableEnded && !response.destroyed) {
        response.destroy();
      }
    });
    request.on("end", () => {
      if (failed) return;
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          onError(400, "body must be a JSON object");
          return;
        }
        onDone(parsed as Record<string, unknown>);
      } catch {
        onError(400, "invalid JSON");
      }
    });
  };

  const server = http.createServer((request, response) => {
    request.on("error", () => {
      if (!response.destroyed) response.destroy();
    });
    response.on("error", () => {
      if (!response.destroyed) response.destroy();
    });
    let url: URL;
    try {
      url = new URL(request.url ?? "/", "http://127.0.0.1");
    } catch {
      response.writeHead(400, { "content-type": "application/json; charset=utf-8" });
      response.end(JSON.stringify({ error: "malformed URL" }));
      return;
    }

    if (url.pathname === "/mcp" || url.pathname === "/sse" || url.pathname === "/messages") {
      if (mcp.handle(request, response)) return;
    }

    const origin = typeof request.headers.origin === "string" ? request.headers.origin : undefined;
    const cors: Record<string, string> = {};
    if (origin !== undefined) {
      if (!isLoopbackOrigin(origin) && !(options.allowedOrigins ?? []).includes(origin)) {
        response.writeHead(403, { "content-type": "text/plain" });
        response.end("origin not allowed");
        return;
      }
      cors["access-control-allow-origin"] = origin;
      cors["vary"] = "origin";
      cors["access-control-allow-headers"] = "authorization, content-type";
      cors["access-control-allow-methods"] = "GET, POST, OPTIONS";
    }

    let sent = false;
    const send = (status: number, body: unknown, extra: Record<string, string> = {}): void => {
      if (sent) return;
      sent = true;
      const text = typeof body === "string" ? body : JSON.stringify(body);
      response.writeHead(status, {
        ...cors,
        "content-type":
          typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8",
        "content-length": String(Buffer.byteLength(text, "utf8")),
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "content-security-policy":
          "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ...extra,
      });
      response.end(text);
    };

    if (request.method === "OPTIONS") {
      response.writeHead(204, cors);
      response.end();
      return;
    }

    if (request.method === "GET" && url.pathname === "/healthz") {
      send(200, { ok: true, name: PACKAGE_NAME, version: PACKAGE_VERSION, tools: mcp.toolCount });
      return;
    }

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      send(200, SERVE_PAGE, { "content-type": "text/html; charset=utf-8" });
      return;
    }

    if (!authorized(request)) {
      send(401, { error: "unauthorized" }, { "www-authenticate": 'Bearer realm="prompt-redact"' });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/audit") {
      send(200, playgroundVault.audit());
      return;
    }

    if (request.method === "POST" && url.pathname === "/api/redact") {
      readJson(
        request,
        response,
        (body) => {
          try {
            const text = typeof body.text === "string" ? body.text : "";
            const result = playgroundVault.redact(text, "serve:playground");
            send(200, {
              redacted: result.text,
              hits: result.hits,
              overflows: result.overflows,
              findings: result.findings,
            });
          } catch (err) {
            if (err instanceof VaultCapacityError) {
              send(503, { error: err.message });
              return;
            }
            send(500, { error: "internal error" });
          }
        },
        (status, message, extra) => send(status, { error: message }, extra)
      );
      return;
    }

    if (request.method === "POST" && url.pathname === "/api/rehydrate") {
      if (token === null) {
        send(403, {
          error:
            "rehydrate requires a bearer token; plaintext disclosure is disabled when the inspector runs with --no-auth",
        });
        return;
      }
      readJson(
        request,
        response,
        (body) => {
          const text = typeof body.text === "string" ? body.text : "";
          send(200, { text: playgroundVault.rehydrate(text) });
        },
        (status, message, extra) => send(status, { error: message }, extra)
      );
      return;
    }

    if (request.method === "POST" && url.pathname === "/api/sse-simulate") {
      if (token === null) {
        send(403, {
          error:
            "sse simulation returns rehydrated plaintext; it requires a bearer token and is disabled with --no-auth",
        });
        return;
      }
      readJson(
        request,
        response,
        (body) => {
          void (async () => {
            try {
              const text = typeof body.text === "string" ? body.text : "";
              const red = playgroundVault.redact(text, "serve:sse-sim");
              const half = Math.max(1, Math.floor(red.text.length / 2));
              const chunks = [
                `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: red.text.slice(0, half) } }] })}\n\n`,
                `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: red.text.slice(half) } }] })}\n\n`,
                `data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\n`,
                "data: [DONE]\n\n",
              ];
              const encoder = new TextEncoder();
              const stream = new ReadableStream<Uint8Array>({
                start(controller) {
                  for (const c of chunks) controller.enqueue(encoder.encode(c));
                  controller.close();
                },
              }).pipeThrough(createSseRehydrationTransform(playgroundVault, "openai"));
              const rehydratedSse = await new Response(stream).text();
              send(200, {
                tokenizedOutbound: red.text,
                hits: red.hits,
                rehydratedSse,
              });
            } catch (err) {
              if (err instanceof VaultCapacityError) {
                send(503, { error: err.message });
                return;
              }
              send(500, { error: "sse simulation failed" });
            }
          })();
        },
        (status, message, extra) => send(status, { error: message }, extra)
      );
      return;
    }

    send(404, { error: "not found" });
  });

  server.on("clientError", (_error, socket) => {
    if (socket.writable) {
      socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    } else {
      socket.destroy();
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  const addr = server.address();
  const actualPort = typeof addr === "object" && addr !== null ? addr.port : port;
  const display = host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host;
  const urlHost = display.includes(":") ? `[${display}]` : display;

  return {
    url: `http://${urlHost}:${actualPort}/`,
    host: display,
    port: actualPort,
    token,
    close: async () => {
      await mcp.close();
      server.closeAllConnections();
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    },
  };
}
