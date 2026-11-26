import * as http from "node:http";
import { timingSafeEqual } from "node:crypto";
import { createAuditRecorder } from "../core/audit.js";
import {
  PayloadDepthError,
  redactPayload,
  rehydrateJsonEncodedString,
  rehydratePayload,
} from "../core/payload.js";
import { wrapResponseWithRehydration } from "../core/sse.js";
import { VaultCapacityError, createVault } from "../core/vault.js";
import type { AuditRecorder, AuditSummary, SecretVault, VaultOptions } from "../types.js";
import { PACKAGE_NAME, PACKAGE_VERSION } from "../version.js";
import { resolveUpstreamTarget, type ProxyUpstreamConfig } from "./protocol.js";

export interface ProxyServerOptions extends ProxyUpstreamConfig {
  host?: string;
  port?: number;
  token?: string | null;
  dryRun?: boolean;
  maxBodyBytes?: number;
  /** Maximum buffered non-SSE upstream response size. Defaults to 32 MiB. */
  maxResponseBytes?: number;
  /** Time allowed for upstream response headers. Defaults to 120 s. */
  upstreamTimeoutMs?: number;
  vaultOptions?: VaultOptions;
  log?: (line: string) => void;
}

export interface ProxyServerHandle {
  url: string;
  host: string;
  port: number;
  token: string | null;
  audit(): AuditSummary;
  close(): Promise<void>;
}

const DEFAULT_PORT = 4790;
const DEFAULT_MAX_BODY = 16 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE = 32 * 1024 * 1024;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 120_000;
const MAX_IN_FLIGHT = 32;
const DRAIN_TIMEOUT_MS = 30_000;
const MAX_SESSIONS = 64;
const UTF8_FATAL = new TextDecoder("utf-8", { fatal: true });

function isLoopbackHost(host: string): boolean {
  return host === "127.0.0.1" || host === "localhost" || host === "::1" || host === "[::1]";
}

function parseBearer(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1].trim() : null;
}

function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  return left.length === right.length && timingSafeEqual(left, right);
}

function isBinaryContentType(contentType: string): boolean {
  return (
    contentType.startsWith("image/") ||
    contentType.startsWith("audio/") ||
    contentType.startsWith("video/") ||
    contentType.startsWith("application/octet-stream") ||
    contentType.startsWith("application/pdf") ||
    contentType.startsWith("application/zip")
  );
}

function isTextOrJsonResponse(contentType: string): boolean {
  if (contentType === "") return true;
  return (
    contentType.includes("json") ||
    contentType.startsWith("text/") ||
    contentType.includes("xml") ||
    contentType.includes("x-www-form-urlencoded")
  );
}

async function readBodyWithLimit(response: Response, limit: number): Promise<Buffer> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const declaredBytes = Number(declared);
    if (Number.isFinite(declaredBytes) && declaredBytes > limit) {
      await response.body?.cancel().catch(() => undefined);
      throw new Error(`upstream response exceeds ${limit} bytes`);
    }
  }
  const body = response.body;
  if (!body) return Buffer.alloc(0);
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.length;
      if (total > limit) {
        await reader.cancel().catch(() => undefined);
        throw new Error(`upstream response exceeds ${limit} bytes`);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks);
}

function buildUpstreamHeaders(
  incoming: http.IncomingHttpHeaders,
  proxyToken: string | null,
  bodyBytes?: Buffer
): Headers {
  const headers = new Headers();
  for (const [key, value] of Object.entries(incoming)) {
    if (value === undefined) continue;
    const lower = key.toLowerCase();
    if (
      lower === "host" ||
      lower === "connection" ||
      lower === "content-length" ||
      lower === "transfer-encoding" ||
      lower === "accept-encoding" ||
      lower === "content-encoding" ||
      lower === "cookie" ||
      lower === "referer" ||
      lower === "keep-alive" ||
      lower === "proxy-connection" ||
      lower === "te" ||
      lower === "trailer" ||
      lower === "upgrade" ||
      lower === "x-prompt-redact-token" ||
      lower === "x-prompt-redact-session" ||
      lower === "x-prompt-redact-mode" ||
      lower === "x-prompt-redact-dry-run"
    ) {
      continue;
    }
    const joined = Array.isArray(value) ? value.join(", ") : value;
    if (lower === "authorization" && proxyToken !== null) {
      const bearer = parseBearer(joined);
      if (bearer !== null && constantTimeEquals(bearer, proxyToken)) {
        continue;
      }
    }
    headers.set(key, joined);
  }
  if (bodyBytes !== undefined) {
    headers.set("content-length", String(bodyBytes.length));
  }
  return headers;
}

export async function startProxyServer(options: ProxyServerOptions = {}): Promise<ProxyServerHandle> {
  const rawHost = options.host ?? "127.0.0.1";
  const host = rawHost.startsWith("[") && rawHost.endsWith("]") ? rawHost.slice(1, -1) : rawHost;
  const port = options.port ?? DEFAULT_PORT;
  const token = options.token ?? null;
  if (token === null && !isLoopbackHost(host)) {
    throw new Error(
      `Refusing to bind proxy on non-loopback address ${host} without an auth token.`
    );
  }
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE;
  const upstreamTimeoutMs = options.upstreamTimeoutMs ?? DEFAULT_UPSTREAM_TIMEOUT_MS;
  const log = options.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  let inFlight = 0;
  const startedAt = Date.now();
  const auditRecorder: AuditRecorder = options.vaultOptions?.audit ?? createAuditRecorder();
  const sessions = new Map<string, SecretVault>();

  const getVaultForRequest = (request: http.IncomingMessage): {
    vault: SecretVault;
    sessionId: string;
  } => {
    const modeHeader = request.headers["x-prompt-redact-mode"];
    if (modeHeader === "ephemeral" || options.vaultOptions?.mode === "ephemeral") {
      return {
        vault: createVault({ ...options.vaultOptions, mode: "ephemeral", audit: auditRecorder }),
        sessionId: "ephemeral",
      };
    }
    const rawSession = request.headers["x-prompt-redact-session"];
    const sessionId =
      typeof rawSession === "string" && rawSession.trim().length > 0
        ? rawSession.trim().slice(0, 128)
        : "default";
    let vault = sessions.get(sessionId);
    if (vault) {
      sessions.delete(sessionId);
      sessions.set(sessionId, vault);
    } else {
      if (sessions.size >= MAX_SESSIONS) {
        const oldestKey = sessions.keys().next().value;
        if (oldestKey !== undefined) sessions.delete(oldestKey);
      }
      vault = createVault({ ...options.vaultOptions, mode: "session", audit: auditRecorder });
      sessions.set(sessionId, vault);
    }
    return { vault, sessionId };
  };

  const combinedAudit = (): AuditSummary => {
    let vaultSize = 0;
    let overflowCount = 0;
    for (const v of sessions.values()) {
      vaultSize += v.size;
      overflowCount += v.overflowCount;
    }
    return auditRecorder.summary(
      vaultSize,
      options.vaultOptions?.maxEntries ?? 1024,
      overflowCount
    );
  };

  const server = http.createServer((request, response) => {
    response.on("error", () => {
      if (!response.destroyed) response.destroy();
    });
    const sendJson = (status: number, body: unknown, extraHeaders: Record<string, string> = {}): void => {
      if (response.headersSent || response.writableEnded || response.destroyed) return;
      const payload = JSON.stringify(body);
      response.writeHead(status, {
        "content-type": "application/json; charset=utf-8",
        "content-length": String(Buffer.byteLength(payload, "utf8")),
        "x-content-type-options": "nosniff",
        ...extraHeaders,
      });
      response.end(payload);
    };

    if (token !== null) {
      const dedicated =
        typeof request.headers["x-prompt-redact-token"] === "string"
          ? request.headers["x-prompt-redact-token"].trim()
          : null;
      const bearer = parseBearer(request.headers.authorization);
      const presented = dedicated ?? bearer;
      if (presented === null || !constantTimeEquals(presented, token)) {
        sendJson(401, { error: "unauthorized" }, { "www-authenticate": 'Bearer realm="prompt-redact"' });
        return;
      }
    }

    let reqUrl: URL;
    try {
      reqUrl = new URL(request.url ?? "/", "http://127.0.0.1");
    } catch {
      sendJson(400, { error: "malformed_url" });
      return;
    }

    if (request.method === "GET" && reqUrl.pathname === "/healthz") {
      const summary = combinedAudit();
      sendJson(200, {
        ok: true,
        name: PACKAGE_NAME,
        version: PACKAGE_VERSION,
        uptimeMs: Date.now() - startedAt,
        sessions: sessions.size,
        vaultSize: summary.vaultSize,
        totalRedactions: summary.totalRedactions,
        overflowCount: summary.overflowCount,
      });
      return;
    }

    if (request.method === "GET" && reqUrl.pathname === "/audit") {
      sendJson(200, combinedAudit());
      return;
    }

    const contentEncoding = String(request.headers["content-encoding"] ?? "").trim().toLowerCase();
    if (contentEncoding !== "" && contentEncoding !== "identity") {
      sendJson(415, {
        error: "unsupported_content_encoding",
        message: "Compressed request bodies cannot be inspected; send uncompressed UTF-8.",
      });
      return;
    }

    const chunks: Buffer[] = [];
    let received = 0;
    let tooLarge = false;
    let drained = 0;

    request.on("data", (chunk: Buffer) => {
      if (tooLarge) {
        // Keep the socket readable just long enough for the 413 to reach the
        // client, but bound the drain so a hostile upload cannot run forever.
        drained += chunk.length;
        if (drained > maxBodyBytes) request.destroy();
        return;
      }
      received += chunk.length;
      if (received > maxBodyBytes) {
        tooLarge = true;
        chunks.length = 0;
        sendJson(413, { error: "payload_too_large", limit: maxBodyBytes }, { connection: "close" });
        return;
      }
      chunks.push(chunk);
    });

    request.on("error", () => {
      if (!response.writableEnded) response.destroy();
    });

    request.on("end", () => {
      if (tooLarge) return;
      if (inFlight >= MAX_IN_FLIGHT) {
        sendJson(503, { error: "server_busy", message: "too many proxy requests are in flight" });
        return;
      }
      inFlight += 1;
      void (async () => {
        const isDryRun =
          options.dryRun === true || request.headers["x-prompt-redact-dry-run"] === "1";

        const { vault, sessionId } = isDryRun
          ? {
              vault: createVault({
                ...options.vaultOptions,
                mode: "ephemeral",
                audit: createAuditRecorder(),
              }),
              sessionId: "dry-run",
            }
          : getVaultForRequest(request);

        let resolved: ReturnType<typeof resolveUpstreamTarget>;
        try {
          resolved = resolveUpstreamTarget(request.url ?? "/", options, request.headers, vault);
        } catch (err) {
          if (err instanceof VaultCapacityError) {
            sendJson(503, {
              error: "vault_capacity_exceeded",
              message: err.message,
              maxEntries: err.maxEntries,
            });
            return;
          }
          sendJson(400, { error: "invalid_upstream", message: (err as Error).message });
          return;
        }

        const rawBuffer = Buffer.concat(chunks);
        let outboundBuffer = rawBuffer;
        let redactedCount = resolved.queryRedactions;
        let overflowCount = resolved.queryOverflows;
        const byRule: Record<string, number> = { ...resolved.queryByRule };
        let sanitizedPayloadForDryRun: unknown = undefined;

        const method = request.method ?? "GET";
        const contentType = String(request.headers["content-type"] ?? "").toLowerCase();

        if (rawBuffer.length > 0) {
          if (isBinaryContentType(contentType) || rawBuffer.includes(0)) {
            sendJson(415, {
              error: "binary_payload_unsupported",
              message: "Opaque binary request bodies cannot be verified for plaintext secrets.",
            });
            return;
          }

          let text: string;
          try {
            text = UTF8_FATAL.decode(rawBuffer);
          } catch {
            sendJson(415, {
              error: "non_utf8_payload_unsupported",
              message: "Request body is not valid UTF-8.",
            });
            return;
          }

          const trimmed = text.trimStart();
          const maybeJson = contentType.includes("json") || trimmed.startsWith("{") || trimmed.startsWith("[");
          let parsed: unknown;
          let isJson = false;
          if (maybeJson) {
            try {
              parsed = JSON.parse(text);
              isJson = true;
            } catch {
              isJson = false;
            }
          }

          try {
            if (isJson) {
              const redaction = redactPayload(parsed, vault, `proxy:${resolved.protocol}:${resolved.targetHost}`);
              redactedCount += redaction.redactedCount;
              overflowCount += redaction.overflowCount;
              for (const [r, c] of Object.entries(redaction.byRule)) {
                byRule[r] = (byRule[r] ?? 0) + c;
              }
              sanitizedPayloadForDryRun = redaction.payload;
              outboundBuffer = Buffer.from(JSON.stringify(redaction.payload), "utf8");
            } else {
              const res = vault.redact(text, `proxy:${resolved.protocol}:${resolved.targetHost}`);
              redactedCount += res.hits;
              overflowCount += res.overflows;
              for (const f of res.findings) {
                byRule[f.rule] = (byRule[f.rule] ?? 0) + f.count;
              }
              sanitizedPayloadForDryRun = res.text;
              outboundBuffer = Buffer.from(res.text, "utf8");
            }
          } catch (err) {
            if (err instanceof VaultCapacityError) {
              sendJson(503, {
                error: "vault_capacity_exceeded",
                message: err.message,
                maxEntries: err.maxEntries,
              });
              return;
            }
            if (err instanceof PayloadDepthError) {
              sendJson(400, {
                error: "payload_depth_exceeded",
                message: err.message,
              });
              return;
            }
            throw err;
          }
        }

        if (isDryRun) {
          sendJson(200, {
            dryRun: true,
            protocol: resolved.protocol,
            upstreamUrl: resolved.targetUrl,
            sessionId,
            redactedCount,
            overflowCount,
            byRule,
            sanitizedBody: sanitizedPayloadForDryRun ?? null,
          });
          return;
        }

        const abortController = new AbortController();
        const onAbort = (): void => {
          if (!response.writableEnded) {
            abortController.abort();
          }
        };
        request.on("aborted", onAbort);
        response.on("close", onAbort);

        let upstreamTimedOut = false;
        const headerTimer = setTimeout(() => {
          upstreamTimedOut = true;
          abortController.abort();
        }, upstreamTimeoutMs);

        try {
          const upstreamHeaders = buildUpstreamHeaders(
            request.headers,
            token,
            method === "GET" || method === "HEAD" ? undefined : outboundBuffer
          );
          const upstreamResponse = await fetch(resolved.targetUrl, {
            method,
            headers: upstreamHeaders,
            body: method === "GET" || method === "HEAD" ? undefined : new Uint8Array(outboundBuffer),
            redirect: "manual",
            signal: abortController.signal,
          });
          clearTimeout(headerTimer);

          const responseContentType = (upstreamResponse.headers.get("content-type") ?? "").toLowerCase();
          const baseHeaders: Record<string, string> = {};
          upstreamResponse.headers.forEach((value, key) => {
            const lower = key.toLowerCase();
            if (
              lower === "content-length" ||
              lower === "content-encoding" ||
              lower === "transfer-encoding" ||
              lower === "connection" ||
              lower === "keep-alive" ||
              lower === "proxy-connection" ||
              lower === "te" ||
              lower === "trailer" ||
              lower === "upgrade"
            ) {
              return;
            }
            baseHeaders[key] = value;
          });
          baseHeaders["x-prompt-redact-count"] = String(redactedCount);
          baseHeaders["x-prompt-redact-overflows"] = String(overflowCount);
          baseHeaders["x-prompt-redact-session"] = sessionId;

          if (responseContentType.includes("text/event-stream") && upstreamResponse.body) {
            const wrapped = wrapResponseWithRehydration(
              upstreamResponse,
              vault,
              resolved.protocol
            );
            response.writeHead(upstreamResponse.status, {
              ...baseHeaders,
              "content-type": "text/event-stream; charset=utf-8",
              "cache-control": "no-cache, no-transform",
              "x-accel-buffering": "no",
            });
            const reader = wrapped.body?.getReader();
            if (!reader) {
              response.end();
              return;
            }
            const waitForDrain = (): Promise<void> =>
              new Promise((resolve) => {
                const timer = setTimeout(() => {
                  cleanup();
                  if (!response.destroyed) response.destroy();
                  resolve();
                }, DRAIN_TIMEOUT_MS);
                if (typeof timer.unref === "function") timer.unref();
                const cleanup = (): void => {
                  clearTimeout(timer);
                  response.off("drain", done);
                  response.off("close", done);
                  response.off("error", done);
                };
                const done = (): void => {
                  cleanup();
                  resolve();
                };
                response.on("drain", done);
                response.on("close", done);
                response.on("error", done);
              });
            let streamErrored = false;
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                if (value && value.length > 0 && !response.writableEnded && !response.destroyed) {
                  const accepted = response.write(value);
                  if (!accepted) await waitForDrain();
                }
              }
            } catch (streamErr) {
              streamErrored = true;
              log(`proxy sse stream error: ${(streamErr as Error).message}`);
              if (!response.destroyed) {
                // Destroy without an Error: emitting an 'error' event on a
                // response with no listener can crash the process.
                response.destroy();
              }
            } finally {
              reader.releaseLock();
              if (!streamErrored && !response.writableEnded && !response.destroyed) {
                response.end();
              }
            }
            return;
          }

          const rawRespBytes = await readBodyWithLimit(upstreamResponse, maxResponseBytes);
          let finalBytes = rawRespBytes;
          if (
            vault.size > 0 &&
            !isBinaryContentType(responseContentType) &&
            isTextOrJsonResponse(responseContentType) &&
            !rawRespBytes.includes(0)
          ) {
            // Only re-encode when the bytes are definitely valid UTF-8. A body
            // without a textual content type may be binary; decoding it with
            // replacement characters silently corrupted such responses.
            let rawResponseText: string | null = null;
            try {
              rawResponseText = UTF8_FATAL.decode(rawRespBytes);
            } catch {
              rawResponseText = null;
            }
            if (rawResponseText !== null) {
              let finalBodyText = rawResponseText;
              if (responseContentType.includes("json")) {
                try {
                  const parsedResp = JSON.parse(rawResponseText) as unknown;
                  finalBodyText = JSON.stringify(rehydratePayload(parsedResp, vault));
                } catch {
                  finalBodyText = rehydrateJsonEncodedString(rawResponseText, vault);
                }
              } else {
                finalBodyText = vault.rehydrate(rawResponseText);
              }
              finalBytes = Buffer.from(finalBodyText, "utf8");
            }
          }

          response.writeHead(upstreamResponse.status, {
            ...baseHeaders,
            "content-length": String(finalBytes.length),
          });
          response.end(finalBytes);
        } catch (err) {
          clearTimeout(headerTimer);
          if (abortController.signal.aborted) {
            if (upstreamTimedOut) {
              sendJson(504, {
                error: "upstream_timeout",
                message: "upstream did not produce response headers in time",
              });
            } else if (!response.writableEnded && !response.destroyed) {
              response.destroy();
            }
            return;
          }
          sendJson(502, {
            error: "upstream_error",
            message: (err as Error).message,
          });
        } finally {
          clearTimeout(headerTimer);
          request.off("aborted", onAbort);
          response.off("close", onAbort);
        }
      })()
        .catch((err: unknown) => {
          log(`proxy error: ${(err as Error).message}`);
          sendJson(500, { error: "internal_proxy_error" });
        })
        .finally(() => {
          inFlight = Math.max(0, inFlight - 1);
        });
    });
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
  const displayHost = host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host;
  const urlHost = displayHost.includes(":") ? `[${displayHost}]` : displayHost;

  return {
    url: `http://${urlHost}:${actualPort}`,
    host: displayHost,
    port: actualPort,
    token,
    audit: combinedAudit,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    },
  };
}
