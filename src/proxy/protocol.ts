import type * as http from "node:http";
import type { SseProtocol } from "../core/sse.js";
import type { SecretVault } from "../types.js";

export interface ProxyUpstreamConfig {
  anthropicUpstream?: string;
  openaiUpstream?: string;
  upstream?: string;
}

export interface ResolvedUpstream {
  protocol: Exclude<SseProtocol, "auto">;
  targetUrl: string;
  targetHost: string;
  queryRedactions: number;
  queryOverflows: number;
  queryByRule: Record<string, number>;
}

export function normalizeUpstreamBase(raw: string, label: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    // Do not echo the raw value: upstream URLs can contain userinfo.
    throw new Error(`Invalid ${label} URL.`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`${label} must use http or https protocol (received ${url.protocol}).`);
  }
  return raw.replace(/\/+$/, "");
}

function isAnthropicRequest(pathname: string, headers?: http.IncomingHttpHeaders): boolean {
  if (
    pathname.startsWith("/v1/messages") ||
    pathname === "/messages" ||
    pathname.startsWith("/v1/complete")
  ) {
    return true;
  }
  if (!headers) return false;
  if (headers["anthropic-version"] !== undefined || headers["anthropic-beta"] !== undefined) {
    return true;
  }
  const hasApiKey = headers["x-api-key"] !== undefined;
  const auth = typeof headers.authorization === "string" ? headers.authorization.trim() : "";
  if (hasApiKey && !/^Bearer\s+/i.test(auth)) {
    return true;
  }
  return false;
}

export function resolveUpstreamTarget(
  requestUrl: string,
  config: ProxyUpstreamConfig,
  headers?: http.IncomingHttpHeaders,
  vault?: SecretVault
): ResolvedUpstream {
  let parsed: URL;
  try {
    parsed = new URL(requestUrl, "http://127.0.0.1");
  } catch {
    throw new Error("Malformed request URL.");
  }
  const pathname = parsed.pathname;
  const protocol: Exclude<SseProtocol, "auto"> = isAnthropicRequest(pathname, headers)
    ? "anthropic"
    : "openai";

  const baseRaw =
    config.upstream ??
    (protocol === "anthropic"
      ? (config.anthropicUpstream ?? "https://api.anthropic.com")
      : (config.openaiUpstream ?? "https://api.openai.com"));

  const base = normalizeUpstreamBase(baseRaw, `${protocol} upstream`);
  const baseUrl = new URL(base);
  const basePath = baseUrl.pathname.replace(/\/+$/, "");
  const rawEffectivePath =
    basePath.endsWith("/v1") && pathname.startsWith("/v1/")
      ? pathname.slice(3)
      : pathname;

  let queryRedactions = 0;
  let queryOverflows = 0;
  const queryByRule: Record<string, number> = {};
  let effectivePath = rawEffectivePath;
  let search = parsed.search;

  if (vault) {
    const segments = rawEffectivePath.split("/");
    let pathChanged = false;
    const rewrittenSegments = segments.map((seg) => {
      if (seg.length === 0) return seg;
      let decoded = seg;
      try {
        decoded = decodeURIComponent(seg);
      } catch {
        decoded = seg;
      }
      const red = vault.redact(decoded, `proxy:${protocol}:${baseUrl.host}:path`);
      if (red.hits > 0) {
        pathChanged = true;
        queryRedactions += red.hits;
        queryOverflows += red.overflows;
        for (const f of red.findings) {
          queryByRule[f.rule] = (queryByRule[f.rule] ?? 0) + f.count;
        }
        return encodeURIComponent(red.text);
      }
      return seg;
    });
    if (pathChanged) {
      effectivePath = rewrittenSegments.join("/");
    }
  }

  if (vault && parsed.search.length > 1) {
    const rewritten = new URLSearchParams();
    let changed = false;
    for (const [k, v] of parsed.searchParams.entries()) {
      const kRed = vault.redact(k, `proxy:${protocol}:${baseUrl.host}:query`);
      const vRed = vault.redact(v, `proxy:${protocol}:${baseUrl.host}:query`, k);
      const hits = kRed.hits + vRed.hits;
      if (hits > 0) changed = true;
      queryRedactions += hits;
      queryOverflows += kRed.overflows + vRed.overflows;
      for (const f of [...kRed.findings, ...vRed.findings]) {
        queryByRule[f.rule] = (queryByRule[f.rule] ?? 0) + f.count;
      }
      rewritten.append(kRed.text, vRed.text);
    }
    if (changed) {
      const serialized = rewritten.toString();
      search = serialized ? `?${serialized}` : "";
    }
  }

  const targetUrl = `${baseUrl.origin}${basePath}${effectivePath}${search}`;
  return {
    protocol,
    targetUrl,
    targetHost: baseUrl.host,
    queryRedactions,
    queryOverflows,
    queryByRule,
  };
}
