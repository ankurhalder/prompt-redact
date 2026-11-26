export interface HookEnvelope {
  toolName: string | null;
  toolInput: Record<string, unknown> | null;
}

const MAX_HOOK_STRINGS = 16384;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Claude Code passes a JSON envelope on stdin. Flatten its strings as
 * key=value pairs so credential assignments remain detectable (scanning a
 * bare value would lose the key context).
 */
function collectHookStrings(value: unknown, out: string[], depth = 0): void {
  if (depth > 32 || out.length >= MAX_HOOK_STRINGS) return;
  if (typeof value === "string") {
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectHookStrings(item, out, depth + 1);
    return;
  }
  if (isRecord(value)) {
    for (const [key, child] of Object.entries(value)) {
      if (typeof child === "string") {
        out.push(`${key}=${child}`);
      } else {
        collectHookStrings(child, out, depth + 1);
      }
    }
  }
}

export function extractHookText(raw: string): string {
  try {
    const parsed: unknown = JSON.parse(raw);
    const strings: string[] = [];
    collectHookStrings(parsed, strings);
    return strings.length > 0 ? strings.join("\n") : raw;
  } catch {
    return raw;
  }
}

export function parseHookEnvelope(raw: string): HookEnvelope | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) return null;
  const toolName = typeof parsed.tool_name === "string" ? parsed.tool_name : null;
  const toolInput = isRecord(parsed.tool_input) ? parsed.tool_input : null;
  return { toolName, toolInput };
}
