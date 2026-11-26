import type { PayloadRedactionResult, RedactTextResult, SecretVault, VaultOptions } from "../types.js";
import { createVault } from "./vault.js";

const MAX_WALK_DEPTH = 64;

export class PayloadDepthError extends Error {
  readonly maxDepth: number;

  constructor(maxDepth: number) {
    super(`Payload exceeds maximum nesting depth of ${maxDepth}; fail-closed abort triggered.`);
    this.name = "PayloadDepthError";
    this.maxDepth = maxDepth;
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const jsonTokenPatterns = new WeakMap<SecretVault, RegExp>();

function jsonTokenPattern(vault: SecretVault): RegExp {
  let pattern = jsonTokenPatterns.get(vault);
  if (pattern === undefined) {
    pattern = new RegExp(
      `<<${escapeRegExp(vault.tokenPrefix)}:${escapeRegExp(vault.salt)}:\\d+>>`,
      "g"
    );
    jsonTokenPatterns.set(vault, pattern);
  }
  pattern.lastIndex = 0;
  return pattern;
}

export function rehydrateJsonEncodedString(text: string, vault: SecretVault): string {
  if (!text || vault.size === 0) return text;
  const pattern = jsonTokenPattern(vault);
  return text.replace(pattern, (token) => {
    const secret = vault.resolveToken(token);
    return secret === undefined ? token : JSON.stringify(secret).slice(1, -1);
  });
}

function isJsonEncodedField(keyPath: string, parent: Record<string, unknown> | null): boolean {
  if (keyPath.endsWith("/function/arguments") || keyPath.endsWith("/partial_json")) {
    return true;
  }
  if (
    keyPath.endsWith("/arguments") &&
    parent !== null &&
    (parent.type === "function_call" ||
      typeof parent.call_id === "string" ||
      typeof parent.name === "string")
  ) {
    return true;
  }
  return false;
}

function collectStrings(
  value: unknown,
  out: Array<{ text: string; contextKey?: string }>,
  depth = 0
): void {
  if (depth > MAX_WALK_DEPTH) {
    throw new PayloadDepthError(MAX_WALK_DEPTH);
  }
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const entry of value) {
      if (typeof entry === "string") {
        out.push({ text: entry });
      } else {
        collectStrings(entry, out, depth + 1);
      }
    }
    return;
  }
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    out.push({ text: key });
    const entry = record[key];
    if (typeof entry === "string") {
      out.push({ text: entry, contextKey: key });
    } else {
      collectStrings(entry, out, depth + 1);
    }
  }
}

function setOwnProperty(record: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(record, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

function walkAndTransform(
  value: unknown,
  transform: (text: string, keyPath: string, parent: Record<string, unknown> | null) => string,
  depth = 0,
  keyPath = ""
): void {
  if (depth > MAX_WALK_DEPTH) {
    throw new PayloadDepthError(MAX_WALK_DEPTH);
  }
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      const entry = value[i];
      const childPath = `${keyPath}/${i}`;
      if (typeof entry === "string") {
        value[i] = transform(entry, childPath, null);
      } else {
        walkAndTransform(entry, transform, depth + 1, childPath);
      }
    }
    return;
  }
  const record = value as Record<string, unknown>;
  const entries = Object.entries(record);
  let keyChanged = false;
  const rebuilt: Array<[string, unknown]> = [];
  for (const [rawKey, entry] of entries) {
    const newKey = transform(rawKey, `${keyPath}/@key`, record);
    if (newKey !== rawKey) keyChanged = true;
    const childPath = `${keyPath}/${newKey}`;
    if (typeof entry === "string") {
      const nextVal = transform(entry, childPath, record);
      rebuilt.push([newKey, nextVal]);
    } else {
      walkAndTransform(entry, transform, depth + 1, childPath);
      rebuilt.push([newKey, entry]);
    }
  }
  if (keyChanged) {
    for (const k of Object.keys(record)) {
      delete record[k];
    }
  }
  for (const [k, v] of rebuilt) {
    setOwnProperty(record, k, v);
  }
}

/**
 * Iterative depth check that runs BEFORE JSON cloning. The recursive walkers
 * below are depth-guarded, but JSON.parse/JSON.stringify can overflow the
 * stack on very deep documents before those guards ever run, producing a raw
 * RangeError instead of the documented fail-closed PayloadDepthError.
 */
function assertWithinDepth(value: unknown): void {
  const seen = new WeakSet<object>();
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  while (stack.length > 0) {
    const current = stack.pop() as { value: unknown; depth: number };
    if (current.depth > MAX_WALK_DEPTH) {
      throw new PayloadDepthError(MAX_WALK_DEPTH);
    }
    const entry = current.value;
    if (entry === null || typeof entry !== "object") continue;
    if (seen.has(entry as object)) continue;
    seen.add(entry as object);
    if (Array.isArray(entry)) {
      for (const item of entry) {
        stack.push({ value: item, depth: current.depth + 1 });
      }
    } else {
      for (const child of Object.values(entry as Record<string, unknown>)) {
        stack.push({ value: child, depth: current.depth + 1 });
      }
    }
  }
}

function cloneJson<T>(value: T): T {
  try {
    return JSON.parse(JSON.stringify(value)) as T;
  } catch (err) {
    if (err instanceof RangeError) {
      throw new PayloadDepthError(MAX_WALK_DEPTH);
    }
    throw err;
  }
}

export function redactPayload<T>(
  payload: T,
  vaultOrOptions?: SecretVault | VaultOptions,
  source = "payload"
): PayloadRedactionResult<T> {
  const vault =
    vaultOrOptions && "redact" in vaultOrOptions
      ? vaultOrOptions
      : createVault(vaultOrOptions);
  let redactedCount = 0;
  let overflowCount = 0;
  const byRule: Record<string, number> = {};

  const recordResult = (result: RedactTextResult): string => {
    redactedCount += result.hits;
    overflowCount += result.overflows;
    for (const finding of result.findings) {
      byRule[finding.rule] = (byRule[finding.rule] ?? 0) + finding.count;
    }
    return result.text;
  };

  if (typeof payload === "string") {
    const redactedText = recordResult(vault.redact(payload, source));
    return {
      payload: redactedText as unknown as T,
      redactedCount,
      overflowCount,
      byRule,
      vault,
    };
  }

  if (payload === null || payload === undefined || typeof payload !== "object") {
    return {
      payload,
      redactedCount: 0,
      overflowCount: 0,
      byRule: {},
      vault,
    };
  }

  assertWithinDepth(payload);
  const cloned = cloneJson(payload);
  const strings: Array<{ text: string; contextKey?: string }> = [];
  collectStrings(cloned, strings);
  const results = vault.redactBatch(strings, source);
  let cursor = 0;
  walkAndTransform(cloned, () => {
    const res = results[cursor] as RedactTextResult;
    cursor += 1;
    return recordResult(res);
  });

  return {
    payload: cloned,
    redactedCount,
    overflowCount,
    byRule,
    vault,
  };
}

export function rehydratePayload<T>(payload: T, vault: SecretVault): T {
  if (vault.size === 0 || payload === null || payload === undefined) return payload;
  if (typeof payload === "string") {
    return vault.rehydrate(payload) as unknown as T;
  }
  if (typeof payload !== "object") return payload;
  assertWithinDepth(payload);
  const cloned = cloneJson(payload);
  walkAndTransform(cloned, (text, keyPath, parent) => {
    if (isJsonEncodedField(keyPath, parent)) {
      return rehydrateJsonEncodedString(text, vault);
    }
    return vault.rehydrate(text);
  });
  return cloned;
}
