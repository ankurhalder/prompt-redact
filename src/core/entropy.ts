import type { EntropyConfig } from "../types.js";

const PLACEHOLDER_VALUE =
  /^(?:changeme|change_me|change-me|todo|tbd|xxx+|x{3,}|placeholder|dummy|sample|example|replace_?me|insert_?here|your[_-].*|none|null|undefined|password|secret|redacted|masked)$/i;

const TOKEN_SHAPE =
  /^(?:<<[A-Za-z0-9_-]+:[A-Za-z0-9_-]+:(?:\d+|[a-f0-9]+)>>|<<redact-masked:[a-f0-9]+>>|<<redact-hash:[a-f0-9]+>>)$/;

const PURE_HEX = /^[0-9a-fA-F]+$/;

const CANDIDATE_PATTERN = /(?<![A-Za-z0-9_/+=-])[A-Za-z0-9_/+=-]{16,256}(?![A-Za-z0-9_/+=-])/g;

export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i] as string;
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

export function isPlaceholderValue(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) return true;
  if (TOKEN_SHAPE.test(trimmed)) return true;
  if (PLACEHOLDER_VALUE.test(trimmed)) return true;
  if (/^\[REDACTED(?::[^\]]*)?\]$/i.test(trimmed)) return true;
  if (/^\*+$/.test(trimmed)) return true;
  return false;
}

function hasMixedClasses(value: string): boolean {
  let classes = 0;
  if (/[a-z]/.test(value)) classes += 1;
  if (/[A-Z]/.test(value)) classes += 1;
  if (/[0-9]/.test(value)) classes += 1;
  if (/[_/+=-]/.test(value)) classes += 1;
  return classes >= 3;
}

function looksLikePathOrIdentifier(value: string): boolean {
  if (value.includes("/") && !value.includes("=") && !value.includes("+")) {
    const slashCount = value.split("/").length - 1;
    if (slashCount >= 2 && /^[a-z0-9._/-]+$/i.test(value)) return true;
  }
  if (/^[a-z]+(?:[A-Z][a-z0-9]+){2,}$/.test(value)) return true;
  if (/^[a-z0-9]+(?:_[a-z0-9]+){2,}$/.test(value)) return true;
  return false;
}

export function findHighEntropySpans(
  text: string,
  config?: EntropyConfig
): Array<{ start: number; end: number; value: string }> {
  if (!config?.enabled) return [];
  const minLength = Math.max(16, config.minLength ?? 24);
  const threshold = config.threshold ?? 4.2;
  const spans: Array<{ start: number; end: number; value: string }> = [];
  CANDIDATE_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = CANDIDATE_PATTERN.exec(text)) !== null) {
    const value = match[0];
    if (value.length < minLength) continue;
    if (PURE_HEX.test(value) && value.length <= 64) continue;
    if (isPlaceholderValue(value)) continue;
    if (!hasMixedClasses(value)) continue;
    if (looksLikePathOrIdentifier(value)) continue;
    if (shannonEntropy(value) >= threshold) {
      spans.push({ start: match.index, end: match.index + value.length, value });
    }
  }
  return spans;
}
