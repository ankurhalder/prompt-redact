import * as crypto from "node:crypto";
import type {
  AuditRecorder,
  AuditSummary,
  OverflowPolicy,
  RedactTextResult,
  SecretRule,
  SecretVault,
  VaultMode,
  VaultOptions,
} from "../types.js";
import { createAuditRecorder } from "./audit.js";
import { compileAllowlist, isAllowlisted } from "./config.js";
import { findHighEntropySpans, isPlaceholderValue } from "./entropy.js";
import {
  ASSIGNMENT_RULE_NAMES,
  DEFAULT_SECRET_PATTERNS,
  PEM_BLOCK_PATTERN,
  PEM_UNTERMINATED_PATTERN,
  isStrongCredentialKey,
  textMayContainCredentialAssignment,
} from "./patterns.js";

export const DEFAULT_MAX_VAULT_ENTRIES = 1024;
export const DEFAULT_TOKEN_PREFIX = "redact";

export class VaultCapacityError extends Error {
  readonly maxEntries: number;
  readonly rule: string;

  constructor(maxEntries: number, rule: string) {
    super(
      `Vault capacity of ${maxEntries} distinct secrets exceeded on rule "${rule}". Fail-closed abort triggered.`
    );
    this.name = "VaultCapacityError";
    this.maxEntries = maxEntries;
    this.rule = rule;
  }
}

export interface CandidateSpan {
  start: number;
  end: number;
  rule: string;
}

interface CompiledRule {
  rule: string;
  pattern: RegExp;
  valueGroup?: number;
}

interface MatchWithIndices {
  indices?: Array<[number, number] | undefined>;
}

const NON_CREDENTIAL_VALUE_RE =
  /^(?:string|number|boolean|bigint|symbol|unknown|any|never|void|null|undefined|true|false|await|async|new|this|typeof|delete|yield|function|return|process\.env(?:\.[A-Za-z0-9_]+)*|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|Buffer|Record|object)$/i;
const AWS_SECRET_VALUE_RE =
  /^(?=[A-Za-z0-9/+=]{40}$)(?=[A-Za-z0-9/+=]{0,39}[A-Z])(?=[A-Za-z0-9/+=]{0,39}[a-z])(?=[A-Za-z0-9/+=]{0,39}[0-9])[A-Za-z0-9/+=]{40}$/;
const UUID_VALUE_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function classifyContextualValueRule(text: string): string {
  const trimmed = text.trim();
  if (AWS_SECRET_VALUE_RE.test(trimmed)) return "aws-secret-access-key";
  if (UUID_VALUE_RE.test(trimmed)) return "postmark-uuid-secret";
  return "credential-assignment-structured";
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function advanceIndex(text: string, index: number, unicode: boolean): number {
  if (!unicode) return index + 1;
  const first = text.charCodeAt(index);
  if (first >= 0xd800 && first <= 0xdbff) {
    const second = text.charCodeAt(index + 1);
    if (second >= 0xdc00 && second <= 0xdfff) return index + 2;
  }
  return index + 1;
}

function compileGlobalRule(rule: SecretRule): CompiledRule {
  const flags = new Set(rule.pattern.flags.replace(/[gy]/g, "").split(""));
  flags.add("g");
  if (rule.valueGroup !== undefined) flags.add("d");
  return {
    rule: rule.rule,
    pattern: new RegExp(rule.pattern.source, [...flags].join("")),
    ...(rule.valueGroup === undefined ? {} : { valueGroup: rule.valueGroup }),
  };
}

/**
 * Overflow masks are deliberately NOT derived from the secret. A deterministic
 * hash (even HMAC with the vault salt) is an offline oracle for low-entropy
 * secrets because the salt travels in normal tokens; a random opaque mask
 * cannot be verified or brute-forced and cannot be correlated across calls.
 */
function opaqueOverflowMask(): string {
  return `<<redact-masked:${crypto.randomBytes(6).toString("hex")}>>`;
}

export function coalesceSpans(spans: CandidateSpan[]): CandidateSpan[] {
  if (spans.length <= 1) return spans;
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
  const merged: CandidateSpan[] = [];
  for (const span of sorted) {
    const prev = merged[merged.length - 1];
    if (!prev || span.start >= prev.end) {
      merged.push({ ...span });
      continue;
    }
    if (span.end > prev.end) {
      prev.end = span.end;
    }
  }
  return merged;
}

export function createVault(options: VaultOptions = {}): SecretVault {
  const mode: VaultMode = options.mode ?? "session";
  const tokenPrefix =
    (options.tokenPrefix ?? DEFAULT_TOKEN_PREFIX).replace(/[^A-Za-z0-9_-]/g, "") ||
    DEFAULT_TOKEN_PREFIX;
  const sanitizedSalt = options.salt?.replace(/[^A-Za-z0-9_-]/g, "");
  const salt =
    sanitizedSalt && sanitizedSalt.length > 0
      ? sanitizedSalt
      : crypto.randomBytes(16).toString("hex");
  const maxEntries = options.maxEntries ?? DEFAULT_MAX_VAULT_ENTRIES;
  if (!Number.isInteger(maxEntries) || maxEntries < 1) {
    throw new Error(`maxEntries must be a positive integer (received ${String(maxEntries)}).`);
  }
  const overflowPolicy: OverflowPolicy = options.overflowPolicy ?? "hash";
  const audit: AuditRecorder = options.audit ?? createAuditRecorder();
  const defaultSource = options.source ?? "vault";
  const allowlist = compileAllowlist(options.allowlist);
  const rules = (options.rules ?? DEFAULT_SECRET_PATTERNS).map(compileGlobalRule);

  const escapedPrefix = escapeRegex(tokenPrefix);
  const escapedSalt = escapeRegex(salt);
  const existingTokenPattern = new RegExp(
    `<<(?:${escapedPrefix}:${escapedSalt}:\\d+|redact-masked:[a-f0-9]{12}|redact-hash:[a-f0-9]{12})>>`,
    "g"
  );
  const activeTokenPattern = new RegExp(
    `<<${escapedPrefix}:${escapedSalt}:\\d+>>`,
    "g"
  );

  const bySecret = new Map<string, string>();
  const byToken = new Map<string, string>();
  let nextIndex = 1;
  let overflowCount = 0;
  let maxTokenLength = `<<redact-masked:000000000000>>`.length;

  const tokenFor = (secret: string, rule: string): { token: string; overflowed: boolean } => {
    const existing = bySecret.get(secret);
    if (existing !== undefined) {
      return { token: existing, overflowed: false };
    }
    if (bySecret.size >= maxEntries) {
      if (overflowPolicy === "error") {
        throw new VaultCapacityError(maxEntries, rule);
      }
      overflowCount += 1;
      const mask = opaqueOverflowMask();
      maxTokenLength = Math.max(maxTokenLength, mask.length);
      return { token: mask, overflowed: true };
    }
    const token = `<<${tokenPrefix}:${salt}:${nextIndex}>>`;
    nextIndex += 1;
    bySecret.set(secret, token);
    byToken.set(token, secret);
    maxTokenLength = Math.max(maxTokenLength, token.length);
    return { token, overflowed: false };
  };

  const tokenRangesIn = (text: string): Array<[number, number]> => {
    const ranges: Array<[number, number]> = [];
    existingTokenPattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = existingTokenPattern.exec(text)) !== null) {
      ranges.push([match.index, match.index + match[0].length]);
    }
    return ranges;
  };

  const containedInExistingToken = (
    ranges: Array<[number, number]>,
    start: number,
    end: number
  ): boolean => ranges.some(([rs, re]) => start >= rs && end <= re);

  const collectSpans = (text: string, contextKey?: string): CandidateSpan[] => {
    if (!text || text.length === 0) return [];
    const existingRanges = tokenRangesIn(text);
    const candidates: CandidateSpan[] = [];

    for (const blockPattern of [PEM_BLOCK_PATTERN, PEM_UNTERMINATED_PATTERN]) {
      blockPattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = blockPattern.exec(text)) !== null) {
        if (match[0].length === 0) {
          blockPattern.lastIndex = advanceIndex(text, match.index, blockPattern.unicode);
          continue;
        }
        const start = match.index;
        const end = start + match[0].length;
        if (containedInExistingToken(existingRanges, start, end)) continue;
        const matchedText = text.slice(start, end);
        if (!isAllowlisted(matchedText, allowlist)) {
          candidates.push({ start, end, rule: "private-key-block" });
        }
      }
    }

    const assignmentHint = textMayContainCredentialAssignment(text);
    for (const { rule, pattern, valueGroup } of rules) {
      if (!assignmentHint && ASSIGNMENT_RULE_NAMES.has(rule)) continue;
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(text)) !== null) {
        if (match[0].length === 0) {
          pattern.lastIndex = advanceIndex(text, match.index, pattern.unicode);
          continue;
        }
        const group =
          valueGroup === undefined
            ? undefined
            : (match as RegExpExecArray & MatchWithIndices).indices?.[valueGroup];
        const start = group ? group[0] : match.index;
        const end = group ? group[1] : match.index + match[0].length;
        if (end <= start) continue;
        if (containedInExistingToken(existingRanges, start, end)) continue;
        const value = text.slice(start, end);
        if (isPlaceholderValue(value)) continue;
        if (isAllowlisted(value, allowlist)) continue;
        candidates.push({ start, end, rule });
      }
    }

    for (const entropySpan of findHighEntropySpans(text, options.entropy)) {
      if (containedInExistingToken(existingRanges, entropySpan.start, entropySpan.end)) continue;
      if (isAllowlisted(entropySpan.value, allowlist)) continue;
      candidates.push({ start: entropySpan.start, end: entropySpan.end, rule: "high-entropy" });
    }

    const merged = coalesceSpans(candidates);
    if (
      merged.length === 0 &&
      contextKey !== undefined &&
      isStrongCredentialKey(contextKey) &&
      text.trim().length >= 6 &&
      text.length <= 4096 &&
      !containedInExistingToken(existingRanges, 0, text.length) &&
      !isPlaceholderValue(text) &&
      !NON_CREDENTIAL_VALUE_RE.test(text.trim()) &&
      !isAllowlisted(text, allowlist)
    ) {
      return [{ start: 0, end: text.length, rule: classifyContextualValueRule(text) }];
    }

    return merged;
  };

  const applySpans = (text: string, spans: readonly CandidateSpan[], source: string): RedactTextResult => {
    if (spans.length === 0) {
      return { text, hits: 0, overflows: 0, findings: [] };
    }

    const parts: string[] = [];
    const ruleCounts = new Map<string, number>();
    const overflowCounts = new Map<string, number>();
    let cursor = 0;
    let hits = 0;
    let overflows = 0;

    for (const span of spans) {
      const secret = text.slice(span.start, span.end);
      const { token, overflowed } = tokenFor(secret, span.rule);
      parts.push(text.slice(cursor, span.start));
      parts.push(token);
      cursor = span.end;
      hits += 1;
      if (overflowed) {
        overflows += 1;
        overflowCounts.set(span.rule, (overflowCounts.get(span.rule) ?? 0) + 1);
      }
      ruleCounts.set(span.rule, (ruleCounts.get(span.rule) ?? 0) + 1);
    }
    parts.push(text.slice(cursor));

    const findings = [...ruleCounts.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([rule, count]) => ({ rule, count }));

    for (const { rule, count } of findings) {
      const ruleOverflows = overflowCounts.get(rule) ?? 0;
      audit.record({
        source,
        rule,
        count,
        ...(ruleOverflows > 0 ? { overflowed: true, overflowCount: ruleOverflows } : {}),
      });
    }

    return { text: parts.join(""), hits, overflows, findings };
  };

  return {
    get mode(): VaultMode {
      return mode;
    },
    get salt(): string {
      return salt;
    },
    get tokenPrefix(): string {
      return tokenPrefix;
    },
    get size(): number {
      return byToken.size;
    },
    get maxEntries(): number {
      return maxEntries;
    },
    get overflowCount(): number {
      return overflowCount;
    },
    get maxTokenLength(): number {
      return maxTokenLength;
    },
    redact(text: string, source = defaultSource, contextKey?: string): RedactTextResult {
      if (!text || text.length === 0) {
        return { text, hits: 0, overflows: 0, findings: [] };
      }
      const spans = collectSpans(text, contextKey);
      if (spans.length === 0) {
        return { text, hits: 0, overflows: 0, findings: [] };
      }
      if (overflowPolicy === "error") {
        const projected = new Set<string>();
        for (const span of spans) {
          const secret = text.slice(span.start, span.end);
          if (!bySecret.has(secret)) {
            projected.add(secret);
            if (bySecret.size + projected.size > maxEntries) {
              throw new VaultCapacityError(maxEntries, span.rule);
            }
          }
        }
      }
      return applySpans(text, spans, source);
    },
    redactBatch(
      items: ReadonlyArray<string | { text: string; contextKey?: string }>,
      source = defaultSource
    ): RedactTextResult[] {
      const normalized = items.map((item) =>
        typeof item === "string" ? { text: item } : item
      );
      const allSpans = normalized.map((item) => collectSpans(item.text, item.contextKey));
      if (overflowPolicy === "error") {
        const projected = new Set<string>();
        for (let i = 0; i < normalized.length; i += 1) {
          const t = (normalized[i] as { text: string }).text;
          for (const span of allSpans[i] as CandidateSpan[]) {
            const secret = t.slice(span.start, span.end);
            if (!bySecret.has(secret)) {
              projected.add(secret);
              if (bySecret.size + projected.size > maxEntries) {
                throw new VaultCapacityError(maxEntries, span.rule);
              }
            }
          }
        }
      }
      return normalized.map((item, i) =>
        applySpans(item.text, allSpans[i] as CandidateSpan[], source)
      );
    },
    rehydrate(text: string): string {
      if (!text || byToken.size === 0) return text;
      activeTokenPattern.lastIndex = 0;
      return text.replace(activeTokenPattern, (token) => byToken.get(token) ?? token);
    },
    resolveToken(token: string): string | undefined {
      return byToken.get(token);
    },
    replacements(): Array<[string, string]> {
      return [...byToken.entries()].sort((a, b) => b[0].length - a[0].length);
    },
    audit(): AuditSummary {
      return audit.summary(byToken.size, maxEntries, overflowCount);
    },
  };
}
