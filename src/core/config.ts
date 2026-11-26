import * as fs from "node:fs";
import * as path from "node:path";
import type {
  AllowlistEntry,
  AuditRecorder,
  OverflowPolicy,
  PromptRedactConfig,
  SecretRule,
  SecretRuleInput,
  SecretVault,
  VaultMode,
} from "../types.js";
import { DEFAULT_SECRET_PATTERNS } from "./patterns.js";
import { createVault } from "./vault.js";

export const CONFIG_FILENAME = "prompt-redact.config.json";

interface CharSetMask {
  words: [number, number, number, number];
  universal: boolean;
}

function emptyMask(universal = false): CharSetMask {
  return { words: [0, 0, 0, 0], universal };
}

function addCharCode(mask: CharSetMask, code: number, ignoreCase: boolean): void {
  const addSingle = (c: number): void => {
    if (c >= 0 && c < 128) {
      mask.words[c >>> 5] |= 1 << (c & 31);
    } else {
      mask.universal = true;
    }
  };
  addSingle(code);
  if (ignoreCase) {
    if (code >= 65 && code <= 90) addSingle(code + 32);
    else if (code >= 97 && code <= 122) addSingle(code - 32);
  }
}

function addRange(mask: CharSetMask, from: number, to: number, ignoreCase: boolean): void {
  const lo = Math.min(from, to);
  const hi = Math.max(from, to);
  if (hi >= 128) {
    mask.universal = true;
    return;
  }
  for (let c = lo; c <= hi; c += 1) {
    addCharCode(mask, c, ignoreCase);
  }
}

function addWordMask(mask: CharSetMask): void {
  addRange(mask, 48, 57, false);
  addRange(mask, 65, 90, false);
  addCharCode(mask, 95, false);
  addRange(mask, 97, 122, false);
}

function addDigitMask(mask: CharSetMask): void {
  addRange(mask, 48, 57, false);
}

function addSpaceMask(mask: CharSetMask): void {
  for (const c of [9, 10, 11, 12, 13, 32]) {
    addCharCode(mask, c, false);
  }
}

function masksOverlap(a: CharSetMask, b: CharSetMask): boolean {
  if (a.universal || b.universal) return true;
  return (
    (a.words[0] & b.words[0]) !== 0 ||
    (a.words[1] & b.words[1]) !== 0 ||
    (a.words[2] & b.words[2]) !== 0 ||
    (a.words[3] & b.words[3]) !== 0
  );
}

function unionMasks(a: CharSetMask, b: CharSetMask): CharSetMask {
  return {
    universal: a.universal || b.universal,
    words: [
      a.words[0] | b.words[0],
      a.words[1] | b.words[1],
      a.words[2] | b.words[2],
      a.words[3] | b.words[3],
    ],
  };
}

function readClassMask(
  source: string,
  openIndex: number,
  ignoreCase: boolean,
  unicode: boolean
): { mask: CharSetMask; endIndex: number } {
  const mask = emptyMask(false);
  let i = openIndex + 1;
  let negated = false;
  if (source[i] === "^") {
    negated = true;
    i += 1;
  }
  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === "]") {
      if (negated) {
        return {
          mask: {
            universal: true,
            words: [
              ~mask.words[0],
              ~mask.words[1],
              ~mask.words[2],
              ~mask.words[3],
            ],
          },
          endIndex: i,
        };
      }
      return { mask, endIndex: i };
    }
    if (ch === "\\") {
      const esc = source[i + 1];
      if (esc === "p" || esc === "P") {
        if (unicode && source[i + 2] === "{") {
          const close = source.indexOf("}", i + 3);
          if (close !== -1) {
            mask.universal = true;
            i = close + 1;
            continue;
          }
        }
        if (esc !== undefined) addCharCode(mask, esc.charCodeAt(0), ignoreCase);
        i += 2;
        continue;
      }
      if (esc === "x" && /^[0-9a-fA-F]{2}$/.test(source.slice(i + 2, i + 4))) {
        addCharCode(mask, parseInt(source.slice(i + 2, i + 4), 16), ignoreCase);
        i += 4;
        continue;
      }
      if (esc === "u") {
        if (source[i + 2] === "{") {
          const close = source.indexOf("}", i + 3);
          if (close !== -1) {
            const code = parseInt(source.slice(i + 3, close), 16);
            if (Number.isFinite(code) && code >= 0 && code <= 0x10ffff) {
              addCharCode(mask, code, ignoreCase);
            } else {
              mask.universal = true;
            }
            i = close + 1;
            continue;
          }
        } else if (/^[0-9a-fA-F]{4}$/.test(source.slice(i + 2, i + 6))) {
          addCharCode(mask, parseInt(source.slice(i + 2, i + 6), 16), ignoreCase);
          i += 6;
          continue;
        }
      }
      if (esc === "n") addCharCode(mask, 10, false);
      else if (esc === "r") addCharCode(mask, 13, false);
      else if (esc === "t") addCharCode(mask, 9, false);
      else if (esc === "f") addCharCode(mask, 12, false);
      else if (esc === "v") addCharCode(mask, 11, false);
      else if (esc === "b") addCharCode(mask, 8, false);
      else if (esc === "0") addCharCode(mask, 0, false);
      else if (esc === "w") addWordMask(mask);
      else if (esc === "d") addDigitMask(mask);
      else if (esc === "s") addSpaceMask(mask);
      else if (esc === "W" || esc === "D" || esc === "S") mask.universal = true;
      else if (esc !== undefined) addCharCode(mask, esc.charCodeAt(0), ignoreCase);
      i += 2;
      continue;
    }
    if (source[i + 1] === "-" && source[i + 2] !== undefined && source[i + 2] !== "]" && source[i + 2] !== "\\") {
      addRange(mask, ch.charCodeAt(0), source.charCodeAt(i + 2), ignoreCase);
      i += 3;
      continue;
    }
    addCharCode(mask, ch.charCodeAt(0), ignoreCase);
    i += 1;
  }
  return { mask: emptyMask(true), endIndex: source.length - 1 };
}

function readQuantifier(
  source: string,
  index: number
): { present: boolean; repeating: boolean; optional: boolean; nextIndex: number } {
  const ch = source[index];
  if (ch === "*") {
    let next = index + 1;
    if (source[next] === "?" || source[next] === "+") next += 1;
    return { present: true, repeating: true, optional: true, nextIndex: next };
  }
  if (ch === "+") {
    let next = index + 1;
    if (source[next] === "?" || source[next] === "+") next += 1;
    return { present: true, repeating: true, optional: false, nextIndex: next };
  }
  if (ch === "?") {
    let next = index + 1;
    if (source[next] === "?" || source[next] === "+") next += 1;
    return { present: true, repeating: false, optional: true, nextIndex: next };
  }
  if (ch === "{") {
    const rest = source.slice(index);
    const match = /^\{(\d+)(?:,(\d*))?\}/.exec(rest);
    if (match) {
      const min = Number(match[1]);
      const maxStr = match[2];
      const repeating =
        (maxStr === undefined && min > 1) ||
        maxStr === "" ||
        (maxStr !== undefined && Number(maxStr) > 1);
      let next = index + match[0].length;
      if (source[next] === "?" || source[next] === "+") next += 1;
      return { present: true, repeating, optional: min === 0, nextIndex: next };
    }
  }
  return { present: false, repeating: false, optional: false, nextIndex: index };
}

export function validatePatternSafety(pattern: RegExp, rule: string): void {
  const stateless = new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, ""));
  if (stateless.test("")) {
    throw new Error(
      `Secret rule "${rule}" can match an empty string. Require at least one character.`
    );
  }
  const source = pattern.source;
  const ignoreCase = pattern.flags.includes("i");
  const unicodeMode = pattern.flags.includes("u");
  const stack: Array<{
    hasQuantifier: boolean;
    hasAlternation: boolean;
    hasBackreference: boolean;
    isAssertion: boolean;
    branchEntryMask: CharSetMask;
    trailingRepeatingMask: CharSetMask | null;
    prevRepeatingMask: CharSetMask | null;
  }> = [
    {
      hasQuantifier: false,
      hasAlternation: false,
      hasBackreference: false,
      isAssertion: false,
      branchEntryMask: emptyMask(false),
      trailingRepeatingMask: null,
      prevRepeatingMask: null,
    },
  ];
  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i] as string;
    const top = stack[stack.length - 1]!;
    if (ch === "^" || ch === "$") {
      continue;
    }
    if (ch === "\\") {
      const next = source[i + 1];
      if (next === "b" || next === "B") {
        i += 1;
        continue;
      }
      if (next !== undefined && ((next >= "1" && next <= "9") || next === "k")) {
        let refEnd = i + 2;
        if (next === "k" && source[refEnd] === "<") {
          const closeAngle = source.indexOf(">", refEnd + 1);
          if (closeAngle !== -1) refEnd = closeAngle + 1;
        } else {
          while (refEnd < source.length && source[refEnd]! >= "0" && source[refEnd]! <= "9") {
            refEnd += 1;
          }
        }
        const q = readQuantifier(source, refEnd);
        if (q.repeating) {
          throw new Error(
            `Secret rule "${rule}" contains a quantified backreference that risks catastrophic backtracking.`
          );
        }
        top.hasBackreference = true;
        top.prevRepeatingMask = q.optional ? top.prevRepeatingMask : null;
        i = q.nextIndex - 1;
        continue;
      }
      const escMask = emptyMask(false);
      let atomEnd = next === undefined ? i + 1 : i + 2;
      if (next === "p" || next === "P") {
        if (unicodeMode && source[i + 2] === "{") {
          const close = source.indexOf("}", i + 3);
          if (close !== -1) {
            escMask.universal = true;
            atomEnd = close + 1;
          }
        }
        if (!escMask.universal && next !== undefined) {
          addCharCode(escMask, next.charCodeAt(0), ignoreCase);
        }
      } else if (next === "x" && /^[0-9a-fA-F]{2}$/.test(source.slice(i + 2, i + 4))) {
        addCharCode(escMask, parseInt(source.slice(i + 2, i + 4), 16), ignoreCase);
        atomEnd = i + 4;
      } else if (next === "u") {
        if (source[i + 2] === "{") {
          const close = source.indexOf("}", i + 3);
          if (close !== -1) {
            const code = parseInt(source.slice(i + 3, close), 16);
            if (Number.isFinite(code) && code >= 0 && code <= 0x10ffff) {
              addCharCode(escMask, code, ignoreCase);
            } else {
              escMask.universal = true;
            }
            atomEnd = close + 1;
          }
        } else if (/^[0-9a-fA-F]{4}$/.test(source.slice(i + 2, i + 6))) {
          addCharCode(escMask, parseInt(source.slice(i + 2, i + 6), 16), ignoreCase);
          atomEnd = i + 6;
        }
      } else if (next === "n") addCharCode(escMask, 10, false);
      else if (next === "r") addCharCode(escMask, 13, false);
      else if (next === "t") addCharCode(escMask, 9, false);
      else if (next === "f") addCharCode(escMask, 12, false);
      else if (next === "v") addCharCode(escMask, 11, false);
      else if (next === "0") addCharCode(escMask, 0, false);
      else if (next === "w") addWordMask(escMask);
      else if (next === "d") addDigitMask(escMask);
      else if (next === "s") addSpaceMask(escMask);
      else if (next === "W" || next === "D" || next === "S") escMask.universal = true;
      else if (next !== undefined) addCharCode(escMask, next.charCodeAt(0), ignoreCase);
      const q = readQuantifier(source, atomEnd);
      if (q.repeating) {
        if (top.prevRepeatingMask && masksOverlap(top.prevRepeatingMask, escMask)) {
          throw new Error(
            `Secret rule "${rule}" contains adjacent overlapping quantifiers that risk catastrophic backtracking.`
          );
        }
        top.hasQuantifier = true;
        top.prevRepeatingMask = escMask;
      } else if (!q.optional) {
        // Literal separators only break backtracking adjacency when they are
        // disjoint from the previous repeated class. Keeping the mask when
        // they overlap closes the "w+aw+a..." and ".*a.*a" bypasses.
        if (!(top.prevRepeatingMask && masksOverlap(top.prevRepeatingMask, escMask))) {
          top.prevRepeatingMask = null;
        }
      }
      i = q.nextIndex - 1;
      continue;
    }
    if (ch === "[") {
      const { mask, endIndex } = readClassMask(source, i, ignoreCase, unicodeMode);
      const q = readQuantifier(source, endIndex + 1);
      if (q.repeating) {
        if (top.prevRepeatingMask && masksOverlap(top.prevRepeatingMask, mask)) {
          throw new Error(
            `Secret rule "${rule}" contains adjacent overlapping quantifiers that risk catastrophic backtracking.`
          );
        }
        top.hasQuantifier = true;
        top.prevRepeatingMask = mask;
      } else if (!q.optional) {
        if (!(top.prevRepeatingMask && masksOverlap(top.prevRepeatingMask, mask))) {
          top.prevRepeatingMask = null;
        }
      }
      i = q.nextIndex - 1;
      continue;
    }
    if (ch === "(") {
      let bodyStart = i + 1;
      let isAssertion = false;
      if (source[bodyStart] === "?") {
        if (source[bodyStart + 1] === "=" || source[bodyStart + 1] === "!") {
          isAssertion = true;
          bodyStart += 2;
        } else if (
          source[bodyStart + 1] === "<" &&
          (source[bodyStart + 2] === "=" || source[bodyStart + 2] === "!")
        ) {
          isAssertion = true;
          bodyStart += 3;
        } else if (source[bodyStart + 1] === ":") {
          bodyStart += 2;
        } else if (source[bodyStart + 1] === "<") {
          const closeAngle = source.indexOf(">", bodyStart + 2);
          if (closeAngle !== -1) bodyStart = closeAngle + 1;
        }
      }
      stack.push({
        hasQuantifier: false,
        hasAlternation: false,
        hasBackreference: false,
        isAssertion,
        branchEntryMask: emptyMask(false),
        trailingRepeatingMask: null,
        prevRepeatingMask: null,
      });
      i = bodyStart - 1;
      continue;
    }
    if (ch === "|") {
      top.hasAlternation = true;
      if (top.prevRepeatingMask) {
        top.trailingRepeatingMask = top.trailingRepeatingMask
          ? unionMasks(top.trailingRepeatingMask, top.prevRepeatingMask)
          : top.prevRepeatingMask;
      }
      top.prevRepeatingMask = null;
      continue;
    }
    if (ch === ")") {
      const group = stack.pop();
      const parent = stack[stack.length - 1];
      const q = readQuantifier(source, i + 1);
      if (group && q.repeating) {
        if (group.hasQuantifier || group.hasAlternation || group.hasBackreference) {
          throw new Error(
            `Secret rule "${rule}" contains nested quantifiers or repeated alternation that risk catastrophic backtracking.`
          );
        }
        if (parent && !group.isAssertion) {
          const groupMask = group.branchEntryMask;
          if (parent.prevRepeatingMask && masksOverlap(parent.prevRepeatingMask, groupMask)) {
            throw new Error(
              `Secret rule "${rule}" contains adjacent overlapping quantifiers that risk catastrophic backtracking.`
            );
          }
          parent.hasQuantifier = true;
          parent.prevRepeatingMask = groupMask;
        }
      } else if (group && parent) {
        if (group.hasQuantifier) parent.hasQuantifier = true;
        if (group.hasAlternation) parent.hasAlternation = true;
        if (group.hasBackreference) parent.hasBackreference = true;
        if (!group.isAssertion && !q.optional) {
          const groupTrailing =
            group.prevRepeatingMask && group.trailingRepeatingMask
              ? unionMasks(group.prevRepeatingMask, group.trailingRepeatingMask)
              : (group.prevRepeatingMask ?? group.trailingRepeatingMask);
          parent.prevRepeatingMask = groupTrailing;
        }
      }
      if (q.nextIndex > i + 1) {
        i = q.nextIndex - 1;
      }
      continue;
    }
    const q = readQuantifier(source, i);
    if (q.nextIndex > i) {
      if (q.repeating) top.hasQuantifier = true;
      i = q.nextIndex - 1;
      continue;
    }
    const atomMask = emptyMask(ch === ".");
    if (ch !== ".") {
      addCharCode(atomMask, ch.charCodeAt(0), ignoreCase);
    }
    top.branchEntryMask = unionMasks(top.branchEntryMask, atomMask);
    const nextQ = readQuantifier(source, i + 1);
    if (nextQ.repeating) {
      if (top.prevRepeatingMask && masksOverlap(top.prevRepeatingMask, atomMask)) {
        throw new Error(
          `Secret rule "${rule}" contains adjacent overlapping quantifiers that risk catastrophic backtracking.`
        );
      }
      top.hasQuantifier = true;
      top.prevRepeatingMask = atomMask;
    } else if (!nextQ.optional) {
      if (!(top.prevRepeatingMask && masksOverlap(top.prevRepeatingMask, atomMask))) {
        top.prevRepeatingMask = null;
      }
    }
    if (nextQ.nextIndex > i + 1) {
      i = nextQ.nextIndex - 1;
    }
  }
}

export function compileSecretRules(rules: readonly SecretRuleInput[]): SecretRule[] {
  if (!Array.isArray(rules)) {
    throw new Error("customPatterns must be an array of secret rules.");
  }
  let generated = 0;
  return rules.map((entry, index) => {
    const where = `customPatterns[${index}]`;
    if (entry instanceof RegExp) {
      generated += 1;
      const flags = new Set(entry.flags.replace(/[gy]/g, "").split(""));
      const compiled = new RegExp(entry.source, [...flags].join(""));
      validatePatternSafety(compiled, `custom-${generated}`);
      return { rule: `custom-${generated}`, pattern: compiled };
    }
    if (typeof entry === "string") {
      generated += 1;
      let compiled: RegExp;
      try {
        compiled = new RegExp(entry, "i");
      } catch {
        // V8 error messages can echo the pattern; never copy them into a
        // user-visible error because the pattern may embed a credential.
        throw new Error(`Invalid regular expression in ${where}.`);
      }
      validatePatternSafety(compiled, `custom-${generated}`);
      return { rule: `custom-${generated}`, pattern: compiled };
    }
    if (typeof entry === "object" && entry !== null) {
      const candidate = entry as {
        rule?: unknown;
        pattern?: unknown;
        flags?: unknown;
        valueGroup?: unknown;
      };
      if (typeof candidate.rule !== "string" || candidate.rule.trim() === "") {
        throw new Error(`${where}.rule must be a non-empty string.`);
      }
      let valueGroup: number | undefined;
      if (candidate.valueGroup !== undefined) {
        if (
          typeof candidate.valueGroup !== "number" ||
          !Number.isInteger(candidate.valueGroup) ||
          candidate.valueGroup < 0
        ) {
          throw new Error(`${where}.valueGroup must be a non-negative integer.`);
        }
        valueGroup = candidate.valueGroup;
      }
      let compiled: RegExp;
      if (candidate.pattern instanceof RegExp) {
        const flags = new Set(candidate.pattern.flags.replace(/[gy]/g, "").split(""));
        if (valueGroup !== undefined) flags.add("d");
        compiled = new RegExp(candidate.pattern.source, [...flags].join(""));
      } else if (typeof candidate.pattern === "string") {
        const rawFlags = typeof candidate.flags === "string" ? candidate.flags : "i";
        const flags = new Set(rawFlags.replace(/[gy]/g, "").split(""));
        if (valueGroup !== undefined) flags.add("d");
        try {
          compiled = new RegExp(candidate.pattern, [...flags].join(""));
        } catch {
          throw new Error(`Invalid regular expression for rule "${candidate.rule}".`);
        }
      } else {
        throw new Error(`${where}.pattern must be a RegExp or string.`);
      }
      validatePatternSafety(compiled, candidate.rule);
      return {
        rule: candidate.rule,
        pattern: compiled,
        ...(valueGroup === undefined ? {} : { valueGroup }),
      };
    }
    throw new Error(`${where} must be a RegExp, string, or { rule, pattern }.`);
  });
}

export interface CompiledAllowlist {
  exact: Set<string>;
  patterns: RegExp[];
}

export function compileAllowlist(entries?: readonly AllowlistEntry[]): CompiledAllowlist {
  const exact = new Set<string>();
  const patterns: RegExp[] = [];
  if (!entries) return { exact, patterns };
  if (!Array.isArray(entries)) {
    throw new Error("allowlist must be an array.");
  }
  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    if (typeof entry === "string") {
      exact.add(entry);
    } else if (entry instanceof RegExp) {
      const compiled = new RegExp(entry.source, entry.flags.replace(/[gy]/g, ""));
      validatePatternSafety(compiled, `allowlist[${i}]`);
      patterns.push(compiled);
    } else if (entry && typeof entry === "object" && typeof entry.pattern === "string") {
      const flags = typeof entry.flags === "string" ? entry.flags.replace(/[gy]/g, "") : "";
      let compiled: RegExp;
      try {
        compiled = new RegExp(entry.pattern, flags);
      } catch {
        throw new Error(`Invalid regular expression in allowlist[${i}].`);
      }
      validatePatternSafety(compiled, `allowlist[${i}]`);
      patterns.push(compiled);
    } else {
      throw new Error(`allowlist[${i}] must be a string, RegExp, or { pattern, flags }.`);
    }
  }
  return { exact, patterns };
}

export function isAllowlisted(value: string, compiled: CompiledAllowlist): boolean {
  if (compiled.exact.has(value)) return true;
  for (const pattern of compiled.patterns) {
    pattern.lastIndex = 0;
    if (pattern.test(value)) return true;
  }
  return false;
}

export function loadConfigFile(cwd: string, explicitPath?: string): {
  config: PromptRedactConfig;
  file: string | null;
} {
  const candidate = explicitPath ? path.resolve(cwd, explicitPath) : path.join(cwd, CONFIG_FILENAME);
  if (!fs.existsSync(candidate)) {
    if (explicitPath) {
      throw new Error(`Configuration file not found: ${candidate}`);
    }
    return { config: {}, file: null };
  }
  if (!candidate.toLowerCase().endsWith(".json")) {
    throw new Error(
      `Refusing non-JSON configuration file "${candidate}". Only data-only .json configs are supported.`
    );
  }
  const raw = fs.readFileSync(candidate, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid JSON in ${candidate}: ${(err as Error).message}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Config in ${candidate} must be a JSON object.`);
  }
  const obj = parsed as PromptRedactConfig;
  const allowedConfigKeys = new Set([
    "$schema",
    "tokenPrefix",
    "maxEntries",
    "overflowPolicy",
    "mode",
    "entropy",
    "allowlist",
    "customPatterns",
    "excludePaths",
    "exec",
  ]);
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    if (!allowedConfigKeys.has(key)) {
      throw new Error(
        `Unknown configuration key "${key}" in ${candidate}. Accepted keys: ${[...allowedConfigKeys].filter((k) => k !== "$schema").sort().join(", ")}.`
      );
    }
  }
  if (obj.tokenPrefix !== undefined && (typeof obj.tokenPrefix !== "string" || obj.tokenPrefix.trim() === "")) {
    throw new Error("tokenPrefix in config must be a non-empty string.");
  }
  if (obj.maxEntries !== undefined && (!Number.isInteger(obj.maxEntries) || obj.maxEntries < 1)) {
    throw new Error("maxEntries in config must be a positive integer.");
  }
  if (
    obj.overflowPolicy !== undefined &&
    obj.overflowPolicy !== "hash" &&
    obj.overflowPolicy !== "error"
  ) {
    throw new Error('overflowPolicy in config must be "hash" or "error".');
  }
  if (obj.mode !== undefined && obj.mode !== "session" && obj.mode !== "ephemeral") {
    throw new Error('mode in config must be "session" or "ephemeral".');
  }
  if (obj.entropy !== undefined) {
    if (!obj.entropy || typeof obj.entropy !== "object" || Array.isArray(obj.entropy)) {
      throw new Error("entropy in config must be an object.");
    }
    const allowedEntropyKeys = new Set(["enabled", "threshold", "minLength"]);
    for (const key of Object.keys(obj.entropy as Record<string, unknown>)) {
      if (!allowedEntropyKeys.has(key)) {
        throw new Error(`Unknown entropy configuration key "${key}".`);
      }
    }
    if (obj.entropy.enabled !== undefined && typeof obj.entropy.enabled !== "boolean") {
      throw new Error("entropy.enabled in config must be a boolean.");
    }
    if (
      obj.entropy.threshold !== undefined &&
      (typeof obj.entropy.threshold !== "number" || !Number.isFinite(obj.entropy.threshold) || obj.entropy.threshold <= 0)
    ) {
      throw new Error("entropy.threshold in config must be a positive finite number.");
    }
    if (
      obj.entropy.minLength !== undefined &&
      (!Number.isInteger(obj.entropy.minLength) || obj.entropy.minLength < 16)
    ) {
      throw new Error("entropy.minLength in config must be an integer >= 16.");
    }
  }
  if (obj.excludePaths !== undefined) {
    if (!Array.isArray(obj.excludePaths) || obj.excludePaths.some((p) => typeof p !== "string")) {
      throw new Error("excludePaths in config must be an array of strings.");
    }
  }
  if (obj.exec !== undefined) {
    if (!obj.exec || typeof obj.exec !== "object" || Array.isArray(obj.exec)) {
      throw new Error("exec in config must be an object.");
    }
    const allowedExecKeys = new Set(["enabled", "allowCommands"]);
    for (const key of Object.keys(obj.exec as Record<string, unknown>)) {
      if (!allowedExecKeys.has(key)) {
        throw new Error(`Unknown exec configuration key "${key}".`);
      }
    }
    if (obj.exec.enabled !== undefined && typeof obj.exec.enabled !== "boolean") {
      throw new Error("exec.enabled in config must be a boolean.");
    }
    if (obj.exec.allowCommands !== undefined) {
      if (
        !Array.isArray(obj.exec.allowCommands) ||
        obj.exec.allowCommands.some((cmd) => typeof cmd !== "string" || cmd.trim() === "")
      ) {
        throw new Error("exec.allowCommands in config must be an array of non-empty strings.");
      }
    }
  }
  if (obj.customPatterns !== undefined) {
    compileSecretRules(obj.customPatterns);
  }
  if (obj.allowlist !== undefined) {
    compileAllowlist(obj.allowlist);
  }
  return { config: obj, file: candidate };
}

export function buildVaultFromConfig(
  cwd: string,
  options: {
    config?: PromptRedactConfig;
    configPath?: string;
    noConfig?: boolean;
    source?: string;
    mode?: VaultMode;
    maxEntries?: number;
    overflowPolicy?: OverflowPolicy;
    audit?: AuditRecorder;
  } = {}
): { vault: SecretVault; config: PromptRedactConfig } {
  const config =
    options.config ??
    (options.noConfig ? {} : loadConfigFile(cwd, options.configPath).config);
  const customRules = config.customPatterns ? compileSecretRules(config.customPatterns) : [];
  const vault = createVault({
    mode: options.mode ?? config.mode ?? "session",
    source: options.source ?? "vault",
    tokenPrefix: config.tokenPrefix,
    maxEntries: options.maxEntries ?? config.maxEntries,
    overflowPolicy: options.overflowPolicy ?? config.overflowPolicy ?? "hash",
    allowlist: config.allowlist,
    entropy: config.entropy,
    rules: [...DEFAULT_SECRET_PATTERNS, ...customRules],
    ...(options.audit ? { audit: options.audit } : {}),
  });
  return { vault, config };
}
