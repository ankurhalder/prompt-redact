import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { compileAllowlist, compileSecretRules, isAllowlisted, loadConfigFile } from "../core/config.js";
import { findHighEntropySpans, isPlaceholderValue } from "../core/entropy.js";
import {
  ASSIGNMENT_RULE_NAMES,
  DEFAULT_SECRET_PATTERNS,
  PEM_BLOCK_PATTERN,
  PEM_UNTERMINATED_PATTERN,
  textMayContainCredentialAssignment,
} from "../core/patterns.js";
import { decodeTextBufferDetailed } from "../core/text.js";
import { coalesceSpans, type CandidateSpan } from "../core/vault.js";
import type {
  EntropyConfig,
  PromptRedactConfig,
  ScanFinding,
  ScanReport,
  ScanSkip,
  ScanSkipReason,
  SecretRule,
} from "../types.js";

const DEFAULT_EXCLUDES = new Set([
  "node_modules",
  ".git",
  "dist",
  ".next",
  "coverage",
  "audit.md",
  "audit.sarif",
]);

const MAX_SCAN_BYTES = 8 * 1024 * 1024;

export interface ScanOptions {
  targetPath?: string;
  staged?: boolean;
  config?: PromptRedactConfig;
  noConfig?: boolean;
  /**
   * Strict mode turns every skip into a failure. A gate cannot prove that a
   * skipped file (binary, oversize, unreadable, symlink, invalid UTF-8) is
   * free of secrets, so verify-mode treats any skip as a failed check.
   */
  strict?: boolean;
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

function isExcludedRelative(rel: string, excludes: ReadonlySet<string>): boolean {
  const parts = rel.split("/");
  for (const ex of excludes) {
    const clean = ex.replace(/\/+$/, "");
    if (!clean) continue;
    if (clean.includes("/")) {
      if (rel === clean || rel.startsWith(`${clean}/`)) {
        return true;
      }
    } else if (parts.includes(clean)) {
      return true;
    }
  }
  return false;
}

function resolveAncestorRealpath(targetPath: string): string {
  const resolved = path.resolve(targetPath);
  const trailing: string[] = [];
  let cur = resolved;
  while (!fs.existsSync(cur)) {
    const parent = path.dirname(cur);
    if (parent === cur) {
      return resolved;
    }
    trailing.unshift(path.basename(cur));
    cur = parent;
  }
  const realBase = fs.realpathSync(cur);
  return trailing.length === 0 ? realBase : path.join(realBase, ...trailing);
}

function walkFiles(
  rootDir: string,
  excludes: Set<string>,
  out: string[],
  skipped: ScanSkip[],
  relPrefix = ""
): void {
  const entries = fs.readdirSync(rootDir, { withFileTypes: true });
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of entries) {
    const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
    if (isExcludedRelative(rel, excludes)) continue;
    if (entry.isSymbolicLink()) {
      skipped.push({ file: rel, reason: "symlink" });
      continue;
    }
    const full = path.join(rootDir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(full, excludes, out, skipped, rel);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
}

function stagedEntriesIn(cwd: string): { repoRoot: string; relPaths: string[] } {
  const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
  const raw = execFileSync(
    "git",
    ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
    { cwd: repoRoot, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
  );
  const relPaths = raw.split("\0").filter((item) => item.length > 0);
  return { repoRoot, relPaths };
}

function readStagedBlob(repoRoot: string, relPath: string): Buffer {
  return execFileSync("git", ["show", `:${relPath}`], {
    cwd: repoRoot,
    encoding: "buffer",
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function compileRulesForScan(config: PromptRedactConfig): Array<{
  rule: string;
  pattern: RegExp;
  valueGroup?: number;
}> {
  const custom = config.customPatterns ? compileSecretRules(config.customPatterns) : [];
  const all: SecretRule[] = [...DEFAULT_SECRET_PATTERNS, ...custom];
  return all.map((entry) => {
    const flags = new Set(entry.pattern.flags.replace(/[gy]/g, "").split(""));
    flags.add("g");
    if (entry.valueGroup !== undefined) flags.add("d");
    return {
      rule: entry.rule,
      pattern: new RegExp(entry.pattern.source, [...flags].join("")),
      ...(entry.valueGroup === undefined ? {} : { valueGroup: entry.valueGroup }),
    };
  });
}

function buildLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    const ch = text.charCodeAt(i);
    if (ch === 13) {
      if (text.charCodeAt(i + 1) === 10) i += 1;
      starts.push(i + 1);
    } else if (ch === 10) {
      starts.push(i + 1);
    }
  }
  return starts;
}

function lineForOffset(starts: readonly number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if ((starts[mid] as number) <= offset) lo = mid + 1;
    else hi = mid - 1;
  }
  return Math.max(1, hi + 1);
}

interface CompiledScan {
  rules: Array<{ rule: string; pattern: RegExp; valueGroup?: number }>;
  allowlist: ReturnType<typeof compileAllowlist>;
  entropy?: EntropyConfig;
}

function scanTextWithCompiled(
  text: string,
  fileLabel: string,
  compiledScan: CompiledScan
): ScanFinding[] {
  if (!text || text.length === 0) return [];
  const { rules: compiled, allowlist } = compiledScan;
  const candidates: CandidateSpan[] = [];

  for (const pemPattern of [PEM_BLOCK_PATTERN, PEM_UNTERMINATED_PATTERN]) {
    pemPattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pemPattern.exec(text)) !== null) {
      if (match[0].length === 0) {
        pemPattern.lastIndex = advanceIndex(text, match.index, pemPattern.unicode);
        continue;
      }
      const start = match.index;
      const end = start + match[0].length;
      if (!isAllowlisted(match[0], allowlist)) {
        candidates.push({ start, end, rule: "private-key-block" });
      }
    }
  }

  const assignmentHint = textMayContainCredentialAssignment(text);
  for (const { rule, pattern, valueGroup } of compiled) {
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
          : (match as RegExpExecArray & { indices?: Array<[number, number] | undefined> })
              .indices?.[valueGroup];
      const start = group ? group[0] : match.index;
      const end = group ? group[1] : match.index + match[0].length;
      if (end <= start) continue;
      const value = text.slice(start, end);
      if (isPlaceholderValue(value)) continue;
      if (isAllowlisted(value, allowlist)) continue;
      candidates.push({ start, end, rule });
    }
  }

  for (const span of findHighEntropySpans(text, compiledScan.entropy)) {
    if (!isAllowlisted(span.value, allowlist)) {
      candidates.push({ start: span.start, end: span.end, rule: "high-entropy" });
    }
  }

  const merged = coalesceSpans(candidates);
  if (merged.length === 0) return [];

  const lineStarts = buildLineStarts(text);
  const byLine = new Map<number, Set<string>>();
  for (const span of merged) {
    const line = lineForOffset(lineStarts, span.start);
    let set = byLine.get(line);
    if (!set) {
      set = new Set<string>();
      byLine.set(line, set);
    }
    set.add(span.rule);
  }

  const findings: ScanFinding[] = [];
  for (const [line, rules] of [...byLine.entries()].sort(([a], [b]) => a - b)) {
    for (const rule of [...rules].sort()) {
      findings.push({ file: fileLabel, line, rule });
    }
  }
  return findings;
}

export function scanTextForFindings(
  text: string,
  fileLabel: string,
  config: PromptRedactConfig = {}
): ScanFinding[] {
  return scanTextWithCompiled(text, fileLabel, {
    rules: compileRulesForScan(config),
    allowlist: compileAllowlist(config.allowlist),
    ...(config.entropy === undefined ? {} : { entropy: config.entropy }),
  });
}

export function scanPath(cwd: string, options: ScanOptions = {}): ScanReport {
  const config = options.config ?? (options.noConfig ? {} : loadConfigFile(cwd).config);
  const excludes = new Set<string>([...DEFAULT_EXCLUDES, ...(config.excludePaths ?? [])]);
  const strict = options.strict === true;
  const compiledScan: CompiledScan = {
    rules: compileRulesForScan(config),
    allowlist: compileAllowlist(config.allowlist),
    ...(config.entropy === undefined ? {} : { entropy: config.entropy }),
  };

  let scannedFiles = 0;
  const findings: ScanFinding[] = [];
  const skipped: ScanSkip[] = [];
  const byRuleMap = new Map<string, number>();

  const skip = (file: string, reason: ScanSkipReason): void => {
    skipped.push({ file, reason });
  };

  const processBuffer = (raw: Buffer, displayRel: string): void => {
    if (raw.length > MAX_SCAN_BYTES) {
      skip(displayRel, "oversize");
      return;
    }
    const decoded = decodeTextBufferDetailed(raw);
    if (!decoded.ok) {
      skip(displayRel, decoded.reason);
      return;
    }
    scannedFiles += 1;
    const fileFindings = scanTextWithCompiled(decoded.text, displayRel, compiledScan);
    for (const f of fileFindings) {
      findings.push(f);
      byRuleMap.set(f.rule, (byRuleMap.get(f.rule) ?? 0) + 1);
    }
  };

  if (options.staged) {
    const { repoRoot, relPaths } = stagedEntriesIn(cwd);
    const realRepo = fs.realpathSync(repoRoot);
    const scopeTargetRaw = options.targetPath ? path.resolve(cwd, options.targetPath) : path.resolve(cwd);
    const realTarget = resolveAncestorRealpath(scopeTargetRaw);
    const scopeRel = path.relative(realRepo, realTarget).replace(/\\/g, "/");
    const targetIsFile =
      (fs.existsSync(realTarget) && fs.statSync(realTarget).isFile()) ||
      relPaths.includes(scopeRel);

    for (const rel of relPaths) {
      if (isExcludedRelative(rel, excludes)) continue;
      if (scopeRel !== "") {
        if (targetIsFile) {
          if (rel !== scopeRel) continue;
        } else if (!rel.startsWith(`${scopeRel}/`) && rel !== scopeRel) {
          continue;
        }
      }
      try {
        const raw = readStagedBlob(repoRoot, rel);
        processBuffer(raw, rel);
      } catch {
        skip(rel, "unreadable");
      }
    }
  } else {
    const target = options.targetPath ? path.resolve(cwd, options.targetPath) : cwd;
    if (!fs.existsSync(target)) {
      throw new Error(`Scan target does not exist: ${target}`);
    }
    const stat = fs.statSync(target);
    let targets: string[] = [];
    if (stat.isFile()) {
      targets = [target];
    } else if (stat.isDirectory()) {
      const relTarget = path.relative(cwd, target).replace(/\\/g, "/");
      const initialPrefix =
        relTarget !== "" && relTarget !== "." && !relTarget.startsWith("..") && !path.isAbsolute(relTarget)
          ? relTarget
          : "";
      if (!initialPrefix || !isExcludedRelative(initialPrefix, excludes)) {
        walkFiles(target, excludes, targets, skipped, initialPrefix);
      }
    } else {
      throw new Error(`Scan target is neither a file nor a directory: ${target}`);
    }

    for (const file of targets) {
      const rel = path.relative(cwd, file).replace(/\\/g, "/") || path.basename(file);
      try {
        const lstat = fs.lstatSync(file);
        if (lstat.isSymbolicLink()) {
          skip(rel, "symlink");
          continue;
        }
        if (!lstat.isFile()) {
          skip(rel, "unreadable");
          continue;
        }
        processBuffer(fs.readFileSync(file), rel);
      } catch {
        skip(rel, "unreadable");
      }
    }
  }

  const byRule: Record<string, number> = {};
  for (const [rule, count] of [...byRuleMap.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    byRule[rule] = count;
  }

  // Every skip is a coverage gap in strict mode: a binary file can still
  // contain ASCII credentials, and an unreadable file cannot be cleared.
  return {
    scannedFiles,
    skippedFiles: skipped.length,
    skipped,
    strict,
    findings,
    byRule,
    clean: findings.length === 0 && (!strict || skipped.length === 0),
  };
}
