import * as fs from "node:fs";
import * as path from "node:path";
import { assertWritableInsideRepository, writeFileInsideRepository } from "../core/fs-safe.js";
import { SKILL_NAME, renderCursorRule, renderSkill } from "./skill.js";

export type SkillTarget = "claude" | "cursor" | "all";
export const SKILL_TARGETS: SkillTarget[] = ["claude", "cursor", "all"];

export interface SkillWrite {
  target: Exclude<SkillTarget, "all">;
  path: string;
  action: "created" | "updated" | "unchanged";
}

export interface SkillInstallResult {
  cwd: string;
  written: SkillWrite[];
  gitignored: string[];
  secureFiles: string[];
  notes: string[];
}

export interface SkillInstallOptions {
  track?: boolean;
  secure?: boolean;
}

const REFUSED = "Refusing to install skill";

const GUARD_COMMAND = "npx --no-install prompt-redact guard --hook || exit 2";
const VERIFY_COMMAND = "npx --no-install prompt-redact verify --hook || exit 2";

const DENY_READ = [
  "Read(./.env)",
  "Read(./.env.*)",
  "Read(./**/.env)",
  "Read(./**/.env.*)",
  "Read(./**/*.pem)",
  "Read(./**/*.key)",
  "Read(./**/*.p12)",
  "Read(./**/*.pfx)",
  "Read(./**/id_rsa)",
  "Read(./**/id_dsa)",
  "Read(./**/id_ecdsa)",
  "Read(./**/id_ed25519)",
  "Read(./**/.npmrc)",
  "Read(./**/.pypirc)",
  "Read(./**/.netrc)",
  "Read(./**/.aws/credentials)",
  "Read(./**/.kube/config)",
  "Read(./**/.ssh/**)",
] as const;

const ALLOW_MCP = [
  "mcp__prompt-redact__airlock_read_file",
  "mcp__prompt-redact__airlock_exec",
  "mcp__prompt-redact__redact_text",
  "mcp__prompt-redact__redact_payload",
  "mcp__prompt-redact__redact_verify",
  "mcp__prompt-redact__redact_audit",
] as const;

const CURSOR_IGNORE = [
  ".env",
  ".env.*",
  "!.env.example",
  "!.env.sample",
  "!.env.template",
  "**/*.pem",
  "**/*.key",
  "**/*.p12",
  "**/*.pfx",
  "**/id_rsa",
  "**/id_dsa",
  "**/id_ecdsa",
  "**/id_ed25519",
  "**/.npmrc",
  "**/.pypirc",
  "**/.netrc",
  "**/.ssh/**",
  "**/.aws/credentials",
  "**/.kube/config",
] as const;

function targetPath(cwd: string, target: Exclude<SkillTarget, "all">): string {
  switch (target) {
    case "claude":
      return path.join(cwd, ".claude", "skills", SKILL_NAME, "SKILL.md");
    case "cursor":
      return path.join(cwd, ".cursor", "rules", SKILL_NAME + ".mdc");
  }
}

function contentFor(target: Exclude<SkillTarget, "all">): string {
  return target === "claude" ? renderSkill() : renderCursorRule();
}

function writeIfChanged(
  cwd: string,
  target: Exclude<SkillTarget, "all">,
  filePath: string,
  content: string
): SkillWrite {
  const existing = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : null;
  if (existing === content) return { target, path: filePath, action: "unchanged" };
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileInsideRepository(cwd, filePath, content, REFUSED);
  return { target, path: filePath, action: existing === null ? "created" : "updated" };
}

function appendGitignore(cwd: string, relPaths: string[]): string[] {
  if (relPaths.length === 0) return [];
  const ignoreFile = path.join(cwd, ".gitignore");
  const existing = fs.existsSync(ignoreFile) ? fs.readFileSync(ignoreFile, "utf8") : "";
  const lines = new Set(existing.split(/\r?\n/).map((l) => l.trim()));
  const added: string[] = [];
  for (const rel of relPaths) {
    const posix = rel.replace(/\\/g, "/");
    if (!lines.has(posix)) {
      added.push(posix);
    }
  }
  if (added.length > 0) {
    const prefix = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
    writeFileInsideRepository(
      cwd,
      ignoreFile,
      existing + prefix + added.join("\n") + "\n",
      REFUSED
    );
  }
  return added;
}

function readIfExists(filePath: string): string | null {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : null;
}

function refuse(message: string): never {
  throw new Error(REFUSED + ": " + message);
}

function parseJsonObject(filePath: string, text: string | null): Record<string, unknown> {
  if (text === null || text.trim().length === 0) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    refuse(filePath + " is not valid JSON (" + (err as Error).message + "). No files were changed.");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    refuse(filePath + " must contain a JSON object. No files were changed.");
  }
  return parsed as Record<string, unknown>;
}

function ensureObject(
  parent: Record<string, unknown>,
  key: string,
  filePath: string
): Record<string, unknown> {
  const current = parent[key];
  if (current === undefined) {
    const created: Record<string, unknown> = {};
    parent[key] = created;
    return created;
  }
  if (current === null || typeof current !== "object" || Array.isArray(current)) {
    refuse(filePath + ' has a non-object "' + key + '" value. No files were changed.');
  }
  return current as Record<string, unknown>;
}

function ensureStringArray(
  parent: Record<string, unknown>,
  key: string,
  filePath: string
): string[] {
  const current = parent[key];
  if (current === undefined) {
    const created: string[] = [];
    parent[key] = created;
    return created;
  }
  if (!Array.isArray(current) || !current.every((item) => typeof item === "string")) {
    refuse(filePath + ' has a non-string-array "' + key + '" value. No files were changed.');
  }
  return current as string[];
}

function addMissing(target: string[], values: readonly string[]): void {
  for (const value of values) {
    if (!target.includes(value)) target.push(value);
  }
}

function hasHookCommand(entries: unknown[], command: string): boolean {
  return entries.some((entry) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return false;
    const hooks = (entry as Record<string, unknown>).hooks;
    if (!Array.isArray(hooks)) return false;
    return hooks.some(
      (hook) =>
        hook !== null &&
        typeof hook === "object" &&
        !Array.isArray(hook) &&
        (hook as Record<string, unknown>).command === command
    );
  });
}

function ensureHookList(
  hooks: Record<string, unknown>,
  event: string,
  filePath: string
): unknown[] {
  const current = hooks[event];
  if (current === undefined) {
    const created: unknown[] = [];
    hooks[event] = created;
    return created;
  }
  if (!Array.isArray(current)) {
    refuse(filePath + ' has a non-array hooks."' + event + '" value. No files were changed.');
  }
  return current;
}

function mergeMcpConfig(filePath: string, text: string | null): string {
  const root = parseJsonObject(filePath, text);
  const servers = ensureObject(root, "mcpServers", filePath);
  servers["prompt-redact"] = {
    command: "npx",
    args: ["--no-install", "prompt-redact", "mcp"],
  };
  return JSON.stringify(root, null, 2) + "\n";
}

function mergeClaudeSettings(filePath: string, text: string | null): string {
  const root = parseJsonObject(filePath, text);
  const permissions = ensureObject(root, "permissions", filePath);
  addMissing(ensureStringArray(permissions, "deny", filePath), DENY_READ);
  addMissing(ensureStringArray(permissions, "allow", filePath), ALLOW_MCP);

  const hooks = ensureObject(root, "hooks", filePath);
  const preToolUse = ensureHookList(hooks, "PreToolUse", filePath);
  if (!hasHookCommand(preToolUse, GUARD_COMMAND)) {
    preToolUse.push({
      matcher: "Read|Edit|Write|MultiEdit|Grep|Bash",
      hooks: [{ type: "command", command: GUARD_COMMAND }],
    });
  }
  const userPromptSubmit = ensureHookList(hooks, "UserPromptSubmit", filePath);
  if (!hasHookCommand(userPromptSubmit, VERIFY_COMMAND)) {
    userPromptSubmit.push({
      hooks: [{ type: "command", command: VERIFY_COMMAND }],
    });
  }
  return JSON.stringify(root, null, 2) + "\n";
}

function mergeCursorIgnore(text: string | null): string {
  const lines = new Set(
    (text ?? "")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
  );
  for (const pattern of CURSOR_IGNORE) lines.add(pattern);
  return [...lines].join("\n") + "\n";
}

interface SecureWrite {
  target: Exclude<SkillTarget, "all">;
  path: string;
  content: string;
}

function buildSecureWrites(
  cwd: string,
  wanted: Array<Exclude<SkillTarget, "all">>
): SecureWrite[] {
  const writes: SecureWrite[] = [];
  if (wanted.includes("claude")) {
    const mcpPath = path.join(cwd, ".mcp.json");
    writes.push({
      target: "claude",
      path: mcpPath,
      content: mergeMcpConfig(mcpPath, readIfExists(mcpPath)),
    });
    const settingsPath = path.join(cwd, ".claude", "settings.json");
    writes.push({
      target: "claude",
      path: settingsPath,
      content: mergeClaudeSettings(settingsPath, readIfExists(settingsPath)),
    });
  }
  if (wanted.includes("cursor")) {
    const mcpPath = path.join(cwd, ".cursor", "mcp.json");
    writes.push({
      target: "cursor",
      path: mcpPath,
      content: mergeMcpConfig(mcpPath, readIfExists(mcpPath)),
    });
    const ignorePath = path.join(cwd, ".cursorignore");
    writes.push({
      target: "cursor",
      path: ignorePath,
      content: mergeCursorIgnore(readIfExists(ignorePath)),
    });
  }
  return writes;
}

export function installSkill(
  cwd: string,
  target: SkillTarget = "all",
  options: SkillInstallOptions = {}
): SkillInstallResult {
  const written: SkillWrite[] = [];
  const notes: string[] = [];
  const wanted: Array<Exclude<SkillTarget, "all">> =
    target === "all" ? ["claude", "cursor"] : [target];
  const secureWrites = options.secure === true ? buildSecureWrites(cwd, wanted) : [];

  for (const item of wanted) {
    assertWritableInsideRepository(cwd, targetPath(cwd, item), REFUSED);
  }
  for (const file of secureWrites) {
    assertWritableInsideRepository(cwd, file.path, REFUSED);
  }
  if (!options.track) {
    assertWritableInsideRepository(cwd, path.join(cwd, ".gitignore"), REFUSED);
  }

  for (const item of wanted) {
    written.push(writeIfChanged(cwd, item, targetPath(cwd, item), contentFor(item)));
  }
  for (const file of secureWrites) {
    written.push(writeIfChanged(cwd, file.target, file.path, file.content));
  }

  let gitignored: string[] = [];
  if (!options.track) {
    // Add entries for updated/unchanged files too: a file installed earlier
    // with --track must become ignored when a later run drops --track.
    const relPaths = written
      .filter((entry) => !secureWrites.some((file) => file.path === entry.path))
      .map((entry) => path.relative(cwd, entry.path).replace(/\\/g, "/"));
    gitignored = appendGitignore(cwd, relPaths);
  } else {
    notes.push("--track enabled: installed skill files were not added to .gitignore.");
  }

  if (options.secure === true) {
    notes.push(
      "Secure agent configs installed and left tracked: .mcp.json, .claude/settings.json, .cursor/mcp.json, .cursorignore. " +
        "Install prompt-redact as a project devDependency so npx --no-install can start the MCP server and hooks."
    );
  }

  return {
    cwd,
    written,
    gitignored,
    secureFiles: secureWrites.map((file) => file.path),
    notes,
  };
}

export function isSkillTarget(value: string): value is SkillTarget {
  return (SKILL_TARGETS as string[]).includes(value);
}
