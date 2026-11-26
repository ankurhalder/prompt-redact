import { execFile, spawn } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { scanTextForFindings } from "../audit/scanner.js";
import { PayloadDepthError, redactPayload } from "../core/payload.js";
import { VaultCapacityError } from "../core/vault.js";
import type { SecretVault } from "../types.js";
import { readConfinedText, resolveConfinedDirectory } from "./confine.js";
import type { JsonObject } from "./protocol.js";
import type { McpTool, ToolAnnotations, ToolContext, ToolOutcome } from "./types.js";

const READ_ONLY: ToolAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

const VAULT_MUTATING: ToolAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false,
};

const EXEC_ANNOTATIONS: ToolAnnotations = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true,
};

function commandMatchesAllowlist(command: string, allowCommands: readonly string[]): boolean {
  const fold = (value: string): string =>
    process.platform === "win32" ? value.toLowerCase() : value;
  const normalized = fold(command);
  const base = fold(path.basename(command));
  return allowCommands.some((entry) => {
    const candidate = fold(entry.trim());
    if (candidate.length === 0) return false;
    return candidate.includes("/") || candidate.includes("\\")
      ? candidate === normalized
      : candidate === base;
  });
}

const MAX_EXEC_RAW_BYTES = 1024 * 1024;
const MAX_EXEC_RETURN_BYTES = 256 * 1024;
const MAX_TOOL_TEXT_BYTES = 4 * 1024 * 1024;
const DEFAULT_EXEC_TIMEOUT_MS = 15_000;
const MAX_EXEC_TIMEOUT_MS = 120_000;

const SAFE_INHERITED_ENV_KEYS = [
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "SystemRoot",
  "COMSPEC",
  "ComSpec",
  "HOME",
  "USERPROFILE",
  "TMPDIR",
  "TEMP",
  "TMP",
  "LANG",
  "LC_ALL",
  "TERM",
  "NODE_ENV",
] as const;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function relativeDisplayPath(cwd: string, targetPath: string): string {
  let base = path.resolve(cwd);
  try {
    base = fs.realpathSync(base);
  } catch {
    base = path.resolve(cwd);
  }
  return path.relative(base, targetPath).replace(/\\/g, "/");
}

function preserveNewlinesForRedactedLines(redacted: string, vault: SecretVault): string {
  if (!redacted || vault.size === 0) return redacted;
  const pattern = new RegExp(
    `<<${escapeRegExp(vault.tokenPrefix)}:${escapeRegExp(vault.salt)}:\\d+>>`,
    "g"
  );
  return redacted.replace(pattern, (token) => {
    const secret = vault.resolveToken(token);
    if (secret === undefined || !secret.includes("\n")) return token;
    let nl = 0;
    for (let i = 0; i < secret.length; i += 1) {
      if (secret.charCodeAt(i) === 10) nl += 1;
    }
    return nl > 0 ? `${token}${"\n".repeat(nl)}` : token;
  });
}

function buildSafeBaseEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of SAFE_INHERITED_ENV_KEYS) {
    const val = process.env[key];
    if (val !== undefined) {
      env[key] = val;
    }
  }
  return env;
}

function resolveVaultTokensInString(
  input: string,
  vault: SecretVault
): { resolved: string; unresolved: string[] } {
  const prefix = escapeRegExp(vault.tokenPrefix);
  const tokenOrHashPattern = new RegExp(
    `<<(?:${prefix}:[A-Za-z0-9_-]+:\\d+|redact-masked:[a-f0-9]{12}|redact-hash:[a-f0-9]{12})>>`,
    "g"
  );
  const unresolved: string[] = [];
  const resolved = input.replace(tokenOrHashPattern, (token) => {
    const secret = vault.resolveToken(token);
    if (secret === undefined) {
      unresolved.push(token);
      return token;
    }
    return secret;
  });
  return { resolved, unresolved };
}

function scrubWithVault(text: string, vault: SecretVault, source: string): string {
  if (!text) return text;
  let scrubbed = vault.redact(text, source).text;
  const bySecretLength = [...vault.replacements()]
    .filter(([, secret]) => secret.length > 0)
    .sort((a, b) => b[1].length - a[1].length);
  if (bySecretLength.length === 0) return scrubbed;

  const secretToToken = new Map<string, string>();
  const secretParts: string[] = [];
  for (const [token, secret] of bySecretLength) {
    if (!secretToToken.has(secret)) {
      secretToToken.set(secret, token);
      secretParts.push(escapeRegExp(secret));
    }
  }
  const tokenGuard = `<<(?:${escapeRegExp(vault.tokenPrefix)}:${escapeRegExp(vault.salt)}:\\d+|redact-masked:[a-f0-9]{12}|redact-hash:[a-f0-9]{12})>>`;
  const matcher = new RegExp(`${tokenGuard}|${secretParts.join("|")}`, "g");
  scrubbed = scrubbed.replace(matcher, (matched) => secretToToken.get(matched) ?? matched);
  return scrubbed;
}

function stripTrailingIncompleteLine(text: string, wasTruncated: boolean): string {
  if (!wasTruncated) return text;
  const lastNewline = text.lastIndexOf("\n");
  if (lastNewline < 0) return "";
  return text.slice(0, lastNewline + 1);
}

function capScrubbedText(text: string): { text: string; capped: boolean } {
  if (Buffer.byteLength(text, "utf8") <= MAX_EXEC_RETURN_BYTES) {
    return { text, capped: false };
  }
  const buf = Buffer.from(text, "utf8").subarray(0, MAX_EXEC_RETURN_BYTES);
  let slice = buf.toString("utf8");
  const lastNewline = slice.lastIndexOf("\n");
  if (lastNewline > 0) {
    slice = slice.slice(0, lastNewline + 1);
  } else {
    const lastOpen = slice.lastIndexOf("<<");
    const lastClose = slice.lastIndexOf(">>");
    if (lastOpen > lastClose) {
      slice = slice.slice(0, lastOpen);
    }
  }
  return { text: slice, capped: true };
}

export function buildTools(): McpTool[] {
  return [
    {
      name: "redact_text",
      title: "Redact Text",
      description:
        "Tokenize secrets in plain text using the active session vault. Returns sanitized text and zero-plaintext rule counts.",
      inputSchema: {
        type: "object",
        properties: {
          text: { type: "string", description: "Input text to redact." },
          source: { type: "string", description: "Ignored; audit source labels are fixed.", default: "mcp:redact_text" },
        },
        required: ["text"],
      },
      annotations: VAULT_MUTATING,
      cost: "cheap",
      async handler(args: JsonObject, context: ToolContext): Promise<ToolOutcome> {
        const text = String(args.text ?? "");
        if (Buffer.byteLength(text, "utf8") > MAX_TOOL_TEXT_BYTES) {
          return {
            text: "redact_text refused: input exceeds 4 MiB; use the proxy or CLI for larger payloads.",
            isError: true,
          };
        }
        const result = context.vault.redact(text, "mcp:redact_text");
        const structured: JsonObject = {
          text: result.text,
          hits: result.hits,
          overflows: result.overflows,
          findings: result.findings,
        };
        return {
          text: result.text,
          structured,
        };
      },
    },
    {
      name: "redact_payload",
      title: "Redact JSON Payload",
      description:
        "Deeply tokenize secrets inside an OpenAI, Anthropic, or arbitrary JSON payload using the session vault.",
      inputSchema: {
        type: "object",
        properties: {
          payload: {
            type: ["object", "array", "string"],
            description: "JSON payload or serialized JSON string to sanitize.",
          },
          source: { type: "string", description: "Ignored; audit source labels are fixed.", default: "mcp:redact_payload" },
        },
        required: ["payload"],
      },
      annotations: VAULT_MUTATING,
      cost: "cheap",
      async handler(args: JsonObject, context: ToolContext): Promise<ToolOutcome> {
        const source = "mcp:redact_payload";
        const raw = args.payload;
        if (typeof raw === "string") {
          if (Buffer.byteLength(raw, "utf8") > MAX_TOOL_TEXT_BYTES) {
            return {
              text: "redact_payload refused: input exceeds 4 MiB; use the proxy or CLI for larger payloads.",
              isError: true,
            };
          }
        } else if (raw !== null && typeof raw === "object") {
          try {
            if (Buffer.byteLength(JSON.stringify(raw), "utf8") > MAX_TOOL_TEXT_BYTES) {
              return {
                text: "redact_payload refused: payload exceeds 4 MiB; use the proxy or CLI for larger payloads.",
                isError: true,
              };
            }
          } catch {
            return {
              text: "redact_payload refused: payload could not be serialized.",
              isError: true,
            };
          }
        }
        let parsed: unknown = raw;
        if (typeof raw === "string") {
          try {
            parsed = JSON.parse(raw);
          } catch {
            parsed = raw;
          }
        }
        try {
          const result = redactPayload(parsed, context.vault, source);
          const structured: JsonObject = {
            payload: result.payload as JsonObject,
            redactedCount: result.redactedCount,
            overflowCount: result.overflowCount,
            byRule: result.byRule,
          };
          return {
            text: JSON.stringify(structured, null, 2),
            structured,
          };
        } catch (err) {
          if (err instanceof PayloadDepthError || err instanceof VaultCapacityError) {
            return { text: `redact_payload refused: ${err.message}`, isError: true };
          }
          throw err;
        }
      },
    },
    {
      name: "airlock_read_file",
      title: "Airlock Read File",
      description:
        "Read a workspace file inside the MCP server and return secret-tokenized contents. Symlinks, hard links, and paths outside the workspace are refused.",
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", description: "File path relative to workspace root." },
          fromLine: { type: "integer", description: "1-based start line.", minimum: 1, default: 1 },
          lineCount: { type: "integer", description: "Maximum lines to return.", minimum: 1, maximum: 2000, default: 200 },
          maxBytes: { type: "integer", description: "Maximum file bytes to read.", minimum: 1, maximum: 4194304, default: 1048576 },
        },
        required: ["path"],
      },
      annotations: VAULT_MUTATING,
      cost: "medium",
      async handler(args: JsonObject, context: ToolContext): Promise<ToolOutcome> {
        const target = String(args.path ?? "");
        const fromLine = typeof args.fromLine === "number" ? args.fromLine : 1;
        const lineCount = typeof args.lineCount === "number" ? args.lineCount : 200;
        const maxBytes = typeof args.maxBytes === "number" ? args.maxBytes : 1024 * 1024;

        const read = readConfinedText(context.roots, target, maxBytes);
        if (!read.ok) {
          return { text: `airlock_read_file refused: ${read.message}`, isError: true };
        }

        const displayRel = relativeDisplayPath(context.cwd, read.path);
        const red = context.vault.redact(read.text, `mcp:file:${displayRel}`);
        const preservedText = preserveNewlinesForRedactedLines(red.text, context.vault);
        const allLines = preservedText.split(/\r?\n/);
        const visibleLines = preservedText.endsWith("\n") ? allLines.slice(0, -1) : allLines;
        const startIdx = Math.max(0, fromLine - 1);
        const slice = visibleLines.slice(startIdx, startIdx + lineCount);
        const content = slice.join("\n");

        const structured: JsonObject = {
          path: displayRel,
          fromLine,
          returnedLines: slice.length,
          totalLines: visibleLines.length,
          hits: red.hits,
          overflows: red.overflows,
          content,
        };
        return {
          text: content,
          structured,
        };
      },
    },
    {
      name: "airlock_exec",
      title: "Airlock Execute Command",
      description:
        "Execute an allowlisted local command. Disabled by default; when exec.enabled is true in config, <<redact:...>> tokens in args or env are resolved from the local vault at runtime and stdout/stderr are re-scrubbed before returning. The child process itself is outside the vault boundary: only enable this for commands you trust with every secret in the vault.",
      inputSchema: {
        type: "object",
        properties: {
          command: { type: "string", description: "Executable name or path (no shell interpolation)." },
          args: {
            type: "array",
            items: { type: "string" },
            description: "Argument array; <<redact:...>> tokens are resolved locally from the vault.",
          },
          env: {
            type: "object",
            description: "Optional extra environment key/value pairs; <<redact:...>> tokens are resolved locally.",
          },
          cwd: { type: "string", description: "Working directory relative to workspace root.", default: "." },
          timeoutMs: {
            type: "integer",
            description: "Execution timeout in milliseconds.",
            minimum: 100,
            maximum: MAX_EXEC_TIMEOUT_MS,
            default: DEFAULT_EXEC_TIMEOUT_MS,
          },
        },
        required: ["command"],
      },
      annotations: EXEC_ANNOTATIONS,
      cost: "expensive",
      async handler(args: JsonObject, context: ToolContext): Promise<ToolOutcome> {
        const command = String(args.command ?? "").trim();
        if (command.length === 0) {
          return { text: "airlock_exec failed: command must not be empty.", isError: true };
        }
        if (command.includes("\0")) {
          return { text: "airlock_exec refused: command must not contain NUL bytes.", isError: true };
        }
        const policy = context.exec;
        if (!policy || policy.enabled !== true) {
          return {
            text:
              "airlock_exec is disabled. Enable it explicitly with \"exec\": { \"enabled\": true, \"allowCommands\": [...] } in prompt-redact.config.json.",
            isError: true,
          };
        }
        if (policy.allowCommands.length === 0) {
          return {
            text: "airlock_exec is enabled but exec.allowCommands is empty; refusing every command.",
            isError: true,
          };
        }
        if (!commandMatchesAllowlist(command, policy.allowCommands)) {
          return {
            text: `airlock_exec refused: "${command}" is not listed in exec.allowCommands.`,
            isError: true,
          };
        }
        const rawArgs = Array.isArray(args.args) ? args.args.map((a) => String(a)) : [];
        const resolvedArgs: string[] = [];
        for (const item of rawArgs) {
          const res = resolveVaultTokensInString(item, context.vault);
          if (res.unresolved.length > 0) {
            return {
              text: `airlock_exec refused: unresolved vault token(s) in args (${res.unresolved.join(", ")}).`,
              isError: true,
            };
          }
          if (res.resolved.includes("\0")) {
            return {
              text: "airlock_exec refused: args must not contain NUL bytes.",
              isError: true,
            };
          }
          resolvedArgs.push(res.resolved);
        }

        const childEnv: NodeJS.ProcessEnv = buildSafeBaseEnv();
        if (args.env && typeof args.env === "object" && !Array.isArray(args.env)) {
          for (const [k, v] of Object.entries(args.env as Record<string, unknown>)) {
            if (k.includes("\0")) {
              return {
                text: "airlock_exec refused: environment variable names must not contain NUL bytes.",
                isError: true,
              };
            }
            const res = resolveVaultTokensInString(String(v ?? ""), context.vault);
            if (res.unresolved.length > 0) {
              return {
                text: `airlock_exec refused: unresolved vault token(s) in env.${k}.`,
                isError: true,
              };
            }
            if (res.resolved.includes("\0")) {
              return {
                text: `airlock_exec refused: env.${k} must not contain NUL bytes.`,
                isError: true,
              };
            }
            childEnv[k] = res.resolved;
          }
        }

        const relCwd = typeof args.cwd === "string" ? args.cwd : ".";
        const dirResult = resolveConfinedDirectory(context.roots, relCwd);
        if (!dirResult.ok) {
          return { text: `airlock_exec refused: ${dirResult.message}`, isError: true };
        }

        const timeoutMs =
          typeof args.timeoutMs === "number"
            ? Math.min(MAX_EXEC_TIMEOUT_MS, Math.max(100, args.timeoutMs))
            : DEFAULT_EXEC_TIMEOUT_MS;

        return await new Promise<ToolOutcome>((resolve) => {
          const detached = process.platform !== "win32";
          let child: ReturnType<typeof spawn>;
          try {
            child = spawn(command, resolvedArgs, {
              cwd: dirResult.path,
              env: childEnv,
              shell: false,
              detached,
              windowsHide: true,
              stdio: ["ignore", "pipe", "pipe"],
            });
          } catch (err) {
            const rawMsg = err instanceof Error ? err.message : String(err);
            try {
              const safeMsg = scrubWithVault(rawMsg, context.vault, "mcp:exec:spawn");
              resolve({ text: `airlock_exec failed: ${safeMsg}`, isError: true });
            } catch {
              resolve({
                text: "airlock_exec failed closed: spawn error could not be scrubbed.",
                isError: true,
              });
            }
            return;
          }

          const stdoutChunks: Buffer[] = [];
          const stderrChunks: Buffer[] = [];
          let stdoutBytes = 0;
          let stderrBytes = 0;
          let stdoutTruncated = false;
          let stderrTruncated = false;
          let timedOut = false;
          let settled = false;
          let forceKillTimer: ReturnType<typeof setTimeout> | null = null;
          let abandonTimer: ReturnType<typeof setTimeout> | null = null;

          const finishWith = (outcome: ToolOutcome): void => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (forceKillTimer) clearTimeout(forceKillTimer);
            if (abandonTimer) clearTimeout(abandonTimer);
            resolve(outcome);
          };

          const buildCloseOutcome = (code: number | null): ToolOutcome => {
            const rawStdout = stripTrailingIncompleteLine(
              Buffer.concat(stdoutChunks).toString("utf8"),
              stdoutTruncated
            );
            const rawStderr = stripTrailingIncompleteLine(
              Buffer.concat(stderrChunks).toString("utf8"),
              stderrTruncated
            );
            try {
              const scrubbedStdout = scrubWithVault(rawStdout, context.vault, "mcp:exec:stdout");
              const scrubbedStderr = scrubWithVault(rawStderr, context.vault, "mcp:exec:stderr");
              const cappedOut = capScrubbedText(scrubbedStdout);
              const cappedErr = capScrubbedText(scrubbedStderr);
              const truncated =
                stdoutTruncated || stderrTruncated || cappedOut.capped || cappedErr.capped;
              const structured: JsonObject = {
                exitCode: code ?? -1,
                timedOut,
                truncated,
                stdout: cappedOut.text,
                stderr: cappedErr.text,
              };
              return {
                text: JSON.stringify(structured, null, 2),
                structured,
                ...(timedOut ? { isError: true } : {}),
              };
            } catch (err) {
              const message =
                err instanceof VaultCapacityError
                  ? err.message
                  : "Output scrubbing failed closed.";
              return {
                text: JSON.stringify({
                  exitCode: code ?? -1,
                  timedOut,
                  truncated: true,
                  stdout: "",
                  stderr: "",
                  error: message,
                }),
                isError: true,
              };
            }
          };

          const sendSignal = (sig: NodeJS.Signals): void => {
            try {
              if (detached && child.pid !== undefined) {
                process.kill(-child.pid, sig);
              } else {
                child.kill(sig);
              }
            } catch {
              try {
                child.kill(sig);
              } catch {
                return;
              }
            }
          };

          const killChild = (): void => {
            sendSignal("SIGTERM");
            if (forceKillTimer === null) {
              forceKillTimer = setTimeout(() => {
                if (process.platform === "win32" && child.pid !== undefined) {
                  try {
                    execFile("taskkill", ["/pid", String(child.pid), "/T", "/F"], { windowsHide: true }, () => {
                      return;
                    });
                  } catch {
                    sendSignal("SIGKILL");
                  }
                } else {
                  sendSignal("SIGKILL");
                }
                try {
                  child.stdout?.destroy();
                } catch {
                  return;
                }
                try {
                  child.stderr?.destroy();
                } catch {
                  return;
                }
                abandonTimer = setTimeout(() => {
                  finishWith(buildCloseOutcome(-1));
                }, 150);
                if (typeof abandonTimer.unref === "function") abandonTimer.unref();
              }, 500);
              if (typeof forceKillTimer.unref === "function") forceKillTimer.unref();
            }
          };

          const timer = setTimeout(() => {
            timedOut = true;
            killChild();
          }, timeoutMs);

          context.onCancel?.(() => {
            killChild();
          });

          child.stdout?.on("data", (chunk: Buffer) => {
            if (stdoutBytes >= MAX_EXEC_RAW_BYTES) {
              stdoutTruncated = true;
              return;
            }
            const remaining = MAX_EXEC_RAW_BYTES - stdoutBytes;
            const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
            if (chunk.length > remaining) stdoutTruncated = true;
            stdoutChunks.push(slice);
            stdoutBytes += slice.length;
          });

          child.stderr?.on("data", (chunk: Buffer) => {
            if (stderrBytes >= MAX_EXEC_RAW_BYTES) {
              stderrTruncated = true;
              return;
            }
            const remaining = MAX_EXEC_RAW_BYTES - stderrBytes;
            const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
            if (chunk.length > remaining) stderrTruncated = true;
            stderrChunks.push(slice);
            stderrBytes += slice.length;
          });

          child.on("error", (err) => {
            try {
              const safeMsg = scrubWithVault(err.message, context.vault, "mcp:exec:error");
              finishWith({ text: `airlock_exec failed: ${safeMsg}`, isError: true });
            } catch {
              finishWith({
                text: "airlock_exec failed closed: output scrubbing exceeded vault capacity.",
                isError: true,
              });
            }
          });

          child.on("close", (code) => {
            finishWith(buildCloseOutcome(code));
          });
        });
      },
    },
    {
      name: "redact_audit",
      title: "Redaction Session Audit",
      description:
        "Return zero-plaintext redaction counts, rule breakdowns, vault capacity usage, and recent audit events for the active MCP session.",
      inputSchema: {
        type: "object",
        properties: {},
      },
      annotations: READ_ONLY,
      cost: "cheap",
      async handler(_args: JsonObject, context: ToolContext): Promise<ToolOutcome> {
        const summary = context.vault.audit();
        return {
          text: JSON.stringify(summary, null, 2),
          structured: summary as unknown as JsonObject,
        };
      },
    },
    {
      name: "redact_verify",
      title: "Verify Zero Plaintext Leaks",
      description:
        "Verify that supplied text or a confined workspace file contains zero unredacted secret patterns. Returns rule and line locations only (never secret values).",
      inputSchema: {
        type: "object",
        properties: {
          text: { type: "string", description: "Text to inspect for unredacted secrets." },
          path: { type: "string", description: "Workspace-relative file path to inspect." },
        },
      },
      annotations: READ_ONLY,
      cost: "medium",
      async handler(args: JsonObject, context: ToolContext): Promise<ToolOutcome> {
        const hasText = typeof args.text === "string";
        const hasPath = typeof args.path === "string";
        if (!hasText && !hasPath) {
          return { text: 'redact_verify requires either "text" or "path".', isError: true };
        }
        if (hasText && hasPath) {
          return { text: 'redact_verify accepts "text" or "path", not both.', isError: true };
        }
        if (hasText && Buffer.byteLength(String(args.text), "utf8") > MAX_TOOL_TEXT_BYTES) {
          return {
            text: "redact_verify refused: text exceeds 4 MiB; scan the file path instead.",
            isError: true,
          };
        }
        let targetText = hasText ? String(args.text) : "";
        let targetLabel = "inline";
        if (hasPath) {
          const read = readConfinedText(context.roots, String(args.path));
          if (!read.ok) {
            return { text: `redact_verify refused: ${read.message}`, isError: true };
          }
          targetText = read.text;
          targetLabel = relativeDisplayPath(context.cwd, read.path);
        }
        const findings = scanTextForFindings(targetText, targetLabel, context.config).map((f) => ({
          line: f.line,
          rule: f.rule,
        }));
        const structured: JsonObject = {
          target: targetLabel,
          clean: findings.length === 0,
          findingsCount: findings.length,
          findings,
        };
        return {
          text: JSON.stringify(structured, null, 2),
          structured,
        };
      },
    },
  ];
}
