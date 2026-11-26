import * as fs from "node:fs";
import * as path from "node:path";
import { parseArgs } from "node:util";
import { buildAgentContract, renderContractText } from "./agent/contract.js";
import { installSkill, isSkillTarget } from "./agent/install-skill.js";
import { COMMAND_OPTION_SCOPE, commandsForOption, type CommandName } from "./agent/option-scope.js";
import { renderSkill } from "./agent/skill.js";
import { renderAuditMarkdown } from "./audit/report.js";
import { generateSarifReport } from "./audit/sarif.js";
import { scanPath, scanTextForFindings } from "./audit/scanner.js";
import { buildVaultFromConfig, compileSecretRules, loadConfigFile } from "./core/config.js";
import { assertWritableInsideRepository, writeFileInsideRepository } from "./core/fs-safe.js";
import { DEFAULT_SECRET_PATTERNS } from "./core/patterns.js";
import { decodeTextBuffer } from "./core/text.js";
import { startHttpTransport } from "./mcp/http.js";
import { runStdioServer } from "./mcp/run.js";
import { startProxyServer } from "./proxy/server.js";
import { runDoctor, runSetup } from "./proxy/setup.js";
import type { OverflowPolicy, PromptRedactConfig, VaultMode } from "./types.js";
import { PACKAGE_NAME, PACKAGE_VERSION } from "./version.js";
import { startWebServer } from "./web/server.js";

export { buildAgentContract } from "./agent/contract.js";

export class UsageError extends Error {}

class HelpRequested extends Error {}

export const CLI_OPTIONS = {
  cwd: { type: "string" },
  config: { type: "string" },
  "no-config": { type: "boolean" },
  host: { type: "string" },
  port: { type: "string" },
  token: { type: "string" },
  "no-auth": { type: "boolean" },
  "allow-origin": { type: "string" },
  http: { type: "boolean" },
  upstream: { type: "string" },
  "anthropic-upstream": { type: "string" },
  "openai-upstream": { type: "string" },
  "dry-run": { type: "boolean" },
  "max-entries": { type: "string" },
  "overflow-policy": { type: "string" },
  mode: { type: "string" },
  staged: { type: "boolean" },
  stdin: { type: "boolean" },
  hook: { type: "boolean" },
  sarif: { type: "boolean" },
  "out-dir": { type: "string" },
  force: { type: "boolean" },
  autopilot: { type: "boolean" },
  install: { type: "boolean" },
  target: { type: "string" },
  track: { type: "boolean" },
  format: { type: "string" },
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
} as const;

const COMMANDS = new Set<CommandName>([
  "proxy",
  "mcp",
  "serve",
  "scan",
  "verify",
  "setup",
  "doctor",
  "skill",
  "describe",
]);

const SHORT_FLAGS: ReadonlySet<string> = new Set(
  Object.values(CLI_OPTIONS)
    .map((spec) => (spec as { short?: string }).short)
    .filter((short): short is string => typeof short === "string")
    .map((short) => `-${short}`)
);

const USAGE = `
${PACKAGE_NAME} v${PACKAGE_VERSION}
Reversible secret redaction SDK, local LLM proxy, airlock MCP server, and CI secret scanner

Usage:
  prompt-redact <command> [options]

Commands:
  proxy              Start loopback Anthropic/OpenAI intercepting proxy
  mcp                Run airlock MCP server (stdio, or --http)
  serve              Open loopback browser playground + mounted /mcp
  scan [path]        Scan files for secrets and write audit.md (and --sarif)
  verify [path]      Verify workspace, --staged, or --stdin has zero leaks
  setup              Write prompt-redact.config.json and print env setup (--autopilot)
  doctor             Validate Node, config, port availability, and round-trip health
  skill              Print agent skill + hook setup, or --install into repo
  describe           Print machine-readable contract (--format json)

Exit codes:
  0  Clean / success
  1  Findings detected, verification failed, or runtime error
  2  Usage or configuration error
`.trim();

function misdashedLongOption(argv: readonly string[]): string | null {
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i] as string;
    if (token === "--") break;
    if (token.startsWith("--")) {
      const eq = token.indexOf("=");
      const optName = eq >= 0 ? token.slice(2, eq) : token.slice(2);
      const spec = (CLI_OPTIONS as Record<string, { type: string }>)[optName];
      if (eq < 0 && spec && spec.type === "string") {
        i += 1;
      }
      continue;
    }
    if (!/^-[A-Za-z][A-Za-z0-9-]+$/.test(token)) continue;
    if ([...token.slice(1)].every((ch) => SHORT_FLAGS.has(`-${ch}`))) continue;
    return token;
  }
  return null;
}

function parseIntegerOption(raw: string | undefined, name: string, min: number, max?: number): number | undefined {
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new UsageError(`--${name} expects a whole number, received "${raw}".`);
  }
  const value = Number(trimmed);
  if (!Number.isSafeInteger(value) || value < min || (max !== undefined && value > max)) {
    throw new UsageError(
      max === undefined
        ? `--${name} must be at least ${min}, received "${raw}".`
        : `--${name} must be between ${min} and ${max}, received "${raw}".`
    );
  }
  return value;
}

interface ParsedInvocation {
  command: CommandName;
  args: string[];
  cwd: string;
  configPath?: string;
  noConfig: boolean;
  host?: string;
  port?: number;
  token?: string;
  noAuth: boolean;
  allowOrigins?: string[];
  http: boolean;
  upstream?: string;
  anthropicUpstream?: string;
  openaiUpstream?: string;
  dryRun: boolean;
  maxEntries?: number;
  overflowPolicy?: OverflowPolicy;
  mode?: VaultMode;
  staged: boolean;
  stdin: boolean;
  hook: boolean;
  sarif: boolean;
  outDir: string;
  force: boolean;
  autopilot: boolean;
  install: boolean;
  target: string;
  track: boolean;
  format: "text" | "json";
}

export function parseCliArgs(argv: string[]): ParsedInvocation {
  const misdashed = misdashedLongOption(argv);
  if (misdashed !== null) {
    const long = `--${misdashed.slice(1)}`;
    const known = Object.prototype.hasOwnProperty.call(CLI_OPTIONS, misdashed.slice(1));
    throw new UsageError(
      known
        ? `Unknown option '${misdashed}'. Did you mean '${long}'?`
        : `Unknown option '${misdashed}'. Options start with two dashes.`
    );
  }

  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({
      args: argv,
      options: CLI_OPTIONS,
      allowPositionals: true,
      strict: true,
    });
  } catch (err) {
    throw new UsageError((err as Error).message);
  }

  const values = parsed.values as Record<string, string | boolean | undefined>;
  for (const [name, spec] of Object.entries(CLI_OPTIONS)) {
    if (spec.type !== "string") continue;
    const raw = values[name];
    if (raw !== undefined && String(raw).trim() === "") {
      throw new UsageError(`--${name} requires a non-empty value.`);
    }
  }

  if (values.help) {
    process.stdout.write(`${USAGE}\n`);
    throw new HelpRequested();
  }
  if (values.version) {
    process.stdout.write(`v${PACKAGE_VERSION}\n`);
    throw new HelpRequested();
  }

  const cwd = values.cwd !== undefined ? path.resolve(String(values.cwd)) : process.cwd();
  if (!fs.existsSync(cwd) || !fs.statSync(cwd).isDirectory()) {
    throw new UsageError(`--cwd is not an existing directory: ${cwd}`);
  }

  const positionals = parsed.positionals;
  const rawCommand = positionals[0];
  if (!rawCommand) {
    throw new UsageError(`Missing command. Expected one of: ${[...COMMANDS].join(", ")}.`);
  }
  if (!COMMANDS.has(rawCommand as CommandName)) {
    throw new UsageError(
      `Unknown command "${rawCommand}". Expected one of: ${[...COMMANDS].join(", ")}.`
    );
  }
  const command = rawCommand as CommandName;
  const args = positionals.slice(1);

  if ((command === "scan" || command === "verify") && args.length > 1) {
    throw new UsageError(`${command} accepts at most one positional path argument.`);
  }
  if (command !== "scan" && command !== "verify" && args.length > 0) {
    throw new UsageError(`Unexpected argument(s) for ${command}: ${args.join(" ")}.`);
  }

  const formatRaw = values.format === undefined ? "text" : String(values.format);
  if (formatRaw !== "text" && formatRaw !== "json") {
    throw new UsageError(`--format must be "text" or "json", received "${formatRaw}".`);
  }

  const scope = COMMAND_OPTION_SCOPE[command];
  const ignored: string[] = [];
  for (const name of Object.keys(CLI_OPTIONS)) {
    if (scope.includes(name)) continue;
    const val = values[name];
    if (val === undefined || val === false) continue;
    ignored.push(`--${name}`);
  }
  if (ignored.length > 0) {
    const owners = Array.from(
      new Set(ignored.flatMap((f) => commandsForOption(f.replace(/^--/, ""))))
    );
    throw new UsageError(
      `${ignored.join(", ")} ${ignored.length === 1 ? "does" : "do"} not apply to \`${command}\`. Accepted by: ${owners.join(", ")}.`
    );
  }

  const port = parseIntegerOption(
    values.port === undefined ? undefined : String(values.port),
    "port",
    0,
    65535
  );
  const maxEntries = parseIntegerOption(
    values["max-entries"] === undefined ? undefined : String(values["max-entries"]),
    "max-entries",
    1
  );

  let overflowPolicy: OverflowPolicy | undefined;
  if (values["overflow-policy"] !== undefined) {
    const raw = String(values["overflow-policy"]);
    if (raw !== "hash" && raw !== "error") {
      throw new UsageError(`--overflow-policy must be "hash" or "error", received "${raw}".`);
    }
    overflowPolicy = raw;
  }

  let mode: VaultMode | undefined;
  if (values.mode !== undefined) {
    const raw = String(values.mode);
    if (raw !== "session" && raw !== "ephemeral") {
      throw new UsageError(`--mode must be "session" or "ephemeral", received "${raw}".`);
    }
    mode = raw;
  }

  const target = values.target === undefined ? "all" : String(values.target);
  if (command === "skill" && !isSkillTarget(target)) {
    throw new UsageError(`--target must be "claude", "cursor", or "all", received "${target}".`);
  }

  if (values.token !== undefined && values["no-auth"] === true) {
    throw new UsageError("--token and --no-auth cannot be combined.");
  }

  if (values.stdin === true && (values.staged === true || args.length > 0)) {
    throw new UsageError("--stdin cannot be combined with --staged or a positional path.");
  }
  if (values.hook === true) {
    if (values.stdin === true) {
      throw new UsageError("--hook and --stdin cannot be combined.");
    }
    if (values.staged === true || args.length > 0) {
      throw new UsageError("--hook does not accept --staged or a positional path.");
    }
  }

  return {
    command,
    args,
    cwd,
    configPath: values.config === undefined ? undefined : String(values.config),
    noConfig: values["no-config"] === true,
    host: values.host === undefined ? undefined : String(values.host),
    port,
    token: values.token === undefined ? undefined : String(values.token),
    noAuth: values["no-auth"] === true,
    allowOrigins:
      values["allow-origin"] === undefined
        ? undefined
        : String(values["allow-origin"])
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
    http: values.http === true,
    upstream: values.upstream === undefined ? undefined : String(values.upstream),
    anthropicUpstream:
      values["anthropic-upstream"] === undefined ? undefined : String(values["anthropic-upstream"]),
    openaiUpstream:
      values["openai-upstream"] === undefined ? undefined : String(values["openai-upstream"]),
    dryRun: values["dry-run"] === true,
    maxEntries,
    overflowPolicy,
    mode,
    staged: values.staged === true,
    stdin: values.stdin === true,
    hook: values.hook === true,
    sarif: values.sarif === true,
    outDir: values["out-dir"] === undefined ? cwd : path.resolve(cwd, String(values["out-dir"])),
    force: values.force === true,
    autopilot: values.autopilot === true,
    install: values.install === true,
    target,
    track: values.track === true,
    format: formatRaw,
  };
}

function loadConfigForCli(parsed: ParsedInvocation): PromptRedactConfig {
  if (parsed.noConfig) return {};
  try {
    return loadConfigFile(parsed.cwd, parsed.configPath).config;
  } catch (err) {
    throw new UsageError((err as Error).message);
  }
}

function waitForSignal(onClose: () => Promise<void>): Promise<number> {
  return new Promise((resolve) => {
    let closed = false;
    const shutdown = (): void => {
      if (closed) return;
      closed = true;
      process.off("SIGINT", shutdown);
      process.off("SIGTERM", shutdown);
      void onClose().then(
        () => resolve(0),
        (err: unknown) => {
          process.stderr.write(`Error during shutdown: ${(err as Error).message}\n`);
          resolve(1);
        }
      );
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  });
}

const MAX_STDIN_BYTES = 8 * 1024 * 1024;
const MAX_HOOK_STRINGS = 16384;

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
  if (value !== null && typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (typeof child === "string") {
        out.push(`${key}=${child}`);
      } else {
        collectHookStrings(child, out, depth + 1);
      }
    }
  }
}

function extractHookText(raw: string): string {
  try {
    const parsed: unknown = JSON.parse(raw);
    const strings: string[] = [];
    collectHookStrings(parsed, strings);
    return strings.length > 0 ? strings.join("\n") : raw;
  } catch {
    return raw;
  }
}

function readAllStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let settled = false;
    const onData = (chunk: Buffer | string): void => {
      if (settled) return;
      const buf = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
      totalBytes += buf.length;
      if (totalBytes > MAX_STDIN_BYTES) {
        settled = true;
        cleanup();
        process.stdin.pause();
        reject(new Error(`stdin exceeds ${MAX_STDIN_BYTES}-byte limit; fail-closed abort.`));
        return;
      }
      chunks.push(buf);
    };
    const onEnd = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      const text = decodeTextBuffer(Buffer.concat(chunks));
      if (text === null) {
        reject(new Error("stdin contains binary or non-UTF-8 data; fail-closed abort."));
        return;
      }
      resolve(text);
    };
    const onError = (err: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    };
    const cleanup = (): void => {
      process.stdin.off("data", onData);
      process.stdin.off("end", onEnd);
      process.stdin.off("error", onError);
    };
    process.stdin.on("data", onData);
    process.stdin.on("end", onEnd);
    process.stdin.on("error", onError);
  });
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  let parsed: ParsedInvocation;
  try {
    parsed = parseCliArgs(argv);
  } catch (err) {
    if (err instanceof HelpRequested) return 0;
    if (err instanceof UsageError) {
      process.stderr.write(`Error: ${err.message}\n`);
      return 2;
    }
    process.stderr.write(`Error: ${(err as Error).message}\n`);
    return 1;
  }

  try {
    switch (parsed.command) {
      case "describe": {
        const contract = buildAgentContract();
        process.stdout.write(
          parsed.format === "json"
            ? `${JSON.stringify(contract, null, 2)}\n`
            : `${renderContractText(contract)}\n`
        );
        return 0;
      }

      case "skill": {
        if (!parsed.install) {
          const text = renderSkill();
          if (parsed.format === "json") {
            process.stdout.write(`${JSON.stringify({ skill: text }, null, 2)}\n`);
          } else {
            process.stdout.write(text);
          }
          return 0;
        }
        const target = isSkillTarget(parsed.target) ? parsed.target : "all";
        const result = installSkill(parsed.cwd, target, { track: parsed.track });
        if (parsed.format === "json") {
          process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
        } else {
          for (const item of result.written) {
            process.stdout.write(`${item.action}: ${item.path}\n`);
          }
          if (result.gitignored.length > 0) {
            process.stdout.write(`gitignored: ${result.gitignored.join(", ")}\n`);
          }
          for (const note of result.notes) {
            process.stderr.write(`${note}\n`);
          }
        }
        return 0;
      }

      case "doctor": {
        const result = await runDoctor(parsed.cwd, parsed.port ?? 4790, parsed.configPath);
        if (parsed.format === "json") {
          process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
        } else {
          for (const check of result.checks) {
            process.stdout.write(`[${check.ok ? "OK" : "FAIL"}] ${check.id}: ${check.detail}\n`);
          }
          process.stdout.write(`\nEnv setup:\n  ${result.envHints.anthropicBash}\n  ${result.envHints.openaiBash}\n`);
        }
        return result.ok ? 0 : 1;
      }

      case "setup": {
        const setupResult = runSetup(parsed.cwd, {
          force: parsed.force,
          port: parsed.port ?? 4790,
          dryRun: parsed.dryRun,
        });
        const doctorResult = parsed.autopilot
          ? await runDoctor(parsed.cwd, parsed.port ?? 4790, parsed.configPath)
          : undefined;
        if (parsed.format === "json") {
          process.stdout.write(
            `${JSON.stringify({ setup: setupResult, ...(doctorResult ? { doctor: doctorResult } : {}) }, null, 2)}\n`
          );
        } else {
          const actionLabel = setupResult.dryRun && setupResult.action !== "kept"
            ? setupResult.action === "created"
              ? "would create"
              : "would overwrite"
            : setupResult.action;
          process.stdout.write(`${actionLabel}: ${setupResult.configPath}\n`);
          process.stdout.write(`  ${setupResult.envHints.anthropicBash}\n`);
          process.stdout.write(`  ${setupResult.envHints.openaiBash}\n`);
          if (doctorResult) {
            for (const c of doctorResult.checks) {
              process.stdout.write(`[${c.ok ? "OK" : "FAIL"}] ${c.id}: ${c.detail}\n`);
            }
          }
        }
        return doctorResult && !doctorResult.ok ? 1 : 0;
      }

      case "scan":
      case "verify": {
        const config = loadConfigForCli(parsed);
        // The gate must not accept widening rules from the repository it is
        // inspecting. A trusted config must be passed explicitly.
        if (parsed.command === "verify" && !parsed.noConfig && parsed.configPath === undefined) {
          config.allowlist = [];
          config.excludePaths = [];
        }
        const rules = [
          ...DEFAULT_SECRET_PATTERNS,
          ...(config.customPatterns ? compileSecretRules(config.customPatterns) : []),
        ];

        if (parsed.command === "verify" && parsed.hook) {
          try {
            const raw = await readAllStdin();
            const findings = scanTextForFindings(extractHookText(raw), "<hook>", config);
            if (findings.length > 0) {
              for (const f of findings) {
                process.stderr.write(
                  `LEAK [${f.rule}] hook input (value withheld)\n`
                );
              }
              process.stderr.write(
                "prompt-redact: blocked by verify --hook (exit 2); remove the secret or tokenize it first.\n"
              );
              return 2;
            }
            return 0;
          } catch (err) {
            process.stderr.write(
              `prompt-redact: hook scan failed closed: ${(err as Error).message}\n`
            );
            return 2;
          }
        }

        if (parsed.command === "verify" && parsed.stdin) {
          const text = await readAllStdin();
          const findings = scanTextForFindings(text, "<stdin>", config);
          const byRule: Record<string, number> = {};
          for (const f of findings) byRule[f.rule] = (byRule[f.rule] ?? 0) + 1;
          const stdinReport = {
            scannedFiles: 1,
            skippedFiles: 0,
            skipped: [],
            strict: true,
            findings,
            byRule,
            clean: findings.length === 0,
          };
          if (parsed.sarif) {
            const sarifPath = path.join(parsed.outDir, "audit.sarif");
            assertWritableInsideRepository(parsed.cwd, sarifPath, "Refusing to write SARIF report");
            fs.mkdirSync(parsed.outDir, { recursive: true });
            writeFileInsideRepository(
              parsed.cwd,
              sarifPath,
              generateSarifReport(stdinReport, rules, PACKAGE_VERSION),
              "Refusing to write SARIF report"
            );
          }
          if (parsed.format === "json") {
            process.stdout.write(`${JSON.stringify(stdinReport, null, 2)}\n`);
          } else if (stdinReport.clean) {
            process.stdout.write("clean: 0 secret findings on stdin\n");
          } else {
            for (const f of stdinReport.findings) {
              process.stderr.write(`LEAK [${f.rule}] ${f.file}:${f.line} (value withheld)\n`);
            }
          }
          return stdinReport.clean ? 0 : 1;
        }

        const scanReport = scanPath(parsed.cwd, {
          targetPath: parsed.args[0],
          staged: parsed.staged,
          config,
          noConfig: parsed.noConfig,
          strict: parsed.command === "verify",
        });
        if (parsed.command === "scan") {
          const auditMdPath = path.join(parsed.outDir, "audit.md");
          assertWritableInsideRepository(parsed.cwd, auditMdPath, "Refusing to write audit report");
          fs.mkdirSync(parsed.outDir, { recursive: true });
          writeFileInsideRepository(
            parsed.cwd,
            auditMdPath,
            renderAuditMarkdown(scanReport),
            "Refusing to write audit report"
          );
        }
        if (parsed.sarif) {
          const sarifPath = path.join(parsed.outDir, "audit.sarif");
          assertWritableInsideRepository(parsed.cwd, sarifPath, "Refusing to write SARIF report");
          fs.mkdirSync(parsed.outDir, { recursive: true });
          writeFileInsideRepository(
            parsed.cwd,
            sarifPath,
            generateSarifReport(scanReport, rules, PACKAGE_VERSION),
            "Refusing to write SARIF report"
          );
        }

        if (parsed.format === "json") {
          process.stdout.write(`${JSON.stringify(scanReport, null, 2)}\n`);
        } else if (scanReport.clean) {
          process.stdout.write(
            `clean: ${scanReport.scannedFiles} file(s) scanned, 0 secret findings\n`
          );
        } else {
          for (const f of scanReport.findings) {
            process.stderr.write(`FINDING [${f.rule}] ${f.file}:${f.line} (value withheld)\n`);
          }
          if (parsed.command === "verify") {
            for (const entry of scanReport.skipped) {
              process.stderr.write(
                `SKIPPED [${entry.reason}] ${entry.file} (could not be verified; strict mode fails)\n`
              );
            }
          }
        }
        return scanReport.clean ? 0 : 1;
      }

      case "proxy": {
        const config = loadConfigForCli(parsed);
        const customRules = config.customPatterns ? compileSecretRules(config.customPatterns) : [];
        const proxy = await startProxyServer({
          host: parsed.host,
          port: parsed.port,
          token: parsed.token ?? null,
          upstream: parsed.upstream,
          anthropicUpstream: parsed.anthropicUpstream,
          openaiUpstream: parsed.openaiUpstream,
          dryRun: parsed.dryRun,
          vaultOptions: {
            mode: parsed.mode ?? config.mode ?? "session",
            tokenPrefix: config.tokenPrefix,
            maxEntries: parsed.maxEntries ?? config.maxEntries,
            overflowPolicy: parsed.overflowPolicy ?? config.overflowPolicy ?? "hash",
            allowlist: config.allowlist,
            entropy: config.entropy,
            rules: [...DEFAULT_SECRET_PATTERNS, ...customRules],
          },
        });
        if (parsed.format === "json") {
          process.stdout.write(
            `${JSON.stringify({ url: proxy.url, host: proxy.host, port: proxy.port, dryRun: parsed.dryRun })}\n`
          );
        } else {
          process.stderr.write(`prompt-redact proxy listening on ${proxy.url}\n`);
          process.stderr.write(`  ANTHROPIC_BASE_URL=${proxy.url}\n`);
          process.stderr.write(`  OPENAI_BASE_URL=${proxy.url}/v1\n`);
        }
        return await waitForSignal(() => proxy.close());
      }

      case "mcp": {
        const config = loadConfigForCli(parsed);
        const { vault: mcpVault } = buildVaultFromConfig(parsed.cwd, {
          config,
          noConfig: parsed.noConfig,
          source: "mcp",
          maxEntries: parsed.maxEntries,
          overflowPolicy: parsed.overflowPolicy,
        });
        if (!parsed.http) {
          return await runStdioServer({
            cwd: parsed.cwd,
            vault: mcpVault,
            config,
            noConfig: parsed.noConfig,
          });
        }
        const transport = await startHttpTransport({
          cwd: parsed.cwd,
          host: parsed.host,
          port: parsed.port,
          token: parsed.noAuth ? null : parsed.token,
          allowedOrigins: parsed.allowOrigins,
          noConfig: parsed.noConfig,
          config,
          vault: mcpVault,
        });
        process.stderr.write(`prompt-redact mcp http listening on ${transport.url}/mcp\n`);
        if (transport.token) {
          process.stderr.write(`Bearer token: ${transport.token}\n`);
        }
        return await waitForSignal(() => transport.close());
      }

      case "serve": {
        const config = loadConfigForCli(parsed);
        const handle = await startWebServer({
          cwd: parsed.cwd,
          host: parsed.host,
          port: parsed.port,
          token: parsed.noAuth ? null : parsed.token,
          allowedOrigins: parsed.allowOrigins,
          noConfig: parsed.noConfig,
          config,
        });
        process.stderr.write(`prompt-redact inspector listening on ${handle.url}\n`);
        if (handle.token) {
          process.stderr.write(`Bearer token: ${handle.token}\n`);
        }
        return await waitForSignal(() => handle.close());
      }
    }
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`Error: ${err.message}\n`);
      return 2;
    }
    if (parsed.format === "json") {
      process.stdout.write(
        `${JSON.stringify({ error: { message: (err as Error).message, exitCode: 1 } })}\n`
      );
    }
    process.stderr.write(`Error: ${(err as Error).message}\n`);
    return 1;
  }
}
