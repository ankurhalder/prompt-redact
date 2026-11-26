import { DEFAULT_MAX_VAULT_ENTRIES, DEFAULT_TOKEN_PREFIX } from "../core/vault.js";
import { LEGACY_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS } from "../mcp/protocol.js";
import { buildTools } from "../mcp/tools.js";
import { PACKAGE_NAME, PACKAGE_VERSION, SCHEMA_VERSION } from "../version.js";
import { optionAppliesTo } from "./option-scope.js";

export const CONTRACT_VERSION = "1.0.0";

export interface AgentContract {
  package: string;
  version: string;
  schemaVersion: string;
  contractVersion: string;
  summary: string;
  requires: { node: string; dependencies: string[] };
  bins: string[];
  commands: Array<{
    name: string;
    summary: string;
    positionals: string[];
    exits: number[];
  }>;
  exitCodes: Record<string, string>;
  options: Array<{
    flag: string;
    type: "string" | "boolean";
    default: string | boolean;
    appliesTo: string;
    summary: string;
  }>;
  config: {
    fileName: string;
    settings: Array<{ key: string; type: string; default: unknown; summary: string }>;
  };
  mcp: {
    command: string;
    protocolVersions: { modern: readonly string[]; legacy: readonly string[] };
    tools: Array<{
      name: string;
      title: string;
      summary: string;
      readOnly: boolean;
      cost: string;
      parameters: string[];
      required: string[];
    }>;
  };
}

export function buildAgentContract(): AgentContract {
  const tools = buildTools().map((tool) => ({
    name: tool.name,
    title: tool.title,
    summary: tool.description,
    readOnly: tool.annotations.readOnlyHint,
    cost: tool.cost,
    parameters: Object.keys(tool.inputSchema.properties),
    required: tool.inputSchema.required ?? [],
  }));

  return {
    package: PACKAGE_NAME,
    version: PACKAGE_VERSION,
    schemaVersion: SCHEMA_VERSION,
    contractVersion: CONTRACT_VERSION,
    summary:
      "Deterministic, reversible secret redaction SDK, local Anthropic/OpenAI proxy, MCP airlock server with an opt-in command executor, and zero-plaintext audit scanner.",
    requires: { node: ">=18.3.0", dependencies: [] },
    bins: [PACKAGE_NAME],
    commands: [
      {
        name: "proxy",
        summary: "Start loopback Anthropic/OpenAI intercepting proxy with reversible SSE rehydration.",
        positionals: [],
        exits: [0, 1, 2],
      },
      {
        name: "mcp",
        summary:
          "Start the airlock MCP server over stdio or Streamable HTTP (--http). airlock_exec is disabled unless exec.enabled plus exec.allowCommands are configured.",
        positionals: [],
        exits: [0, 1, 2],
      },
      {
        name: "serve",
        summary: "Start the loopback web playground inspector with mounted /mcp endpoint.",
        positionals: [],
        exits: [0, 1, 2],
      },
      {
        name: "scan",
        summary: "Scan files or directories for unredacted secrets and emit audit.md / audit.sarif.",
        positionals: ["[path]"],
        exits: [0, 1, 2],
      },
      {
        name: "verify",
        summary:
          "Strict gate for workspace, staged files, --stdin, or a Claude Code hook envelope (--hook, exit 2 on findings). Any unverifiable skipped file fails.",
        positionals: ["[path]"],
        exits: [0, 1, 2],
      },
      {
        name: "setup",
        summary: "Write data-only prompt-redact.config.json and print proxy env hints.",
        positionals: [],
        exits: [0, 1, 2],
      },
      {
        name: "doctor",
        summary: "Check Node version, config validity, port availability, and vault round-trip health.",
        positionals: [],
        exits: [0, 1, 2],
      },
      {
        name: "skill",
        summary: "Print bundled agent skill + hook guidance, or --install into .claude/skills and .cursor/rules.",
        positionals: [],
        exits: [0, 1, 2],
      },
      {
        name: "describe",
        summary: "Print this machine-readable contract (--format json).",
        positionals: [],
        exits: [0, 2],
      },
    ],
    exitCodes: {
      "0": "success / clean (no secrets leaked)",
      "1": "findings detected, verification failed, or runtime failure",
      "2": "usage or configuration error",
    },
    options: [
      { flag: "--cwd", type: "string", default: ".", appliesTo: optionAppliesTo("cwd"), summary: "Target workspace directory." },
      { flag: "--config", type: "string", default: "prompt-redact.config.json", appliesTo: optionAppliesTo("config"), summary: "Path to data-only JSON configuration file." },
      { flag: "--no-config", type: "boolean", default: false, appliesTo: optionAppliesTo("no-config"), summary: "Ignore config file and use built-in defaults." },
      { flag: "--host", type: "string", default: "127.0.0.1", appliesTo: optionAppliesTo("host"), summary: "Bind host for proxy, mcp --http, or serve." },
      { flag: "--port", type: "string", default: "4790 (proxy), 4791 (mcp --http), 4788 (serve)", appliesTo: optionAppliesTo("port"), summary: "Port to listen on (0 selects an ephemeral port)." },
      { flag: "--token", type: "string", default: "generated (mcp --http, serve) / unset (proxy)", appliesTo: optionAppliesTo("token"), summary: "Bearer token for HTTP endpoints (required on non-loopback proxy; generated by default for mcp --http and serve; printed to stderr)." },
      { flag: "--no-auth", type: "boolean", default: false, appliesTo: optionAppliesTo("no-auth"), summary: "Disable bearer auth on loopback mcp --http or serve. Plaintext-revealing inspector endpoints remain disabled." },
      { flag: "--allow-origin", type: "string", default: "unset", appliesTo: optionAppliesTo("allow-origin"), summary: "Comma-separated extra CORS origins." },
      { flag: "--http", type: "boolean", default: false, appliesTo: optionAppliesTo("http"), summary: "Serve MCP over Streamable HTTP instead of stdio." },
      { flag: "--upstream", type: "string", default: "unset", appliesTo: optionAppliesTo("upstream"), summary: "Override upstream base URL for all proxy traffic." },
      { flag: "--anthropic-upstream", type: "string", default: "https://api.anthropic.com", appliesTo: optionAppliesTo("anthropic-upstream"), summary: "Anthropic upstream base URL." },
      { flag: "--openai-upstream", type: "string", default: "https://api.openai.com", appliesTo: optionAppliesTo("openai-upstream"), summary: "OpenAI upstream base URL." },
      { flag: "--dry-run", type: "boolean", default: false, appliesTo: optionAppliesTo("dry-run"), summary: "Inspect and tokenize without sending upstream or writing files." },
      { flag: "--max-entries", type: "string", default: String(DEFAULT_MAX_VAULT_ENTRIES), appliesTo: optionAppliesTo("max-entries"), summary: "Maximum reversible secrets held per vault session." },
      { flag: "--overflow-policy", type: "string", default: "hash", appliesTo: optionAppliesTo("overflow-policy"), summary: "Fail-closed overflow policy: hash or error." },
      { flag: "--mode", type: "string", default: "session", appliesTo: optionAppliesTo("mode"), summary: "Proxy session policy: session (stable tokens) or ephemeral (new vault per request). The SDK and MCP server always keep a per-process vault." },
      { flag: "--staged", type: "boolean", default: false, appliesTo: optionAppliesTo("staged"), summary: "Scan or verify staged git files only." },
      { flag: "--stdin", type: "boolean", default: false, appliesTo: optionAppliesTo("stdin"), summary: "Verify text read from stdin." },
      { flag: "--hook", type: "boolean", default: false, appliesTo: optionAppliesTo("hook"), summary: "Verify a Claude Code hook JSON envelope from stdin; exits 2 (blocking) on findings." },
      { flag: "--sarif", type: "boolean", default: false, appliesTo: optionAppliesTo("sarif"), summary: "Write audit.sarif (SARIF 2.1.0)." },
      { flag: "--out-dir", type: "string", default: ".", appliesTo: optionAppliesTo("out-dir"), summary: "Directory where audit.md and audit.sarif are written." },
      { flag: "--force", type: "boolean", default: false, appliesTo: optionAppliesTo("force"), summary: "Overwrite existing config file during setup." },
      { flag: "--autopilot", type: "boolean", default: false, appliesTo: optionAppliesTo("autopilot"), summary: "Non-interactive setup + doctor verification." },
      { flag: "--install", type: "boolean", default: false, appliesTo: optionAppliesTo("install"), summary: "Install skill files into .claude/skills and .cursor/rules." },
      { flag: "--target", type: "string", default: "all", appliesTo: optionAppliesTo("target"), summary: "Skill target: claude, cursor, or all." },
      { flag: "--track", type: "boolean", default: false, appliesTo: optionAppliesTo("track"), summary: "Do not add installed skill files to .gitignore." },
      { flag: "--format", type: "string", default: "text", appliesTo: optionAppliesTo("format"), summary: "Output format: text or json." },
    ],
    config: {
      fileName: "prompt-redact.config.json",
      settings: [
        { key: "tokenPrefix", type: "string", default: DEFAULT_TOKEN_PREFIX, summary: "Prefix inside <<prefix:salt:n>> tokens." },
        { key: "maxEntries", type: "number", default: DEFAULT_MAX_VAULT_ENTRIES, summary: "Maximum reversible entries before fail-closed overflow." },
        { key: "overflowPolicy", type: "string", default: "hash", summary: "hash (opaque random mask, not derivable from the secret) or error (abort)." },
        { key: "mode", type: "string", default: "session", summary: "Proxy session policy: session or ephemeral. Ignored by the SDK and MCP server." },
        { key: "entropy", type: "object", default: { enabled: false, threshold: 4.2, minLength: 24 }, summary: "Optional Shannon-entropy detector." },
        { key: "allowlist", type: "array", default: [], summary: "Strings or /regex/ patterns excluded from redaction." },
        { key: "customPatterns", type: "array", default: [], summary: "Data-only custom secret rules." },
        { key: "excludePaths", type: "array", default: ["node_modules", ".git", "dist"], summary: "Paths skipped by scan/verify." },
        { key: "exec", type: "object", default: { enabled: false, allowCommands: [] }, summary: "airlock_exec opt-in: enabled plus an explicit command allowlist. Disabled by default." },
      ],
    },
    mcp: {
      command: "npx prompt-redact mcp",
      protocolVersions: {
        modern: MODERN_PROTOCOL_VERSIONS,
        legacy: LEGACY_PROTOCOL_VERSIONS,
      },
      tools,
    },
  };
}

export function renderContractText(contract: AgentContract): string {
  const lines: string[] = [];
  lines.push(`${contract.package} v${contract.version}`);
  lines.push(contract.summary);
  lines.push("");
  lines.push("Commands:");
  for (const cmd of contract.commands) {
    lines.push(`  ${cmd.name.padEnd(12)} ${cmd.summary}`);
  }
  lines.push("");
  lines.push("Exit codes:");
  for (const [code, meaning] of Object.entries(contract.exitCodes)) {
    lines.push(`  ${code}  ${meaning}`);
  }
  lines.push("");
  lines.push("MCP tools:");
  for (const tool of contract.mcp.tools) {
    lines.push(`  ${tool.name.padEnd(20)} ${tool.summary}`);
  }
  lines.push("");
  lines.push("Use `prompt-redact describe --format json` for the machine-readable contract.");
  return lines.join("\n");
}
