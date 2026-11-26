# prompt-redact

Deterministic, reversible secret redaction for LLM workflows: a zero-runtime-dependency TypeScript SDK, a loopback Anthropic/OpenAI proxy, an MCP "airlock" server, and a strict secret scanner/gate.

prompt-redact replaces credential-shaped values with opaque tokens before prompt content leaves the machine, and restores the values locally when the model echoes a token. It is a **detection and tokenization layer, not a sandbox**.

---

## Security model (read this first)

**What the tool does:** for values matched by the configured catalog (or the optional entropy detector), the proxy, file reader, and SDK emit tokens instead of the plaintext. Rehydration happens locally, in the same vault.

**What it does not do:**

- It does not prove that every secret is detected. Detection is heuristic (patterns plus optional Shannon entropy). Unlabeled, low-entropy strings can pass through. Give secrets a recognizable shape, add `customPatterns`, or enable `entropy`.
- The proxy redacts request **bodies**, path segments, and query values. It does **not** redact arbitrary HTTP headers. `Authorization` and `x-api-key` are forwarded to the configured upstream by design; `Cookie` and `Referer` are stripped.
- Secret values live in process memory for the lifetime of the vault. There is no zeroization or secure enclave.
- There is no TLS. Keep listeners on loopback unless you put a TLS terminator in front. Binding a listener to a non-loopback host requires (and still sends in cleartext) a bearer token.
- `airlock_exec` is **disabled by default**. Once enabled, every allowlisted command can read the vault (tokens are resolved into its args/env), so a prompt-injected model can exfiltrate secrets through that command. Only enable it for commands and models you trust with every secret in the vault.
- The CI gate does not trust configuration from the repository it inspects. `verify` ignores a repo-local `allowlist`/`excludePaths`; pass a trusted `--config` if you need them. Expected binaries should be explicitly excluded in a trusted config.
- The scanner cannot verify files it cannot read. `verify` treats every skipped file (binary, oversized, unreadable, symlinked, invalid UTF-8) as a failed check. `scan` reports them but stays a report, not a gate.
- The MCP airlock cannot stop native file or shell tools from bypassing it. The secure installer (skill --install --secure) adds permission deny rules and a guard hook, but this remains a guard, not a sandbox.

### What you can rely on

- Tokens are stable within a session/vault, so multi-turn prompt prefixes remain cacheable.
- Redaction is fail-closed on vault saturation: `overflowPolicy: "hash"` emits a **random opaque mask** (`<<redact-masked:0123456789ab>>`, not derivable from the secret); `"error"` aborts the whole operation.
- SSE rehydration is chunk-boundary safe: tokens split across TCP, UTF-8, or JSON-string boundaries are reassembled before the client sees them.
- `audit.md`, SARIF, `/audit`, `redact_audit`, and `redact_verify` record rule IDs, paths, line numbers, and counts — never matched values.

---

## Requirements

- Node.js **>= 18.3.0** for the runtime (uses `node:util.parseArgs` and `server.closeAllConnections`).
- Node.js >= 20 to run the development/test suite (`@modelcontextprotocol/client` is test-only).
- Zero runtime dependencies.

---

## Quick start

### 1. Local LLM proxy (Anthropic + OpenAI)

```bash
npx prompt-redact setup --autopilot
npx prompt-redact proxy --port 4790
```

Point clients at the proxy:

```bash
# Claude Code
export ANTHROPIC_BASE_URL="http://127.0.0.1:4790"

# OpenAI-compatible clients (Cursor, Cline, OpenCode, ...)
export OPENAI_BASE_URL="http://127.0.0.1:4790/v1"
```

PowerShell:

```powershell
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:4790"
$env:OPENAI_BASE_URL = "http://127.0.0.1:4790/v1"
```

Useful options:

- `--dry-run` (or header `x-prompt-redact-dry-run: 1`) returns the tokenized outbound payload without contacting the upstream.
- `--mode ephemeral` creates a fresh vault per proxy request; `session` (default) keeps tokens stable across turns. This option is proxy-only.
- `--max-entries` / `--overflow-policy hash|error` control fail-closed behavior at vault capacity.
- `--token` requires a bearer token from clients. The proxy strips that bearer value before forwarding; a separate upstream credential belongs in `Authorization`/`x-api-key` and is forwarded.

### 2. Airlock MCP server

```bash
npx prompt-redact mcp                 # stdio
npx prompt-redact mcp --http --port 4791
```

`--http` generates a bearer token and prints it once to stderr. Loopback is the default; non-loopback binding requires a token and is cleartext. `--no-auth` is accepted only on loopback and leaves plaintext-revealing inspector endpoints disabled. Query-string tokens for the legacy SSE endpoints are rejected by default; they are available only to SDK callers that explicitly set `allowQueryToken`.

| Tool | Purpose |
| --- | --- |
| `redact_text` | Tokenize text through the active vault. |
| `redact_payload` | Deep-tokenize arbitrary JSON (keys and values). |
| `airlock_read_file` | Read a confined workspace file with credentials replaced by tokens. |
| `airlock_exec` | **Opt-in.** Run an allowlisted command with vault tokens resolved in args/env; stdout/stderr are re-scrubbed. |
| `redact_audit` | Zero-plaintext rule/capacity/audit summary. |
| `redact_verify` | Scan text or a confined file for unredacted credential patterns (rule/line only). |

To enable the executor, add this to `prompt-redact.config.json`:

```json
{
  "exec": {
    "enabled": true,
    "allowCommands": ["git", "node"]
  }
}
```

An empty allowlist refuses everything. Entries without a path separator match the executable basename; entries with one match the full path. Enabling `airlock_exec` is equivalent to granting those commands access to the vault.

### 3. Secure agent setup (recommended for the airlock)

Native Read/Bash tools bypass the MCP server. To make the airlock the default path, install the MCP config, Claude Code permission deny rules, and hooks together:

    npm i -D prompt-redact
    npx prompt-redact skill --install --secure

This writes:

- .mcp.json (Claude Code) and .cursor/mcp.json (Cursor)
- .claude/settings.json: denies native reads of .env, keys, SSH material, and cloud credentials; allowlists the six MCP tools; runs guard --hook on PreToolUse and verify --hook on UserPromptSubmit
- .cursorignore for the same sensitive paths
- the skill and rule files

guard --hook blocks native reads/commands that target credentials and blocks literal secrets; the MCP tools remain allowlisted. This closes the common bypass, but it is a guard, not a sandbox: obfuscated shell can evade heuristics, and airlock_exec remains a trust boundary for every allowlisted command.

### When the airlock helps - and when it doesn't

Useful when:

- the agent is restricted to the MCP tools, or the secure installer is applied;
- the model must inspect .env/configs and run authenticated commands without plaintext entering the model;
- you need an audit trail.

Not a boundary when:

- native Read/Bash remain available and unguarded;
- the model is untrusted and airlock_exec is enabled (allowlisted commands can exfiltrate);
- you expect protection from a malicious local process or a compromised host.

### 4. Scanner and CI gate

```bash
npx prompt-redact scan --sarif          # writes audit.md + audit.sarif, exit 1 on findings
npx prompt-redact verify                # strict gate over the workspace
npx prompt-redact verify --staged       # simulate the index, not the working tree
npx prompt-redact verify --stdin        # stdin, e.g. a pre-commit hook
npx prompt-redact verify --hook         # Claude Code hook envelope on stdin; exit 2 blocks
```

`verify` is strict: every skipped file fails the check, and a repo-local config cannot widen allowlists/exclusions. Pass `--config /path/to/trusted.json` (or `--no-config`) for a trusted gate. `scan` is a report: it lists skipped files but exits on findings only.

Exit codes: **0** success/clean, **1** findings or runtime failure, **2** usage/config error (and `verify --hook` / `guard --hook` use **2** for findings so Claude Code blocks the action).

### 5. Agent skill and hooks

```bash
npx prompt-redact skill --install
```

Writes `.claude/skills/prompt-redact/SKILL.md` and `.cursor/rules/prompt-redact.mdc` (Cursor frontmatter included) and adds both to `.gitignore` unless `--track` is used. Add `--secure` to also install the MCP/permission/hook configuration described in section 3.

Claude Code hook example:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "npx --no-install prompt-redact verify --hook" }] }
    ],
    "PreToolUse": [
      { "matcher": "Read|Edit|Write|MultiEdit|Grep|Bash", "hooks": [{ "type": "command", "command": "npx --no-install prompt-redact guard --hook" }] }
    ]
  }
}
```

`--hook` parses the JSON envelope on stdin and emits exit code **2** on findings, which is the only code Claude Code treats as blocking. The PreToolUse guard blocks native credential reads/commands; the prompt hook scans submitted text.

---

## Programmatic SDK

```ts
import {
  createVault,
  redactPayload,
  rehydratePayload,
} from "prompt-redact";

const vault = createVault({ mode: "session", maxEntries: 1024, overflowPolicy: "hash" });

const { payload } = redactPayload(
  { messages: [{ role: "user", content: process.env.ANTHROPIC_API_KEY ?? "" }] },
  vault
);
// send `payload` to the model, then restore locally:
const restored = rehydratePayload(payload, vault);
```

Token example: `<<redact:0123456789abcdef0123456789abcdef:1>>` (prefix, 32-hex salt, index). Overflow masks look like `<<redact-masked:0123456789ab>>` (opaque; not reversible and not derived from the secret). The legacy `<<redact-hash:...>>` form is still recognized as a placeholder for compatibility.

For streaming responses, pipe the upstream body through `createSseRehydrationTransform(vault, protocol, options)` (or `wrapResponseWithRehydration`). It supports OpenAI chat/completions, the Responses API, and Anthropic events, including tokens split across frames, multiple choices, tool-call JSON, and `id:`/`retry:` fields.

---

## Configuration

`prompt-redact.config.json` is data-only JSON. Unknown keys are rejected instead of silently ignored.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `tokenPrefix` | string | `"redact"` | Token prefix. |
| `maxEntries` | integer | `1024` | Distinct secrets before the overflow policy applies. |
| `overflowPolicy` | string | `"hash"` | `hash` = random opaque mask; `error` = abort. |
| `mode` | string | `"session"` | Proxy session policy; ignored by the SDK/MCP/scanner/serve. |
| `entropy` | object | disabled | `{ enabled, threshold, minLength }` for unlabeled high-entropy values. |
| `allowlist` | array | `[]` | Exact strings or `{ pattern, flags }` regexes that suppress findings. |
| `customPatterns` | array | `[]` | `{ rule, pattern, flags?, valueGroup? }`; validated against catastrophic backtracking heuristics. |
| `excludePaths` | array | `["node_modules",".git","dist"]` | Paths skipped by scan/verify (trusted config only in verify). |
| `exec` | object | `{ enabled:false, allowCommands:[] }` | `airlock_exec` opt-in and command allowlist. |

Example:

```json
{
  "maxEntries": 1024,
  "overflowPolicy": "hash",
  "entropy": { "enabled": true, "threshold": 4.2, "minLength": 24 },
  "customPatterns": [{ "rule": "corp-token", "pattern": "CORP_[A-Z0-9]{12}" }],
  "exec": { "enabled": false, "allowCommands": [] }
}
```

---

## CLI reference

| Command | What it does |
| --- | --- |
| `proxy` | Loopback Anthropic/OpenAI proxy (default port 4790). |
| `mcp` | MCP server over stdio or `--http` (default HTTP port 4791). |
| `serve` | Loopback inspector/playground with `/mcp` mounted (default port 4788). |
| `scan [path]` | Scan and write `audit.md`; `--sarif` writes `audit.sarif`. |
| `verify [path]` | Strict gate: workspace, `--staged`, `--stdin`, or `--hook`. |
| `guard` | PreToolUse hook for native Read/Bash credential access; exits 2 to block. |
| `setup` | Write the default config and print env hints (`--autopilot` also runs doctor). |
| `doctor` | Check Node, config, port, and a vault round-trip. |
| `skill` | Print or install the agent skill (`--install`, `--target`, `--track`, `--secure`). |
| `describe` | Machine-readable agent contract (`--format json`). |

Common flags: `--cwd`, `--config`, `--no-config`, `--host`, `--port`, `--token`, `--no-auth`, `--allow-origin`, `--max-entries`, `--overflow-policy`, `--mode` (proxy), `--format`, `--help`, `--version`. The skill installer also accepts `--secure`. Run `describe --format json` for the authoritative per-command option matrix.

The inspector (`serve`) requires a bearer token by default; its `/api/rehydrate` and `/api/sse-simulate` endpoints (which reveal plaintext) are disabled entirely under `--no-auth`. The page sets CSP/frame-protection headers, and the token is kept in `sessionStorage`, not persistent storage.

---

## Benchmarks

Measured with `npm run benchmark` on Node v24.12.0, win32-x64. These are indicative, not guarantees.

| Case | Measured |
| --- | --- |
| SDK redact, 10 KB secret-dense | ~5.1 ms median |
| SDK redact, 100 KB secret-dense | ~49 ms median |
| SDK redact, 100 KB ordinary prose | **~0.87 ms** median |
| SDK rehydrate, 100 KB | ~0.39 ms median |
| Proxy overhead, 2.6 KB JSON | ~+1.0 ms |
| Proxy overhead, 2.6 KB SSE | ~+1.2 ms |
| Proxy overhead, 100 KB prose | ~+2.9 ms |

The secret-dense payload contains two credential shapes per ~120-character line; the prose case exercises the credential-assignment prefilter. Earlier README revisions quoted much lower numbers measured before the catalog grew — the benchmark script is the source of truth.

---

## Development

```bash
npm ci
npm run typecheck     # tsc --noEmit
npm test              # builds, then runs 72 tests
npm run verify        # typecheck + tests + pack-check + real tarball install check
npm run benchmark     # SDK + proxy timings
```

CI runs `npm run verify` on Node 20 and 22. Versioning is currently `0.1.0`.

### Release

`0.1.0` is the current release candidate. [`.github/workflows/release.yml`](.github/workflows/release.yml) publishes on a `v*` tag with npm provenance; it expects an `NPM_TOKEN` repository secret (or npm trusted publishing) and a tag matching `package.json` (`v0.1.0`). `prepublishOnly` re-runs the check suite and `prepack` rebuilds `dist`, so a publish cannot ship stale output.

---

## License

MIT © Ankur Halder
