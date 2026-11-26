# Changelog

## 0.1.0 — 2026-11-26

Initial release.

- Reversible redaction SDK with session vaults, atomic fail-closed overflow,
  random opaque overflow masks, and 128-bit salts.
- Loopback Anthropic/OpenAI proxy with JSON/text/path/query redaction,
  chunk-safe SSE rehydration (OpenAI chat, Responses, Anthropic), dry-run,
  response limits, upstream timeouts, and a concurrency cap.
- MCP airlock server (stdio + Streamable HTTP) with confined file reads,
  token-aware execution (**disabled by default**), audit, and verify tools.
- Strict `verify` gate that fails on every skipped file and ignores repo-local
  allowlists/exclusions; `verify --hook` exits 2 for Claude Code.
- Scanner with BOM/BOM-less UTF-16 decoding, staged-index scanning, SARIF, and
  markdown audit reports that never record values.
- Agent skill installer for Claude Code and Cursor with a working blocking hook.
- Hardened inspector: CSP/frame headers, session-scoped token storage, and
  plaintext-revealing endpoints disabled under `--no-auth`.
- `guard --hook`: blocks native Read/Bash access to credential-bearing paths,
  native environment dumps, and literal secrets; use it on PreToolUse.
- `skill --install --secure`: writes Claude/Cursor MCP configs, Claude permission
  deny/allow rules, the guard/verify hooks, and .cursorignore so the airlock is
  the default path rather than an optional one.
- Native-tool and `airlock_exec` limits are documented; the guard is a
  best-effort control, not a sandbox.
- Atomic confined writes, descriptor-based confined reads, and stricter
  configuration validation (unknown keys rejected).
- Release tooling: 70-test suite, CJS/ESM/bundle checks, tarball install check,
  CI on Node 20/22, and tag-triggered provenance publishing.
