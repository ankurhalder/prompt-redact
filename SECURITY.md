# Security policy

## Supported versions

`0.1.x` is the current supported line.

## Reporting a vulnerability

Email **ankur.halder12345@gmail.com** with a subject starting `prompt-redact security`.
Do not include real credentials; a synthetic reproducer is enough.

Please report privately and give a reasonable window to fix before public disclosure.
Useful reports include:

- a redaction bypass through the proxy, MCP tools, or scanner;
- a token/rehydration leak, including across sessions or error paths;
- a confinement escape in `airlock_read_file` or a write path;
- an auth/CORS/query-token bypass in the HTTP transports;
- an `airlock_exec` allowlist bypass;
- a practical availability issue (hang, unbounded memory, event-loop block).

## Scope notes

`airlock_exec` is disabled by default and is explicitly documented as a
vault-access boundary for allowlisted commands. Reports that require enabling
it with an allowlisted command and a hostile model are treated as design
limitations, not vulnerabilities, unless the allowlist itself can be bypassed.

`guard --hook` is a best-effort backstop for native tools. Bypasses that rely on
obfuscated shell commands the guard does not model are treated as limitations
of the guard, not a claim that native tools are sandboxed.
