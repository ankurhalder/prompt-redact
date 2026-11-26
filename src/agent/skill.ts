import { PACKAGE_NAME, PACKAGE_VERSION } from "../version.js";

export const SKILL_NAME = "prompt-redact";

const BODY = `# prompt-redact

Keeps plaintext credentials inside localhost while letting coding agents inspect configs, run authenticated commands, and verify zero leaks.

## Core Commands

1. **Read the machine contract first:**
   \`npx ${PACKAGE_NAME} describe --format json\`
2. **Start the local intercepting proxy (Anthropic + OpenAI):**
   \`npx ${PACKAGE_NAME} proxy --port 4790\`
   - Claude Code: \`export ANTHROPIC_BASE_URL=http://127.0.0.1:4790\`
   - OpenAI / Cursor / Cline / OpenCode: \`export OPENAI_BASE_URL=http://127.0.0.1:4790/v1\`
3. **Run the secret-safe MCP server:**
   \`npx ${PACKAGE_NAME} mcp\`
   - \`airlock_read_file\`: read \`.env\`, configs, or logs with secrets replaced by \`<<redact:...>>\`.
   - \`airlock_exec\`: disabled by default. When explicitly enabled with \`exec.enabled\` and \`exec.allowCommands\`, it passes \`<<redact:...>>\` tokens in \`args\`/\`env\` to an allowlisted command and re-scrubs \`stdout\`/\`stderr\`. Enabling it is equivalent to trusting every allowlisted command with the whole vault.
   - \`redact_verify\` / \`redact_audit\`: confirm zero plaintext leaks.
4. **Scan and gate repositories:**
   \`npx ${PACKAGE_NAME} scan --sarif\` (writes \`audit.md\` and \`audit.sarif\`, exit \`1\` on findings).
   \`npx ${PACKAGE_NAME} verify\` is strict: skipped files that could contain text fail the gate. In CI, pass a trusted \`--config\` or let it use built-in defaults; a repo-local config may add patterns but cannot widen allowlists/exclusions.

## Claude Code Hook Guidance

Add a \`UserPromptSubmit\` / \`PreToolUse\` gate in \`.claude/settings.json\`. \`verify --hook\` reads the hook JSON envelope from stdin and **exits 2** on findings, which is the only exit code Claude Code treats as blocking.

\`\`\`json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "npx --no-install prompt-redact verify --hook"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "npx --no-install prompt-redact verify --hook"
          }
        ]
      }
    ]
  }
}
\`\`\`
`;

export function renderSkill(): string {
  return `---
name: ${SKILL_NAME}
description: Prevent plaintext secrets from leaving localhost to an LLM. Use the prompt-redact proxy, airlock MCP tools (airlock_read_file, optional airlock_exec), and zero-plaintext verifier whenever handling credentials, .env files, logs, or API requests.
version: ${PACKAGE_VERSION}
---

${BODY}`;
}

export function renderCursorRule(): string {
  return `---
description: prompt-redact — keep plaintext credentials out of LLM prompts, run the local proxy, and gate secrets in CI.
globs: ["**/*"]
alwaysApply: true
---

${BODY}`;
}
