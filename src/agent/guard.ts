import { scanTextForFindings } from "../audit/scanner.js";
import { extractHookText, parseHookEnvelope } from "./hook.js";

export interface GuardOptions {
  cwd: string;
}

export interface GuardVerdict {
  block: boolean;
  reasons: string[];
}

const SENSITIVE_ENV_EXEMPT = /\.(example|sample|template)$/i;

function normalizePath(value: string): string {
  return value
    .trim()
    .replace(/^["'\x60]+|["'\x60]+$/g, "")
    .replace(/\\/g, "/");
}

/**
 * Heuristic, deliberately conservative: the guard is a backstop for native
 * tools, not a filesystem sandbox. Callers that need hard enforcement should
 * also use the Claude Code permission deny rules emitted by --secure.
 */
export function isSensitivePath(value: string): boolean {
  const normalized = normalizePath(value);
  if (!normalized) return false;
  const segments = normalized.split("/").filter(Boolean);
  const base = segments[segments.length - 1] ?? "";
  if (base.length === 0) return false;
  if (/^\.env$/i.test(base)) return true;
  if (/^\.env\.[A-Za-z0-9._-]+$/i.test(base)) return !SENSITIVE_ENV_EXEMPT.test(base);
  if (/^\.envrc$/i.test(base)) return true;
  if (/^\.(npmrc|pypirc|netrc)$/i.test(base)) return true;
  if (/^\.git-credentials$/i.test(base)) return true;
  if (/^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$/i.test(base)) return true;
  if (/\.(pem|key|p12|pfx|jks|keystore)$/i.test(base)) return true;
  if (/^(secrets?|credentials)\.(json|ya?ml|toml|txt)$/i.test(base)) return true;
  if (/^service-account.*\.json$/i.test(base)) return true;
  if (/\.tfvars$/i.test(base)) return true;
  if (/\.tfstate(?:\.backup)?$/i.test(base)) return true;
  const joined = "/" + segments.join("/").toLowerCase();
  if (joined.includes("/.ssh/") || joined.endsWith("/.ssh")) return true;
  if (joined.includes("/.aws/credentials") || joined.endsWith("/.aws/credentials")) return true;
  if (joined.includes("/.kube/config") || joined.endsWith("/.kube/config")) return true;
  if (joined.includes("/.docker/config.json")) return true;
  if (joined.includes("/.config/gcloud/") && /(credentials|application_default_credentials)\.json$/i.test(base)) {
    return true;
  }
  return false;
}

const READ_COMMAND = /\b(?:cat|type|more|less|head|tail|grep|egrep|fgrep|rg|awk|sed|cut|sort|uniq|xxd|hexdump|base64|strings|tar|zip|scp|curl|wget|invoke-webrequest|iwr|get-content|gc|select-string|sls|copy-item|cp|move|mv|robocopy|source|git\s+(?:show|diff|grep|cat-file))\b/i;
const SCRIPT_READ = /\b(?:readFileSync|readFile|open\s*\(|file\.readall|fs\.read|read_text|read_bytes)\b/i;

const ENV_DUMP_PATTERNS: readonly RegExp[] = [
  /\bprintenv\b/i,
  /(?:^|[;&|]\s*)env\s*(?:$|\|)/i,
  /\bset\s*(?:$|\|)/i,
  /\bexport\s+-p\b/i,
  /\bdeclare\s+-x\b/i,
  /\bget-childitem\s+env:/i,
  /\bgci\s+env:/i,
  /\bget-item\s+env:/i,
  /\bdir\s+env:/i,
  /\[environment\]::getenvironmentvariables/i,
  /\b(?:echo|printf|write-output|write-host)\s+["']?(?:\$env:|\$\{?)[a-z0-9_]*(?:key|token|secret|password|pass|credential|auth)[a-z0-9_]*/i,
  /\b(?:echo|printf)\s+["']?%[^%]*(?:key|token|secret|password|pass|credential|auth)[^%]*%/i,
  /\bprocess\.env\.[a-z0-9_]*(?:key|token|secret|password|pass|credential|auth)[a-z0-9_]*/i,
  /\bprocess\.env\[\s*["'][^"']*(?:key|token|secret|password|pass|credential|auth)[^"']*["']\s*\]/i,
  /\b(?:console\.log|console\.error|json\.stringify|stringify)\s*\(\s*process\.env\b/i,
  /\bos\.environ\b/i,
  /\bos\.getenv\(\s*["'][^"']*(?:key|token|secret|password|pass|credential|auth)[^"']*["']/i,
];

function filePathOf(input: Record<string, unknown> | null): string | null {
  if (!input) return null;
  for (const key of ["file_path", "path", "notebook_path", "target_file"]) {
    const value = input[key];
    if (typeof value === "string" && value.trim().length > 0) return value;
  }
  return null;
}

function commandOf(input: Record<string, unknown> | null): string | null {
  if (!input) return null;
  const value = input.command;
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function commandContainsSensitivePath(command: string): boolean {
  const tokens = command.split(/[\s"'\x60|&;<>()]+/).filter(Boolean);
  for (const token of tokens) {
    const cleaned = token.replace(/^[^=]+=/, "").replace(/^["'\x60]+|["'\x60]+$/g, "");
    if (isSensitivePath(cleaned)) return true;
    for (const part of cleaned.split(/[=,:]/)) {
      if (isSensitivePath(part)) return true;
    }
  }
  const raw = command.match(/\.env(?:\.[A-Za-z0-9._-]+)?|id_(?:rsa|dsa|ecdsa|ed25519)|[A-Za-z0-9._-]+\.(?:pem|key|p12|pfx|jks|keystore)/gi) ?? [];
  return raw.some(isSensitivePath);
}

export function evaluateHook(raw: string, _options: GuardOptions): GuardVerdict {
  const envelope = parseHookEnvelope(raw);
  if (!envelope) {
    return { block: true, reasons: ["hook JSON could not be parsed; failing closed"] };
  }

  const toolName = envelope.toolName ?? "";
  // The prompt-redact airlock is the supported path; do not guard its own calls.
  if (toolName.startsWith("mcp__")) {
    return { block: false, reasons: [] };
  }

  const reasons: string[] = [];
  if (toolName === "Read" || toolName === "Grep") {
    const target = filePathOf(envelope.toolInput);
    if (target !== null && isSensitivePath(target)) {
      reasons.push(
        "native " + toolName + " of a credential-bearing path is blocked; use airlock_read_file instead"
      );
    }
  }

  if (toolName === "Bash") {
    const command = commandOf(envelope.toolInput);
    if (command !== null) {
      if ((READ_COMMAND.test(command) || SCRIPT_READ.test(command)) && commandContainsSensitivePath(command)) {
        reasons.push(
          "native shell access to a credential-bearing file is blocked; use airlock_exec with <<redact:...>> tokens"
        );
      }
      if (ENV_DUMP_PATTERNS.some((pattern) => pattern.test(command))) {
        reasons.push(
          "native environment dumping is blocked; use airlock_exec to pass only the tokens a command needs"
        );
      }
    }
  }

  const findings = scanTextForFindings(extractHookText(raw), "<hook>", {});
  if (findings.length > 0) {
    const rules = [...new Set(findings.map((finding) => finding.rule))].sort();
    reasons.push("hook input contains unredacted secret(s): " + rules.join(", "));
  }

  const unique = [...new Set(reasons)];
  return { block: unique.length > 0, reasons: unique };
}
