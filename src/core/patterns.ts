import type { SecretRule } from "../types.js";

const ENV_SUFFIX =
  "(?:[_-](?:prod|production|staging|stage|dev|development|test|testing|qa|live|local|primary|secondary|backup|old|new|v\\d{1,3}|\\d{1,3}))?";

const STRONG_CREDENTIAL_NAME =
  "(?:password|passwd|passphrase|pwd|api[_-]?key|api[_-]?secret|access[_-]?key|" +
  "secret[_-]?access[_-]?key|secret[_-]?key|client[_-]?secret[_-]?key|client[_-]?secret|" +
  "private[_-]?key|aws[_-]?secret[_-]?access[_-]?key|access[_-]?token|refresh[_-]?token|" +
  "auth[_-]?token|session[_-]?token|session[_-]?key|signing[_-]?key|encryption[_-]?key|" +
  `master[_-]?key|webhook[_-]?key|db[_-]?key|credential|secret|token)${ENV_SUFFIX}`;

const EXCLUDED_GENERIC_KEYS =
  "(?:primary|foreign|composite|partition|sort|clustering|cache|lookup|routing|id|index|map|object|bucket|table|row|column|react|item|element|aria|hot|short)[_-]key";

const GENERAL_KEY_SUFFIX_NAME =
  `(?!(?:id[-_]token|${EXCLUDED_GENERIC_KEYS})\\b)[A-Za-z0-9][A-Za-z0-9_-]{0,47}[_-](?:key|credential)${ENV_SUFFIX}`;

const NOT_A_LITERAL_VALUE =
  "(?!(?:string|number|boolean|bigint|symbol|unknown|any|never|void|null|undefined|true|false|" +
  "await|async|new|this|typeof|delete|yield|function|return|process\\.env|Buffer|Record|object)\\b)";

export const CREDENTIAL_KEY_TAIL = new RegExp(
  `(?:^|[^a-zA-Z0-9])(?:(?<!id[-_])${STRONG_CREDENTIAL_NAME}|${GENERAL_KEY_SUFFIX_NAME})$`,
  "i"
);

const EXCLUDED_GENERIC_KEY_RE = new RegExp(`^${EXCLUDED_GENERIC_KEYS}$`, "i");

export function isStrongCredentialKey(key: string): boolean {
  const trimmed = key.trim();
  if (trimmed.length === 0 || trimmed.length > 128) return false;
  if (/^id[-_]?token$/i.test(trimmed)) return false;
  if (EXCLUDED_GENERIC_KEY_RE.test(trimmed)) return false;
  return CREDENTIAL_KEY_TAIL.test(trimmed);
}

const ASSIGN = String.raw`(?<![=!<>])[:=](?!=)`;
const NOT_AFTER_QUOTE = String.raw`(?<!["'])`;
const NOT_A_NAMESPACED_IDENTIFIER = String.raw`(?![a-z][a-z0-9]*(?:\.[a-z][a-z0-9-]*)+/)`;
const QUOTED_CREDENTIAL_KEY = `["']?(?:(?!id[-_]token["'])[A-Za-z0-9_$-]{0,64}${STRONG_CREDENTIAL_NAME}|${GENERAL_KEY_SUFFIX_NAME})(?:\\\\)?["']`;
const UNQUOTED_STRONG_NAME = `(?:(?<!id[-_])${STRONG_CREDENTIAL_NAME}|\\b${GENERAL_KEY_SUFFIX_NAME})`;

/**
 * Cheap prefilter for the expensive credential-assignment rules. Every one of
 * them needs a credential-ish key followed by : or =, so prose without that
 * shape can skip them entirely. This is a conservative superset: a false
 * negative here would be a missed detection, so keep every strong name.
 */
const ASSIGNMENT_HINT =
  /(?:key|token|secret|password|passwd|passphrase|pwd|credential)[^A-Za-z0-9]{0,12}[:=]/i;

export const ASSIGNMENT_RULE_NAMES: ReadonlySet<string> = new Set([
  "aws-secret-access-key",
  "postmark-uuid-secret",
  "credential-assignment-quoted",
  "credential-assignment-json-escaped",
  "credential-assignment-unquoted",
  "env-secret-assignment",
]);

export function textMayContainCredentialAssignment(text: string): boolean {
  return ASSIGNMENT_HINT.test(text);
}

export const PEM_BLOCK_PATTERN =
  /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:(?!-----BEGIN)[\s\S]){0,16384}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g;

export const PEM_UNTERMINATED_PATTERN =
  /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:(?:\r\n|\n|\r)(?:(?:[ \t]*(?:Proc-Type|DEK-Info|Comment|Version):[^\r\n]*[ \t]*(?:\r\n|\n|\r))|(?:[ \t]*(?:\r\n|\n|\r))){0,16}(?:[ \t]*(?:(?:#|\/\/|;|\*)[ \t]*)?["'`]?[A-Za-z0-9+/=]{8,}["'`]?[ \t]*(?:[,;+]?)[ \t]*(?:\r\n|\n|\r|$)){1,512}|(?:\\r)?\\n(?:[A-Za-z0-9+/=]{0,256}(?:\\r)?\\n){0,512}[A-Za-z0-9+/=]{8,256})/g;

export const DEFAULT_SECRET_PATTERNS: SecretRule[] = [
  {
    rule: "private-key-header",
    pattern:
      /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|-----BEGIN (?:RSA |OPENSSH |EC |PGP |DSA |ENCRYPTED )?PRIVATE KEY-----/,
  },
  {
    rule: "base64-private-key",
    pattern: /LS0tLS1CRUdJTi[A-Za-z0-9+/]{40,2048}={0,2}/,
  },
  {
    rule: "jwt-token",
    pattern:
      /eyJ[A-Za-z0-9_-]{8,1024}={0,2}(?:\.|%2[eE])eyJ[A-Za-z0-9_-]{8,1024}={0,2}(?:(?:\.|%2[eE])[A-Za-z0-9_-]{1,1024}={0,2})?/,
  },
  {
    rule: "aws-access-key-id",
    pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA|ABIA)[0-9A-Z]{16}\b/,
  },
  {
    rule: "aws-secret-access-key",
    pattern: new RegExp(
      `(?:["']${STRONG_CREDENTIAL_NAME}["']|${NOT_AFTER_QUOTE}${STRONG_CREDENTIAL_NAME})\\s{0,8}${ASSIGN}\\s{0,8}["']?([A-Za-z0-9/+=]{40})["']?`,
      "i"
    ),
    valueGroup: 1,
  },
  {
    rule: "github-token",
    pattern:
      /\b(?:gh[pousr]_[A-Za-z0-9]{20,251}|github_pat_[A-Za-z0-9_]{22,251})\b/,
  },
  {
    rule: "slack-token",
    pattern: /\bxox[baprsdc]-[0-9A-Za-z-]{10,250}\b/,
  },
  {
    rule: "slack-webhook-url",
    pattern: /hooks\.slack\.com\/services\/T[A-Z0-9]{6,12}\/B[A-Z0-9]{6,12}\/[A-Za-z0-9]{20,32}/,
  },
  {
    rule: "stripe-key",
    pattern: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,247}\b/,
  },
  {
    rule: "google-api-key",
    pattern: /\bAIza[0-9A-Za-z_-]{33,40}\b/,
  },
  {
    rule: "google-oauth-client-secret",
    pattern: /\bGOCSPX-[A-Za-z0-9_-]{20,64}\b/,
  },
  {
    rule: "openai-anthropic-key",
    pattern: /\bsk-(?:ant-[a-z0-9-]{2,32}-|proj-|svcacct-|admin-|live-)?[A-Za-z0-9_-]{16,240}\b/,
  },
  {
    rule: "brevo-api-key",
    pattern: /\bxkeysib-[A-Za-z0-9-]{40,200}\b/,
  },
  {
    rule: "resend-api-key",
    pattern: /\bre_[A-Za-z0-9_]{20,200}\b/,
  },
  {
    rule: "sendgrid-key",
    pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/,
  },
  {
    rule: "mailgun-api-key",
    pattern: /\bkey-[0-9a-zA-Z]{32}\b/,
  },
  {
    rule: "npm-token",
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/,
  },
  {
    rule: "pypi-token",
    pattern: /\bpypi-[A-Za-z0-9_-]{50,180}\b/,
  },
  {
    rule: "twilio-api-key",
    pattern: /\bSK[0-9a-fA-F]{32}\b/,
  },
  {
    rule: "digitalocean-token",
    pattern: /\bdop_v1_[0-9a-f]{64}\b/,
  },
  {
    rule: "azure-storage-account-key",
    pattern: /AccountKey=([A-Za-z0-9+/=]{80,100})/,
    valueGroup: 1,
  },
  {
    rule: "known-vendor-token",
    pattern:
      /\b(?:glpat-[A-Za-z0-9_-]{20,64}|glrt-[A-Za-z0-9_-]{20,64}|hvs\.[A-Za-z0-9_-]{20,128}|hvb\.[A-Za-z0-9_-]{20,128}|whsec_[A-Za-z0-9]{20,64}|dckr_pat_[A-Za-z0-9_-]{20,64}|hf_[A-Za-z0-9]{30,64}|ya29\.[A-Za-z0-9_-]{20,128}|shpat_[A-Za-z0-9]{20,64}|shpca_[A-Za-z0-9]{20,64}|shppa_[A-Za-z0-9]{20,64}|shpss_[A-Za-z0-9]{20,64}|[0-9]{8,10}:[A-Za-z0-9_-]{35})(?![A-Za-z0-9])/,
  },
  {
    rule: "database-uri-credentials",
    pattern:
      /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|maria(?:db)?|rediss?|amqps?|clickhouse|mssql|sqlserver|oracle):\/\/[^\s:@/"'`;()<>,]{0,128}:([^\s@/"'`;()<>,]{6,256})@[^\s/"'`;()<>,]{1,256}/,
    valueGroup: 1,
  },
  {
    rule: "basic-auth-url",
    pattern:
      /(?:https?|ftp|sftp|ssh|git|smtp|smtps|ldap|ldaps):\/\/[^\s:@/"'`;()<>,]{0,128}:([^\s@/"'`;()<>,]{6,256})@[^\s/"'`;()<>,]{1,256}/i,
    valueGroup: 1,
  },
  {
    rule: "authorization-header",
    pattern:
      /(?:Authorization["']?\s*[:=]\s*["']?(?:Bearer|Basic|Token)\s+|Bearer\s+)([A-Za-z0-9._~+/=-]{16,1024})(?![A-Za-z0-9._~+/=-])/i,
    valueGroup: 1,
  },
  {
    rule: "postmark-uuid-secret",
    pattern:
      /\b(?:POSTMARK[A-Z_]*|API[_-]?KEY|APIKEY|AUTH_TOKEN|ACCESS_TOKEN|SECRET|PASSWORD)\b[^\n:=]{0,32}[:=]\s*["'`]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["'`]?/i,
    valueGroup: 1,
  },
  {
    rule: "credential-assignment-quoted",
    pattern: new RegExp(
      `(?:${QUOTED_CREDENTIAL_KEY}|${NOT_AFTER_QUOTE}${UNQUOTED_STRONG_NAME})\\s{0,8}${ASSIGN}\\s{0,8}${NOT_A_NAMESPACED_IDENTIFIER}(["'\`])((?:(?!\\1)[^\\\\\\n]|\\\\[^\\n]){6,512})\\1`,
      "i"
    ),
    valueGroup: 2,
  },
  {
    rule: "credential-assignment-json-escaped",
    pattern: new RegExp(
      `(?:${QUOTED_CREDENTIAL_KEY}|${NOT_AFTER_QUOTE}${UNQUOTED_STRONG_NAME})\\s{0,8}${ASSIGN}\\s{0,8}${NOT_A_NAMESPACED_IDENTIFIER}\\\\(["'\`])((?:[^\\\\\\n]|\\\\\\\\\\\\\\1|\\\\\\\\(?!\\\\\\1)|\\\\(?!\\1)[^\\\\\\n]){6,512})\\\\\\1`,
      "i"
    ),
    valueGroup: 2,
  },
  {
    rule: "credential-assignment-unquoted",
    pattern: new RegExp(
      `(?:${QUOTED_CREDENTIAL_KEY}|${NOT_AFTER_QUOTE}${UNQUOTED_STRONG_NAME})\\s{0,8}${ASSIGN}\\s{0,8}${NOT_A_LITERAL_VALUE}([A-Za-z0-9/+=_.~\\\\-]{12,256})(?![A-Za-z0-9/+=_.~\\\\-])`,
      "i"
    ),
    valueGroup: 1,
  },
  {
    rule: "env-secret-assignment",
    pattern:
      /(?:^|\n)[ \t]{0,64}(?:export[ \t]{1,8})?(?=[A-Z][A-Z0-9_]{0,191}[ \t]{0,8}=)[A-Z0-9_]{0,96}(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL)[A-Z0-9_]{0,96}[ \t]{0,8}=(?!=)[ \t]{0,8}(?!["'`$<{[\]\s])([^\s#;"'`()]{8,256})(?=$|[\r\n\s#;])/,
    valueGroup: 1,
  },
];
