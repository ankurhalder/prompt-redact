export interface SecretRule {
  rule: string;
  pattern: RegExp;
  valueGroup?: number;
}

export type SecretRuleInput =
  | RegExp
  | string
  | {
      rule: string;
      pattern: RegExp | string;
      valueGroup?: number;
    };

export type AllowlistEntry = string | RegExp | { pattern: string; flags?: string };

/**
 * "hash" is retained as the config value for compatibility; it now emits an
 * opaque random mask (<<redact-masked:...>>) that is not derived from the
 * secret. "error" aborts the whole operation instead.
 */
export type OverflowPolicy = "hash" | "error";

export type VaultMode = "session" | "ephemeral";

export interface EntropyConfig {
  enabled?: boolean;
  threshold?: number;
  minLength?: number;
}

export interface ExecConfig {
  /**
   * Enables the airlock_exec tool. Disabled by default: an enabled executor can
   * unmask vault tokens into an arbitrary child process and is therefore an
   * explicit trust decision, not a safe default.
   */
  enabled?: boolean;
  /**
   * Commands the executor may run. Required when enabled. Entries without a
   * path separator match the executable basename; entries with one match the
   * full command path. Nothing is allowed when the list is empty.
   */
  allowCommands?: string[];
}

export interface PromptRedactConfig {
  tokenPrefix?: string;
  maxEntries?: number;
  overflowPolicy?: OverflowPolicy;
  /**
   * Session policy for the HTTP proxy only. The SDK and MCP server always keep
   * a per-process vault; "ephemeral" additionally creates a fresh vault for
   * every proxy request (including dry-runs). Setting "ephemeral" has no effect
   * on the SDK, MCP, scanner, or serve vaults.
   */
  mode?: VaultMode;
  entropy?: EntropyConfig;
  allowlist?: Array<string | { pattern: string; flags?: string }>;
  customPatterns?: Array<{
    rule: string;
    pattern: string;
    flags?: string;
    valueGroup?: number;
  }>;
  excludePaths?: string[];
  exec?: ExecConfig;
}

export interface AuditEvent {
  timestamp: string;
  source: string;
  rule: string;
  count: number;
  targetHost?: string;
  overflowed?: boolean;
  overflowCount?: number;
}

export interface AuditSummary {
  totalRedactions: number;
  overflowCount: number;
  vaultSize: number;
  maxEntries: number;
  byRule: Record<string, number>;
  events: AuditEvent[];
}

export interface AuditRecorder {
  record(event: Omit<AuditEvent, "timestamp">): void;
  summary(vaultSize: number, maxEntries: number, overflowCount: number): AuditSummary;
  clear(): void;
}

export interface VaultOptions {
  mode?: VaultMode;
  salt?: string;
  tokenPrefix?: string;
  maxEntries?: number;
  overflowPolicy?: OverflowPolicy;
  rules?: readonly SecretRule[];
  allowlist?: readonly AllowlistEntry[];
  entropy?: EntropyConfig;
  audit?: AuditRecorder;
  source?: string;
}

export interface RedactionHit {
  rule: string;
  start: number;
  end: number;
  token: string;
  overflowed: boolean;
}

export interface RedactTextResult {
  text: string;
  hits: number;
  overflows: number;
  findings: Array<{ rule: string; count: number }>;
}

export interface PayloadRedactionResult<T = unknown> {
  payload: T;
  redactedCount: number;
  overflowCount: number;
  byRule: Record<string, number>;
  vault: SecretVault;
}

export interface SecretVault {
  readonly mode: VaultMode;
  readonly salt: string;
  readonly tokenPrefix: string;
  readonly size: number;
  readonly maxEntries: number;
  readonly overflowCount: number;
  readonly maxTokenLength: number;
  redact(text: string, source?: string, contextKey?: string): RedactTextResult;
  redactBatch(
    items: ReadonlyArray<string | { text: string; contextKey?: string }>,
    source?: string
  ): RedactTextResult[];
  rehydrate(text: string): string;
  resolveToken(token: string): string | undefined;
  replacements(): Array<[string, string]>;
  audit(): AuditSummary;
}

export interface ScanFinding {
  file: string;
  line: number;
  rule: string;
}

export type ScanSkipReason =
  | "binary"
  | "oversize"
  | "unreadable"
  | "symlink"
  | "invalid-utf8";

export interface ScanSkip {
  file: string;
  reason: ScanSkipReason;
}

export interface ScanReport {
  scannedFiles: number;
  skippedFiles: number;
  /** Per-file reasons for every skipped entry; never contains file contents. */
  skipped: ScanSkip[];
  /** True when the report was produced in strict mode (see ScanOptions.strict). */
  strict: boolean;
  findings: ScanFinding[];
  byRule: Record<string, number>;
  clean: boolean;
}
