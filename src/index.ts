export { PACKAGE_NAME, PACKAGE_VERSION, SCHEMA_VERSION } from "./version.js";
export {
  DEFAULT_MAX_VAULT_ENTRIES,
  DEFAULT_TOKEN_PREFIX,
  VaultCapacityError,
  coalesceSpans,
  createVault,
} from "./core/vault.js";
export type { CandidateSpan } from "./core/vault.js";
export { PayloadDepthError, redactPayload, rehydrateJsonEncodedString, rehydratePayload } from "./core/payload.js";
export { decodeTextBuffer, decodeTextBufferDetailed } from "./core/text.js";
export type { TextDecodeReason, TextDecodeResult } from "./core/text.js";
export { assertWritableInsideRepository, writeFileInsideRepository } from "./core/fs-safe.js";
export {
  DEFAULT_MAX_SSE_LINE_CHARS,
  SseEventAssembler,
  Utf8StreamFrameDecoder,
  createSseRehydrationTransform,
  detectSseProtocol,
  wrapResponseWithRehydration,
} from "./core/sse.js";
export type { SseEventFrame, SseProtocol, SseRehydrationOptions } from "./core/sse.js";
export {
  DEFAULT_SECRET_PATTERNS,
  PEM_BLOCK_PATTERN,
  PEM_UNTERMINATED_PATTERN,
} from "./core/patterns.js";
export { findHighEntropySpans, isPlaceholderValue, shannonEntropy } from "./core/entropy.js";
export {
  CONFIG_FILENAME,
  buildVaultFromConfig,
  compileAllowlist,
  compileSecretRules,
  isAllowlisted,
  loadConfigFile,
  validatePatternSafety,
} from "./core/config.js";
export { createAuditRecorder } from "./core/audit.js";
export { startProxyServer } from "./proxy/server.js";
export type { ProxyServerHandle, ProxyServerOptions } from "./proxy/server.js";
export { normalizeUpstreamBase, resolveUpstreamTarget } from "./proxy/protocol.js";
export type { ProxyUpstreamConfig, ResolvedUpstream } from "./proxy/protocol.js";
export { buildEnvHints, defaultConfigObject, runDoctor, runSetup } from "./proxy/setup.js";
export type { DoctorCheck, DoctorResult, SetupResult } from "./proxy/setup.js";
export { scanPath, scanTextForFindings } from "./audit/scanner.js";
export type { ScanOptions } from "./audit/scanner.js";
export { renderAuditMarkdown } from "./audit/report.js";
export { generateSarifReport } from "./audit/sarif.js";
export { buildAgentContract, renderContractText } from "./agent/contract.js";
export type { AgentContract } from "./agent/contract.js";
export { installSkill, isSkillTarget, SKILL_TARGETS } from "./agent/install-skill.js";
export type { SkillInstallResult, SkillTarget, SkillWrite } from "./agent/install-skill.js";
export { renderSkill, SKILL_NAME } from "./agent/skill.js";
export { startWebServer } from "./web/server.js";
export type { ServeHandle, ServeOptions } from "./web/server.js";
export type {
  AllowlistEntry,
  AuditEvent,
  AuditRecorder,
  AuditSummary,
  EntropyConfig,
  ExecConfig,
  OverflowPolicy,
  PayloadRedactionResult,
  PromptRedactConfig,
  RedactTextResult,
  RedactionHit,
  ScanFinding,
  ScanReport,
  ScanSkip,
  ScanSkipReason,
  SecretRule,
  SecretRuleInput,
  SecretVault,
  VaultMode,
  VaultOptions,
} from "./types.js";
