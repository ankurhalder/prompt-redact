import {
  DEFAULT_LEGACY_PROTOCOL_VERSION,
  ERROR_CODES,
  LEGACY_PROTOCOL_VERSIONS,
  METHOD,
  META_KEYS,
  MODERN_PROTOCOL_VERSIONS,
  SUPPORTED_PROTOCOL_VERSIONS,
  isJsonObject,
} from "./protocol.js";
import type { JsonObject } from "./protocol.js";

export type ProtocolEra = "legacy" | "modern";

export interface SessionState {
  era: ProtocolEra | null;
  protocolVersion: string | null;
  ready: boolean;
}

export function createSession(): SessionState {
  return { era: null, protocolVersion: null, ready: false };
}

export function isLegacyVersion(version: string): boolean {
  return LEGACY_PROTOCOL_VERSIONS.includes(version);
}

export function isModernVersion(version: string): boolean {
  return MODERN_PROTOCOL_VERSIONS.includes(version);
}

export interface ModernMeta {
  version: string;
  clientCapabilities: JsonObject;
  clientInfo: JsonObject | null;
}

export type MetaInspection =
  | { kind: "absent" }
  | { kind: "incomplete"; missing: string }
  | { kind: "present"; meta: ModernMeta };

export function inspectModernMeta(params: JsonObject | undefined): MetaInspection {
  const raw = params?._meta;
  if (!isJsonObject(raw)) return { kind: "absent" };

  const version = raw[META_KEYS.protocolVersion];
  if (typeof version !== "string" || version.length === 0) {
    return { kind: "incomplete", missing: META_KEYS.protocolVersion };
  }
  const capabilities = raw[META_KEYS.clientCapabilities];
  if (!isJsonObject(capabilities)) {
    return { kind: "incomplete", missing: META_KEYS.clientCapabilities };
  }
  const info = raw[META_KEYS.clientInfo];

  return {
    kind: "present",
    meta: {
      version,
      clientCapabilities: capabilities,
      clientInfo: isJsonObject(info) ? info : null,
    },
  };
}

export function unsupportedVersionData(requested: string): JsonObject {
  return { requested, supported: [...SUPPORTED_PROTOCOL_VERSIONS] };
}

export type EraDecision =
  | { kind: "era"; era: ProtocolEra; version: string | null }
  | { kind: "error"; code: number; message: string; data?: unknown };

export function classifyRequest(
  method: string,
  params: JsonObject | undefined,
  session: SessionState
): EraDecision {
  const inspection = inspectModernMeta(params);

  if (session.era === "modern") {
    if (inspection.kind === "absent") {
      return {
        kind: "error",
        code: ERROR_CODES.invalidRequest,
        message:
          "This request has no _meta. The modern era requires " +
          `"${META_KEYS.protocolVersion}" and "${META_KEYS.clientCapabilities}" on every request.`,
      };
    }
    if (inspection.kind === "incomplete") {
      return {
        kind: "error",
        code: ERROR_CODES.invalidParams,
        message: `The request _meta is missing the required key "${inspection.missing}".`,
      };
    }
    if (!isModernVersion(inspection.meta.version)) {
      return {
        kind: "error",
        code: ERROR_CODES.unsupportedProtocolVersion,
        message: `Unsupported protocol version "${inspection.meta.version}".`,
        data: unsupportedVersionData(inspection.meta.version),
      };
    }
    return { kind: "era", era: "modern", version: inspection.meta.version };
  }

  if (session.era === "legacy") {
    return { kind: "era", era: "legacy", version: session.protocolVersion };
  }

  if (method === METHOD.initialize) {
    return { kind: "era", era: "legacy", version: null };
  }

  if (inspection.kind === "present") {
    if (!isModernVersion(inspection.meta.version)) {
      return {
        kind: "error",
        code: ERROR_CODES.unsupportedProtocolVersion,
        message: `Unsupported protocol version "${inspection.meta.version}".`,
        data: unsupportedVersionData(inspection.meta.version),
      };
    }
    return { kind: "era", era: "modern", version: inspection.meta.version };
  }

  if (inspection.kind === "incomplete") {
    return {
      kind: "error",
      code: ERROR_CODES.invalidParams,
      message: `The request _meta is missing the required key "${inspection.missing}".`,
    };
  }

  if (method === METHOD.discover) {
    return { kind: "era", era: "modern", version: MODERN_PROTOCOL_VERSIONS[0] };
  }

  return { kind: "era", era: "legacy", version: null };
}

export interface LegacyNegotiation {
  version: string;
  matched: boolean;
}

export function negotiateLegacyVersion(requested: unknown): LegacyNegotiation {
  if (typeof requested === "string" && isLegacyVersion(requested)) {
    return { version: requested, matched: true };
  }
  return { version: DEFAULT_LEGACY_PROTOCOL_VERSION, matched: false };
}
