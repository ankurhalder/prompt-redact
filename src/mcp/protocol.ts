export type JsonObject = Record<string, unknown>;
export type JsonRpcId = string | number;

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcSuccessResponse {
  jsonrpc: "2.0";
  id: JsonRpcId | null;
  result: JsonObject;
}

export interface JsonRpcErrorResponse {
  jsonrpc: "2.0";
  id: JsonRpcId | null;
  error: JsonRpcError;
}

export type JsonRpcResponse = JsonRpcSuccessResponse | JsonRpcErrorResponse;

export const LEGACY_PROTOCOL_VERSIONS: readonly string[] = ["2025-11-25", "2025-06-18"];
export const MODERN_PROTOCOL_VERSIONS: readonly string[] = ["2026-07-28"];
export const SUPPORTED_PROTOCOL_VERSIONS: readonly string[] = [
  ...MODERN_PROTOCOL_VERSIONS,
  ...LEGACY_PROTOCOL_VERSIONS,
];
export const DEFAULT_LEGACY_PROTOCOL_VERSION = LEGACY_PROTOCOL_VERSIONS[0];

export const ERROR_CODES = {
  parseError: -32700,
  invalidRequest: -32600,
  methodNotFound: -32601,
  invalidParams: -32602,
  internalError: -32603,
  resourceTooLarge: -32000,
  overloaded: -32001,
  resourceNotFound: -32002,
  headerMismatch: -32020,
  unsupportedProtocolVersion: -32022,
} as const;

export const METHOD = {
  initialize: "initialize",
  initialized: "notifications/initialized",
  discover: "server/discover",
  ping: "ping",
  toolsList: "tools/list",
  toolsCall: "tools/call",
  resourcesList: "resources/list",
  resourcesRead: "resources/read",
  resourceTemplatesList: "resources/templates/list",
  promptsList: "prompts/list",
  promptsGet: "prompts/get",
  cancelled: "notifications/cancelled",
} as const;

export const META_KEYS = {
  protocolVersion: "io.modelcontextprotocol/protocolVersion",
  clientCapabilities: "io.modelcontextprotocol/clientCapabilities",
  clientInfo: "io.modelcontextprotocol/clientInfo",
  serverInfo: "io.modelcontextprotocol/serverInfo",
  progressToken: "progressToken",
} as const;

export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export type JsonSchemaType = "object" | "string" | "number" | "integer" | "boolean" | "array";

export interface JsonSchema {
  type?: JsonSchemaType | readonly JsonSchemaType[];
  description?: string;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: readonly string[];
  default?: string | number | boolean;
  additionalProperties?: boolean;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
}

export interface InputSchema extends JsonSchema {
  type: "object";
  properties: Record<string, JsonSchema>;
}

export function serverInfoMeta(info: {
  name: string;
  title?: string;
  version: string;
}): JsonObject {
  const value: JsonObject = { name: info.name, version: info.version };
  if (info.title) value.title = info.title;
  return { [META_KEYS.serverInfo]: value };
}

export function successResponse(
  id: JsonRpcId | null,
  result: JsonObject,
  modern: boolean,
  info: { name: string; title?: string; version: string }
): JsonRpcSuccessResponse {
  if (!modern) return { jsonrpc: "2.0", id, result };
  const withMeta: JsonObject = {
    ...result,
    resultType: "complete",
    _meta: { ...(isJsonObject(result._meta) ? result._meta : {}), ...serverInfoMeta(info) },
  };
  return { jsonrpc: "2.0", id, result: withMeta };
}

export function errorResponse(
  id: JsonRpcId | null,
  code: number,
  message: string,
  data?: unknown
): JsonRpcErrorResponse {
  const error: JsonRpcError = { code, message };
  if (data !== undefined) error.data = data;
  return { jsonrpc: "2.0", id, error };
}
