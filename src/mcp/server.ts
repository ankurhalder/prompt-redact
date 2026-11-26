import {
  ERROR_CODES,
  METHOD,
  SUPPORTED_PROTOCOL_VERSIONS,
  errorResponse,
  isJsonObject,
  successResponse,
} from "./protocol.js";
import type { JsonObject, JsonRpcId, JsonRpcResponse } from "./protocol.js";
import { classifyRequest, createSession, inspectModernMeta, negotiateLegacyVersion } from "./era.js";
import type { SessionState } from "./era.js";
import { applyDefaults, coerceNumericStrings, validateArguments } from "./schema.js";
import type {
  McpPrompt,
  McpServerInfo,
  McpTool,
  PromptMessage,
  ResourceProvider,
  ToolContext,
  ToolOutcome,
} from "./types.js";

export interface McpServerOptions {
  info: McpServerInfo;
  instructions: string;
  tools: McpTool[];
  resources: ResourceProvider;
  prompts: McpPrompt[];
  context: ToolContext;
  cancellations?: Map<JsonRpcId, Set<() => void>>;
  notify?: (message: JsonObject) => void;
}

export interface McpServer {
  handle(message: unknown): Promise<JsonRpcResponse | null>;
  readonly session: SessionState;
}

function capabilities(): JsonObject {
  return {
    tools: { listChanged: false },
    resources: { subscribe: false, listChanged: false },
    prompts: { listChanged: false },
  };
}

function requestIdOf(message: JsonObject): JsonRpcId | null {
  const raw = message.id;
  return typeof raw === "string" || typeof raw === "number" ? raw : null;
}

export function createMcpServer(options: McpServerOptions): McpServer {
  const session = createSession();
  const toolsByName = new Map(options.tools.map((tool) => [tool.name, tool]));
  const promptsByName = new Map(options.prompts.map((prompt) => [prompt.name, prompt]));

  const identity = (): JsonObject => ({
    name: options.info.name,
    title: options.info.title,
    version: options.info.version,
    websiteUrl: options.info.websiteUrl,
  });

  const ok = (id: JsonRpcId | null, result: JsonObject, modern: boolean): JsonRpcResponse =>
    successResponse(id, result, modern, options.info);

  const cacheable = (result: JsonObject): JsonObject => ({
    ...result,
    cacheScope: "private",
    ttlMs: 0,
  });

  const cancellations = options.cancellations ?? new Map<JsonRpcId, Set<() => void>>();

  function handleNotification(method: string, params: JsonObject | undefined): void {
    if (method === METHOD.initialized && session.era === "legacy" && session.protocolVersion !== null) {
      session.ready = true;
    }
    if (method === "notifications/cancelled") {
      const requestId = params?.requestId;
      if (typeof requestId === "string" || typeof requestId === "number") {
        const callbacks = cancellations.get(requestId);
        if (callbacks !== undefined) {
          cancellations.delete(requestId);
          for (const cancel of callbacks) {
            cancel();
          }
        }
      }
    }
  }

  function initialize(id: JsonRpcId, params: JsonObject | undefined): JsonRpcResponse {
    const negotiation = negotiateLegacyVersion(params?.protocolVersion);
    session.era = "legacy";
    session.protocolVersion = negotiation.version;
    session.ready = true;
    options.context.log(
      negotiation.matched
        ? `mcp: client initialized with protocol ${negotiation.version}`
        : `mcp: client asked for an unsupported version and was offered ${negotiation.version}`
    );
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: negotiation.version,
        capabilities: capabilities(),
        serverInfo: identity(),
        instructions: options.instructions,
      },
    };
  }

  function discover(id: JsonRpcId): JsonRpcResponse {
    return ok(
      id,
      cacheable({
        supportedVersions: [...SUPPORTED_PROTOCOL_VERSIONS],
        capabilities: capabilities(),
        instructions: options.instructions,
      }),
      true
    );
  }

  function listTools(id: JsonRpcId, modern: boolean): JsonRpcResponse {
    const tools = options.tools.map((tool) => ({
      name: tool.name,
      title: tool.title,
      description: tool.description,
      inputSchema: tool.inputSchema,
      ...(tool.outputSchema ? { outputSchema: tool.outputSchema } : {}),
      annotations: tool.annotations,
      _meta: { "prompt-redact/cost": tool.cost },
    }));
    return ok(id, cacheable({ tools }), modern);
  }

  async function callTool(
    id: JsonRpcId,
    modern: boolean,
    params: JsonObject | undefined
  ): Promise<JsonRpcResponse> {
    const name = params?.name;
    if (typeof name !== "string") {
      return errorResponse(id, ERROR_CODES.invalidParams, 'tools/call requires a "name" string.');
    }
    const tool = toolsByName.get(name);
    if (!tool) {
      const known = [...toolsByName.keys()].sort().join(", ");
      return errorResponse(id, ERROR_CODES.invalidParams, `Unknown tool "${name}". Available: ${known}.`);
    }

    const rawArguments = params?.arguments ?? {};
    if (!isJsonObject(rawArguments)) {
      return errorResponse(id, ERROR_CODES.invalidParams, '"arguments" must be a JSON object.');
    }

    const supplied = coerceNumericStrings(tool.inputSchema, rawArguments);
    const problems = validateArguments(tool.inputSchema, supplied);
    if (problems.length > 0) {
      return ok(
        id,
        {
          content: [{ type: "text", text: `Invalid arguments for ${tool.name}:\n- ${problems.join("\n- ")}` }],
          isError: true,
        },
        modern
      );
    }

    const args = applyDefaults(tool.inputSchema, supplied);
    const meta = params?._meta;
    const progressToken =
      isJsonObject(meta) && (typeof meta.progressToken === "string" || typeof meta.progressToken === "number")
        ? meta.progressToken
        : undefined;
    let registeredCancel: (() => void) | undefined;
    const callContext: ToolContext = {
      ...options.context,
      onCancel: (cancel) => {
        registeredCancel = cancel;
        let callbacks = cancellations.get(id);
        if (callbacks === undefined) {
          callbacks = new Set<() => void>();
          cancellations.set(id, callbacks);
        }
        callbacks.add(cancel);
      },
      ...(progressToken === undefined || options.notify === undefined
        ? {}
        : {
            notify: (event: { message: string; progress?: number; total?: number }) => {
              const progress: JsonObject = {
                progressToken,
                progress: event.progress ?? 0,
                ...(event.total === undefined ? {} : { total: event.total }),
                message: event.message,
              };
              options.notify?.({ jsonrpc: "2.0", method: "notifications/progress", params: progress });
            },
          }),
    };
    let outcome: ToolOutcome;
    try {
      outcome = await tool.handler(args, callContext);
    } catch (error) {
      const rawDetail = error instanceof Error ? error.message : String(error);
      let safeDetail = "internal error (scrubbing failed closed)";
      try {
        safeDetail = options.context.vault.redact(rawDetail, `mcp:error:${tool.name}`).text;
        for (const [token, secret] of options.context.vault.replacements()) {
          if (secret.length > 0 && safeDetail.includes(secret)) {
            safeDetail = safeDetail.split(secret).join(token);
          }
        }
      } catch {
        safeDetail = "internal error (scrubbing failed closed)";
      }
      options.context.log(`mcp: tool ${tool.name} failed: ${safeDetail}`);
      return ok(
        id,
        { content: [{ type: "text", text: `${tool.name} failed: ${safeDetail}` }], isError: true },
        modern
      );
    } finally {
      if (registeredCancel !== undefined) {
        const callbacks = cancellations.get(id);
        if (callbacks !== undefined) {
          callbacks.delete(registeredCancel);
          if (callbacks.size === 0) {
            cancellations.delete(id);
          }
        }
      }
    }

    return ok(
      id,
      {
        content: [{ type: "text", text: outcome.text }],
        ...(outcome.structured ? { structuredContent: outcome.structured } : {}),
        ...(outcome.isError ? { isError: true } : {}),
      },
      modern
    );
  }

  async function listResources(id: JsonRpcId, modern: boolean): Promise<JsonRpcResponse> {
    const resources = await options.resources.list(options.context);
    return ok(id, cacheable({ resources }), modern);
  }

  async function readResource(
    id: JsonRpcId,
    modern: boolean,
    params: JsonObject | undefined
  ): Promise<JsonRpcResponse> {
    const uri = params?.uri;
    if (typeof uri !== "string") {
      return errorResponse(id, ERROR_CODES.invalidParams, 'resources/read requires a "uri" string.');
    }
    const contents = await options.resources.read(uri, options.context);
    if (!contents) {
      return errorResponse(
        id,
        modern ? ERROR_CODES.invalidParams : ERROR_CODES.resourceNotFound,
        `Unknown resource "${uri}".`
      );
    }
    return ok(id, cacheable({ contents: [contents] }), modern);
  }

  function listPrompts(id: JsonRpcId, modern: boolean): JsonRpcResponse {
    const prompts = options.prompts.map((prompt) => ({
      name: prompt.name,
      ...(prompt.title ? { title: prompt.title } : {}),
      description: prompt.description,
      arguments: prompt.arguments,
    }));
    return ok(id, cacheable({ prompts }), modern);
  }

  function getPrompt(
    id: JsonRpcId,
    modern: boolean,
    params: JsonObject | undefined
  ): JsonRpcResponse {
    const name = params?.name;
    if (typeof name !== "string") {
      return errorResponse(id, ERROR_CODES.invalidParams, 'prompts/get requires a "name" string.');
    }
    const prompt = promptsByName.get(name);
    if (!prompt) {
      const known = [...promptsByName.keys()].sort().join(", ");
      return errorResponse(id, ERROR_CODES.invalidParams, `Unknown prompt "${name}". Available: ${known}.`);
    }
    const rawArguments = params?.arguments ?? {};
    if (!isJsonObject(rawArguments)) {
      return errorResponse(id, ERROR_CODES.invalidParams, '"arguments" must be a JSON object.');
    }
    const missing = (prompt.arguments ?? []).filter((argument) => {
      if (argument.required !== true) return false;
      const value = rawArguments[argument.name];
      return typeof value !== "string" || value.trim() === "";
    });
    if (missing.length > 0) {
      return errorResponse(
        id,
        ERROR_CODES.invalidParams,
        `Prompt "${name}" requires: ${missing.map((a) => a.name).join(", ")}.`
      );
    }
    const built = prompt.build(rawArguments);
    const messages: PromptMessage[] = built.messages.map((message) => ({
      role: message.role,
      content: { type: "text", text: message.content.text },
    }));
    return ok(id, { description: built.description, messages }, modern);
  }

  async function route(
    name: string,
    id: JsonRpcId,
    modern: boolean,
    params: JsonObject | undefined
  ): Promise<JsonRpcResponse> {
    switch (name) {
      case METHOD.initialize:
        return modern
          ? errorResponse(
              id,
              ERROR_CODES.methodNotFound,
              '"initialize" does not exist in this protocol revision; call "server/discover".'
            )
          : initialize(id, params);
      case METHOD.discover:
        return discover(id);
      case METHOD.ping:
        return modern
          ? errorResponse(
              id,
              ERROR_CODES.methodNotFound,
              '"ping" was removed in this protocol revision; call "server/discover".'
            )
          : ok(id, {}, modern);
      default:
        break;
    }

    if (!modern && !session.ready) {
      return errorResponse(
        id,
        ERROR_CODES.invalidRequest,
        'This connection has not been initialized. Send "initialize" first.'
      );
    }

    switch (name) {
      case METHOD.toolsList:
        return listTools(id, modern);
      case METHOD.toolsCall:
        return callTool(id, modern, params);
      case METHOD.resourcesList:
        return listResources(id, modern);
      case METHOD.resourcesRead:
        return readResource(id, modern, params);
      case METHOD.resourceTemplatesList:
        return ok(id, cacheable({ resourceTemplates: options.resources.templates() }), modern);
      case METHOD.promptsList:
        return listPrompts(id, modern);
      case METHOD.promptsGet:
        return getPrompt(id, modern, params);
      default:
        return errorResponse(id, ERROR_CODES.methodNotFound, `Unknown method "${name}".`);
    }
  }

  async function dispatch(message: unknown): Promise<JsonRpcResponse | null> {
    if (!isJsonObject(message)) {
      return errorResponse(
        null,
        ERROR_CODES.invalidRequest,
        Array.isArray(message)
          ? "Batch requests are not supported: send one JSON-RPC message per line."
          : "Message is not a JSON object."
      );
    }
    const isRequest = Object.prototype.hasOwnProperty.call(message, "id");
    const method = message.method;
    const params = message.params;

    if (message.jsonrpc !== "2.0" && isRequest) {
      return errorResponse(requestIdOf(message), ERROR_CODES.invalidRequest, 'Message must carry "jsonrpc": "2.0".');
    }
    if (typeof method !== "string" || method.length === 0) {
      return isRequest
        ? errorResponse(requestIdOf(message), ERROR_CODES.invalidRequest, 'Message must carry a "method" string.')
        : null;
    }
    if (params !== undefined && !isJsonObject(params)) {
      return isRequest
        ? errorResponse(requestIdOf(message), ERROR_CODES.invalidRequest, '"params" must be a JSON object when present.')
        : null;
    }
    const named = params as JsonObject | undefined;

    const decision = classifyRequest(method, named, session);
    const modern = decision.kind === "era" ? decision.era === "modern" : session.era === "modern";

    const commitsEra = (): boolean => {
      if (decision.kind !== "era") return false;
      if (isRequest && method === METHOD.initialize) return true;
      return decision.era === "modern" && inspectModernMeta(named).kind === "present";
    };

    if (!isRequest) {
      if (decision.kind === "era" && commitsEra() && session.era === null) {
        session.era = decision.era;
        session.protocolVersion = decision.version;
        if (decision.era === "modern") session.ready = true;
      }
      handleNotification(method, named);
      return null;
    }

    const id = requestIdOf(message);
    if (id === null) {
      return errorResponse(null, ERROR_CODES.invalidRequest, 'A request "id" must be a string or a number.');
    }
    if (decision.kind === "error") {
      return errorResponse(id, decision.code, decision.message, decision.data);
    }
    if (decision.kind === "era" && session.era === null && commitsEra()) {
      session.era = decision.era;
      session.protocolVersion = decision.version;
      if (decision.era === "modern") session.ready = true;
    }

    return route(method, id, modern, named);
  }

  return {
    session,
    async handle(message: unknown): Promise<JsonRpcResponse | null> {
      try {
        return await dispatch(message);
      } catch (error) {
        const rawDetail = error instanceof Error ? error.message : String(error);
        let detail = "internal error";
        try {
          detail = options.context.vault.redact(rawDetail, "mcp:internal").text;
          for (const [token, secret] of options.context.vault.replacements()) {
            if (secret.length > 0 && detail.includes(secret)) {
              detail = detail.split(secret).join(token);
            }
          }
        } catch {
          detail = "internal error (scrubbing failed closed)";
        }
        options.context.log(`mcp: internal error: ${detail}`);
        const id = isJsonObject(message) ? requestIdOf(message) : null;
        return errorResponse(id, ERROR_CODES.internalError, "Internal server error.");
      }
    },
  };
}
