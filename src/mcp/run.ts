import { buildVaultFromConfig } from "../core/config.js";
import { DEFAULT_SECRET_PATTERNS } from "../core/patterns.js";
import type { PromptRedactConfig, SecretVault } from "../types.js";
import { PACKAGE_NAME, PACKAGE_VERSION } from "../version.js";
import { ERROR_CODES, errorResponse, isJsonObject } from "./protocol.js";
import type { JsonObject, JsonRpcId } from "./protocol.js";
import { createMcpServer } from "./server.js";
import type { McpServer } from "./server.js";
import { createLineReader, createWriter } from "./stdio.js";
import { buildTools } from "./tools.js";
import type { ExecPolicy, McpPrompt, ResourceProvider, ToolContext } from "./types.js";

const PROJECT_URL = "https://github.com/ankurhalder/prompt-redact";

export const SERVER_INSTRUCTIONS =
  "prompt-redact airlock MCP server. Use airlock_read_file instead of raw file reads on credential-bearing files, use airlock_exec to run commands using <<redact:...>> tokens without exposing plaintext credentials, and use redact_audit / redact_verify to confirm zero leaks.";

export interface ServerOptions {
  cwd: string;
  vault?: SecretVault;
  config?: PromptRedactConfig;
  cancellations?: Map<JsonRpcId, Set<() => void>>;
  notify?: (message: JsonObject) => void;
  roots?: string[];
  noConfig?: boolean;
  log?: (line: string) => void;
}

function buildResourceProvider(): ResourceProvider {
  return {
    async list() {
      return [
        {
          uri: "redact://audit",
          name: "audit",
          title: "Session Redaction Audit",
          description: "Zero-plaintext redaction counts and vault capacity status.",
          mimeType: "application/json",
        },
        {
          uri: "redact://rules",
          name: "rules",
          title: "Built-in Secret Rules",
          description: "List of built-in secret rule identifiers.",
          mimeType: "application/json",
        },
      ];
    },
    templates() {
      return [];
    },
    async read(uri: string, context: ToolContext) {
      if (uri === "redact://audit") {
        return {
          uri,
          mimeType: "application/json",
          text: JSON.stringify(context.vault.audit(), null, 2),
        };
      }
      if (uri === "redact://rules") {
        return {
          uri,
          mimeType: "application/json",
          text: JSON.stringify(
            DEFAULT_SECRET_PATTERNS.map((r) => r.rule),
            null,
            2
          ),
        };
      }
      return null;
    },
  };
}

function buildPrompts(): McpPrompt[] {
  return [
    {
      name: "airlock_workflow",
      title: "Airlock Secret-Safe Workflow",
      description: "Instructions for reading files and executing authenticated commands without seeing plaintext secrets.",
      arguments: [
        { name: "task", description: "The engineering task to perform safely.", required: true },
      ],
      build(args: JsonObject) {
        const task = String(args.task ?? "");
        return {
          description: "Secret-safe airlock execution workflow",
          messages: [
            {
              role: "user",
              content: {
                type: "text",
                text:
                  `Task: ${task}\n\n` +
                  "Rules:\n" +
                  "1. Use airlock_read_file to inspect .env, configs, or logs so secrets arrive as <<redact:...>> tokens.\n" +
                  "2. Pass <<redact:...>> tokens into airlock_exec args/env when running authenticated commands.\n" +
                  "3. Never attempt to unmask or print raw secrets; run redact_verify before finishing.",
              },
            },
          ],
        };
      },
    },
  ];
}

export function createServer(options: ServerOptions): McpServer {
  const cwd = options.cwd;
  const roots = options.roots && options.roots.length > 0 ? options.roots : [cwd];
  const built = buildVaultFromConfig(cwd, {
    config: options.config,
    noConfig: options.noConfig,
    source: "mcp",
  });
  const vault = options.vault ?? built.vault;
  const resolvedConfig = options.config ?? built.config;
  const execConfig = resolvedConfig.exec;
  const exec: ExecPolicy = {
    enabled: execConfig?.enabled === true,
    allowCommands: [...(execConfig?.allowCommands ?? [])],
  };
  const context: ToolContext = {
    cwd,
    roots,
    vault,
    config: resolvedConfig,
    exec,
    ...(options.noConfig === true ? { noConfig: true } : {}),
    log: options.log ?? ((line: string) => process.stderr.write(`${line}\n`)),
  };

  return createMcpServer({
    info: {
      name: PACKAGE_NAME,
      title: "prompt-redact",
      version: PACKAGE_VERSION,
      websiteUrl: PROJECT_URL,
    },
    instructions: SERVER_INSTRUCTIONS,
    tools: buildTools(),
    resources: buildResourceProvider(),
    prompts: buildPrompts(),
    context,
    ...(options.cancellations === undefined ? {} : { cancellations: options.cancellations }),
    ...(options.notify === undefined ? {} : { notify: options.notify }),
  });
}

export async function runStdioServer(options: ServerOptions): Promise<number> {
  const log = options.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  const writer = createWriter(process.stdout);
  let writeChain: Promise<void> = Promise.resolve();
  const send = (message: unknown): Promise<void> => {
    writeChain = writeChain.then(() => writer.write(message)).catch((error: unknown) => {
      log(`mcp: could not write a response: ${error instanceof Error ? error.message : String(error)}`);
    });
    return writeChain;
  };
  const server = createServer({
    ...options,
    notify: (message) => {
      void send(message);
    },
  });

  const MAX_IN_FLIGHT = 4;
  let inFlight = 0;
  let inputEnded = false;
  let resolveDone: (code: number) => void = () => undefined;
  const finished = new Promise<number>((resolve) => {
    resolveDone = resolve;
  });
  const onStreamError = (err: Error): void => {
    log(`mcp: stdio error: ${err.message}`);
    resolveDone(1);
  };
  process.stdin.on("error", onStreamError);
  process.stdout.on("error", onStreamError);
  const finishIfIdle = (): void => {
    if (inputEnded && inFlight === 0) resolveDone(0);
  };

  const handleLine = async (line: string): Promise<void> => {
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      await send(errorResponse(null, ERROR_CODES.parseError, "Message is not valid JSON."));
      return;
    }
    const response = await server.handle(message);
    if (response) await send(response);
  };

  const rejectOverloaded = (line: string): void => {
    let id: JsonRpcId | null = null;
    try {
      const parsed: unknown = JSON.parse(line);
      if (!isJsonObject(parsed)) return;
      if (typeof parsed.id === "string" || typeof parsed.id === "number") id = parsed.id;
      else return;
    } catch {
      return;
    }
    void send(
      errorResponse(
        id,
        ERROR_CODES.overloaded,
        `The server is already handling ${MAX_IN_FLIGHT} requests; retry this one when it is free.`
      )
    );
  };

  const isCancellation = (line: string): boolean => {
    try {
      const parsed: unknown = JSON.parse(line);
      return (
        parsed !== null &&
        typeof parsed === "object" &&
        (parsed as { method?: unknown }).method === "notifications/cancelled"
      );
    } catch {
      return false;
    }
  };

  const stopReading = createLineReader(process.stdin, {
    onOverflow: (bytes) => log(`mcp: discarded an oversized message (${bytes} bytes)`),
    onLine: (line) => {
      if (inFlight >= MAX_IN_FLIGHT) {
        if (isCancellation(line)) {
          void handleLine(line);
          return;
        }
        rejectOverloaded(line);
        return;
      }
      inFlight += 1;
      void handleLine(line).finally(() => {
        inFlight -= 1;
        finishIfIdle();
      });
    },
  });

  const onEnd = (): void => {
    inputEnded = true;
    finishIfIdle();
  };
  process.stdin.on("end", onEnd);
  process.stdin.on("close", onEnd);

  log(`mcp: serving ${options.cwd} over stdio`);

  const code = await finished;
  stopReading();
  process.stdin.off("end", onEnd);
  process.stdin.off("close", onEnd);
  process.stdin.off("error", onStreamError);
  process.stdout.off("error", onStreamError);
  await writeChain;
  return code;
}
