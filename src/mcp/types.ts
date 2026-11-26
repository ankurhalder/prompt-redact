import type { InputSchema, JsonObject } from "./protocol.js";
import type { PromptRedactConfig, SecretVault } from "../types.js";

export interface ExecPolicy {
  enabled: boolean;
  allowCommands: string[];
}

export interface ToolContext {
  cwd: string;
  roots: string[];
  vault: SecretVault;
  config: PromptRedactConfig;
  /** Explicit opt-in policy for airlock_exec. Disabled unless configured. */
  exec: ExecPolicy;
  noConfig?: boolean;
  log: (line: string) => void;
  notify?: (event: { message: string; progress?: number; total?: number }) => void;
  onCancel?: (cancel: () => void) => void;
}

export interface ToolAnnotations {
  readOnlyHint: boolean;
  destructiveHint: boolean;
  idempotentHint: boolean;
  openWorldHint: boolean;
}

export interface ToolOutcome {
  text: string;
  structured?: JsonObject;
  isError?: boolean;
}

export type ToolCost = "cheap" | "medium" | "expensive";

export interface McpTool {
  name: string;
  title: string;
  description: string;
  inputSchema: InputSchema;
  outputSchema?: InputSchema;
  annotations: ToolAnnotations;
  cost: ToolCost;
  handler(args: JsonObject, context: ToolContext): Promise<ToolOutcome>;
}

export interface McpResourceDescriptor {
  uri: string;
  name: string;
  title?: string;
  description: string;
  mimeType: string;
}

export interface McpResourceContents {
  uri: string;
  mimeType: string;
  text: string;
}

export interface McpResourceTemplate {
  uriTemplate: string;
  name: string;
  title?: string;
  description: string;
  mimeType: string;
}

export interface ResourceProvider {
  list(context: ToolContext): Promise<McpResourceDescriptor[]>;
  templates(): McpResourceTemplate[];
  read(uri: string, context: ToolContext): Promise<McpResourceContents | null>;
}

export interface PromptArgument {
  name: string;
  description: string;
  required: boolean;
}

export interface PromptMessage {
  role: "user" | "assistant";
  content: { type: "text"; text: string };
}

export interface McpPrompt {
  name: string;
  title?: string;
  description: string;
  arguments: PromptArgument[];
  build(args: JsonObject): { description: string; messages: PromptMessage[] };
}

export interface McpServerInfo {
  name: string;
  title: string;
  version: string;
  websiteUrl: string;
}
