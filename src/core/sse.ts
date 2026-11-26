import type { SecretVault } from "../types.js";

export const DEFAULT_MAX_SSE_LINE_CHARS = 1024 * 1024;

export type SseProtocol = "openai" | "anthropic" | "auto";

export interface SseEventFrame {
  eventName?: string;
  data: string;
  /** SSE "last event id" field, forwarded unchanged. */
  id?: string;
  /** SSE reconnection delay field, forwarded unchanged. */
  retry?: string;
}

export interface SseRehydrationOptions {
  /** Maximum characters in a single SSE line. Defaults to 1 MiB. */
  maxLineChars?: number;
  /** Maximum characters buffered for one SSE event. Defaults to 4 MiB. */
  maxEventChars?: number;
  /** Maximum number of partial tokens held across frames. Defaults to 1024. */
  maxCarries?: number;
}

export class SseEventAssembler {
  private eventName: string | undefined;
  private eventId: string | undefined;
  private eventRetry: string | undefined;
  private dataLines: string[] = [];
  private bufferedChars = 0;
  private readonly maxEventChars: number;

  constructor(maxEventChars: number = 4 * 1024 * 1024) {
    this.maxEventChars = maxEventChars;
  }

  public pushLine(line: string): SseEventFrame | null {
    const clean = line.replace(/\r$/, "");
    if (clean.trim().length === 0) {
      return this.takeEvent();
    }
    if (clean.startsWith(":")) {
      return null;
    }
    if (clean.startsWith("event:")) {
      this.eventName = clean.slice(6).trim() || undefined;
      return null;
    }
    if (clean.startsWith("id:")) {
      this.eventId = clean.slice(3).replace(/^ /, "") || undefined;
      return null;
    }
    if (clean.startsWith("retry:")) {
      this.eventRetry = clean.slice(6).trim() || undefined;
      return null;
    }
    if (clean.startsWith("data:")) {
      const payload = clean.slice(5).replace(/^\s/, "");
      this.dataLines.push(payload);
      this.bufferedChars += payload.length;
      if (this.bufferedChars > this.maxEventChars) {
        throw new Error("Upstream SSE event exceeds maximum buffered length");
      }
    }
    return null;
  }

  public flush(): SseEventFrame | null {
    return this.takeEvent();
  }

  private takeEvent(): SseEventFrame | null {
    if (this.dataLines.length === 0 && this.eventName === undefined) {
      return null;
    }
    const frame: SseEventFrame = {
      eventName: this.eventName,
      data: this.dataLines.join("\n"),
      ...(this.eventId === undefined ? {} : { id: this.eventId }),
      ...(this.eventRetry === undefined ? {} : { retry: this.eventRetry }),
    };
    this.eventName = undefined;
    this.eventId = undefined;
    this.eventRetry = undefined;
    this.dataLines = [];
    this.bufferedChars = 0;
    return frame;
  }
}

export class Utf8StreamFrameDecoder {
  private decoder = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });
  private buffer = "";
  private readonly maxLineChars: number;

  constructor(maxLineChars: number = DEFAULT_MAX_SSE_LINE_CHARS) {
    this.maxLineChars = maxLineChars;
  }

  public decodeChunk(bytes: Uint8Array): string[] {
    const text = this.decoder.decode(bytes, { stream: true });
    this.buffer += text;
    // Only the trailing partial line is a candidate for exceeding the limit.
    // Checking the whole chunk here rejected large multi-line chunks that were
    // perfectly valid.
    const lines = this.buffer.split("\n");
    this.buffer = lines.pop() || "";
    if (this.buffer.length > this.maxLineChars) {
      throw new Error("Upstream SSE line exceeds maximum buffered length");
    }
    return lines;
  }

  public flush(): string[] {
    const trailing = this.decoder.decode();
    this.buffer += trailing;
    if (!this.buffer) return [];
    const lines = this.buffer.split("\n");
    this.buffer = "";
    return lines;
  }
}

export function detectSseProtocol(
  parsed: Record<string, unknown>,
  eventName?: string
): "openai" | "anthropic" | null {
  if (
    eventName === "message_start" ||
    eventName === "content_block_start" ||
    eventName === "content_block_delta" ||
    eventName === "content_block_stop" ||
    eventName === "message_delta" ||
    eventName === "message_stop"
  ) {
    return "anthropic";
  }
  const type = parsed.type;
  if (
    type === "message_start" ||
    type === "content_block_start" ||
    type === "content_block_delta" ||
    type === "content_block_stop" ||
    type === "message_delta" ||
    type === "message_stop"
  ) {
    return "anthropic";
  }
  if (
    Array.isArray(parsed.choices) ||
    (typeof parsed.object === "string" && parsed.object.startsWith("chat.completion")) ||
    (typeof type === "string" && type.startsWith("response."))
  ) {
    return "openai";
  }
  return null;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isJsonEncodedPath(
  path: string,
  parsedType?: unknown,
  parent?: Record<string, unknown> | null
): boolean {
  if (path.endsWith("/partial_json") || path.endsWith("/function/arguments")) {
    return true;
  }
  if (path.endsWith("/delta") && parsedType === "response.function_call_arguments.delta") {
    return true;
  }
  if (
    path.endsWith("/arguments") &&
    (parsedType === "response.function_call_arguments.done" ||
      parent?.type === "function_call" ||
      typeof parent?.call_id === "string" ||
      typeof parent?.name === "string")
  ) {
    return true;
  }
  return false;
}

function rehydrateWithTailBoundary(
  merged: string,
  vault: SecretVault,
  jsonEscapeSecret: boolean,
  pattern: RegExp
): { text: string; tailStart: number } {
  if (!merged || vault.size === 0) return { text: merged, tailStart: 0 };
  pattern.lastIndex = 0;
  let out = "";
  let cursor = 0;
  let tailStart = 0;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(merged)) !== null) {
    const token = match[0];
    const secret = vault.resolveToken(token);
    if (secret === undefined) continue;
    const replacement = jsonEscapeSecret ? JSON.stringify(secret).slice(1, -1) : secret;
    out += merged.slice(cursor, match.index) + replacement;
    cursor = match.index + token.length;
    tailStart = out.length;
  }
  out += merged.slice(cursor);
  return { text: out, tailStart };
}

export function createSseRehydrationTransform(
  vault: SecretVault,
  protocolHint: SseProtocol = "auto",
  options: SseRehydrationOptions = {}
): TransformStream<Uint8Array, Uint8Array> {
  const carries = new Map<string, string>();
  type CarryMeta = {
    blockIndex: number;
    deltaType: "text_delta" | "input_json_delta" | "thinking_delta";
    parsedType?: string;
    jsonEncoded: boolean;
    itemId?: string;
    outputIndex?: number;
    contentIndex?: number;
  };
  type ResponseScope = {
    itemId?: string;
    outputIndex?: number;
    contentIndex?: number;
  };
  const carryMeta = new Map<string, CarryMeta>();
  const decoder = new Utf8StreamFrameDecoder(options.maxLineChars ?? DEFAULT_MAX_SSE_LINE_CHARS);
  const assembler = new SseEventAssembler(options.maxEventChars ?? 4 * 1024 * 1024);
  const maxCarries = options.maxCarries ?? 1024;
  const encoder = new TextEncoder();
  const tokenHeader = `<<${vault.tokenPrefix}:${vault.salt}:`;
  const tokenPattern = new RegExp(
    `<<${escapeRegExp(vault.tokenPrefix)}:${escapeRegExp(vault.salt)}:\\d+>>`,
    "g"
  );

  let detectedProtocol: "openai" | "anthropic" =
    protocolHint === "anthropic" ? "anthropic" : "openai";
  let protocolLocked = protocolHint !== "auto";
  let anthropicBlockIndex = 0;
  let anthropicDeltaType: "text_delta" | "input_json_delta" | "thinking_delta" = "text_delta";

  const isPartialTokenPrefix = (candidate: string): boolean => {
    if (candidate.length === 0) return false;
    if (candidate.length <= tokenHeader.length) {
      return tokenHeader.startsWith(candidate);
    }
    if (!candidate.startsWith(tokenHeader)) return false;
    return /^\d+>?$/.test(candidate.slice(tokenHeader.length));
  };

  const holdSuffix = (value: string, safeStart: number): { emit: string; hold: string } => {
    if (vault.size === 0) {
      return { emit: value, hold: "" };
    }
    const maxTokenLength = Math.max(vault.maxTokenLength, tokenHeader.length + 12);
    const tail = value.slice(safeStart);
    let hold = 0;
    const maxHold = Math.min(tail.length, Math.max(0, maxTokenLength - 1));
    for (let length = maxHold; length > 0; length -= 1) {
      const suffix = tail.slice(-length);
      if (isPartialTokenPrefix(suffix)) {
        hold = length;
        break;
      }
    }
    return {
      emit: value.slice(0, value.length - hold),
      hold: value.slice(value.length - hold),
    };
  };

  const logicalIndexSegment = (entry: unknown, arrayIndex: number): string => {
    if (entry && typeof entry === "object" && !Array.isArray(entry)) {
      const idx = (entry as Record<string, unknown>).index;
      if (typeof idx === "number" && Number.isInteger(idx) && idx >= 0) {
        return `@idx=${idx}`;
      }
    }
    return String(arrayIndex);
  };

  const transformStrings = (
    value: unknown,
    path: string,
    parsedType?: unknown,
    responseScope?: ResponseScope
  ): boolean => {
    let changed = false;
    if (Array.isArray(value)) {
      value.forEach((entry, index) => {
        if (
          transformStrings(
            entry,
            `${path}/${logicalIndexSegment(entry, index)}`,
            parsedType,
            responseScope
          )
        ) {
          changed = true;
        }
      });
      return changed;
    }
    if (!value || typeof value !== "object") return changed;
    const record = value as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      const entry = record[key];
      const childPath = `${path}/${key}`;
      if (typeof entry === "string") {
        let carryKey = childPath;
        if (detectedProtocol === "anthropic" && path === "/delta") {
          carryKey = `/block/${anthropicBlockIndex}${childPath}`;
        } else if (
          typeof parsedType === "string" &&
          parsedType.startsWith("response.") &&
          childPath === "/delta"
        ) {
          const itemPart = encodeURIComponent(responseScope?.itemId ?? "");
          const outPart = responseScope?.outputIndex ?? "";
          const contentPart = responseScope?.contentIndex ?? "";
          carryKey = `/resp/${itemPart}/${outPart}/${contentPart}/${parsedType}${childPath}`;
        }
        if (carries.has(carryKey)) changed = true;
        const merged = (carries.get(carryKey) ?? "") + entry;
        const jsonEncoded = isJsonEncodedPath(childPath, parsedType, record);
        const { text: rehydrated, tailStart } = rehydrateWithTailBoundary(
          merged,
          vault,
          jsonEncoded,
          tokenPattern
        );
        const { emit, hold } = holdSuffix(rehydrated, tailStart);
        record[key] = emit;
        if (emit !== entry || hold.length > 0) changed = true;
        if (hold) {
          if (!carries.has(carryKey) && carries.size >= maxCarries) {
            throw new Error("Too many buffered SSE token fragments; aborting stream");
          }
          carries.set(carryKey, hold);
          carryMeta.set(carryKey, {
            blockIndex: anthropicBlockIndex,
            deltaType: anthropicDeltaType,
            jsonEncoded,
            ...(typeof parsedType === "string" ? { parsedType } : {}),
            ...(responseScope?.itemId !== undefined ? { itemId: responseScope.itemId } : {}),
            ...(responseScope?.outputIndex !== undefined ? { outputIndex: responseScope.outputIndex } : {}),
            ...(responseScope?.contentIndex !== undefined ? { contentIndex: responseScope.contentIndex } : {}),
          });
        } else {
          carries.delete(carryKey);
          carryMeta.delete(carryKey);
        }
      } else if (transformStrings(entry, childPath, parsedType, responseScope)) {
        changed = true;
      }
    }
    return changed;
  };

  const writeRaw = (controller: TransformStreamDefaultController<Uint8Array>, text: string): void => {
    controller.enqueue(encoder.encode(text));
  };

  const writeSseEvent = (
    controller: TransformStreamDefaultController<Uint8Array>,
    data: string,
    eventName?: string,
    eventId?: string,
    eventRetry?: string
  ): void => {
    const idLine = eventId === undefined ? "" : `id: ${eventId}\n`;
    const retryLine = eventRetry === undefined ? "" : `retry: ${eventRetry}\n`;
    const eventLine = eventName ? `event: ${eventName}\n` : "";
    const dataLines = data
      .split("\n")
      .map((line) => `data: ${line}`)
      .join("\n");
    writeRaw(controller, `${idLine}${retryLine}${eventLine}${dataLines}\n\n`);
  };

  const buildOpenAiDeltaFrame = (
    carryKey: string,
    pending: string,
    meta?: CarryMeta
  ): Record<string, unknown> => {
    const choiceMatch = /^\/choices\/(?:@idx=)?(\d+)\/delta\/(.+)$/.exec(carryKey);
    if (!choiceMatch) {
      if (carryKey === "/delta" || carryKey.startsWith("/resp/")) {
        return {
          type: meta?.parsedType ?? "response.output_text.delta",
          ...(meta?.itemId !== undefined ? { item_id: meta.itemId } : {}),
          ...(meta?.outputIndex !== undefined ? { output_index: meta.outputIndex } : {}),
          ...(meta?.contentIndex !== undefined ? { content_index: meta.contentIndex } : {}),
          delta: pending,
        };
      }
      return { choices: [{ index: 0, delta: { content: pending }, finish_reason: null }] };
    }
    const choiceIndex = Number(choiceMatch[1]);
    const subPath = choiceMatch[2];
    const toolMatch = /^tool_calls\/(?:@idx=)?(\d+)\/function\/arguments$/.exec(subPath);
    if (toolMatch) {
      return {
        choices: [
          {
            index: choiceIndex,
            delta: { tool_calls: [{ index: Number(toolMatch[1]), function: { arguments: pending } }] },
            finish_reason: null,
          },
        ],
      };
    }
    return {
      choices: [
        {
          index: choiceIndex,
          delta: { [subPath]: pending },
          finish_reason: null,
        },
      ],
    };
  };

  const appendCarryIntoTerminalObject = (
    parsed: Record<string, unknown>,
    carryKey: string,
    pending: string
  ): boolean => {
    if (carryKey.startsWith("/resp/")) return false;
    const rawKey = carryKey.replace(/^\/block\/\d+/, "");
    const segments = rawKey.split("/").filter(Boolean);
    if (segments.length === 0) return false;
    let cur: unknown = parsed;
    for (let i = 0; i < segments.length - 1; i += 1) {
      if (cur === null || typeof cur !== "object") return false;
      const seg = segments[i] as string;
      if (Array.isArray(cur)) {
        if (seg.startsWith("@idx=")) {
          const targetIdx = Number(seg.slice(5));
          cur = cur.find(
            (item) =>
              item &&
              typeof item === "object" &&
              (item as Record<string, unknown>).index === targetIdx
          );
        } else {
          cur = cur[Number(seg)];
        }
      } else {
        cur = (cur as Record<string, unknown>)[seg];
      }
    }
    const last = segments[segments.length - 1] as string;
    if (cur && typeof cur === "object" && !Array.isArray(cur)) {
      const rec = cur as Record<string, unknown>;
      if (typeof rec[last] === "string") {
        rec[last] = `${rec[last]}${pending}`;
        return true;
      }
    }
    return false;
  };

  const flushCarriesAsFrame = (
    controller: TransformStreamDefaultController<Uint8Array>,
    terminalParsed?: Record<string, unknown>,
    shouldFlush?: (carryKey: string, meta: CarryMeta | undefined) => boolean
  ): boolean => {
    if (carries.size === 0) return false;
    let injected = false;
    for (const [carryKey, rawCarry] of [...carries.entries()]) {
      const meta = carryMeta.get(carryKey);
      if (shouldFlush && !shouldFlush(carryKey, meta)) {
        continue;
      }
      const rawPath = carryKey.startsWith("/resp/") ? "/delta" : carryKey;
      const pending = rehydrateWithTailBoundary(
        rawCarry,
        vault,
        meta?.jsonEncoded ?? isJsonEncodedPath(rawPath, meta?.parsedType),
        tokenPattern
      ).text;
      carries.delete(carryKey);
      carryMeta.delete(carryKey);
      if (pending.length === 0) continue;

      if (terminalParsed && appendCarryIntoTerminalObject(terminalParsed, carryKey, pending)) {
        injected = true;
        continue;
      }

      if (detectedProtocol === "anthropic") {
        const blockIdx = meta?.blockIndex ?? anthropicBlockIndex;
        const deltaType =
          carryKey.endsWith("/partial_json")
            ? "input_json_delta"
            : carryKey.endsWith("/thinking")
              ? "thinking_delta"
              : (meta?.deltaType ?? anthropicDeltaType);
        const deltaPayload =
          deltaType === "input_json_delta"
            ? { type: "input_json_delta", partial_json: pending }
            : deltaType === "thinking_delta"
              ? { type: "thinking_delta", thinking: pending }
              : { type: "text_delta", text: pending };
        writeSseEvent(
          controller,
          JSON.stringify({
            type: "content_block_delta",
            index: blockIdx,
            delta: deltaPayload,
          }),
          "content_block_delta"
        );
        continue;
      }

      writeSseEvent(
        controller,
        JSON.stringify(buildOpenAiDeltaFrame(carryKey, pending, meta))
      );
    }
    return injected;
  };

  const updateAnthropicState = (parsed: Record<string, unknown>): void => {
    const type = parsed.type;
    if (type === "content_block_start") {
      if (typeof parsed.index === "number") anthropicBlockIndex = parsed.index;
      const block = parsed.content_block as Record<string, unknown> | undefined;
      if (block?.type === "tool_use") anthropicDeltaType = "input_json_delta";
      else if (block?.type === "thinking") anthropicDeltaType = "thinking_delta";
      else anthropicDeltaType = "text_delta";
    } else if (type === "content_block_delta") {
      if (typeof parsed.index === "number") anthropicBlockIndex = parsed.index;
      const delta = parsed.delta as Record<string, unknown> | undefined;
      if (delta?.type === "input_json_delta") anthropicDeltaType = "input_json_delta";
      else if (delta?.type === "thinking_delta") anthropicDeltaType = "thinking_delta";
      else anthropicDeltaType = "text_delta";
    }
  };

  const isTerminalFrame = (parsed: Record<string, unknown>): boolean => {
    if (detectedProtocol === "anthropic") {
      return parsed.type === "content_block_stop" || parsed.type === "message_stop";
    }
    if (
      parsed.type === "response.output_text.done" ||
      parsed.type === "response.function_call_arguments.done" ||
      parsed.type === "response.completed"
    ) {
      return true;
    }
    const choices = parsed.choices as Array<Record<string, unknown>> | undefined;
    return Array.isArray(choices)
      ? choices.some((c) => c.finish_reason !== undefined && c.finish_reason !== null)
      : false;
  };

  const processFrame = (
    frame: SseEventFrame | null,
    controller: TransformStreamDefaultController<Uint8Array>
  ): void => {
    if (!frame || !frame.data) return;
    if (frame.data === "[DONE]") {
      flushCarriesAsFrame(controller);
      writeSseEvent(controller, "[DONE]", undefined, frame.id, frame.retry);
      return;
    }
    if (!frame.data.trimStart().startsWith("{")) {
      writeSseEvent(controller, vault.rehydrate(frame.data), frame.eventName, frame.id, frame.retry);
      return;
    }
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(frame.data) as Record<string, unknown>;
    } catch {
      writeSseEvent(controller, vault.rehydrate(frame.data), frame.eventName, frame.id, frame.retry);
      return;
    }

    if (!protocolLocked) {
      const detected = detectSseProtocol(parsed, frame.eventName);
      if (detected !== null) {
        detectedProtocol = detected;
        protocolLocked = true;
      }
    }

    if (detectedProtocol === "anthropic") {
      updateAnthropicState(parsed);
    }

    const responseScope: ResponseScope | undefined =
      typeof parsed.type === "string" && parsed.type.startsWith("response.")
        ? {
            ...(typeof parsed.item_id === "string" ? { itemId: parsed.item_id } : {}),
            ...(typeof parsed.output_index === "number" ? { outputIndex: parsed.output_index } : {}),
            ...(typeof parsed.content_index === "number" ? { contentIndex: parsed.content_index } : {}),
          }
        : undefined;

    const stringsChanged = transformStrings(parsed, "", parsed.type, responseScope);
    let injected = false;
    if (isTerminalFrame(parsed)) {
      let shouldFlush: ((carryKey: string, meta: CarryMeta | undefined) => boolean) | undefined;
      if (
        detectedProtocol === "anthropic" &&
        parsed.type === "content_block_stop" &&
        typeof parsed.index === "number"
      ) {
        const blockIdx = parsed.index;
        shouldFlush = (_key, meta) => meta === undefined || meta.blockIndex === blockIdx;
      } else if (
        parsed.type === "response.output_text.done" ||
        parsed.type === "response.function_call_arguments.done"
      ) {
        const expectedDeltaType =
          parsed.type === "response.output_text.done"
            ? "response.output_text.delta"
            : "response.function_call_arguments.delta";
        shouldFlush = (_key, meta) => {
          if (!meta) return true;
          if (meta.parsedType && meta.parsedType !== expectedDeltaType) return false;
          if (responseScope?.itemId !== undefined && meta.itemId !== responseScope.itemId) return false;
          if (responseScope?.outputIndex !== undefined && meta.outputIndex !== responseScope.outputIndex) {
            return false;
          }
          if (responseScope?.contentIndex !== undefined && meta.contentIndex !== responseScope.contentIndex) {
            return false;
          }
          return true;
        };
      } else if (Array.isArray(parsed.choices)) {
        const finishedIndices = new Set<number>();
        parsed.choices.forEach((entry, arrIdx) => {
          if (
            entry &&
            typeof entry === "object" &&
            (entry as Record<string, unknown>).finish_reason !== undefined &&
            (entry as Record<string, unknown>).finish_reason !== null
          ) {
            const idx = (entry as Record<string, unknown>).index;
            finishedIndices.add(typeof idx === "number" ? idx : arrIdx);
          }
        });
        if (finishedIndices.size > 0) {
          shouldFlush = (carryKey) => {
            const match = /^\/choices\/(?:@idx=)?(\d+)\//.exec(carryKey);
            return match ? finishedIndices.has(Number(match[1])) : false;
          };
        }
      }
      injected = flushCarriesAsFrame(controller, parsed, shouldFlush);
    }
    if (stringsChanged || injected) {
      writeSseEvent(controller, JSON.stringify(parsed), frame.eventName, frame.id, frame.retry);
    } else {
      // No token touched this frame: forward the original bytes. Re-serializing
      // every frame would drop duplicate keys and normalise formatting.
      writeSseEvent(controller, frame.data, frame.eventName, frame.id, frame.retry);
    }
  };

  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      for (const line of decoder.decodeChunk(chunk)) {
        processFrame(assembler.pushLine(line), controller);
      }
    },
    flush(controller) {
      for (const line of decoder.flush()) {
        processFrame(assembler.pushLine(line), controller);
      }
      processFrame(assembler.flush(), controller);
      flushCarriesAsFrame(controller);
      carries.clear();
      carryMeta.clear();
    },
  });
}

export function wrapResponseWithRehydration(
  response: Response,
  vault: SecretVault,
  protocolHint: SseProtocol = "auto",
  options: SseRehydrationOptions = {}
): Response {
  if (!response.body || vault.size === 0) return response;
  const body = response.body.pipeThrough(
    createSseRehydrationTransform(vault, protocolHint, options)
  );
  const headers = new Headers(response.headers);
  headers.delete("content-length");
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
