import type { Readable, Writable } from "node:stream";

export const MAX_LINE_BYTES = 32 * 1024 * 1024;

export interface MessageWriter {
  write(value: unknown): Promise<void>;
}

export function createWriter(output: Writable): MessageWriter {
  return {
    write(value: unknown): Promise<void> {
      return new Promise<void>((resolve, reject) => {
        output.write(`${JSON.stringify(value)}\n`, (error?: Error | null) => {
          if (error) reject(error);
          else resolve();
        });
      });
    },
  };
}

export interface LineReaderOptions {
  onLine: (line: string) => void;
  onOverflow?: (bytes: number) => void;
}

/**
 * Line reader for JSON-RPC over stdio.
 *
 * Byte accounting is incremental and newline searching is skipped for chunks
 * that contain no newline, so a single very large message costs O(n) instead
 * of the previous O(n^2) (which re-measured the whole buffer on every chunk).
 */
export function createLineReader(input: Readable, options: LineReaderOptions): () => void {
  let buffer = "";
  let bufferBytes = 0;
  let discarding = false;
  let discardedBytes = 0;

  const deliver = (line: string): void => {
    if (discarding) {
      discarding = false;
      discardedBytes = 0;
      return;
    }
    const trimmed = line.endsWith("\r") ? line.slice(0, -1) : line;
    if (trimmed.trim().length === 0) return;
    options.onLine(trimmed);
  };

  const discardBuffered = (): void => {
    discarding = true;
    discardedBytes += bufferBytes;
    buffer = "";
    bufferBytes = 0;
    options.onOverflow?.(discardedBytes);
  };

  const drain = (): void => {
    let start = 0;
    let index = buffer.indexOf("\n", start);
    while (index >= 0) {
      const line = buffer.slice(start, index);
      if (!discarding && Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) {
        options.onOverflow?.(Buffer.byteLength(line, "utf8"));
      } else {
        deliver(line);
      }
      start = index + 1;
      index = buffer.indexOf("\n", start);
    }
    if (start > 0) {
      const consumedBytes = Buffer.byteLength(buffer.slice(0, start), "utf8");
      buffer = buffer.slice(start);
      bufferBytes = Math.max(0, bufferBytes - consumedBytes);
    }
    if (!discarding && bufferBytes > MAX_LINE_BYTES) discardBuffered();
  };

  const onData = (chunk: string): void => {
    const chunkBytes = Buffer.byteLength(chunk, "utf8");

    if (discarding) {
      const index = chunk.indexOf("\n");
      if (index < 0) {
        discardedBytes += chunkBytes;
        return;
      }
      buffer = chunk.slice(index + 1);
      bufferBytes = Buffer.byteLength(buffer, "utf8");
      deliver("");
      drain();
      return;
    }

    if (chunk.indexOf("\n") < 0) {
      if (bufferBytes + chunkBytes > MAX_LINE_BYTES) {
        discarding = true;
        discardedBytes = bufferBytes + chunkBytes;
        buffer = "";
        bufferBytes = 0;
        options.onOverflow?.(discardedBytes);
        return;
      }
      buffer += chunk;
      bufferBytes += chunkBytes;
      return;
    }

    buffer += chunk;
    bufferBytes += chunkBytes;
    drain();
  };

  const onEnd = (): void => {
    const rest = buffer;
    const restBytes = bufferBytes || Buffer.byteLength(rest, "utf8");
    buffer = "";
    bufferBytes = 0;
    if (rest.length === 0) return;
    if (discarding) {
      discarding = false;
      discardedBytes = 0;
      return;
    }
    if (restBytes > MAX_LINE_BYTES) {
      options.onOverflow?.(restBytes);
      return;
    }
    deliver(rest);
  };

  input.setEncoding("utf8");
  input.on("data", onData);
  input.on("end", onEnd);

  return () => {
    input.off("data", onData);
    input.off("end", onEnd);
  };
}
