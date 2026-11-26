const UTF8_FATAL = new TextDecoder("utf-8", { fatal: true });

export type TextDecodeReason = "binary" | "invalid-utf8";

export type TextDecodeResult =
  | { ok: true; text: string }
  | { ok: false; reason: TextDecodeReason };

function swapUtf16Be(raw: Buffer): string {
  const body = Buffer.from(raw);
  const evenLen = body.length - (body.length % 2);
  for (let i = 0; i < evenLen; i += 2) {
    const tmp = body[i] as number;
    body[i] = body[i + 1] as number;
    body[i + 1] = tmp;
  }
  return body.subarray(0, evenLen).toString("utf16le");
}

function decodeUtf32(raw: Buffer, littleEndian: boolean): string | null {
  if (raw.length % 4 !== 0) return null;
  let out = "";
  for (let i = 0; i < raw.length; i += 4) {
    const cp = littleEndian
      ? ((raw[i] as number) |
          ((raw[i + 1] as number) << 8) |
          ((raw[i + 2] as number) << 16) |
          ((raw[i + 3] as number) << 24)) >>>
        0
      : ((((raw[i] as number) << 24) |
          ((raw[i + 1] as number) << 16) |
          ((raw[i + 2] as number) << 8) |
          (raw[i + 3] as number)) >>>
        0);
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return null;
    out += String.fromCodePoint(cp);
  }
  return out;
}

/**
 * BOM-less UTF-16 text is common on Windows (PowerShell redirection, some
 * editors). Treating it as binary made the scanner silently skip those files,
 * which is a gate bypass. Detect the characteristic alternating NUL layout.
 */
function detectUtf16WithoutBom(raw: Buffer): "le" | "be" | null {
  if (raw.length < 16 || raw.length % 2 !== 0) return null;
  const limit = Math.min(raw.length, 8192);
  let evenNul = 0;
  let oddNul = 0;
  for (let i = 0; i < limit; i += 1) {
    if (raw[i] === 0) {
      if (i % 2 === 0) evenNul += 1;
      else oddNul += 1;
    }
  }
  const threshold = Math.max(4, Math.floor(limit * 0.2));
  const slack = Math.max(1, Math.floor(limit * 0.02));
  if (oddNul >= threshold && evenNul <= slack) return "le";
  if (evenNul >= threshold && oddNul <= slack) return "be";
  return null;
}

export function decodeTextBufferDetailed(raw: Buffer): TextDecodeResult {
  if (raw.length >= 4) {
    if (raw[0] === 0xff && raw[1] === 0xfe && raw[2] === 0x00 && raw[3] === 0x00) {
      const text = decodeUtf32(raw.subarray(4), true);
      return text === null ? { ok: false, reason: "invalid-utf8" } : { ok: true, text };
    }
    if (raw[0] === 0x00 && raw[1] === 0x00 && raw[2] === 0xfe && raw[3] === 0xff) {
      const text = decodeUtf32(raw.subarray(4), false);
      return text === null ? { ok: false, reason: "invalid-utf8" } : { ok: true, text };
    }
  }
  if (raw.length >= 2 && raw[0] === 0xff && raw[1] === 0xfe) {
    return { ok: true, text: raw.subarray(2).toString("utf16le") };
  }
  if (raw.length >= 2 && raw[0] === 0xfe && raw[1] === 0xff) {
    return { ok: true, text: swapUtf16Be(raw.subarray(2)) };
  }
  const guessed = detectUtf16WithoutBom(raw);
  if (guessed === "le") return { ok: true, text: raw.toString("utf16le") };
  if (guessed === "be") return { ok: true, text: swapUtf16Be(raw) };
  if (raw.includes(0)) return { ok: false, reason: "binary" };
  try {
    return { ok: true, text: UTF8_FATAL.decode(raw) };
  } catch {
    return { ok: false, reason: "invalid-utf8" };
  }
}

export function decodeTextBuffer(raw: Buffer): string | null {
  const decoded = decodeTextBufferDetailed(raw);
  return decoded.ok ? decoded.text : null;
}
