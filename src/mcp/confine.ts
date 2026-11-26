import * as fs from "node:fs";
import * as path from "node:path";
import { decodeTextBuffer } from "../core/text.js";

export type ConfinedFailureReason = "missing" | "outside" | "not-file" | "not-dir" | "unreadable";

export interface ConfinedFailure {
  ok: false;
  reason: ConfinedFailureReason;
  message: string;
}

export type ConfinedTextResult =
  | {
      ok: true;
      text: string;
      path: string;
      stats: fs.Stats;
    }
  | ConfinedFailure;

export type ConfinedDirResult =
  | {
      ok: true;
      path: string;
    }
  | ConfinedFailure;

function foldCase(value: string): string {
  return process.platform === "win32" || process.platform === "darwin" ? value.toLowerCase() : value;
}

function isInside(parent: string, child: string): boolean {
  const relative = path.relative(foldCase(parent), foldCase(child));
  return (
    relative === "" ||
    (relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !relative.startsWith("../") &&
      !path.isAbsolute(relative))
  );
}

export function resolveConfinedDirectory(
  roots: readonly string[],
  targetPath: string
): ConfinedDirResult {
  if (targetPath.includes("\0")) {
    return { ok: false, reason: "outside", message: "path contains a NUL byte" };
  }
  const realRoots = roots
    .map((root) => {
      try {
        return fs.realpathSync(path.resolve(root));
      } catch {
        return null;
      }
    })
    .filter((item): item is string => item !== null);

  if (realRoots.length === 0) {
    return { ok: false, reason: "missing", message: "workspace root does not exist" };
  }

  const base = realRoots[0];
  const candidate = path.resolve(base, targetPath);
  if (!realRoots.some((root) => isInside(root, candidate))) {
    return { ok: false, reason: "outside", message: "directory resolves outside allowed workspace roots" };
  }

  let real: string;
  try {
    real = fs.realpathSync(candidate);
  } catch {
    return { ok: false, reason: "missing", message: "directory does not exist" };
  }
  if (!realRoots.some((root) => isInside(root, real))) {
    return { ok: false, reason: "outside", message: "directory resolves outside allowed workspace roots" };
  }
  try {
    if (!fs.statSync(real).isDirectory()) {
      return { ok: false, reason: "not-dir", message: "path is not a directory" };
    }
  } catch {
    return { ok: false, reason: "unreadable", message: "directory could not be inspected" };
  }
  return { ok: true, path: real };
}

export function readConfinedText(
  roots: readonly string[],
  targetPath: string,
  maxBytes = 1024 * 1024
): ConfinedTextResult {
  if (targetPath.length === 0 || targetPath.includes("\0")) {
    return { ok: false, reason: "not-file", message: "file path is empty or contains a NUL byte" };
  }

  const realRoots = roots
    .map((root) => {
      try {
        return fs.realpathSync(path.resolve(root));
      } catch {
        return null;
      }
    })
    .filter((item): item is string => item !== null);

  if (realRoots.length === 0) {
    return { ok: false, reason: "missing", message: "workspace root does not exist" };
  }

  const base = realRoots[0];
  const candidate = path.resolve(base, targetPath);
  if (!realRoots.some((root) => isInside(root, candidate))) {
    return { ok: false, reason: "outside", message: "path resolves outside allowed workspace roots" };
  }

  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(candidate);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return {
      ok: false,
      reason: code === "ENOENT" || code === "ENOTDIR" ? "missing" : "unreadable",
      message:
        code === "ENOENT" || code === "ENOTDIR"
          ? "the file does not exist"
          : "the file could not be inspected",
    };
  }

  if (stats.isSymbolicLink()) {
    return { ok: false, reason: "not-file", message: "refusing to read symbolic link" };
  }
  if (!stats.isFile()) {
    return { ok: false, reason: "not-file", message: "path is not a regular file" };
  }
  if (stats.nlink > 1) {
    return { ok: false, reason: "not-file", message: "refusing to read hard-linked file" };
  }

  let real: string;
  try {
    real = fs.realpathSync(candidate);
  } catch {
    return { ok: false, reason: "unreadable", message: "the file could not be resolved" };
  }
  if (!realRoots.some((root) => isInside(root, real))) {
    return { ok: false, reason: "outside", message: "file resolves outside allowed workspace roots" };
  }
  if (stats.size > maxBytes) {
    return {
      ok: false,
      reason: "unreadable",
      message: `file exceeds ${maxBytes}-byte read limit (${stats.size} bytes)`,
    };
  }
  try {
    // Read through an open descriptor and re-validate the object we actually
    // opened, closing the check-then-read window on the path itself.
    const fd = fs.openSync(real, "r");
    try {
      const fstat = fs.fstatSync(fd);
      if (!fstat.isFile()) {
        return { ok: false, reason: "not-file", message: "path is not a regular file" };
      }
      if (fstat.nlink > 1) {
        return { ok: false, reason: "not-file", message: "refusing to read hard-linked file" };
      }
      if (fstat.size > maxBytes) {
        return {
          ok: false,
          reason: "unreadable",
          message: `file exceeds ${maxBytes}-byte read limit (${fstat.size} bytes)`,
        };
      }
      const raw = fs.readFileSync(fd);
      const text = decodeTextBuffer(raw);
      if (text === null) {
        return { ok: false, reason: "unreadable", message: "binary file cannot be read as text" };
      }
      return { ok: true, text, path: real, stats: fstat };
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return { ok: false, reason: "unreadable", message: "the file could not be read" };
  }
}
