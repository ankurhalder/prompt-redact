import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

export function assertWritableInsideRepository(
  cwd: string,
  filePath: string,
  label = "Refusing to write"
): void {
  const root = fs.realpathSync(cwd);
  const cwdResolved = path.resolve(cwd);
  const absTarget = path.resolve(filePath);
  const relFromCwd = path.relative(cwdResolved, absTarget);
  if (relFromCwd === ".." || relFromCwd.startsWith(`..${path.sep}`) || path.isAbsolute(relFromCwd)) {
    throw new Error(`${label}: ${filePath} resolves outside ${root}.`);
  }

  const normalizedTarget = relFromCwd === "" ? root : path.join(root, relFromCwd);
  const shown = relFromCwd || path.basename(normalizedTarget);

  let stat: fs.Stats | null = null;
  try {
    stat = fs.lstatSync(normalizedTarget);
  } catch {
    stat = null;
  }

  if (stat !== null && stat.isSymbolicLink()) {
    throw new Error(`${label}: ${shown} is a symbolic link or junction.`);
  }
  if (stat !== null && stat.isFile() && stat.nlink > 1) {
    throw new Error(`${label}: ${shown} has ${stat.nlink} hard links.`);
  }

  let existing = normalizedTarget;
  const missing: string[] = [];
  while (true) {
    if (existing === root) break;
    let ancStat: fs.Stats | null = null;
    try {
      ancStat = fs.lstatSync(existing);
    } catch {
      ancStat = null;
    }
    if (ancStat !== null) {
      if (ancStat.isSymbolicLink()) {
        throw new Error(`${label}: ancestor ${existing} is a symbolic link or junction.`);
      }
      break;
    }
    missing.unshift(path.basename(existing));
    const parent = path.dirname(existing);
    if (parent === existing) break;
    existing = parent;
  }
  const realAncestor = fs.realpathSync(existing);
  const resolved = missing.length === 0 ? realAncestor : path.join(realAncestor, ...missing);
  const rel = path.relative(root, resolved);
  if (rel === ".." || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    throw new Error(`${label}: ${shown} resolves outside ${root}.`);
  }
}

/**
 * Write inside the repository through a fresh temp file + rename. The rename
 * replaces the directory entry instead of following it, so a symlink swapped
 * in after the confinement check cannot redirect the write.
 */
export function writeFileInsideRepository(
  cwd: string,
  filePath: string,
  data: string,
  label = "Refusing to write"
): void {
  assertWritableInsideRepository(cwd, filePath, label);
  const dir = path.dirname(filePath);
  const base = path.basename(filePath);
  const temp = path.join(
    dir,
    `.${base}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`
  );
  let fd: number | null = null;
  try {
    fd = fs.openSync(temp, "wx", 0o600);
    fs.writeFileSync(fd, data, "utf8");
    fs.closeSync(fd);
    fd = null;
    fs.renameSync(temp, filePath);
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // best effort
      }
    }
    try {
      fs.unlinkSync(temp);
    } catch {
      // temp was renamed or never created
    }
  }
}
