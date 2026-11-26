import * as fs from "node:fs";
import * as path from "node:path";
import { assertWritableInsideRepository, writeFileInsideRepository } from "../core/fs-safe.js";
import { SKILL_NAME, renderCursorRule, renderSkill } from "./skill.js";

export type SkillTarget = "claude" | "cursor" | "all";
export const SKILL_TARGETS: SkillTarget[] = ["claude", "cursor", "all"];

export interface SkillWrite {
  target: Exclude<SkillTarget, "all">;
  path: string;
  action: "created" | "updated" | "unchanged";
}

export interface SkillInstallResult {
  cwd: string;
  written: SkillWrite[];
  gitignored: string[];
  notes: string[];
}

const REFUSED = "Refusing to install skill";

function targetPath(cwd: string, target: Exclude<SkillTarget, "all">): string {
  switch (target) {
    case "claude":
      return path.join(cwd, ".claude", "skills", SKILL_NAME, "SKILL.md");
    case "cursor":
      return path.join(cwd, ".cursor", "rules", `${SKILL_NAME}.mdc`);
  }
}

function contentFor(target: Exclude<SkillTarget, "all">): string {
  return target === "claude" ? renderSkill() : renderCursorRule();
}

function writeIfChanged(
  cwd: string,
  target: Exclude<SkillTarget, "all">,
  filePath: string,
  content: string
): SkillWrite {
  const existing = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : null;
  if (existing === content) return { target, path: filePath, action: "unchanged" };
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileInsideRepository(cwd, filePath, content, REFUSED);
  return { target, path: filePath, action: existing === null ? "created" : "updated" };
}

function appendGitignore(cwd: string, relPaths: string[]): string[] {
  if (relPaths.length === 0) return [];
  const ignoreFile = path.join(cwd, ".gitignore");
  const existing = fs.existsSync(ignoreFile) ? fs.readFileSync(ignoreFile, "utf8") : "";
  const lines = new Set(existing.split(/\r?\n/).map((l) => l.trim()));
  const added: string[] = [];
  for (const rel of relPaths) {
    const posix = rel.replace(/\\/g, "/");
    if (!lines.has(posix)) {
      added.push(posix);
    }
  }
  if (added.length > 0) {
    const prefix = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
    writeFileInsideRepository(
      cwd,
      ignoreFile,
      `${existing}${prefix}${added.join("\n")}\n`,
      REFUSED
    );
  }
  return added;
}

export function installSkill(
  cwd: string,
  target: SkillTarget = "all",
  options: { track?: boolean } = {}
): SkillInstallResult {
  const written: SkillWrite[] = [];
  const notes: string[] = [];
  const wanted: Array<Exclude<SkillTarget, "all">> =
    target === "all" ? ["claude", "cursor"] : [target];

  for (const item of wanted) {
    assertWritableInsideRepository(cwd, targetPath(cwd, item), REFUSED);
  }
  if (!options.track) {
    assertWritableInsideRepository(cwd, path.join(cwd, ".gitignore"), REFUSED);
  }

  for (const item of wanted) {
    written.push(writeIfChanged(cwd, item, targetPath(cwd, item), contentFor(item)));
  }

  let gitignored: string[] = [];
  if (!options.track) {
    // Add entries for updated/unchanged files too: a file installed earlier
    // with --track must become ignored when a later run drops --track.
    const relPaths = written.map((w) => path.relative(cwd, w.path).replace(/\\/g, "/"));
    gitignored = appendGitignore(cwd, relPaths);
  } else {
    notes.push("--track enabled: installed skill files were not added to .gitignore.");
  }

  return { cwd, written, gitignored, notes };
}

export function isSkillTarget(value: string): value is SkillTarget {
  return (SKILL_TARGETS as string[]).includes(value);
}
