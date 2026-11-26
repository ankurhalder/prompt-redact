import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

const REQUIRED = [
  "dist/index.js",
  "dist/index.cjs",
  "dist/index.d.ts",
  "dist/index.d.cts",
  "dist/cli.js",
  "dist/cli.cjs",
  "dist/cli.d.ts",
  "dist/cli.d.cts",
  "dist/mcp.js",
  "dist/mcp.cjs",
  "dist/mcp.d.ts",
  "dist/mcp.d.cts",
  "dist/bin.js",
  "README.md",
  "LICENSE",
];

function runNpm(args) {
  const options = { cwd: ROOT, encoding: "utf8" };
  return process.platform === "win32"
    ? spawnSync(`npm ${args.join(" ")}`, { ...options, shell: true })
    : spawnSync("npm", args, options);
}

function listTarballFiles() {
  const asJson = runNpm(["pack", "--dry-run", "--json"]);
  const raw = (asJson.stdout ?? "").trim();
  if (asJson.status === 0 && raw.startsWith("[")) {
    try {
      return JSON.parse(raw).flatMap((entry) => (entry.files ?? []).map((file) => file.path));
    } catch {
      return null;
    }
  }
  const plain = runNpm(["pack", "--dry-run"]);
  const text = `${plain.stdout ?? ""}\n${plain.stderr ?? ""}`;
  if (plain.status !== 0) {
    console.error(`npm pack --dry-run exited with code ${plain.status}`);
    console.error(text);
    return null;
  }
  const lines = text.split("\n");
  const start = lines.findIndex((line) => line.includes("Tarball Contents"));
  if (start === -1) return null;
  const files = [];
  for (const line of lines.slice(start + 1)) {
    if (line.includes("Tarball Details") || line.includes("===")) break;
    const cleaned = line.replace(/^npm notice\s+/, "").trim();
    if (!cleaned) continue;
    files.push(cleaned.split(/\s+/).pop());
  }
  return files.filter(Boolean);
}

const files = listTarballFiles();
if (!files) {
  console.error("FAIL: could not read the tarball file list from npm pack --dry-run");
  process.exit(1);
}

const problems = [];
for (const required of REQUIRED) {
  if (!files.includes(required)) problems.push(`missing required file: ${required}`);
}
const sourcemaps = files.filter((file) => file.endsWith(".map"));
if (sourcemaps.length > 0) {
  problems.push(`tarball must not contain .map files: ${sourcemaps.join(", ")}`);
}

const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
const bins = packageJson.bin ?? {};
if (Object.keys(bins).length === 0) {
  problems.push("package.json must declare a bin entry");
}
for (const [name, target] of Object.entries(bins)) {
  if (typeof target !== "string" || target.startsWith("./")) {
    problems.push(`bin["${name}"] must be a normalized path without "./"`);
    continue;
  }
  if (!files.includes(target)) {
    problems.push(`bin["${name}"] target is missing from the tarball: ${target}`);
  }
}
const lockPath = path.join(ROOT, "package-lock.json");
if (fs.existsSync(lockPath)) {
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  const lockRoot = lock.packages?.[""] ?? {};
  const fix = "run `npm install --package-lock-only`";
  if (lock.version !== packageJson.version) {
    problems.push(
      `package-lock.json is at ${lock.version} but the package is at ${packageJson.version} — ${fix}`
    );
  }
  if (lockRoot.version !== packageJson.version) {
    problems.push(
      `package-lock.json packages[""] is at ${lockRoot.version} but the package is at ${packageJson.version} — ${fix}`
    );
  }
  const lockBins = Object.keys(lockRoot.bin ?? {}).sort().join(", ");
  const packageBins = Object.keys(packageJson.bin ?? {}).sort().join(", ");
  if (lockBins !== packageBins) {
    problems.push(
      `package-lock.json lists bins [${lockBins}] but package.json declares [${packageBins}] — ${fix}`
    );
  }
}

if (problems.length > 0) {
  for (const problem of problems) console.error(`FAIL: ${problem}`);
  process.exit(1);
}

console.log(
  `OK: tarball has ${files.length} files, every required entry, no sourcemaps, and valid package metadata for ${packageJson.version}`
);
