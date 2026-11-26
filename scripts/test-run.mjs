import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.join(HERE, "..");

export function suiteFiles(root = REPO_ROOT) {
  return fs
    .readdirSync(path.join(root, "tests"))
    .filter((name) => name.endsWith(".test.js"))
    .sort()
    .map((name) => path.join("tests", name));
}

export function removeTree(target) {
  try {
    fs.rmSync(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return true;
    console.error(`test-run: could not remove ${target}: ${error.message}`);
    return false;
  }
}

export function makeScratchRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "pr-test-run-"));
}

let activeScratch = null;

export function runSuite({
  files = suiteFiles(),
  nodeArgs = [],
  cwd = REPO_ROOT,
  env = process.env,
  stdio = "inherit",
} = {}) {
  const scratch = makeScratchRoot();
  activeScratch = scratch;
  const childEnv = { ...env, TEMP: scratch, TMP: scratch, TMPDIR: scratch };
  delete childEnv.NODE_TEST_CONTEXT;
  return new Promise((resolve) => {
    const settle = (code) => {
      activeScratch = null;
      let leaked = [];
      try {
        leaked = fs.readdirSync(scratch);
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      const removed = removeTree(scratch);
      if (leaked.length > 0) {
        const plural = leaked.length === 1 ? "entry" : "entries";
        const shown = leaked.slice(0, 5).join(", ");
        const more = leaked.length > 5 ? ", ..." : "";
        console.error(`test-run: removed ${leaked.length} leaked temp ${plural}: ${shown}${more}`);
      }
      resolve({ code, scratch, leftovers: leaked.length, removed });
    };
    const child = spawn(process.execPath, ["--test", ...nodeArgs, ...files], {
      cwd,
      env: childEnv,
      stdio,
    });
    child.on("error", (error) => {
      console.error(`test-run: could not start node --test: ${error.message}`);
      settle(1);
    });
    child.on("close", (code, signal) => settle(signal ? 1 : code ?? 1));
  });
}

process.on("exit", () => {
  if (activeScratch) removeTree(activeScratch);
});

const cliPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : "";
if (cliPath === import.meta.url) {
  const result = await runSuite({ nodeArgs: process.argv.slice(2) });
  process.exitCode = result.code;
}
