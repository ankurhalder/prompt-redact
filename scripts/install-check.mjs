import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

function runNpm(args, cwd) {
  if (process.platform === "win32") {
    const quoted = args.map((arg) => (arg.includes(" ") ? `"${arg}"` : arg)).join(" ");
    return spawnSync(`npm ${quoted}`, { cwd, encoding: "utf8", shell: true });
  }
  return spawnSync("npm", args, { cwd, encoding: "utf8" });
}

function runNode(args, cwd) {
  return spawnSync(process.execPath, args, {
    cwd,
    encoding: "utf8",
    windowsHide: true,
  });
}

function fail(message, result) {
  console.error(`FAIL: ${message}`);
  if (result) {
    if (result.stdout) console.error(result.stdout.slice(-2000));
    if (result.stderr) console.error(result.stderr.slice(-2000));
  }
  process.exit(1);
}

const temp = fs.mkdtempSync(path.join(os.tmpdir(), "pr-install-check-"));
try {
  const pack = runNpm(["pack", "--pack-destination", temp, "--silent"], ROOT);
  if (pack.status !== 0) fail("npm pack failed", pack);
  const tarball = fs.readdirSync(temp).find((name) => name.endsWith(".tgz"));
  if (!tarball) fail("npm pack produced no tarball");
  const tarballPath = path.join(temp, tarball);

  fs.writeFileSync(
    path.join(temp, "package.json"),
    JSON.stringify({ name: "pr-install-check", private: true }, null, 2)
  );
  // Extract the tarball directly instead of running npm install: npm 11's
  // allow-scripts policy can reject project-scoped installs on some hosts.
  const extract = spawnSync("tar", ["-xzf", tarballPath, "-C", temp], {
    encoding: "utf8",
    windowsHide: true,
  });
  if (extract.status !== 0) fail("could not extract the packed tarball with tar", extract);
  const extracted = path.join(temp, "package");
  if (!fs.existsSync(extracted)) fail("tarball does not contain a package/ directory");
  fs.mkdirSync(path.join(temp, "node_modules"), { recursive: true });
  fs.renameSync(extracted, path.join(temp, "node_modules", "prompt-redact"));

  const cjs = runNode(
    ["-e", "const p=require('prompt-redact'); if(typeof p.createVault!=='function'||p.PACKAGE_VERSION!=='0.1.0') process.exit(2);"],
    temp
  );
  if (cjs.status !== 0) fail("CJS require of the packed package failed", cjs);

  const esm = runNode(
    ["--input-type=module", "-e", "import { createVault, PACKAGE_VERSION } from 'prompt-redact'; if (typeof createVault !== 'function' || PACKAGE_VERSION !== '0.1.0') process.exit(2);"],
    temp
  );
  if (esm.status !== 0) fail("ESM import of the packed package failed", esm);

  const mcp = runNode(
    ["--input-type=module", "-e", "import { createServer, startHttpTransport } from 'prompt-redact/mcp'; if (typeof createServer !== 'function' || typeof startHttpTransport !== 'function') process.exit(2);"],
    temp
  );
  if (mcp.status !== 0) fail("prompt-redact/mcp export failed", mcp);

  const bin = runNode(
    [path.join(temp, "node_modules", "prompt-redact", "dist", "bin.js"), "describe", "--format", "json"],
    temp
  );
  if (bin.status !== 0) fail("packed bin failed", bin);
  let contract;
  try {
    contract = JSON.parse(bin.stdout);
  } catch {
    fail("packed bin did not emit JSON", bin);
  }
  if (contract.version !== "0.1.0" || contract.mcp.tools.length !== 6) {
    fail(`packed contract mismatch: ${JSON.stringify(contract).slice(0, 200)}`);
  }

  console.log(`OK: packed 0.1.0 installs; CJS, ESM, ./mcp, and the bin all work (${tarball})`);
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
