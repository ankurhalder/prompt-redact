import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { CLI_OPTIONS, buildAgentContract } from "../dist/cli.js";
import { startWebServer } from "../dist/index.js";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const BIN = path.join(ROOT, "dist", "bin.js");

function runCli(args, options = {}) {
  return spawnSync(process.execPath, [BIN, ...args], {
    cwd: options.cwd ?? ROOT,
    input: options.input,
    encoding: "utf8",
    windowsHide: true,
  });
}

test("CLI exit codes: 0 clean, 1 findings, 2 usage error", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-cli-"));
  try {
    fs.writeFileSync(path.join(dir, "clean.ts"), "export const ok = 1;\n", "utf8");
    const clean = runCli(["verify", "--cwd", dir, "--format", "json"]);
    assert.equal(clean.status, 0);
    assert.equal(JSON.parse(clean.stdout).clean, true);

    const secret = "ghp_cliVerifySecretToken1234567890abcdef";
    fs.writeFileSync(path.join(dir, "leak.ts"), `export const tok = "${secret}";\n`, "utf8");
    const dirty = runCli(["scan", "--cwd", dir, "--sarif", "--format", "json"]);
    assert.equal(dirty.status, 1);
    assert.ok(!dirty.stdout.includes(secret));
    assert.ok(!dirty.stderr.includes(secret));
    assert.ok(fs.existsSync(path.join(dir, "audit.md")));
    assert.ok(fs.existsSync(path.join(dir, "audit.sarif")));

    const badFlag = runCli(["verify", "--unknown-flag"]);
    assert.equal(badFlag.status, 2);

    const wrongScope = runCli(["doctor", "--sarif"]);
    assert.equal(wrongScope.status, 2);

    const stdinDirty = runCli(["verify", "--stdin", "--format", "json"], {
      cwd: dir,
      input: `OPENAI_API_KEY=sk-proj-stdinSecret1234567890abcdefghij\n`,
    });
    assert.equal(stdinDirty.status, 1);
    assert.equal(JSON.parse(stdinDirty.stdout).clean, false);

    const stdinClean = runCli(["verify", "--stdin", "--format", "json"], {
      cwd: dir,
      input: "ordinary prompt with no secrets\n",
    });
    assert.equal(stdinClean.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("setup --dry-run writes nothing; doctor honors --config; hook scope is verify-only", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-cli-setup-"));
  try {
    const dry = runCli(["setup", "--cwd", dir, "--dry-run"]);
    assert.equal(dry.status, 0);
    assert.match(dry.stdout, /would create/);
    assert.equal(fs.existsSync(path.join(dir, "prompt-redact.config.json")), false);

    const written = runCli(["setup", "--cwd", dir]);
    assert.equal(written.status, 0);
    assert.ok(fs.existsSync(path.join(dir, "prompt-redact.config.json")));

    const healthy = runCli(["doctor", "--cwd", dir, "--port", "0", "--config", path.join(dir, "prompt-redact.config.json")]);
    assert.equal(healthy.status, 0);

    const badConfig = path.join(dir, "bad.json");
    fs.writeFileSync(badConfig, "{ not json", "utf8");
    const broken = runCli(["doctor", "--cwd", dir, "--port", "0", "--config", badConfig]);
    assert.equal(broken.status, 1);

    const wrongScope = runCli(["scan", "--hook", "--cwd", dir]);
    assert.equal(wrongScope.status, 2);
    const conflict = runCli(["verify", "--hook", "--stdin"], { input: "{}" });
    assert.equal(conflict.status, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("describe --format json contract stays in sync with CLI_OPTIONS", () => {
  const res = runCli(["describe", "--format", "json"]);
  assert.equal(res.status, 0);
  const contract = JSON.parse(res.stdout);
  const direct = buildAgentContract();
  assert.equal(contract.package, direct.package);
  assert.equal(contract.mcp.tools.length, 6);

  const contractFlags = new Set(contract.options.map((o) => o.flag.replace(/^--/, "")));
  for (const key of Object.keys(CLI_OPTIONS)) {
    if (key === "help" || key === "version") continue;
    assert.ok(contractFlags.has(key), `option --${key} missing from describe contract`);
  }
});

test("skill --install writes confined skill files and respects --track vs gitignore", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-skill-"));
  try {
    const first = runCli(["skill", "--install", "--cwd", dir, "--format", "json"]);
    assert.equal(first.status, 0);
    const out = JSON.parse(first.stdout);
    assert.equal(out.written.length, 2);
    assert.ok(fs.existsSync(path.join(dir, ".claude", "skills", "prompt-redact", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(dir, ".cursor", "rules", "prompt-redact.mdc")));
    const gitignore = fs.readFileSync(path.join(dir, ".gitignore"), "utf8");
    assert.ok(gitignore.includes(".claude/skills/prompt-redact/SKILL.md"));
    assert.ok(gitignore.includes(".cursor/rules/prompt-redact.mdc"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("web inspector serves playground, enforces bearer token, and redacts/rehydrates", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-web-"));
  const web = await startWebServer({ cwd: dir, port: 0, log: () => undefined });
  try {
    const page = await fetch(web.url);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /prompt-redact inspector/);

    const unauth = await fetch(`${web.url}api/audit`);
    assert.equal(unauth.status, 401);

    const secret = "sk-proj-webInspectorSecret1234567890abcd";
    const red = await fetch(`${web.url}api/redact`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${web.token}`,
      },
      body: JSON.stringify({ text: `key=${secret}` }),
    });
    assert.equal(red.status, 200);
    const redJson = await red.json();
    assert.equal(redJson.hits, 1);
    assert.ok(!redJson.redacted.includes(secret));

    const reh = await fetch(`${web.url}api/rehydrate`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${web.token}`,
      },
      body: JSON.stringify({ text: redJson.redacted }),
    });
    assert.equal((await reh.json()).text, `key=${secret}`);
  } finally {
    await web.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
