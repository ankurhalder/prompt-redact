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

test("guard --hook blocks native credential access and allows the airlock", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-guard-"));
  const hook = (toolName, toolInput) => JSON.stringify({ tool_name: toolName, tool_input: toolInput });
  const secret = "sk-proj-" + "guardFixtureSecret1234567890";
  try {
    const cases = [
      ["read .env", hook("Read", { file_path: ".env" }), 2],
      ["read .env.local", hook("Read", { file_path: ".env.local" }), 2],
      ["read .env.example", hook("Read", { file_path: ".env.example" }), 0],
      ["read source", hook("Read", { file_path: "src/index.ts" }), 0],
      ["grep .env", hook("Grep", { path: ".env" }), 2],
      ["cat .env", hook("Bash", { command: "cat .env" }), 2],
      ["cat .env.example", hook("Bash", { command: "cat .env.example" }), 0],
      ["npm test", hook("Bash", { command: "npm test" }), 0],
      ["git commit message", hook("Bash", { command: 'git commit -m "docs: explain .env" ' }), 0],
      ["printenv", hook("Bash", { command: "printenv" }), 2],
      ["echo key", hook("Bash", { command: "echo $OPENAI_API_KEY" }), 2],
      ["echo home", hook("Bash", { command: "echo $HOME" }), 0],
      ["node env dump", hook("Bash", { command: 'node -e "console.log(process.env)"' }), 2],
      ["literal secret", hook("Bash", { command: "echo " + secret }), 2],
      ["mcp airlock", hook("mcp__prompt-redact__airlock_read_file", { path: ".env" }), 0],
      ["invalid json", "{not-json", 2],
    ];
    for (const [name, input, expected] of cases) {
      const result = runCli(["guard", "--hook", "--cwd", dir], { cwd: dir, input });
      assert.equal(result.status, expected, name + " (stderr: " + result.stderr + ")");
    }
    const missingHook = runCli(["guard", "--cwd", dir]);
    assert.equal(missingHook.status, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("skill --install --secure writes MCP config, deny rules, and guard hooks", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-secure-"));
  const settingsPath = path.join(dir, ".claude", "settings.json");
  try {
    const first = runCli(["skill", "--install", "--secure", "--cwd", dir, "--format", "json"]);
    assert.equal(first.status, 0, first.stderr);
    const report = JSON.parse(first.stdout);
    const paths = report.written.map((entry) => path.relative(dir, entry.path).replace(/\\/g, "/"));
    for (const expected of [
      ".claude/skills/prompt-redact/SKILL.md",
      ".cursor/rules/prompt-redact.mdc",
      ".mcp.json",
      ".claude/settings.json",
      ".cursor/mcp.json",
      ".cursorignore",
    ]) {
      assert.ok(paths.includes(expected), "missing " + expected);
    }
    assert.equal(report.secureFiles.length, 4);
    assert.ok(!report.gitignored.includes(".mcp.json"));
    assert.ok(!report.gitignored.includes(".claude/settings.json"));

    const settings = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
    assert.ok(settings.permissions.deny.some((line) => line.includes(".env")));
    assert.ok(settings.permissions.deny.some((line) => line.includes(".ssh")));
    assert.ok(settings.permissions.allow.includes("mcp__prompt-redact__airlock_read_file"));
    assert.ok(JSON.stringify(settings.hooks.PreToolUse).includes("guard --hook"));
    assert.ok(JSON.stringify(settings.hooks.UserPromptSubmit).includes("verify --hook"));
    const mcp = JSON.parse(fs.readFileSync(path.join(dir, ".mcp.json"), "utf8"));
    assert.equal(mcp.mcpServers["prompt-redact"].command, "npx");
    assert.deepEqual(mcp.mcpServers["prompt-redact"].args, ["--no-install", "prompt-redact", "mcp"]);
    assert.ok(fs.readFileSync(path.join(dir, ".cursorignore"), "utf8").includes(".env"));

    const second = runCli(["skill", "--install", "--secure", "--cwd", dir, "--format", "json"]);
    assert.equal(second.status, 0, second.stderr);
    const secondReport = JSON.parse(second.stdout);
    assert.ok(secondReport.written.every((entry) => entry.action === "unchanged"));

    // Preserve unrelated settings and hooks during the merge.
    fs.writeFileSync(
      settingsPath,
      JSON.stringify({
        custom: true,
        permissions: { deny: ["Bash(rm:*)"], allow: ["Bash(git:*)"] },
        hooks: {
          PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo custom" }] }],
        },
      }),
      "utf8"
    );
    const merged = runCli(["skill", "--install", "--secure", "--cwd", dir, "--format", "json"]);
    assert.equal(merged.status, 0, merged.stderr);
    const mergedSettings = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
    assert.equal(mergedSettings.custom, true);
    assert.ok(mergedSettings.permissions.deny.includes("Bash(rm:*)"));
    assert.ok(mergedSettings.permissions.allow.includes("Bash(git:*)"));
    assert.ok(JSON.stringify(mergedSettings.hooks.PreToolUse).includes("echo custom"));
    assert.ok(JSON.stringify(mergedSettings.hooks.PreToolUse).includes("guard --hook"));

    const needsInstall = runCli(["skill", "--secure", "--cwd", dir]);
    assert.equal(needsInstall.status, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  const badDir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-secure-bad-"));
  try {
    fs.mkdirSync(path.join(badDir, ".claude"), { recursive: true });
    fs.writeFileSync(path.join(badDir, ".claude", "settings.json"), "{not json", "utf8");
    const bad = runCli(["skill", "--install", "--secure", "--cwd", badDir, "--format", "json"]);
    assert.equal(bad.status, 1);
    assert.equal(fs.existsSync(path.join(badDir, ".mcp.json")), false);
    assert.equal(fs.existsSync(path.join(badDir, ".claude", "skills", "prompt-redact", "SKILL.md")), false);
  } finally {
    fs.rmSync(badDir, { recursive: true, force: true });
  }
});

