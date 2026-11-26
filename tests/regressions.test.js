import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { createRequire } from "node:module";
import { PassThrough } from "node:stream";
import {
  PayloadDepthError,
  createSseRehydrationTransform,
  createVault,
  compileSecretRules,
  loadConfigFile,
  normalizeUpstreamBase,
  redactPayload,
  scanPath,
  startProxyServer,
  installSkill,
  startWebServer,
  validatePatternSafety,
  writeFileInsideRepository,
} from "../dist/index.js";
import { createLineReader, createServer } from "../dist/mcp.js";

const BIN = path.resolve("dist", "bin.js");
const requireCjs = createRequire(import.meta.url);

function tempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

async function callTool(server, name, args) {
  await server.handle({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2025-11-25" },
  });
  return await server.handle({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name, arguments: args },
  });
}

test("CJS bundles expose the same public API as ESM", () => {
  const cjs = requireCjs("../dist/index.cjs");
  assert.equal(typeof cjs.createVault, "function");
  assert.equal(typeof cjs.writeFileInsideRepository, "function");
  assert.equal(cjs.PACKAGE_VERSION, "0.1.0");
  const mcp = requireCjs("../dist/mcp.cjs");
  assert.equal(typeof mcp.createServer, "function");
  assert.equal(typeof mcp.createLineReader, "function");
});

test("overflow masks are opaque and unlinkable", () => {
  const vault = createVault({ maxEntries: 1 });
  vault.redact("sk-proj-fillSlot0000000000000000000000");
  const secret = "sk-proj-overflowSameSecret1234567890abcd";
  const first = vault.redact(`x ${secret}`).text;
  const second = vault.redact(`y ${secret}`).text;
  assert.match(first, /<<redact-masked:[a-f0-9]{12}>>/);
  assert.match(second, /<<redact-masked:[a-f0-9]{12}>>/);
  assert.notEqual(first, second, "masks must not be a deterministic oracle");
  assert.ok(!first.includes(secret));
  assert.ok(!second.includes(secret));
});

test("assignment prefilter never drops a canonical credential shape", () => {
  const samples = [
    "DB_PASSWORD=ShortButLongEnough99",
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "POSTMARK_API_TOKEN=123e4567-e89b-12d3-a456-426614174000",
    'password="SuperSecret12345"',
    '{\\"password\\":\\"SuperSecret12345\\"}',
    "password=SuperSecret12345",
  ];
  for (const sample of samples) {
    const vault = createVault();
    const result = vault.redact(sample);
    assert.ok(result.hits >= 1, `prefilter missed: ${sample}`);
    assert.ok(result.text.includes("<<redact:"), `no token for: ${sample}`);
  }
  // The prefilter is an optimization, not a detection boundary: a bare token
  // with no assignment must still be caught.
  const bare = createVault();
  assert.ok(bare.redact("sk-proj-bareSecret1234567890abcdef").hits >= 1);
});

test("validator rejects literal-separated and unicode property backtracking", () => {
  assert.throws(() => validatePatternSafety(/\w+a\w+a\w+a\w+a\w+$/, "sep"));
  assert.throws(() => validatePatternSafety(/.*a.*a.*a.*$/, "dots"));
  assert.throws(() => validatePatternSafety(new RegExp("\\p{L}+\\p{L}+$", "u"), "unicode"));
  assert.doesNotThrow(() => validatePatternSafety(/[0-9]+[A-Z]+/, "disjoint"));
  assert.doesNotThrow(() => validatePatternSafety(/[a-z]+-[a-z]+/, "dash"));
});

test("configuration rejects unknown top-level keys instead of silently ignoring them", () => {
  const dir = tempDir("pr-reg-cfg-");
  try {
    fs.writeFileSync(
      path.join(dir, "prompt-redact.config.json"),
      JSON.stringify({ customPatern: [] })
    );
    assert.throws(() => loadConfigFile(dir), /Unknown configuration key/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("deep payloads fail with PayloadDepthError before stack overflow", () => {
  let deep = { leaf: "sk-proj-deepSecret1234567890abcdef" };
  for (let i = 0; i < 6000; i += 1) deep = { nested: deep };
  assert.throws(() => redactPayload(deep), PayloadDepthError);
});

test("scanner decodes BOM-less UTF-16LE and strict mode fails on risky skips", () => {
  const dir = tempDir("pr-reg-utf16-");
  const bigDir = tempDir("pr-reg-big-");
  try {
    const secret = "sk-proj-utf16NoBomSecret1234567890abcd";
    fs.writeFileSync(
      path.join(dir, "nobom.env"),
      Buffer.from(`API_KEY=${secret}\n`, "utf16le")
    );
    const report = scanPath(dir, { noConfig: true });
    assert.equal(report.clean, false);
    assert.ok(report.findings.some((f) => f.file === "nobom.env"));

    fs.writeFileSync(
      path.join(bigDir, "big.env"),
      "x".repeat(8 * 1024 * 1024 + 32) + `\nKEY=${secret}\n`
    );
    const standard = scanPath(bigDir, { noConfig: true });
    assert.equal(standard.skipped.length, 1);
    assert.equal(standard.skipped[0].reason, "oversize");
    assert.equal(standard.clean, true);

    const strict = scanPath(bigDir, { noConfig: true, strict: true });
    assert.equal(strict.clean, false);
    assert.equal(strict.strict, true);

    // A binary-looking file can still contain ASCII credentials; strict mode
    // must not pretend it was cleared.
    const binaryDir = tempDir("pr-reg-bin-");
    try {
      fs.writeFileSync(
        path.join(binaryDir, "blob.bin"),
        Buffer.concat([Buffer.from([0x00, 0x01, 0x02]), Buffer.from("ghp_binaryHidden1234567890abcdefghij")])
      );
      const binaryStrict = scanPath(binaryDir, { noConfig: true, strict: true });
      assert.equal(binaryStrict.clean, false);
      assert.ok(binaryStrict.skipped.some((entry) => entry.reason === "binary"));
    } finally {
      fs.rmSync(binaryDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(bigDir, { recursive: true, force: true });
  }
});

test("scanner does not stop after a zero-length custom match", () => {
  const dir = tempDir("pr-reg-zero-");
  try {
    const secret = "sk-proj-afterZeroWidthMatch1234567890abcd";
    fs.writeFileSync(path.join(dir, "leak.txt"), `x ${secret}\n`);
    const report = scanPath(dir, {
      config: { customPatterns: [{ rule: "zero", pattern: "(?<=x)" }] },
    });
    assert.equal(report.clean, false);
    assert.ok(report.findings.some((f) => f.rule === "openai-anthropic-key"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("airlock_exec is disabled by default and requires a non-empty allowlist", async () => {
  const dir = tempDir("pr-reg-exec-");
  try {
    const disabled = createServer({ cwd: dir, log: () => undefined });
    const first = await callTool(disabled, "airlock_exec", {
      command: process.execPath,
      args: ["-e", "0"],
    });
    assert.equal(first.result.isError, true);
    assert.match(first.result.content[0].text, /disabled/);

    const empty = createServer({
      cwd: dir,
      config: { exec: { enabled: true, allowCommands: [] } },
      log: () => undefined,
    });
    const second = await callTool(empty, "airlock_exec", {
      command: process.execPath,
      args: ["-e", "0"],
    });
    assert.equal(second.result.isError, true);
    assert.match(second.result.content[0].text, /allowCommands is empty/);

    const denied = createServer({
      cwd: dir,
      config: { exec: { enabled: true, allowCommands: ["git"] } },
      log: () => undefined,
    });
    const third = await callTool(denied, "airlock_exec", {
      command: process.execPath,
      args: ["-e", "0"],
    });
    assert.equal(third.result.isError, true);
    assert.match(third.result.content[0].text, /not listed/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("redact_verify rejects both text and path; read_file line counts are exact", async () => {
  const dir = tempDir("pr-reg-read-");
  try {
    fs.writeFileSync(path.join(dir, "lines.txt"), "one\ntwo\n", "utf8");
    const server = createServer({ cwd: dir, log: () => undefined });
    const both = await callTool(server, "redact_verify", {
      text: "x",
      path: "lines.txt",
    });
    assert.equal(both.result.isError, true);
    const read = await callTool(server, "airlock_read_file", { path: "lines.txt" });
    assert.equal(read.result.structuredContent.totalLines, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("verify ignores repo-local allowlists; scan reports honestly", () => {
  const dir = tempDir("pr-reg-gate-");
  try {
    const secret = "sk-proj-gateBypassSecret1234567890abcd";
    fs.writeFileSync(path.join(dir, "leak.ts"), `export const k = "${secret}";\n`);
    fs.writeFileSync(
      path.join(dir, "prompt-redact.config.json"),
      JSON.stringify({ allowlist: [{ pattern: ".+" }] })
    );
    const verify = spawnSync(process.execPath, [BIN, "verify", "--cwd", dir, "--format", "json"], {
      encoding: "utf8",
      windowsHide: true,
    });
    assert.equal(verify.status, 1);
    const scan = spawnSync(process.execPath, [BIN, "scan", "--cwd", dir, "--format", "json"], {
      encoding: "utf8",
      windowsHide: true,
    });
    assert.equal(scan.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("verify --hook exits 2 on findings and 0 when clean", () => {
  const dir = tempDir("pr-reg-hook-");
  try {
    const dirty = spawnSync(process.execPath, [BIN, "verify", "--hook", "--cwd", dir], {
      input: JSON.stringify({ prompt: "use password=MyProdPassword1234 now" }),
      encoding: "utf8",
      windowsHide: true,
    });
    assert.equal(dirty.status, 2);
    assert.ok(!dirty.stderr.includes("MyProdPassword1234"));
    const clean = spawnSync(process.execPath, [BIN, "verify", "--hook", "--cwd", dir], {
      input: JSON.stringify({ prompt: "ordinary prompt" }),
      encoding: "utf8",
      windowsHide: true,
    });
    assert.equal(clean.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("SSE forwards id/retry and leaves untouched JSON byte-identical", async () => {
  const vault = createVault({ salt: "aabbccdd" });
  vault.redact("sk-proj-seedSecretValue1234567890abcd");
  const frames = [
    'id: 7\nretry: 1000\ndata: {"a":1,"a":2,"b":"plain"}\n\n',
    "data: [DONE]\n\n",
  ];
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      for (const frame of frames) controller.enqueue(encoder.encode(frame));
      controller.close();
    },
  }).pipeThrough(createSseRehydrationTransform(vault, "openai"));
  const output = await new Response(stream).text();
  assert.ok(output.includes("id: 7"));
  assert.ok(output.includes("retry: 1000"));
  assert.ok(output.includes('"a":1,"a":2'));
});

test("proxy preserves non-UTF-8 bodies that lack a text content type", async () => {
  const bytes = Buffer.from([0x80, 0x81, 0x82, 0xfe, 0x90, 0x91]);
  const upstream = http.createServer((_req, res) => {
    res.writeHead(200);
    res.end(bytes);
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const proxy = await startProxyServer({
    port: 0,
    openaiUpstream: `http://127.0.0.1:${upstream.address().port}`,
    log: () => undefined,
  });
  try {
    await fetch(`${proxy.url}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: "sk-proj-seedBinary1234567890abcdef" }] }),
    }).then((res) => res.arrayBuffer());
    const response = await fetch(`${proxy.url}/v1/other`);
    const out = Buffer.from(await response.arrayBuffer());
    assert.ok(out.equals(bytes));
  } finally {
    await proxy.close();
    upstream.closeAllConnections();
    await new Promise((resolve) => upstream.close(resolve));
  }
});

test("error messages never echo upstream URLs or regex sources", () => {
  const urlError = (() => {
    try {
      normalizeUpstreamBase("http://user:topsecret@[::1", "upstream");
    } catch (err) {
      return err.message;
    }
    return "";
  })();
  assert.ok(urlError.length > 0);
  assert.ok(!urlError.includes("topsecret"));
  assert.ok(!urlError.includes("user"));

  const regexError = (() => {
    try {
      compileSecretRules([{ rule: "bad", pattern: "(sk-proj-regexLeak1234567890abcdef" }]);
    } catch (err) {
      return err.message;
    }
    return "";
  })();
  assert.ok(regexError.length > 0);
  assert.ok(!regexError.includes("regexLeak"));
  assert.ok(!regexError.includes("sk-proj"));
});

test("web inspector refuses plaintext-revealing endpoints without a token", async () => {
  const dir = tempDir("pr-reg-web-");
  const web = await startWebServer({ cwd: dir, port: 0, token: null, log: () => undefined });
  try {
    const rehydrate = await fetch(`${web.url}api/rehydrate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: "x" }),
    });
    assert.equal(rehydrate.status, 403);
    const sse = await fetch(`${web.url}api/sse-simulate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: "sk-proj-webSseSecret1234567890abcdef" }),
    });
    assert.equal(sse.status, 403);
  } finally {
    await web.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("confined writes are atomic, stay inside the root, and leave no temp files", () => {
  const dir = tempDir("pr-reg-atomic-");
  try {
    const target = path.join(dir, "out", "config.json");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    writeFileInsideRepository(dir, target, "first");
    assert.equal(fs.readFileSync(target, "utf8"), "first");
    writeFileInsideRepository(dir, target, "second");
    assert.equal(fs.readFileSync(target, "utf8"), "second");
    const leftovers = fs.readdirSync(path.dirname(target)).filter((name) => name.endsWith(".tmp"));
    assert.deepEqual(leftovers, []);
    assert.throws(() => writeFileInsideRepository(dir, path.join(dir, "..", "escape.txt"), "x"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("proxy does not forward browser credential headers upstream", async () => {
  const captured = [];
  const upstream = http.createServer((req, res) => {
    captured.push(req.headers);
    res.writeHead(200, { "content-type": "application/json" });
    res.end("{}");
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const proxy = await startProxyServer({
    port: 0,
    openaiUpstream: `http://127.0.0.1:${upstream.address().port}`,
    log: () => undefined,
  });
  try {
    await fetch(`${proxy.url}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: "session=super-secret-cookie",
        referer: "https://example.com/?token=secret",
      },
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal(captured[0].cookie, undefined);
    assert.equal(captured[0].referer, undefined);
  } finally {
    await proxy.close();
    upstream.closeAllConnections();
    await new Promise((resolve) => upstream.close(resolve));
  }
});

test("MCP audit labels and session vaults cannot be used to leak plaintext", async () => {
  const dir = tempDir("pr-reg-audit-");
  const captured = [];
  const upstream = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      captured.push(body);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ echo: body }));
    });
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const proxy = await startProxyServer({
    port: 0,
    openaiUpstream: `http://127.0.0.1:${upstream.address().port}`,
    log: () => undefined,
  });
  try {
    const server = createServer({ cwd: dir, log: () => undefined });
    await server.handle({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-11-25" },
    });
    const secretSource = "sk-proj-auditSourceSecret1234567890abcd";
    await server.handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "redact_text", arguments: { text: "hello", source: secretSource } },
    });
    const audit = await server.handle({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "redact_audit", arguments: {} },
    });
    assert.ok(!JSON.stringify(audit.result).includes(secretSource));

    const secret = "sk-proj-sessionIsolationSecret1234567890abcd";
    await fetch(`${proxy.url}/v1/echo`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-prompt-redact-session": "A" },
      body: JSON.stringify({ text: secret }),
    }).then((res) => res.text());
    const tokenA = (captured[0].match(/<<redact:[a-f0-9]+:\d+>>/) || [])[0];
    assert.ok(tokenA);
    const other = await fetch(`${proxy.url}/v1/echo`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-prompt-redact-session": "B" },
      body: JSON.stringify({ text: tokenA }),
    });
    const parsed = await other.json();
    assert.ok(!parsed.echo.includes(secret));
  } finally {
    await proxy.close();
    upstream.closeAllConnections();
    await new Promise((resolve) => upstream.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("SSE carry cap and tool input caps fail closed", async () => {
  const vault = createVault({ salt: "00112233445566778899aabbccddeeff" });
  const token = vault.redact("sk-proj-carryCapSecret1234567890abcdef").text;
  const frame =
    'data: {"choices":[{"index":0,"delta":{"content":"' +
    token.slice(0, 3) +
    '"}},{"index":1,"delta":{"content":"' +
    token.slice(0, 3) +
    '"}}]}\n\n';
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(frame));
      controller.close();
    },
  }).pipeThrough(createSseRehydrationTransform(vault, "openai", { maxCarries: 1 }));
  await assert.rejects(async () => {
    await new Response(stream).text();
  });

  const dir = tempDir("pr-reg-caps-");
  try {
    const server = createServer({ cwd: dir, log: () => undefined });
    await server.handle({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-11-25" },
    });
    const result = await server.handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "redact_text", arguments: { text: "a".repeat(4 * 1024 * 1024 + 1) } },
    });
    assert.equal(result.result.isError, true);
    assert.match(result.result.content[0].text, /exceeds 4 MiB/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("proxy returns 504 when upstream headers never arrive", async () => {
  const upstream = http.createServer((_req, res) => {
    const timer = setTimeout(() => {
      res.writeHead(200);
      res.end("{}");
    }, 3000);
    if (typeof timer.unref === "function") timer.unref();
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const proxy = await startProxyServer({
    port: 0,
    openaiUpstream: `http://127.0.0.1:${upstream.address().port}`,
    upstreamTimeoutMs: 120,
    log: () => undefined,
  });
  try {
    const response = await fetch(`${proxy.url}/v1/slow`);
    assert.equal(response.status, 504);
  } finally {
    await proxy.close();
    upstream.closeAllConnections();
    await new Promise((resolve) => upstream.close(resolve));
  }
});

test("skill installer writes Cursor frontmatter and updates atomically", () => {
  const dir = tempDir("pr-reg-skill-");
  try {
    const first = installSkill(dir);
    assert.ok(first.gitignored.length >= 2);
    const cursor = path.join(dir, ".cursor", "rules", "prompt-redact.mdc");
    const cursorText = fs.readFileSync(cursor, "utf8");
    assert.match(cursorText, /globs:/);
    assert.match(cursorText, /alwaysApply: true/);
    assert.match(cursorText, /verify --hook/);
    fs.writeFileSync(cursor, "stale", "utf8");
    const second = installSkill(dir);
    const updated = second.written.find((entry) => entry.target === "cursor");
    assert.equal(updated.action, "updated");
    assert.ok(!fs.readdirSync(path.dirname(cursor)).some((name) => name.endsWith(".tmp")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("stdio line reader handles a large single line without quadratic cost", async () => {
  const total = 4 * 1024 * 1024;
  const input = new PassThrough();
  const lines = [];
  const stop = createLineReader(input, { onLine: (line) => lines.push(line) });
  const started = performance.now();
  await new Promise((resolve) => {
    const chunks = Math.ceil(total / (64 * 1024));
    const chunk = "a".repeat(64 * 1024);
    let written = 0;
    const pump = () => {
      while (written < chunks) {
        written += 1;
        if (!input.write(written === chunks ? chunk + "\n" : chunk)) {
          input.once("drain", pump);
          return;
        }
      }
      input.end();
    };
    input.on("end", resolve);
    pump();
  });
  stop();
  const elapsed = performance.now() - started;
  assert.equal(lines.length, 1);
  assert.equal(lines[0].length, total);
  assert.ok(elapsed < 2000, `line reader took ${elapsed.toFixed(1)}ms`);
});
