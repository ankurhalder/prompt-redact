import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import {
  PEM_UNTERMINATED_PATTERN,
  PayloadDepthError,
  VaultCapacityError,
  assertWritableInsideRepository,
  buildAgentContract,
  compileAllowlist,
  compileSecretRules,
  createSseRehydrationTransform,
  createVault,
  installSkill,
  isPlaceholderValue,
  redactPayload,
  rehydratePayload,
  resolveUpstreamTarget,
  runSetup,
  scanPath,
  scanTextForFindings,
  startProxyServer,
  startWebServer,
  validatePatternSafety,
} from "../dist/index.js";
import { createServer, startHttpTransport } from "../dist/mcp.js";

test("Finding 1: embedded token substrings never bypass redaction or scanning", () => {
  assert.equal(isPlaceholderValue("<<redact:deadbeef:1>>"), true);
  assert.equal(isPlaceholderValue("<<redact:x:1>>ProdSecretPass99!"), false);

  const vault = createVault({ salt: "deadbeef" });
  const embeddedPass = 'password="<<redact:deadbeef:1>>ProdSecretPass99!"';
  const res = vault.redact(embeddedPass);
  assert.equal(res.hits, 1);
  assert.ok(!res.text.includes("ProdSecretPass99!"));
  assert.equal(vault.rehydrate(res.text), embeddedPass);

  const pemWithComment =
    "-----BEGIN RSA PRIVATE KEY-----\nComment: <<redact:x:1>>\nMIIEowIBAAKCAQEA123456\n-----END RSA PRIVATE KEY-----";
  const pemRes = vault.redact(pemWithComment);
  assert.equal(pemRes.hits, 1);
  assert.ok(!pemRes.text.includes("MIIEowIBAAKCAQEA123456"));

  const scanFindings = scanTextForFindings(embeddedPass, "test.env");
  assert.equal(scanFindings.length, 1);
});

test("Finding 2: partial-overlap spans coalesce instead of leaking secret tails", () => {
  const input =
    "secret=AAAeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0xIn0%2EeyJzdWIiOiIxMjM0NTY3ODkwIn0%2ESflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV";
  const vault = createVault();
  const res = vault.redact(input);
  assert.ok(!res.text.includes("%2EeyJ"));
  assert.ok(!res.text.includes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"));
  assert.equal(vault.rehydrate(res.text), input);

  const findings = scanTextForFindings(input, "overlap.txt");
  assert.equal(findings.length, 1);
});

test("Finding 3: proxy handles non-JSON/query/binary/compressed/Anthropic routing and strips proxy token", async () => {
  const captured = { anthropic: [], openai: [] };
  const makeServer = (bucket) =>
    http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        bucket.push({ url: req.url, headers: req.headers, body: Buffer.concat(chunks) });
        if (req.url?.includes("/binary")) {
          res.writeHead(200, { "content-type": "application/octet-stream" });
          res.end(Buffer.from([0x00, 0x01, 0x02, 0xff]));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      });
    });

  const ant = makeServer(captured.anthropic);
  const oai = makeServer(captured.openai);
  await new Promise((r) => ant.listen(0, "127.0.0.1", r));
  await new Promise((r) => oai.listen(0, "127.0.0.1", r));
  const antUrl = `http://127.0.0.1:${ant.address().port}`;
  const oaiUrl = `http://127.0.0.1:${oai.address().port}`;

  const proxy = await startProxyServer({
    port: 0,
    token: "proxy-secret-token",
    anthropicUpstream: antUrl,
    openaiUpstream: oaiUrl,
  });

  try {
    const secret = "sk-proj-queryAndTextSecret1234567890abcd";
    const textRes = await fetch(`${proxy.url}/v1/chat/completions?api_key=${secret}`, {
      method: "POST",
      headers: {
        "content-type": "text/plain",
        "x-prompt-redact-token": "proxy-secret-token",
        authorization: "Bearer upstream-key-kept",
      },
      body: `plain body ${secret}`,
    });
    assert.equal(textRes.status, 200);
    assert.equal(captured.openai.length, 1);
    assert.ok(!captured.openai[0].url.includes(secret));
    assert.ok(!captured.openai[0].body.toString("utf8").includes(secret));
    assert.equal(captured.openai[0].headers["x-prompt-redact-token"], undefined);
    assert.equal(captured.openai[0].headers.authorization, "Bearer upstream-key-kept");

    const antModelsRes = await fetch(`${proxy.url}/v1/models`, {
      method: "GET",
      headers: {
        authorization: "Bearer proxy-secret-token",
        "anthropic-version": "2023-06-01",
        "x-api-key": "sk-ant-api03-secretHeaderKey1234567890",
      },
    });
    assert.equal(antModelsRes.status, 200);
    assert.equal(captured.anthropic.length, 1);
    assert.equal(captured.anthropic[0].headers.authorization, undefined);

    const gzipRes = await fetch(`${proxy.url}/v1/chat/completions`, {
      method: "POST",
      headers: {
        authorization: "Bearer proxy-secret-token",
        "content-encoding": "gzip",
        "content-type": "application/json",
      },
      body: "compressed",
    });
    assert.equal(gzipRes.status, 415);

    const binUp = await fetch(`${proxy.url}/v1/files`, {
      method: "POST",
      headers: {
        authorization: "Bearer proxy-secret-token",
        "content-type": "application/octet-stream",
      },
      body: new Uint8Array([0x00, 0x61, 0x62]),
    });
    assert.equal(binUp.status, 415);

    const binDown = await fetch(`${proxy.url}/v1/binary`, {
      method: "GET",
      headers: { authorization: "Bearer proxy-secret-token" },
    });
    assert.equal(binDown.status, 200);
    assert.deepEqual(new Uint8Array(await binDown.arrayBuffer()), new Uint8Array([0x00, 0x01, 0x02, 0xff]));
  } finally {
    await proxy.close();
    ant.closeAllConnections();
    oai.closeAllConnections();
    await new Promise((r) => ant.close(r));
    await new Promise((r) => oai.close(r));
  }
});

test("Finding 4: redactPayload handles top-level strings, object keys, and fails closed past depth 64", () => {
  const secret = "sk-proj-topLevelAndKeySecret1234567890";
  const top = redactPayload(secret);
  assert.equal(top.redactedCount, 1);
  assert.ok(!String(top.payload).includes(secret));
  assert.equal(rehydratePayload(top.payload, top.vault), secret);

  const keyRes = redactPayload({ [secret]: "ok" }, top.vault);
  assert.equal(keyRes.redactedCount, 1);
  assert.ok(!JSON.stringify(keyRes.payload).includes(secret));
  assert.equal(Object.keys(rehydratePayload(keyRes.payload, top.vault))[0], secret);

  let deep = { leaf: secret };
  for (let i = 0; i < 70; i += 1) deep = { nested: deep };
  assert.throws(() => redactPayload(deep), PayloadDepthError);
});

test("Finding 5 & 7: serve isolates playground vault from MCP vault and honors project config", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-serve-iso-"));
  const customSecret = "ACME_998877665544";
  fs.writeFileSync(
    path.join(dir, "prompt-redact.config.json"),
    JSON.stringify({ customPatterns: [{ rule: "acme-key", pattern: "ACME_\\d{12}" }] }),
    "utf8"
  );
  fs.writeFileSync(path.join(dir, "secret.txt"), `token=${customSecret}\n`, "utf8");

  const web = await startWebServer({ cwd: dir, port: 0, log: () => undefined });
  const client = new Client({ name: "iso-client", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(`${web.url}mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${web.token}` } },
  });

  try {
    await client.connect(transport);
    const readRes = await client.callTool({ name: "airlock_read_file", arguments: { path: "secret.txt" } });
    const mcpTokenText = readRes.content[0].text;
    assert.ok(!mcpTokenText.includes(customSecret));
    assert.match(mcpTokenText, /<<redact:[a-f0-9]+:1>>/);

    const verifyRes = await client.callTool({ name: "redact_verify", arguments: { path: "secret.txt" } });
    assert.equal(JSON.parse(verifyRes.content[0].text).clean, false);

    const leakAttempt = await fetch(`${web.url}api/rehydrate`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${web.token}` },
      body: JSON.stringify({ text: mcpTokenText }),
    });
    const leaked = (await leakAttempt.json()).text;
    assert.ok(!leaked.includes(customSecret), "playground /api/rehydrate must not unmask MCP vault tokens");
  } finally {
    await client.close();
    await web.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Finding 6: SSE handles terminal split, JSON-escaped tool args, and trailing < in secrets", async () => {
  const pemSecret = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
  const ltSecret = "sk-proj-secretEndingWithLt<";
  const vault = createVault({
    salt: "feedface",
    rules: [{ rule: "lt-secret", pattern: /sk-proj-secretEndingWithLt</ }],
  });
  const pemTok = vault.redact(pemSecret).text;
  const ltTok = vault.redact(ltSecret).text;
  const half = Math.floor(ltTok.length / 2);

  const sseFrames = [
    `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: ltTok.slice(0, half) } }] })}\n\n`,
    `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: ltTok.slice(half) }, finish_reason: "stop" }] })}\n\n`,
    `data: ${JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: `{"pem":"${pemTok.slice(0, 8)}` } }] } }] })}\n\n`,
    `data: ${JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: `${pemTok.slice(8)}"}` } }] }, finish_reason: "tool_calls" }] })}\n\n`,
    "data: [DONE]\n\n",
  ];

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(c) {
      for (const f of sseFrames) c.enqueue(encoder.encode(f));
      c.close();
    },
  }).pipeThrough(createSseRehydrationTransform(vault, "openai"));

  const output = await new Response(stream).text();
  const frames = output
    .split("\n\n")
    .filter((b) => b.startsWith("data: {"))
    .map((b) => JSON.parse(b.slice(6)));

  const content = frames.map((f) => f.choices?.[0]?.delta?.content ?? "").join("");
  assert.equal(content, ltSecret);

  const argJson = frames
    .map((f) => f.choices?.[0]?.delta?.tool_calls?.[0]?.function?.arguments ?? "")
    .join("");
  assert.equal(JSON.parse(argJson).pem, pemSecret);
});

test("Finding 8: staged scan reads git index (not working tree) and decodes UTF-16LE files", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-git-"));
  const sub = path.join(dir, "packages", "app");
  fs.mkdirSync(sub, { recursive: true });
  try {
    spawnSync("git", ["init"], { cwd: dir, windowsHide: true });
    spawnSync("git", ["config", "user.email", "test@example.com"], { cwd: dir, windowsHide: true });
    spawnSync("git", ["config", "user.name", "Test"], { cwd: dir, windowsHide: true });

    const stagedSecret = "ghp_stagedIndexSecret1234567890abcdefghij";
    const envPath = path.join(sub, ".env");
    fs.writeFileSync(envPath, `GH_TOKEN=${stagedSecret}\n`, "utf8");
    spawnSync("git", ["add", "packages/app/.env"], { cwd: dir, windowsHide: true });

    fs.writeFileSync(envPath, "GH_TOKEN=clean\n", "utf8");

    const stagedReport = scanPath(sub, { staged: true, noConfig: true });
    assert.equal(stagedReport.clean, false);
    assert.equal(stagedReport.findings.length, 1);

    const utf16File = path.join(dir, "utf16.env");
    const utf16Content = Buffer.concat([
      Buffer.from([0xff, 0xfe]),
      Buffer.from(`API_KEY=sk-proj-utf16SecretValue1234567890abcd\n`, "utf16le"),
    ]);
    fs.writeFileSync(utf16File, utf16Content);
    const utf16Report = scanPath(dir, { targetPath: "utf16.env", noConfig: true });
    assert.equal(utf16Report.clean, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Finding 9: airlock_exec fails closed on overflow, isolates env, and scrubs longest secret first", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-exec-hard-"));
  const prevSecretEnv = process.env.AMBIENT_HOST_SECRET;
  process.env.AMBIENT_HOST_SECRET = "should-not-leak-to-airlock-exec";
  try {
    const vault = createVault({ maxEntries: 2, overflowPolicy: "error" });
    const shortSecret = "sk-proj-shortSecret1234567890abcdef";
    const longSecret = `${shortSecret}-extraSuffix99`;
    const r1 = vault.redact(shortSecret);
    const r2 = vault.redact(longSecret);
    assert.equal(r1.hits, 1);
    assert.equal(r2.hits, 1);

    const server = createServer({
      cwd: dir,
      vault,
      config: { exec: { enabled: true, allowCommands: [process.execPath] } },
      log: () => undefined,
    });
    await server.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } });

    const execLong = await server.handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "airlock_exec",
        arguments: {
          command: process.execPath,
          args: ["-e", `console.log(${JSON.stringify(longSecret)} + " " + String(process.env.AMBIENT_HOST_SECRET || "none"))`],
        },
      },
    });
    const parsedLong = JSON.parse(execLong.result.content[0].text);
    assert.ok(!parsedLong.stdout.includes(shortSecret));
    assert.ok(!parsedLong.stdout.includes("-extraSuffix99"));
    assert.ok(parsedLong.stdout.includes("none"));

    const execOverflow = await server.handle({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "airlock_exec",
        arguments: {
          command: process.execPath,
          args: ["-e", `console.log("ghp_thirdSecretOverflow1234567890abcdef")`],
        },
      },
    });
    assert.equal(execOverflow.result.isError, true);
    assert.ok(!execOverflow.result.content[0].text.includes("ghp_thirdSecretOverflow"));
  } finally {
    if (prevSecretEnv === undefined) delete process.env.AMBIENT_HOST_SECRET;
    else process.env.AMBIENT_HOST_SECRET = prevSecretEnv;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Finding 11 & 12: atomic vault error, opaque overflow masks, allowlist ReDoS check, JSON-escaped secret, and dangling symlink check", () => {
  const atomicVault = createVault({ maxEntries: 1, overflowPolicy: "error" });
  assert.throws(
    () => atomicVault.redact("sk-proj-firstSecret1234567890abcd sk-proj-secondSecret1234567890abcd"),
    VaultCapacityError
  );
  assert.equal(atomicVault.size, 0);

  const vA = createVault({ maxEntries: 1, overflowPolicy: "hash", salt: "salt1111" });
  const vB = createVault({ maxEntries: 1, overflowPolicy: "hash", salt: "salt2222" });
  vA.redact("sk-proj-fillSlotOne1234567890abcd");
  vB.redact("sk-proj-fillSlotOne1234567890abcd");
  const hA = vA.redact("sk-proj-overflowSecret1234567890abcd").text;
  const hB = vB.redact("sk-proj-overflowSecret1234567890abcd").text;
  assert.notEqual(hA, hB);
  assert.match(hA, /<<redact-masked:[a-f0-9]{12}>>/);
  // A second occurrence in the same overflow vault must not reproduce the
  // same mask: masks are random, not a deterministic oracle for the secret.
  assert.notEqual(hA, vA.redact("sk-proj-overflowSecret1234567890abcd").text);

  assert.throws(() => compileAllowlist([{ pattern: "(a+)+" }]));
  assert.throws(() => validatePatternSafety(/((a)+)+$/, "nested"));
  assert.throws(() => validatePatternSafety(/(a+){2,}$/, "bounded"));
  assert.throws(() => validatePatternSafety(/(a|aa)+$/, "alt"));
  const pathAllow = compileAllowlist(["/api/v1/i", "/usr/local/bin"]);
  assert.equal(pathAllow.patterns.length, 0);
  assert.equal(pathAllow.exact.has("/api/v1/i"), true);
  assert.equal(pathAllow.exact.has("/usr/local/bin"), true);

  const escVault = createVault();
  const escapedLog = '\\"password\\":\\"SuperSecret123!\\"';
  const escRes = escVault.redact(escapedLog);
  assert.equal(escRes.hits, 1);
  assert.ok(!escRes.text.includes("SuperSecret123!"));

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-dangling-"));
  try {
    const linkPath = path.join(dir, ".claude");
    let createdLink = false;
    try {
      fs.symlinkSync(path.join(os.tmpdir(), "nonexistent-outside-target"), linkPath);
      createdLink = true;
    } catch {
      createdLink = false;
    }
    if (createdLink) {
      assert.throws(() => installSkill(dir, "claude"));
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Finding 12: HTTP transport honors config via startHttpTransport without prebuilt vault", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-http-cfg-"));
  fs.writeFileSync(
    path.join(dir, "prompt-redact.config.json"),
    JSON.stringify({ customPatterns: [{ rule: "corp", pattern: "CORP_[0-9]{10}" }] }),
    "utf8"
  );
  const transportServer = await startHttpTransport({ cwd: dir, port: 0, log: () => undefined });
  const client = new Client({ name: "cfg-client", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(`${transportServer.url}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${transportServer.token}` } },
  });
  try {
    await client.connect(transport);
    const res = await client.callTool({
      name: "redact_text",
      arguments: { text: "token=CORP_1234567890" },
    });
    assert.ok(!res.content[0].text.includes("CORP_1234567890"));
  } finally {
    await client.close();
    await transportServer.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Pass 2 #1: credential-assignment-quoted has linear runtime and unquoted catches multiline YAML & prose", () => {
  const vault = createVault();
  const payloads = [
    `password="${"\\'a".repeat(40)}\n`,
    `password='${'\\"a'.repeat(40)}\n`,
    `password=\`${"\\'a".repeat(40)}\n`,
  ];
  for (const p of payloads) {
    const t0 = performance.now();
    const res = vault.redact(p);
    const ms = performance.now() - t0;
    assert.equal(res.hits, 0);
    assert.ok(ms < 50, `ReDoS regression: ${ms.toFixed(1)}ms`);
  }

  const yamlInput = "password: MyProdPassword1234\nusername: admin";
  const yamlRes = vault.redact(yamlInput);
  assert.equal(yamlRes.hits, 1);
  assert.ok(!yamlRes.text.includes("MyProdPassword1234"));
  assert.equal(vault.rehydrate(yamlRes.text), yamlInput);

  const proseInput = "Connect using password=MyProdPassword1234 to staging";
  const proseRes = vault.redact(proseInput);
  assert.equal(proseRes.hits, 1);
  assert.ok(!proseRes.text.includes("MyProdPassword1234"));
  assert.equal(vault.rehydrate(proseRes.text), proseInput);
});

test("Pass 2 #3 & #10 & Pass 1 #3: MCP confine decodes UTF-16, rejects binary, and payload avoids double-rehydration & __proto__ mutation", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-utf16-mcp-"));
  try {
    const secret = "sk-proj-utf16McpSecretValue1234567890abcd";
    fs.writeFileSync(
      path.join(dir, "utf16.env"),
      Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`API_KEY=${secret}\n`, "utf16le")])
    );
    fs.writeFileSync(path.join(dir, "bin.dat"), Buffer.from([0x01, 0x02, 0x00, 0x03]));

    const server = createServer({ cwd: dir, log: () => undefined });
    await server.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } });

    const readUtf16 = await server.handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "airlock_read_file", arguments: { path: "utf16.env" } },
    });
    assert.ok(!readUtf16.result.isError);
    assert.ok(!readUtf16.result.content[0].text.includes(secret));
    assert.match(readUtf16.result.content[0].text, /<<redact:/);

    const verifyUtf16 = await server.handle({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "redact_verify", arguments: { path: "utf16.env" } },
    });
    assert.equal(JSON.parse(verifyUtf16.result.content[0].text).clean, false);

    const readBin = await server.handle({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "airlock_read_file", arguments: { path: "bin.dat" } },
    });
    assert.equal(readBin.result.isError, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  const vault = createVault({ salt: "deadbeef" });
  const tok1 = vault.redact("sk-proj-firstSecretValue1234567890abcd").text;
  for (let i = 2; i <= 9; i += 1) {
    vault.redact(`sk-proj-fillerSecret${i}Value1234567890ab`);
  }
  const tok10 = vault.redact(`password="${tok1}Extra"`).text.match(/<<redact:deadbeef:10>>/)?.[0];
  assert.ok(tok10);
  const rehydrated = rehydratePayload(
    { choices: [{ message: { tool_calls: [{ function: { arguments: JSON.stringify({ val: tok10 }) } }] } }] },
    vault
  );
  assert.equal(
    JSON.parse(rehydrated.choices[0].message.tool_calls[0].function.arguments).val,
    `${tok1}Extra`
  );

  const protoPayload = JSON.parse('{"__proto__":{"a":"sk-proj-protoSecretValue1234567890abcd"}}');
  const protoRed = redactPayload(protoPayload);
  assert.equal(protoRed.redactedCount, 1);
  assert.ok(Object.prototype.hasOwnProperty.call(protoRed.payload, "__proto__"));

  const undefRes = redactPayload(undefined);
  assert.equal(undefRes.payload, undefined);
  assert.equal(undefRes.redactedCount, 0);
});

test("Pass 2 #6 & #7 & #9: atomic redactPayload, Responses API escaping, proxy path redaction, and exact overflowCount", async () => {
  const atomicVault = createVault({ maxEntries: 2, overflowPolicy: "error" });
  assert.throws(
    () =>
      redactPayload(
        {
          messages: [
            { role: "user", content: "a=sk-proj-atomicOne1234567890abcdef b=sk-proj-atomicTwo1234567890abcdef" },
            { role: "user", content: "c=sk-proj-atomicThree1234567890abcd" },
          ],
        },
        atomicVault
      ),
    VaultCapacityError
  );
  assert.equal(atomicVault.size, 0);

  const ovVault = createVault({ maxEntries: 2, overflowPolicy: "hash" });
  const ovRes = ovVault.redact(
    "sk-proj-keyOne1234567890abcdef sk-proj-keyTwo1234567890abcdef sk-proj-keyThree1234567890abcd"
  );
  assert.equal(ovRes.overflows, 1);
  assert.equal(ovVault.audit().overflowCount, 1);

  const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIB\n-----END RSA PRIVATE KEY-----";
  const respVault = createVault({ salt: "12345678" });
  const pemTok = respVault.redact(pem).text;
  const restoredResp = rehydratePayload(
    { output: [{ type: "function_call", name: "deploy", arguments: `{"pem":"${pemTok}"}` }] },
    respVault
  );
  assert.equal(JSON.parse(restoredResp.output[0].arguments).pem, pem);

  const sseStream = new ReadableStream({
    start(c) {
      const enc = new TextEncoder();
      const half = Math.floor(pemTok.length / 2);
      c.enqueue(enc.encode(`data: ${JSON.stringify({ type: "response.function_call_arguments.delta", delta: `{"pem":"${pemTok.slice(0, half)}` })}\n\n`));
      c.enqueue(enc.encode(`data: ${JSON.stringify({ type: "response.function_call_arguments.delta", delta: `${pemTok.slice(half)}"}` })}\n\n`));
      c.enqueue(enc.encode(`data: ${JSON.stringify({ type: "response.output_text.delta", delta: "hi <<redact:1234" })}\n\n`));
      c.enqueue(enc.encode(`data: ${JSON.stringify({ type: "response.completed" })}\n\n`));
      c.close();
    },
  }).pipeThrough(createSseRehydrationTransform(respVault, "openai"));
  const sseOut = await new Response(sseStream).text();
  const events = sseOut
    .split("\n\n")
    .filter((b) => b.startsWith("data: {"))
    .map((b) => JSON.parse(b.slice(6)));
  const argsStr = events
    .filter((e) => e.type === "response.function_call_arguments.delta")
    .map((e) => e.delta)
    .join("");
  assert.equal(JSON.parse(argsStr).pem, pem);
  const completedIdx = events.findIndex((e) => e.type === "response.completed");
  const deltaIdx = events.findIndex((e) => e.type === "response.output_text.delta" && e.delta.includes("<<redact:1234"));
  assert.ok(deltaIdx >= 0 && deltaIdx < completedIdx);
});

test("Pass 2 #3 & #4 & #5 & #8 & Pass 1 #8: multi-choice SSE, HTTP discover, DELETE /mcp, pre-init notification, and symlink setup refusal", async () => {
  const vault = createVault({ salt: "99887766" });
  const sec = "sk-proj-multiChoiceSecret1234567890abcd";
  const tok = vault.redact(sec).text;
  const split = 10;
  const multiStream = new ReadableStream({
    start(c) {
      const enc = new TextEncoder();
      c.enqueue(enc.encode(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: `c0 ${tok.slice(0, split)}` } }] })}\n\n`));
      c.enqueue(enc.encode(`data: ${JSON.stringify({ choices: [{ index: 1, delta: { content: "c1 clean" } }] })}\n\n`));
      c.enqueue(enc.encode(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: `${tok.slice(split)} end` } }] })}\n\n`));
      c.enqueue(enc.encode("data: [DONE]\n\n"));
      c.close();
    },
  }).pipeThrough(createSseRehydrationTransform(vault, "openai"));
  const multiOut = await new Response(multiStream).text();
  const parsed = multiOut
    .split("\n\n")
    .filter((b) => b.startsWith("data: {"))
    .map((b) => JSON.parse(b.slice(6)));
  const c0 = parsed.filter((f) => f.choices?.[0]?.index === 0).map((f) => f.choices[0].delta.content ?? "").join("");
  const c1 = parsed.filter((f) => f.choices?.[0]?.index === 1).map((f) => f.choices[0].delta.content ?? "").join("");
  assert.equal(c0, `c0 ${sec} end`);
  assert.equal(c1, "c1 clean");

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-mcp-state-"));
  const transportServer = await startHttpTransport({ cwd: dir, port: 0, log: () => undefined });
  try {
    const discRes = await fetch(`${transportServer.url}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${transportServer.token}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "server/discover" }),
    });
    assert.equal(discRes.status, 200);
    assert.ok(Array.isArray((await discRes.json()).result.supportedVersions));

    const initRes = await fetch(`${transportServer.url}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${transportServer.token}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "2025-11-25" } }),
    });
    const sid = initRes.headers.get("mcp-session-id");
    assert.ok(sid);

    const delRes = await fetch(`${transportServer.url}/mcp`, {
      method: "DELETE",
      headers: {
        authorization: `Bearer ${transportServer.token}`,
        "mcp-session-id": sid,
      },
    });
    assert.equal(delRes.status, 204);

    const afterDel = await fetch(`${transportServer.url}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${transportServer.token}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/list" }),
    });
    const afterJson = await afterDel.json();
    assert.equal(afterJson.error.code, -32600);
  } finally {
    await transportServer.close();
  }

  const eraServer = createServer({ cwd: dir, log: () => undefined });
  await eraServer.handle({ jsonrpc: "2.0", method: "notifications/initialized" });
  const modList = await eraServer.handle({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
    params: {
      _meta: {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
      },
    },
  });
  assert.ok(Array.isArray(modList.result.tools));

  const targetOutside = path.join(os.tmpdir(), `pr-symlink-target-${Date.now()}.txt`);
  fs.writeFileSync(targetOutside, "untouched", "utf8");
  let linkCreated = false;
  try {
    fs.symlinkSync(targetOutside, path.join(dir, "prompt-redact.config.json"));
    linkCreated = true;
  } catch {
    linkCreated = false;
  }
  try {
    if (linkCreated) {
      assert.throws(() => runSetup(dir, { force: true }));
      assert.equal(fs.readFileSync(targetOutside, "utf8"), "untouched");
    }
  } finally {
    fs.rmSync(targetOutside, { force: true });
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Audit 3 #1: airlock_exec refuses NUL bytes in command, args, and env without leaking vault secrets", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-nul-"));
  try {
    const vault = createVault({ salt: "feedface" });
    const secret = "sk-proj-nulByteVaultSecret1234567890abcd";
    const tok = vault.redact(secret).text;
    const server = createServer({
      cwd: dir,
      vault,
      config: { exec: { enabled: true, allowCommands: [process.execPath] } },
      log: () => undefined,
    });
    await server.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } });

    const argRes = await server.handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "airlock_exec", arguments: { command: process.execPath, args: [`\u0000${tok}`] } },
    });
    assert.equal(argRes.result.isError, true);
    assert.ok(!argRes.result.content[0].text.includes(secret));

    const envRes = await server.handle({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "airlock_exec",
        arguments: { command: process.execPath, args: ["-e", "0"], env: { SECRET_VAL: `\u0000${tok}` } },
      },
    });
    assert.equal(envRes.result.isError, true);
    assert.ok(!envRes.result.content[0].text.includes(secret));

    const cmdRes = await server.handle({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "airlock_exec", arguments: { command: `node\u0000${tok}` } },
    });
    assert.equal(cmdRes.result.isError, true);
    assert.ok(!cmdRes.result.content[0].text.includes(secret));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Audit 3 #2 & #3 & Audit 2 #1 #2 #3 #5 #6: structured context, SSE isolation, generic keys, and ReDoS bounds", async () => {
  const ctxVault = createVault({ salt: "cafe1234" });
  const inputPayload = {
    type: "tool_use",
    name: "connect_db",
    input: {
      password: "MyProdPassword1234",
      aws_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      db_key: "DbSecretKeyValue1234",
      signing_credential: "SignCredSecret1234",
      api_key_prod: "ProdApiKeySecret1234",
      id_token: "publicClaimTokenValue123",
      primary_key: "user_id_column_name",
      role: "admin",
    },
  };
  const ctxRed = redactPayload(inputPayload, ctxVault);
  assert.equal(ctxRed.redactedCount, 5);
  assert.equal(ctxRed.payload.input.id_token, "publicClaimTokenValue123");
  assert.equal(ctxRed.payload.input.primary_key, "user_id_column_name");
  assert.equal(ctxRed.payload.input.role, "admin");
  assert.ok(!JSON.stringify(ctxRed.payload).includes("MyProdPassword1234"));
  assert.ok(!JSON.stringify(ctxRed.payload).includes("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
  assert.deepEqual(rehydratePayload(ctxRed.payload, ctxVault), inputPayload);

  const qVault = createVault({ salt: "11223344" });
  const qResolved = resolveUpstreamTarget(
    "/v1/chat/completions?password=MyProdPassword1234&mode=fast",
    { openaiUpstream: "https://api.openai.com" },
    {},
    qVault
  );
  assert.equal(qResolved.queryRedactions, 1);
  assert.ok(!qResolved.targetUrl.includes("MyProdPassword1234"));
  assert.ok(qResolved.targetUrl.includes("mode=fast"));

  const multiSec = "sk-proj-choiceZeroSecret1234567890abcd";
  const multiVault = createVault({ salt: "22334455" });
  const multiTok = multiVault.redact(multiSec).text;
  const splitIdx = 11;
  const choiceStream = new ReadableStream({
    start(c) {
      const enc = new TextEncoder();
      c.enqueue(enc.encode(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: `a ${multiTok.slice(0, splitIdx)}` } }] })}\n\n`));
      c.enqueue(enc.encode(`data: ${JSON.stringify({ choices: [{ index: 1, delta: {}, finish_reason: "stop" }] })}\n\n`));
      c.enqueue(enc.encode(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: `${multiTok.slice(splitIdx)} b` }, finish_reason: "stop" }] })}\n\n`));
      c.enqueue(enc.encode("data: [DONE]\n\n"));
      c.close();
    },
  }).pipeThrough(createSseRehydrationTransform(multiVault, "openai"));
  const choiceOut = await new Response(choiceStream).text();
  const choiceFrames = choiceOut
    .split("\n\n")
    .filter((b) => b.startsWith("data: {"))
    .map((b) => JSON.parse(b.slice(6)));
  const c0Text = choiceFrames
    .filter((f) => f.choices?.[0]?.index === 0)
    .map((f) => f.choices[0].delta?.content ?? "")
    .join("");
  assert.equal(c0Text, `a ${multiSec} b`);

  const respItemVault = createVault({ salt: "55667788" });
  const pemSec = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIB\n-----END RSA PRIVATE KEY-----";
  const pemTok = respItemVault.redact(pemSec).text;
  const itemSplit = 10;
  const itemStream = new ReadableStream({
    start(c) {
      const enc = new TextEncoder();
      c.enqueue(enc.encode(`data: ${JSON.stringify({ type: "response.output_text.delta", item_id: "msg_1", output_index: 0, content_index: 0, delta: `p1 ${pemTok.slice(0, itemSplit)}` })}\n\n`));
      c.enqueue(enc.encode(`data: ${JSON.stringify({ type: "response.output_text.delta", item_id: "msg_2", output_index: 1, content_index: 0, delta: "p2 clean" })}\n\n`));
      c.enqueue(enc.encode(`data: ${JSON.stringify({ type: "response.output_text.delta", item_id: "msg_1", output_index: 0, content_index: 0, delta: pemTok.slice(itemSplit) })}\n\n`));
      c.enqueue(enc.encode(`data: ${JSON.stringify({ type: "response.function_call_arguments.done", item_id: "fc_1", arguments: `{"key":"${pemTok}"}` })}\n\n`));
      c.enqueue(enc.encode(`data: ${JSON.stringify({ type: "response.completed" })}\n\n`));
      c.close();
    },
  }).pipeThrough(createSseRehydrationTransform(respItemVault, "openai"));
  const itemOut = await new Response(itemStream).text();
  const itemEvents = itemOut
    .split("\n\n")
    .filter((b) => b.startsWith("data: {"))
    .map((b) => JSON.parse(b.slice(6)));
  const msg1Text = itemEvents
    .filter((e) => e.type === "response.output_text.delta" && e.item_id === "msg_1")
    .map((e) => e.delta)
    .join("");
  assert.equal(msg1Text, `p1 ${pemSec}`);
  const fcDone = itemEvents.find((e) => e.type === "response.function_call_arguments.done");
  assert.equal(JSON.parse(fcDone.arguments).key, pemSec);

  assert.throws(() => validatePatternSafety(/^\w+\w+=$/, "poly-redos"));
  assert.throws(() => validatePatternSafety(/([a-z]+)\1+/, "backref-redos"));
  assert.doesNotThrow(() => validatePatternSafety(/[0-9]+[A-Z]+/, "disjoint-quant"));

  const t0 = performance.now();
  const eqRes = createVault().redact(`Authorization: Bearer ${"=".repeat(1200)}a`);
  const eqMs = performance.now() - t0;
  assert.equal(eqRes.hits, 0);
  assert.ok(eqMs < 50, `Bearer backtracking regression: ${eqMs.toFixed(1)}ms`);

  const crlfTruncPem = String.raw`"-----BEGIN PRIVATE KEY-----\r\nMIIEowIBAAKCAQEA123456\r\nABCDEFGH12345678"`;
  assert.equal(new RegExp(PEM_UNTERMINATED_PATTERN.source).test(crlfTruncPem), true);
});

test("Audit 3 #4 #5 #6 #7 #8 & Audit 2 #4 #7: MCP cancel isolation, scanner excludes/staged, line numbers, IPv6 & redirect manual", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-audit3-"));
  const subDir = path.join(dir, "packages", "app");
  const vendorDir = path.join(subDir, "vendor");
  fs.mkdirSync(vendorDir, { recursive: true });
  try {
    fs.writeFileSync(path.join(vendorDir, ".env"), "API_KEY=sk-proj-vendorExcluded1234567890abcd\n", "utf8");
    fs.writeFileSync(path.join(subDir, "app.env"), "API_KEY=sk-proj-appIncluded1234567890abcdef\n", "utf8");

    const subReport = scanPath(dir, {
      targetPath: "packages/app",
      config: { excludePaths: ["packages/app/vendor"] },
    });
    assert.equal(subReport.scannedFiles, 1);
    assert.equal(subReport.findings[0].file, "packages/app/app.env");

    spawnSync("git", ["init"], { cwd: dir, windowsHide: true });
    spawnSync("git", ["config", "user.email", "test@example.com"], { cwd: dir, windowsHide: true });
    spawnSync("git", ["config", "user.name", "Test"], { cwd: dir, windowsHide: true });
    const deletedPath = path.join(subDir, "deleted.env");
    fs.writeFileSync(deletedPath, "GH_TOKEN=ghp_stagedDeletedLeaf1234567890abcdefghij\n", "utf8");
    spawnSync("git", ["add", "packages/app/deleted.env"], { cwd: dir, windowsHide: true });
    fs.rmSync(deletedPath);

    const deletedStaged = scanPath(dir, { staged: true, targetPath: "packages/app/deleted.env", noConfig: true });
    assert.equal(deletedStaged.clean, false);
    assert.equal(deletedStaged.findings[0].file, "packages/app/deleted.env");

    const multiLineFile = path.join(dir, "lines.txt");
    fs.writeFileSync(
      multiLineFile,
      [
        "header=1",
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEA1111111111111111",
        "MIIEowIBAAKCAQEA2222222222222222",
        "-----END RSA PRIVATE KEY-----",
        "API_KEY=sk-proj-lineSixSecret1234567890abcdef",
      ].join("\n"),
      "utf8"
    );
    const mcpServer = createServer({ cwd: dir, log: () => undefined });
    await mcpServer.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } });
    const sliceRes = await mcpServer.handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "airlock_read_file", arguments: { path: "lines.txt", fromLine: 6, lineCount: 1 } },
    });
    assert.equal(sliceRes.result.structuredContent.totalLines, 6);
    assert.match(sliceRes.result.content[0].text, /^API_KEY=<<redact:/);

    const contract = buildAgentContract();
    const tokenOpt = contract.options.find((o) => o.flag === "--token");
    assert.ok(tokenOpt);
    assert.notEqual(tokenOpt.default, "generated");

    const cancelServer = await startHttpTransport({
      cwd: dir,
      port: 0,
      config: { exec: { enabled: true, allowCommands: [process.execPath] } },
      log: () => undefined,
    });
    try {
      const slowCallA = fetch(`${cancelServer.url}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${cancelServer.token}`,
          "user-agent": "client-a",
          "mcp-protocol-version": "2026-07-28",
          "mcp-method": "tools/call",
          "mcp-name": "airlock_exec",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 99,
          method: "tools/call",
          params: {
            name: "airlock_exec",
            arguments: { command: process.execPath, args: ["-e", "setTimeout(() => console.log('done-a'), 4000)"] },
            _meta: {
              "io.modelcontextprotocol/protocolVersion": "2026-07-28",
              "io.modelcontextprotocol/clientCapabilities": {},
            },
          },
        }),
      });
      let settledA = false;
      const slowA = slowCallA.then(async (res) => {
        settledA = true;
        return await res.json();
      });
      await new Promise((r) => setTimeout(r, 150));

      const crossCancel = await fetch(`${cancelServer.url}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${cancelServer.token}`,
          "user-agent": "client-b",
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 99 } }),
      });
      assert.equal(crossCancel.status, 202);
      await new Promise((r) => setTimeout(r, 150));
      assert.equal(settledA, false);

      const tCancel = performance.now();
      const sameCancel = await fetch(`${cancelServer.url}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${cancelServer.token}`,
          "user-agent": "client-a",
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 99 } }),
      });
      assert.equal(sameCancel.status, 202);
      const outcomeA = await slowA;
      assert.ok(performance.now() - tCancel < 2500);
      const parsedOutA = JSON.parse(outcomeA.result.content[0].text);
      assert.notEqual(parsedOutA.exitCode, 0);
      assert.ok(!parsedOutA.stdout.includes("done-a"));
    } finally {
      await cancelServer.close();
    }

    const redirectUpstream = http.createServer((_req, res) => {
      res.writeHead(302, { location: "https://redirect.example.invalid/steal" });
      res.end();
    });
    await new Promise((resolve) => redirectUpstream.listen(0, "127.0.0.1", resolve));
    const ruAddr = redirectUpstream.address();
    const proxy = await startProxyServer({
      openaiUpstream: `http://127.0.0.1:${ruAddr.port}`,
      port: 0,
      log: () => undefined,
    });
    try {
      const redirRes = await fetch(`${proxy.url}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: "hi" }] }),
        redirect: "manual",
      });
      assert.equal(redirRes.status, 302);
    } finally {
      await proxy.close();
      await new Promise((resolve) => redirectUpstream.close(resolve));
    }

    const linkCwd = path.join(dir, "symlink-cwd");
    let cwdLinked = false;
    try {
      fs.symlinkSync(subDir, linkCwd, "dir");
      cwdLinked = true;
    } catch {
      cwdLinked = false;
    }
    if (cwdLinked) {
      assert.doesNotThrow(() =>
        assertWritableInsideRepository(linkCwd, path.join(linkCwd, "report", "audit.md"), "Refusing")
      );
    }

    try {
      const v6Proxy = await startProxyServer({ host: "[::1]", port: 0, log: () => undefined });
      assert.equal(new URL(v6Proxy.url).hostname, "[::1]");
      await v6Proxy.close();
    } catch (err) {
      if (!(err instanceof Error) || (!err.message.includes("EADDRNOTAVAIL") && !err.message.includes("EAFNOSUPPORT"))) {
        throw err;
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
