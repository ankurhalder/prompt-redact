import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { createServer, startHttpTransport } from "../dist/mcp.js";

const SECRET = "sk-proj-mcpAirlockSecretValue1234567890";
const EXPECTED_SHA = crypto.createHash("sha256").update(SECRET, "utf8").digest("hex");

test("MCP dispatcher handles both legacy and modern protocol eras", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-mcp-era-"));
  try {
    const legacy = createServer({ cwd: dir, log: () => undefined });
    const init = await legacy.handle({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-11-25" },
    });
    assert.equal(init.result.protocolVersion, "2025-11-25");
    const tools = await legacy.handle({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    assert.equal(tools.result.tools.length, 6);

    const modern = createServer({ cwd: dir, log: () => undefined });
    const disc = await modern.handle({ jsonrpc: "2.0", id: 1, method: "server/discover" });
    assert.ok(Array.isArray(disc.result.supportedVersions));
    assert.equal(disc.result.resultType, "complete");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("MCP Streamable HTTP conforms with @modelcontextprotocol/client and airlock_exec resolves tokens safely", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-mcp-http-"));
  const outsideFile = path.join(os.tmpdir(), `pr-outside-${Date.now()}.txt`);
  fs.writeFileSync(outsideFile, "OPENAI_API_KEY=sk-proj-outsideSecret1234567890123456\n", "utf8");
  fs.writeFileSync(path.join(dir, ".env"), `API_KEY=${SECRET}\n`, "utf8");

  const transportServer = await startHttpTransport({
    cwd: dir,
    port: 0,
    config: { exec: { enabled: true, allowCommands: [process.execPath] } },
    log: () => undefined,
  });

  const client = new Client({ name: "test-client", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(`${transportServer.url}/mcp`), {
    requestInit: {
      headers: {
        Authorization: `Bearer ${transportServer.token}`,
      },
    },
  });

  try {
    await client.connect(transport);
    const list = await client.listTools();
    const names = list.tools.map((t) => t.name).sort();
    assert.deepEqual(names, [
      "airlock_exec",
      "airlock_read_file",
      "redact_audit",
      "redact_payload",
      "redact_text",
      "redact_verify",
    ]);

    const readEnv = await client.callTool({
      name: "airlock_read_file",
      arguments: { path: ".env" },
    });
    const envText = readEnv.content[0].text;
    assert.ok(!envText.includes(SECRET));
    const tokenMatch = envText.match(/<<redact:[a-f0-9]+:\d+>>/);
    assert.ok(tokenMatch, "expected vault token from airlock_read_file");
    const token = tokenMatch[0];

    const traversal = await client.callTool({
      name: "airlock_read_file",
      arguments: { path: outsideFile },
    });
    assert.equal(traversal.isError, true);

    const execResult = await client.callTool({
      name: "airlock_exec",
      arguments: {
        command: process.execPath,
        args: [
          "-e",
          "const crypto = require('node:crypto'); const sha = crypto.createHash('sha256').update(process.env.INJECTED_KEY).digest('hex'); console.log('sha=' + sha + ' echo=' + process.argv[1]);",
          token,
        ],
        env: { INJECTED_KEY: token },
      },
    });
    assert.ok(!execResult.isError);
    const execJson = JSON.parse(execResult.content[0].text);
    assert.equal(execJson.exitCode, 0);
    assert.ok(execJson.stdout.includes(`sha=${EXPECTED_SHA}`), "child process must receive real secret");
    assert.ok(!execJson.stdout.includes(SECRET), "stdout must re-scrub any echoed secret");
    assert.ok(execJson.stdout.includes("echo=<<redact:"), "echoed secret must be re-tokenized");

    const verifyClean = await client.callTool({
      name: "redact_verify",
      arguments: { text: envText },
    });
    assert.equal(JSON.parse(verifyClean.content[0].text).clean, true);

    const verifyDirty = await client.callTool({
      name: "redact_verify",
      arguments: { path: ".env" },
    });
    const dirtyJson = JSON.parse(verifyDirty.content[0].text);
    assert.equal(dirtyJson.clean, false);
    assert.equal(dirtyJson.findingsCount, 1);
    assert.ok(!JSON.stringify(dirtyJson).includes(SECRET));

    const audit = await client.callTool({ name: "redact_audit", arguments: {} });
    const auditJson = JSON.parse(audit.content[0].text);
    assert.ok(auditJson.totalRedactions >= 2);
    assert.ok(!JSON.stringify(auditJson).includes(SECRET));
  } finally {
    await client.close();
    await transportServer.close();
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(outsideFile, { force: true });
  }
});

test("MCP stdio child process conforms with @modelcontextprotocol/client StdioClientTransport", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-mcp-stdio-"));
  const binPath = path.resolve("dist", "bin.js");
  const client = new Client({ name: "stdio-test-client", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [binPath, "mcp", "--cwd", dir],
    stderr: "pipe",
  });
  try {
    await client.connect(transport);
    const list = await client.listTools();
    assert.equal(list.tools.length, 6);
    const res = await client.callTool({
      name: "redact_text",
      arguments: { text: `token=${SECRET}` },
    });
    assert.ok(!res.content[0].text.includes(SECRET));
    assert.match(res.content[0].text, /<<redact:[a-f0-9]+:1>>/);
  } finally {
    await client.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
