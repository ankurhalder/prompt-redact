import test from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { runDoctor, runSetup, startProxyServer } from "../dist/index.js";

const SECRET = "sk-proj-proxyTestSecretKey1234567890abcd";
const SECRET_GH = "ghp_proxyGithubSecretToken1234567890abcdef";

async function startMockUpstream(handler) {
  const captured = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const bodyText = Buffer.concat(chunks).toString("utf8");
      captured.push({ url: req.url, method: req.method, headers: req.headers, body: bodyText });
      handler(req, res, bodyText);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  return {
    url: `http://127.0.0.1:${addr.port}`,
    captured,
    close: async () => {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

test("proxy strips OpenAI secrets outbound, preserves session token stability, and rehydrates SSE", async () => {
  const upstream = await startMockUpstream((_req, res, bodyText) => {
    const body = JSON.parse(bodyText);
    const token = body.messages[0].content.match(/<<redact:[a-f0-9]+:\d+>>/)[0];
    res.writeHead(200, { "content-type": "text/event-stream" });
    const half = Math.floor(token.length / 2);
    res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: `key=${token.slice(0, half)}` } }] })}\n\n`);
    res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: token.slice(half) } }] })}\n\n`);
    res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\n`);
    res.write("data: [DONE]\n\n");
    res.end();
  });

  const proxy = await startProxyServer({ port: 0, openaiUpstream: upstream.url });
  try {
    const res1 = await fetch(`${proxy.url}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-prompt-redact-session": "agent-1" },
      body: JSON.stringify({ model: "gpt-4o", stream: true, messages: [{ role: "user", content: `use ${SECRET}` }] }),
    });
    assert.equal(res1.status, 200);
    assert.equal(res1.headers.get("x-prompt-redact-count"), "1");
    const text1 = await res1.text();
    assert.ok(!text1.includes("<<redact:"));
    assert.ok(text1.includes(SECRET));
    assert.ok(!upstream.captured[0].body.includes(SECRET));

    const res2 = await fetch(`${proxy.url}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-prompt-redact-session": "agent-1" },
      body: JSON.stringify({ model: "gpt-4o", stream: true, messages: [{ role: "user", content: `again ${SECRET}` }] }),
    });
    await res2.text();
    const token1 = upstream.captured[0].body.match(/<<redact:[a-f0-9]+:\d+>>/)[0];
    const token2 = upstream.captured[1].body.match(/<<redact:[a-f0-9]+:\d+>>/)[0];
    assert.equal(token1, token2);

    const auditRes = await fetch(`${proxy.url}/audit`);
    const audit = await auditRes.json();
    assert.equal(audit.totalRedactions, 2);
    assert.ok(!JSON.stringify(audit).includes(SECRET));
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test("proxy strips Anthropic secrets outbound and rehydrates Anthropic SSE stream", async () => {
  const upstream = await startMockUpstream((_req, res, bodyText) => {
    const body = JSON.parse(bodyText);
    const token = body.messages[0].content.match(/<<redact:[a-f0-9]+:\d+>>/)[0];
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write(`event: content_block_start\ndata: ${JSON.stringify({ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } })}\n\n`);
    res.write(`event: content_block_delta\ndata: ${JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: token.slice(0, 6) } })}\n\n`);
    res.write(`event: content_block_delta\ndata: ${JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: token.slice(6) } })}\n\n`);
    res.write(`event: content_block_stop\ndata: ${JSON.stringify({ type: "content_block_stop", index: 0 })}\n\n`);
    res.write(`event: message_stop\ndata: ${JSON.stringify({ type: "message_stop" })}\n\n`);
    res.end();
  });

  const proxy = await startProxyServer({ port: 0, anthropicUpstream: upstream.url });
  try {
    const res = await fetch(`${proxy.url}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "claude-sonnet-4-20250514", max_tokens: 64, stream: true, messages: [{ role: "user", content: `gh=${SECRET_GH}` }] }),
    });
    assert.equal(res.status, 200);
    const body = await res.text();
    assert.ok(!upstream.captured[0].body.includes(SECRET_GH));
    assert.ok(!body.includes("<<redact:"));
    assert.ok(body.includes(SECRET_GH));
    assert.ok(!body.includes('"choices"'));
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test("proxy dry-run inspects without contacting upstream and fail-closed error aborts with 503", async () => {
  const upstream = await startMockUpstream((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end("{}");
  });

  const dryProxy = await startProxyServer({ port: 0, openaiUpstream: upstream.url, dryRun: true });
  try {
    const res = await fetch(`${dryProxy.url}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: SECRET }] }),
    });
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.dryRun, true);
    assert.equal(json.redactedCount, 1);
    assert.ok(!JSON.stringify(json).includes(SECRET));
    assert.equal(upstream.captured.length, 0);
  } finally {
    await dryProxy.close();
  }

  const strictProxy = await startProxyServer({
    port: 0,
    openaiUpstream: upstream.url,
    vaultOptions: { maxEntries: 1, overflowPolicy: "error" },
  });
  try {
    const overflowRes = await fetch(`${strictProxy.url}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: `${SECRET} ${SECRET_GH}` }] }),
    });
    assert.equal(overflowRes.status, 503);
    const body = await overflowRes.json();
    assert.equal(body.error, "vault_capacity_exceeded");
    assert.ok(!JSON.stringify(body).includes(SECRET));
    assert.ok(!JSON.stringify(body).includes(SECRET_GH));
    assert.equal(upstream.captured.length, 0);
  } finally {
    await strictProxy.close();
    await upstream.close();
  }
});

test("setup writes data-only config and doctor verifies environment", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-setup-"));
  try {
    const setup1 = runSetup(dir);
    assert.equal(setup1.action, "created");
    assert.ok(fs.existsSync(path.join(dir, "prompt-redact.config.json")));
    const setup2 = runSetup(dir);
    assert.equal(setup2.action, "kept");
    const doctor = await runDoctor(dir, 0);
    assert.equal(doctor.ok, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
