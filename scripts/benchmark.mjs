import * as http from "node:http";
import { createVault, redactPayload, rehydratePayload, startProxyServer } from "../dist/index.js";

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

function p95(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))];
}

function buildPayload(bytesApprox, secretCount) {
  const secrets = [];
  for (let i = 0; i < secretCount; i += 1) {
    secrets.push(`sk-proj-benchSecret${String(i).padStart(4, "0")}AbCdEfGhIjKlMnOpQrStUv`);
  }
  const chunk = `Context line with safe code and key=${secrets[0]} and gh=ghp_1234567890abcdefghijklmnopqrstuvwxyz1234.\n`;
  const repeats = Math.max(1, Math.floor(bytesApprox / chunk.length));
  return {
    model: "claude-sonnet-4-20250514",
    messages: [{ role: "user", content: chunk.repeat(repeats) }],
  };
}

function benchSdk(label, bytesApprox) {
  const payload = buildPayload(bytesApprox, 4);
  const vault = createVault({ mode: "session" });
  const redTimes = [];
  const rehTimes = [];
  for (let i = 0; i < 50; i += 1) {
    const t0 = performance.now();
    const out = redactPayload(payload, vault);
    const t1 = performance.now();
    rehydratePayload(out.payload, vault);
    const t2 = performance.now();
    redTimes.push(t1 - t0);
    rehTimes.push(t2 - t1);
  }
  return {
    label,
    payloadBytes: Buffer.byteLength(JSON.stringify(payload), "utf8"),
    redactMedianMs: Number(median(redTimes).toFixed(3)),
    redactP95Ms: Number(p95(redTimes).toFixed(3)),
    rehydrateMedianMs: Number(median(rehTimes).toFixed(3)),
    rehydrateP95Ms: Number(p95(rehTimes).toFixed(3)),
  };
}

function benchProse(bytesApprox) {
  const base = "lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt.\n";
  const text = base.repeat(Math.ceil(bytesApprox / base.length)).slice(0, bytesApprox);
  const payload = { model: "gpt-4o", messages: [{ role: "user", content: text }] };
  const vault = createVault({ mode: "session" });
  const redTimes = [];
  const rehTimes = [];
  for (let i = 0; i < 50; i += 1) {
    const t0 = performance.now();
    const out = redactPayload(payload, vault);
    const t1 = performance.now();
    rehydratePayload(out.payload, vault);
    const t2 = performance.now();
    redTimes.push(t1 - t0);
    rehTimes.push(t2 - t1);
  }
  return {
    label: "100KB-prose",
    payloadBytes: Buffer.byteLength(JSON.stringify(payload), "utf8"),
    redactMedianMs: Number(median(redTimes).toFixed(3)),
    redactP95Ms: Number(p95(redTimes).toFixed(3)),
    rehydrateMedianMs: Number(median(rehTimes).toFixed(3)),
    rehydrateP95Ms: Number(p95(rehTimes).toFixed(3)),
  };
}

async function benchProxy() {
  const secret = "sk-proj-proxyBenchSecret1234567890abcdef";
  const upstream = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const tokenMatch = body.match(/<<redact:[a-f0-9]+:\d+>>/);
      const reply = tokenMatch ? tokenMatch[0] : "none";
      if (req.url === "/v1/stream") {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: reply.slice(0, 6) } }] })}\n\n`);
        res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: reply.slice(6) } }] })}\n\n`);
        res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\n`);
        res.write("data: [DONE]\n\n");
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ choices: [{ message: { content: reply } }] }));
    });
  });

  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const upUrl = `http://127.0.0.1:${upstream.address().port}`;
  const proxy = await startProxyServer({ port: 0, openaiUpstream: upUrl });

  const bodyJson = JSON.stringify({
    model: "gpt-4o",
    messages: [{ role: "user", content: `Check key=${secret}\n${"normal line of code\n".repeat(120)}` }],
  });

  const directJson = [];
  const proxyJson = [];
  const directSse = [];
  const proxySse = [];

  try {
    for (let i = 0; i < 30; i += 1) {
      let t0 = performance.now();
      await (await fetch(`${upUrl}/v1/chat/completions`, { method: "POST", headers: { "content-type": "application/json" }, body: bodyJson })).text();
      directJson.push(performance.now() - t0);

      t0 = performance.now();
      await (await fetch(`${proxy.url}/v1/chat/completions`, { method: "POST", headers: { "content-type": "application/json" }, body: bodyJson })).text();
      proxyJson.push(performance.now() - t0);

      t0 = performance.now();
      await (await fetch(`${upUrl}/v1/stream`, { method: "POST", headers: { "content-type": "application/json" }, body: bodyJson })).text();
      directSse.push(performance.now() - t0);

      t0 = performance.now();
      await (await fetch(`${proxy.url}/v1/stream`, { method: "POST", headers: { "content-type": "application/json" }, body: bodyJson })).text();
      proxySse.push(performance.now() - t0);
    }
  } finally {
    await proxy.close();
    upstream.closeAllConnections();
    await new Promise((resolve) => upstream.close(resolve));
  }

  return {
    payloadBytes: Buffer.byteLength(bodyJson, "utf8"),
    jsonDirectMedianMs: Number(median(directJson).toFixed(3)),
    jsonProxyMedianMs: Number(median(proxyJson).toFixed(3)),
    jsonOverheadMs: Number((median(proxyJson) - median(directJson)).toFixed(3)),
    sseDirectMedianMs: Number(median(directSse).toFixed(3)),
    sseProxyMedianMs: Number(median(proxySse).toFixed(3)),
    sseOverheadMs: Number((median(proxySse) - median(directSse)).toFixed(3)),
  };
}

const results = {
  node: process.version,
  platform: `${process.platform}-${process.arch}`,
  sdk: [benchSdk("10KB", 10 * 1024), benchSdk("100KB", 100 * 1024), benchProse(100 * 1024)],
  proxy: await benchProxy(),
};
console.log(JSON.stringify(results, null, 2));
