import test from "node:test";
import assert from "node:assert/strict";
import { createVault, wrapResponseWithRehydration } from "../dist/index.js";

const SECRET = "sk-proj-splitStreamSecretValue1234567890";

async function streamThroughChunks(chunks, vault, protocolHint = "auto") {
  const encoder = new TextEncoder();
  const upstream = new Response(
    new ReadableStream({
      start(controller) {
        for (const chunk of chunks) {
          controller.enqueue(typeof chunk === "string" ? encoder.encode(chunk) : chunk);
        }
        controller.close();
      },
    }),
    { status: 200, headers: { "content-type": "text/event-stream" } }
  );
  const wrapped = wrapResponseWithRehydration(upstream, vault, protocolHint);
  return await wrapped.text();
}

test("OpenAI SSE rehydrates token split at every possible byte boundary", async () => {
  const vault = createVault({ salt: "11223344" });
  const { text: redacted } = vault.redact(`key=${SECRET}`);
  const token = vault.replacements()[0][0];
  assert.ok(redacted.includes(token));

  for (let split = 1; split < token.length; split += 1) {
    const head = token.slice(0, split);
    const tail = token.slice(split);
    const frames = [
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: `prefix ${head}` } }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: `${tail} suffix` } }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\n`,
      "data: [DONE]\n\n",
    ];
    const output = await streamThroughChunks(frames, vault, "openai");
    assert.ok(!output.includes("<<redact:"), `token leaked at split=${split}`);
    assert.ok(output.includes(`prefix ${SECRET} suffix`) || output.includes(SECRET));
  }
});

test("Anthropic SSE rehydrates split tokens and emits native content_block_delta on flush", async () => {
  const vault = createVault({ salt: "aabbccdd" });
  vault.redact(SECRET);
  const token = vault.replacements()[0][0];
  const half = Math.floor(token.length / 2);

  const frames = [
    `event: message_start\ndata: ${JSON.stringify({ type: "message_start", message: { id: "msg_1" } })}\n\n`,
    `event: content_block_start\ndata: ${JSON.stringify({ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } })}\n\n`,
    `event: content_block_delta\ndata: ${JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: `here: ${token.slice(0, half)}` } })}\n\n`,
    `event: content_block_delta\ndata: ${JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: token.slice(half) } })}\n\n`,
    `event: content_block_stop\ndata: ${JSON.stringify({ type: "content_block_stop", index: 0 })}\n\n`,
    `event: message_stop\ndata: ${JSON.stringify({ type: "message_stop" })}\n\n`,
  ];

  const output = await streamThroughChunks(frames, vault, "auto");
  assert.ok(!output.includes("<<redact:"));
  assert.ok(!output.includes('"choices"'), "Anthropic stream must never emit OpenAI delta shape");

  const reassembled = output
    .split("\n\n")
    .filter((block) => block.includes("content_block_delta"))
    .map((block) => {
      const dataLine = block.split("\n").find((l) => l.startsWith("data: "));
      return JSON.parse(dataLine.slice(6)).delta.text;
    })
    .join("");
  assert.equal(reassembled, `here: ${SECRET}`);
});

test("Anthropic truncated stream flushes held prefix as content_block_delta, never OpenAI choices", async () => {
  const vault = createVault({ salt: "55667788" });
  vault.redact(SECRET);
  const partialPrefix = "<<redact:5566";
  const frames = [
    `event: content_block_start\ndata: ${JSON.stringify({ type: "content_block_start", index: 2, content_block: { type: "text", text: "" } })}\n\n`,
    `event: content_block_delta\ndata: ${JSON.stringify({ type: "content_block_delta", index: 2, delta: { type: "text_delta", text: `approx ${partialPrefix}` } })}\n\n`,
  ];
  const output = await streamThroughChunks(frames, vault, "auto");
  assert.ok(!output.includes('"choices"'));
  assert.ok(output.includes("event: content_block_delta"));
  assert.ok(output.includes(partialPrefix));
});

test("arbitrary 1-byte and multi-byte UTF-8 TCP chunk splits preserve emojis and rehydrate tokens", async () => {
  const vault = createVault({ salt: "cafebabe" });
  vault.redact(SECRET);
  const token = vault.replacements()[0][0];
  const payload =
    `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: `🔐 ${token.slice(0, 7)}` } }] })}\n\n` +
    `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: `${token.slice(7)} 🚀` } }] })}\n\n` +
    "data: [DONE]\n\n";
  const allBytes = new TextEncoder().encode(payload);
  const singleByteChunks = [];
  for (let i = 0; i < allBytes.length; i += 3) {
    singleByteChunks.push(allBytes.slice(i, i + 3));
  }
  const output = await streamThroughChunks(singleByteChunks, vault, "openai");
  assert.ok(!output.includes("<<redact:"));
  const text = output
    .split("\n\n")
    .filter((b) => b.startsWith("data: {"))
    .map((b) => JSON.parse(b.slice(6)).choices[0].delta.content)
    .join("");
  assert.equal(text, `🔐 ${SECRET} 🚀`);
});
