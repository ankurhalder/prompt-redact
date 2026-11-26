import test from "node:test";
import assert from "node:assert/strict";
import {
  VaultCapacityError,
  createVault,
  redactPayload,
  rehydratePayload,
} from "../dist/index.js";

const SECRET_OPENAI = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
const SECRET_GITHUB = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234";
const SECRET_AWS = "AKIAIOSFODNN7EXAMPLE";

test("vault round-trips secrets deterministically within a session", () => {
  const vault = createVault({ mode: "session", salt: "deadbeef" });
  const first = vault.redact(`primary=${SECRET_OPENAI} backup=${SECRET_GITHUB}`);
  assert.equal(first.hits, 2);
  assert.equal(first.overflows, 0);
  assert.ok(!first.text.includes(SECRET_OPENAI));
  assert.ok(!first.text.includes(SECRET_GITHUB));
  assert.match(first.text, /<<redact:deadbeef:1>>/);
  assert.match(first.text, /<<redact:deadbeef:2>>/);

  const second = vault.redact(`repeat ${SECRET_OPENAI}`);
  assert.equal(second.text, "repeat <<redact:deadbeef:1>>");
  assert.equal(vault.size, 2);

  const restored = vault.rehydrate(`${first.text}\n${second.text}`);
  assert.ok(restored.includes(SECRET_OPENAI));
  assert.ok(restored.includes(SECRET_GITHUB));
  assert.ok(!restored.includes("<<redact:"));
});

test("redaction is idempotent across repeated passes", () => {
  const vault = createVault({ mode: "session" });
  const input = `token=${SECRET_OPENAI} aws=${SECRET_AWS}`;
  const once = vault.redact(input);
  const twice = vault.redact(once.text);
  assert.equal(twice.hits, 0);
  assert.equal(twice.text, once.text);
});

test("separate ephemeral vaults never share token namespaces", () => {
  const a = redactPayload({ messages: [{ role: "user", content: SECRET_OPENAI }] });
  const b = redactPayload({ messages: [{ role: "user", content: SECRET_OPENAI }] });
  const tokenA = a.vault.replacements()[0][0];
  const tokenB = b.vault.replacements()[0][0];
  assert.notEqual(tokenA, tokenB);
  assert.equal(b.vault.rehydrate(tokenA), tokenA);
  assert.equal(a.vault.rehydrate(tokenA), SECRET_OPENAI);
});

test("fail-closed hash policy never leaks plaintext past maxEntries", () => {
  const vault = createVault({ maxEntries: 32, overflowPolicy: "hash" });
  const secrets = [];
  for (let i = 0; i < 40; i += 1) {
    const s = `sk-live-secret-${String(i).padStart(4, "0")}-abcdefghijklmnop`;
    secrets.push(s);
    const res = vault.redact(`key=${s}`);
    assert.ok(!res.text.includes(s), `secret ${i} leaked in clear`);
    if (i < 32) {
      assert.equal(res.overflows, 0);
      assert.match(res.text, /<<redact:[a-f0-9]+:\d+>>/);
    } else {
      assert.equal(res.overflows, 1);
      assert.match(res.text, /<<redact-masked:[a-f0-9]{12}>>/);
    }
  }
  assert.equal(vault.size, 32);
  assert.equal(vault.overflowCount, 8);
  const auditJson = JSON.stringify(vault.audit());
  for (const s of secrets) {
    assert.ok(!auditJson.includes(s), "audit summary must never contain plaintext");
  }
});

test("fail-closed error policy throws VaultCapacityError without leaking", () => {
  const vault = createVault({ maxEntries: 2, overflowPolicy: "error" });
  vault.redact(`a=${SECRET_OPENAI}`);
  vault.redact(`b=${SECRET_GITHUB}`);
  assert.throws(
    () => vault.redact(`c=${SECRET_AWS}`),
    (err) =>
      err instanceof VaultCapacityError &&
      !err.message.includes(SECRET_AWS) &&
      err.maxEntries === 2
  );
});

test("allowlist and custom tokenPrefix are respected", () => {
  const vault = createVault({
    tokenPrefix: "airlock",
    allowlist: [SECRET_AWS],
  });
  const res = vault.redact(`aws=${SECRET_AWS} gh=${SECRET_GITHUB}`);
  assert.ok(res.text.includes(SECRET_AWS));
  assert.ok(!res.text.includes(SECRET_GITHUB));
  assert.match(res.text, /<<airlock:[a-f0-9]+:1>>/);
});

test("rehydrate handles payloads exceeding 1 MiB without silent cutoff", () => {
  const vault = createVault();
  const res = vault.redact(SECRET_OPENAI);
  const padding = "x".repeat(1_200_000);
  const huge = `${padding}${res.text}`;
  const restored = vault.rehydrate(huge);
  assert.ok(restored.endsWith(SECRET_OPENAI));
  assert.ok(!restored.includes("<<redact:"));
});

test("deep JSON payload redaction and rehydration work on Anthropic and OpenAI shapes", () => {
  const sessionVault = createVault({ mode: "session" });
  const payload = {
    model: "claude-sonnet-4-20250514",
    system: [{ type: "text", text: `Use ${SECRET_OPENAI}` }],
    messages: [
      {
        role: "user",
        content: [
          { type: "text", text: `Connect to ${SECRET_GITHUB}` },
          { type: "tool_result", content: `aws=${SECRET_AWS}` },
        ],
      },
    ],
    tools: [{ name: "deploy", description: `Uses ${SECRET_OPENAI}` }],
  };
  const originalSnapshot = JSON.stringify(payload);
  const redacted = redactPayload(payload, sessionVault);
  assert.equal(JSON.stringify(payload), originalSnapshot);
  const wire = JSON.stringify(redacted.payload);
  assert.ok(!wire.includes(SECRET_OPENAI));
  assert.ok(!wire.includes(SECRET_GITHUB));
  assert.ok(!wire.includes(SECRET_AWS));
  assert.equal(redacted.redactedCount, 4);
  assert.equal(sessionVault.size, 3);

  const rehydrated = rehydratePayload(redacted.payload, sessionVault);
  assert.equal(JSON.stringify(rehydrated), originalSnapshot);
});
