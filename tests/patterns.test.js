import test from "node:test";
import assert from "node:assert/strict";
import {
  compileSecretRules,
  createVault,
  validatePatternSafety,
} from "../dist/index.js";

// Provider-shaped values are assembled at runtime so the repository contains
// no literal token that GitHub push protection (or downstream scanners) flags.
const fake = (...parts) => parts.join("");

const PATTERNS_TO_CATCH = [
  ["mongodb", fake("mongodb+srv://admin:", "SuperSecretPass1234", "@cluster0.mongodb.net/prod")],
  ["redis", fake("rediss://:", "myRedisPassword12345", "@redis.internal:6379/0")],
  ["github-classic", fake("ghp_", "123456789012345678901234567890123456")],
  ["github-fine-grained", `github_pat_${"a".repeat(82)}`],
  ["aws-access-key", fake("AKIA", "IOSFODNN7EXAMPLE")],
  ["google-api-key", fake("AIza", "SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGt6")],
  ["stripe-live", fake("sk_", "live_", "51H7abcDEFghiJKLmnoPQRstuVWX12345")],
  ["jwt", fake("eyJ", "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.", "eyJ", "zdWIiOiIxMjM0NTY3ODkwIn0.", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")],
  ["bearer", fake("Authorization: Bearer ", "eyJ", "hbGciOiJub25lIn0.", "abcdefghijk123456789")],
  ["sendgrid", `SG.${"a".repeat(22)}.${"b".repeat(43)}`],
  ["brevo", `xkeysib-${"a".repeat(45)}`],
  ["resend", `re_${"A1b2C3d4E5".repeat(3)}`],
  ["pem", fake("-----BEGIN ", "RSA PRIVATE KEY-----", "\nMIIEowIBAAKCAQEA1234567890\n-----END ", "RSA PRIVATE KEY-----")],
  ["env-assignment", "DATABASE_PASSWORD=CorrectHorseBatteryStaple99"],
  ["postmark-uuid", "POSTMARK_API_TOKEN=123e4567-e89b-12d3-a456-426614174000"],
];

test("built-in catalog catches all expected credential formats and restores them", () => {
  for (const [label, sample] of PATTERNS_TO_CATCH) {
    const vault = createVault();
    const res = vault.redact(sample);
    assert.ok(res.hits >= 1, `${label} was not detected`);
    assert.ok(res.text.includes("<<redact:"), `${label} did not produce a token`);
    assert.equal(vault.rehydrate(res.text), sample, `${label} failed round-trip rehydration`);
  }
});

test("ordinary prose, type annotations, and placeholders are left untouched", () => {
  const vault = createVault();
  const safeInputs = [
    "Explain how a token bucket rate limiter works.",
    "interface Config { token: string; password: null; maxTokens: number; }",
    'const apiKey = "changeme"; const password = "placeholder";',
    "http://localhost:3000/v1/messages",
    "const token = await refreshToken(client);",
  ];
  for (const line of safeInputs) {
    const res = vault.redact(line);
    assert.equal(res.hits, 0, `false positive on: ${line}`);
    assert.equal(res.text, line);
  }
});

test("entropy detector catches high-entropy blobs when enabled without touching normal code", () => {
  const vault = createVault({
    entropy: { enabled: true, minLength: 24, threshold: 4.1 },
  });
  const blob = "Zx9$kLm2Pq7Rt4Vw8Ny1Bc5Df3Gh6Jk0".replace("$", "A");
  const res = vault.redact(`secretValue = "${blob}" and path = src/core/vault/index`);
  assert.ok(!res.text.includes(blob));
  assert.ok(res.text.includes("src/core/vault/index"));
});

test("custom rule validator rejects empty-matching and catastrophic backtracking patterns", () => {
  assert.throws(() => validatePatternSafety(/(?:)/, "empty-rule"));
  assert.throws(() => validatePatternSafety(/(a+)+/, "redos-rule"));
  const compiled = compileSecretRules([
    { rule: "corp-key", pattern: "CORP_[A-Z0-9]{12}", flags: "" },
  ]);
  assert.equal(compiled.length, 1);
  const vault = createVault({ rules: compiled });
  const res = vault.redact("token CORP_ABCDEF123456");
  assert.equal(res.hits, 1);
  assert.equal(vault.rehydrate(res.text), "token CORP_ABCDEF123456");
});

test("large adversarial input completes in linear time", () => {
  const vault = createVault();
  const noisy = `${"eyJ1234567890_".repeat(5000)} ok`;
  const started = performance.now();
  const res = vault.redact(noisy);
  const elapsedMs = performance.now() - started;
  assert.equal(res.hits, 0);
  assert.ok(elapsedMs < 250, `scan took ${elapsedMs.toFixed(1)}ms`);
});
