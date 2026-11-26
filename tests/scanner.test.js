import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  DEFAULT_SECRET_PATTERNS,
  generateSarifReport,
  renderAuditMarkdown,
  scanPath,
} from "../dist/index.js";

const SECRET_GH = "ghp_scanSecretTestToken1234567890abcdef";
const SECRET_AWS = "AKIAIOSFODNN7EXAMPLE";

test("scanner detects secrets, writes zero-plaintext audit.md and valid SARIF 2.1.0", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-scan-"));
  try {
    fs.writeFileSync(path.join(dir, "app.ts"), `const k = "${SECRET_GH}";\n`, "utf8");
    fs.writeFileSync(path.join(dir, ".env"), `AWS_KEY=${SECRET_AWS}\n`, "utf8");
    fs.writeFileSync(path.join(dir, "clean.txt"), "hello world\n", "utf8");

    const report = scanPath(dir);
    assert.equal(report.clean, false);
    assert.equal(report.scannedFiles, 3);
    assert.equal(report.findings.length, 2);

    const md = renderAuditMarkdown(report);
    assert.ok(!md.includes(SECRET_GH));
    assert.ok(!md.includes(SECRET_AWS));
    assert.ok(md.includes("app.ts"));
    assert.ok(md.includes(".env"));

    const sarifText = generateSarifReport(report, DEFAULT_SECRET_PATTERNS, "0.1.0");
    assert.ok(!sarifText.includes(SECRET_GH));
    assert.ok(!sarifText.includes(SECRET_AWS));
    const sarif = JSON.parse(sarifText);
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs[0].results.length, 2);
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, ".env");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
