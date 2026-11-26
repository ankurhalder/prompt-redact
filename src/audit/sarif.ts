import * as crypto from "node:crypto";
import { DEFAULT_SECRET_PATTERNS } from "../core/patterns.js";
import type { ScanReport, SecretRule } from "../types.js";

const SARIF_VERSION = "2.1.0";
const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

const BUILTIN_RULE_IDS: ReadonlyMap<string, string> = new Map(
  [
    ...DEFAULT_SECRET_PATTERNS.map((rule) => rule.rule),
    "private-key-block",
    "high-entropy",
  ].map((name, index) => [name, `PR${String(index + 1).padStart(3, "0")}`] as const)
);

function ruleIdFor(name: string): string {
  const builtin = BUILTIN_RULE_IDS.get(name);
  if (builtin !== undefined) return builtin;
  const digest = crypto.createHash("sha256").update(name).digest("hex").slice(0, 8);
  return `PR${digest.toUpperCase()}`;
}

export function generateSarifReport(
  report: ScanReport,
  rules: readonly SecretRule[],
  toolVersion: string
): string {
  const ruleNames = Array.from(
    new Set([...rules.map((r) => r.rule), ...report.findings.map((f) => f.rule)])
  ).sort();

  const ruleIndex = new Map<string, number>();
  const sarifRules = ruleNames.map((name, index) => {
    ruleIndex.set(name, index);
    return {
      id: ruleIdFor(name),
      name,
      shortDescription: { text: `Credential pattern matched by rule "${name}"` },
      defaultConfiguration: { level: "error" as const },
      help: {
        text:
          "A credential-shaped value was detected at this location. Replace it with a secret reference or tokenize it before sending to an upstream model.",
      },
    };
  });

  const results = report.findings
    .map((finding) => {
      const uri = finding.file
        .replace(/\\/g, "/")
        .split("/")
        .map((segment) => encodeURIComponent(segment))
        .join("/");
      const line = Math.max(1, finding.line);
      return {
        ruleId: ruleIdFor(finding.rule),
        ruleIndex: ruleIndex.get(finding.rule) ?? 0,
        level: "error" as const,
        message: {
          text: `Credential-shaped value detected (rule: ${finding.rule}). Value withheld.`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri, uriBaseId: "%SRCROOT%" },
              region: { startLine: line },
            },
          },
        ],
        partialFingerprints: {
          promptRedactFinding: `${uri}#L${line}#${finding.rule}`,
        },
      };
    })
    .sort((a, b) => {
      const left = a.locations[0].physicalLocation.artifactLocation.uri;
      const right = b.locations[0].physicalLocation.artifactLocation.uri;
      return (
        (left < right ? -1 : left > right ? 1 : 0) ||
        a.locations[0].physicalLocation.region.startLine -
          b.locations[0].physicalLocation.region.startLine
      );
    });

  const sarifLog = {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: "prompt-redact",
            version: toolVersion,
            informationUri: "https://github.com/ankurhalder/prompt-redact",
            rules: sarifRules,
          },
        },
        originalUriBaseIds: { "%SRCROOT%": { uri: "file:///" } },
        results,
      },
    ],
  };

  return `${JSON.stringify(sarifLog, null, 2)}\n`;
}
