import type { ScanReport } from "../types.js";

function cell(value: string): string {
  return value.replace(/`/g, "'").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

export function renderAuditMarkdown(report: ScanReport): string {
  const lines: string[] = [];
  lines.push("# prompt-redact Audit Report");
  lines.push("");
  lines.push(
    "Matched credential values are never written to this report. Only file paths, line numbers, and rule identifiers are recorded."
  );
  lines.push("");
  const skipped = report.skipped ?? [];
  const status = report.clean
    ? "clean"
    : report.findings.length === 0 && report.strict
      ? "failed (strict mode: files were skipped)"
      : "findings detected";
  lines.push(`- **Status**: ${status}`);
  lines.push(`- **Mode**: ${report.strict ? "strict" : "standard"}`);
  lines.push(`- **Scanned files**: ${report.scannedFiles}`);
  lines.push(`- **Skipped files**: ${report.skippedFiles}`);
  lines.push(`- **Total findings**: ${report.findings.length}`);
  lines.push("");

  const ruleEntries = Object.entries(report.byRule);
  if (ruleEntries.length > 0) {
    lines.push("## Findings by Rule");
    lines.push("");
    lines.push("| Rule | Count |");
    lines.push("| --- | ---: |");
    for (const [rule, count] of ruleEntries) {
      lines.push(`| \`${cell(rule)}\` | ${count} |`);
    }
    lines.push("");
  }

  if (report.findings.length > 0) {
    lines.push("## Locations");
    lines.push("");
    lines.push("| File | Line | Rule |");
    lines.push("| --- | ---: | --- |");
    for (const finding of report.findings) {
      lines.push(`| \`${cell(finding.file)}\` | ${finding.line} | \`${cell(finding.rule)}\` |`);
    }
    lines.push("");
  }

  if (skipped.length > 0) {
    lines.push("## Skipped Files");
    lines.push("");
    lines.push("| File | Reason |");
    lines.push("| --- | --- |");
    for (const entry of skipped) {
      lines.push(`| \`${cell(entry.file)}\` | ${cell(entry.reason)} |`);
    }
    lines.push("");
    if (report.strict) {
      lines.push(
        "Strict mode fails on every skipped file. Re-run with a trusted configuration that explicitly excludes expected binaries, or remove the unreadable/symlinked/oversize entry."
      );
      lines.push("");
    }
  }

  return `${lines.join("\n")}\n`;
}
