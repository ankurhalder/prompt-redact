import type { AuditEvent, AuditRecorder, AuditSummary } from "../types.js";

const MAX_RETAINED_EVENTS = 500;
const MAX_SOURCE_LENGTH = 160;

function safeSourceLabel(source: string): string {
  const collapsed = String(source).replace(/[\r\n\t]+/g, " ").trim();
  return collapsed.length === 0 ? "unknown" : collapsed.slice(0, MAX_SOURCE_LENGTH);
}

export function createAuditRecorder(): AuditRecorder {
  const events: AuditEvent[] = [];
  const byRule = new Map<string, number>();
  let totalRedactions = 0;
  let recordedOverflows = 0;

  return {
    record(event: Omit<AuditEvent, "timestamp">): void {
      const overflowDelta =
        event.overflowCount ?? (event.overflowed ? event.count : 0);
      const entry: AuditEvent = {
        timestamp: new Date().toISOString(),
        source: safeSourceLabel(event.source),
        rule: event.rule,
        count: event.count,
        ...(event.targetHost ? { targetHost: event.targetHost } : {}),
        ...(overflowDelta > 0 ? { overflowed: true, overflowCount: overflowDelta } : {}),
      };
      if (events.length >= MAX_RETAINED_EVENTS) {
        events.shift();
      }
      events.push(entry);
      totalRedactions += event.count;
      recordedOverflows += overflowDelta;
      byRule.set(event.rule, (byRule.get(event.rule) ?? 0) + event.count);
    },
    summary(vaultSize: number, maxEntries: number, overflowCount: number): AuditSummary {
      const ruleObj: Record<string, number> = {};
      for (const [rule, count] of [...byRule.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
        ruleObj[rule] = count;
      }
      return {
        totalRedactions,
        overflowCount: Math.max(overflowCount, recordedOverflows),
        vaultSize,
        maxEntries,
        byRule: ruleObj,
        events: [...events],
      };
    },
    clear(): void {
      events.length = 0;
      byRule.clear();
      totalRedactions = 0;
      recordedOverflows = 0;
    },
  };
}
