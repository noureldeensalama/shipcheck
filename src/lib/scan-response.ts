import type { Finding } from "../types.js";

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2 };

/**
 * Findings returned to the calling agent are capped: a pathological repo
 * must not dump unbounded JSON into the model's context (every token is
 * paid for twice — once to read, once to reason about). Critical findings
 * always survive truncation; the summary says honestly what was cut.
 */
export const MAX_RETURNED_FINDINGS = 100;

export interface ScanSummary {
  total: number;
  by_severity: { critical: number; high: number; medium: number };
  truncated?: boolean;
  total_before_truncation?: number;
  /** Stacks inferred from manifests (Flutter/Dart, Rust, Python…). */
  project_types?: string[];
  /** Honest coverage warning when a detected stack lacks endpoint coverage. */
  coverage_caveat?: string;
  note: string;
}

export interface ScanResult {
  summary: ScanSummary;
  findings: Finding[];
}

export function buildScanResult(allFindings: Finding[]): ScanResult {
  const by_severity = {
    critical: allFindings.filter((f) => f.severity === "critical").length,
    high: allFindings.filter((f) => f.severity === "high").length,
    medium: allFindings.filter((f) => f.severity === "medium").length,
  };

  const sorted = [...allFindings].sort(
    (a, b) => (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3),
  );
  const truncated = sorted.length > MAX_RETURNED_FINDINGS;
  const findings = truncated ? sorted.slice(0, MAX_RETURNED_FINDINGS) : sorted;

  let note =
    "These are warnings about common risky patterns we know how to spot — not a legal review and not a guarantee. Finding nothing just means nothing matched these specific checks; other problems can still exist.";
  if (truncated) {
    note +=
      ` We found more warnings than fit in one report (${sorted.length} total) and kept the most serious ones first.` +
      ` Run a scan again with a categories filter to see the rest.`;
  }

  return {
    summary: {
      total: findings.length,
      by_severity,
      ...(truncated ? { truncated: true, total_before_truncation: sorted.length } : {}),
      note,
    },
    findings,
  };
}
