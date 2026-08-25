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
    "These are risk-pattern findings, not a legal compliance determination. Zero findings means nothing in these five categories was detected — it does not mean the app is safe to ship.";
  if (truncated) {
    note +=
      ` OUTPUT TRUNCATED: ${sorted.length} findings exceeded the ${MAX_RETURNED_FINDINGS}-finding response cap. ` +
      `Critical and high findings are shown first; re-run scan_repo with a 'categories' filter to see the rest.`;
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
