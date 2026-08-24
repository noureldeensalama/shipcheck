import { test } from "node:test";
import assert from "node:assert/strict";
import fg from "fast-glob";
import { buildScanResult, MAX_RETURNED_FINDINGS } from "../lib/scan-response.js";
import type { Finding } from "../types.js";

function fakeFinding(severity: Finding["severity"], file: string): Finding {
  return {
    category: "exposed-secrets",
    severity,
    file,
    description: `finding for ${file}`,
    why_it_matters: "why",
    suggested_fix: "fix",
  };
}

test("buildScanResult orders critical-first and caps output honestly", () => {
  const many: Finding[] = [];
  for (let i = 0; i < MAX_RETURNED_FINDINGS + 30; i++) {
    // interleave severities so ordering actually has to work
    many.push(fakeFinding(i % 3 === 0 ? "critical" : i % 3 === 1 ? "high" : "medium", `f${i}.js`));
  }

  const result = buildScanResult(many);
  assert.equal(result.summary.truncated, true);
  assert.equal(result.summary.total_before_truncation, many.length);
  assert.equal(result.findings.length, MAX_RETURNED_FINDINGS);
  assert.match(result.summary.note, /OUTPUT TRUNCATED/);

  // every critical must have survived the cap
  const criticalTotal = many.filter((f) => f.severity === "critical").length;
  const criticalKept = result.findings.filter((f) => f.severity === "critical").length;
  assert.equal(criticalKept, Math.min(criticalTotal, MAX_RETURNED_FINDINGS));
});

test("buildScanResult does not truncate small scans", () => {
  const result = buildScanResult([fakeFinding("high", "a.js")]);
  assert.equal(result.summary.truncated, undefined);
  assert.equal(result.summary.total_before_truncation, undefined);
  assert.equal(result.findings.length, 1);
});
