import { test } from "node:test";
import assert from "node:assert/strict";
import fg from "fast-glob";
import { paymentHandling } from "../detectors/payment-handling.js";
import type { Finding } from "../types.js";

test("fires on raw card fields with no processor SDK in the file", async () => {
  const rootDir = "./test-fixtures/vulnerable-app";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });

  const findings = await paymentHandling({ rootDir, files });
  assert.equal(findings.length, 2, `expected checkout.html + payment-mixed.ts to fire; got ${JSON.stringify(findings.map((f: Finding) => f.file))}`);

  const f = findings.find((x: Finding) => x.file === "src/checkout.html");
  assert.ok(f, "expected checkout.html finding");
  assert.equal(f!.category, "client-side-payment");
  assert.equal(f!.severity, "critical");
  assert.match(f!.description, /collects card numbers or CVV codes directly/);
});

test("fires when a real input field appears after an unrelated card-word mention", async () => {
  // Regression: v1 checked only the FIRST card-hint occurrence for input
  // context, so a file whose first mention was a redaction word-list escaped
  // detection even with a genuine <input name="cvv"> later in the file.
  const rootDir = "./test-fixtures/vulnerable-app";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });

  const findings = await paymentHandling({ rootDir, files });
  const mixed = findings.find((f: Finding) => f.file === "src/payment-mixed.ts");
  assert.ok(mixed, "mixed redaction-list + real input file must still fire");
});

test("Stripe Elements hosted fields with card-looking ids do NOT fire (false-positive regression)", async () => {
  const rootDir = "./test-fixtures/clean-app";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });

  const findings = await paymentHandling({ rootDir, files });
  assert.deepEqual(
    findings,
    [],
    "card-field ids alongside Stripe Elements SDK must not produce a finding",
  );
});

test("analytics scrubber listing card/cvv words does NOT fire (dogfood regression)", async () => {
  // Found dogfooding FounderDive: a PostHog client listed "card|cvv" among
  // property names it redacts; no input field exists anywhere near them.
  const rootDir = "./test-fixtures/clean-app";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });

  const findings = await paymentHandling({ rootDir, files });
  const scrubberFindings = findings.filter((f: Finding) => f.file.includes("analytics-scrubber"));
  assert.deepEqual(
    scrubberFindings,
    [],
    "redaction word lists mentioning card/cvv must not produce a finding",
  );
});
