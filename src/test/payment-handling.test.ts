import { test } from "node:test";
import assert from "node:assert/strict";
import fg from "fast-glob";
import { paymentHandling } from "../detectors/payment-handling.js";
import type { Finding } from "../types.js";

test("fires on raw card fields with no processor SDK in the file", async () => {
  const rootDir = "./test-fixtures/vulnerable-app";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });

  const findings = await paymentHandling({ rootDir, files });
  assert.equal(findings.length, 1);

  const f = findings[0];
  assert.equal(f.category, "client-side-payment");
  assert.equal(f.severity, "critical");
  assert.equal(f.file, "src/checkout.html");
  assert.match(f.description, /raw card-number\/CVV field/);
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
