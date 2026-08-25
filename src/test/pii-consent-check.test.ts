import { test } from "node:test";
import assert from "node:assert/strict";
import fg from "fast-glob";
import { piiConsentCheck } from "../detectors/pii-consent-check.js";

test("fires when data collection exists but no privacy/consent artifact is found", async () => {
  const rootDir = "./test-fixtures/vulnerable-app";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });

  const findings = await piiConsentCheck({ rootDir, files });
  assert.equal(findings.length, 1);

  const f = findings[0];
  assert.equal(f.category, "pii-no-consent");
  assert.equal(f.severity, "high");
  assert.match(f.description, /Google Analytics/);
  assert.match(f.description, /Email input field/);
  assert.match(f.description, /no privacy policy or consent popup anywhere in the project/);
});

test("bare 'privacy policy' mentions in code do NOT count as an artifact (dogfood tightening)", async () => {
  // launch-checklist.ts contains the words "privacy policy" and "consent" in
  // checklist strings. Under the old word-match rule this suppressed the
  // finding; only links/routes/dedicated files count now.
  const rootDir = "./test-fixtures/vulnerable-app";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });

  const findings = await piiConsentCheck({ rootDir, files });
  assert.equal(findings.length, 1, "checklist mentions must not suppress the finding");
});

test("same collectors with a privacy policy artifact present do NOT fire (false-positive regression)", async () => {
  const rootDir = "./test-fixtures/clean-app";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });

  const findings = await piiConsentCheck({ rootDir, files });
  assert.deepEqual(findings, [], "a privacy-policy artifact must suppress the finding");
});
