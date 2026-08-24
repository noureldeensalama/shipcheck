import { test } from "node:test";
import assert from "node:assert/strict";
import fg from "fast-glob";
import { readFile } from "node:fs/promises";
import { licenseCheck, parsePubspecLock, classifyPubLicenseTags } from "../detectors/license-check.js";
import type { Finding } from "../types.js";

const rootDir = "./test-fixtures/vulnerable-app";

test("license checker is silent when node_modules are not installed (documented v1 behavior)", async () => {
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });
  const findings = await licenseCheck({ rootDir, files });
  // vulnerable-app has no node_modules — uninstalled deps are skipped, not flagged.
  const npmFindings = findings.filter((f: Finding) => f.file.startsWith("node_modules/"));
  assert.deepEqual(npmFindings, []);
});

test("parsePubspecLock extracts hosted packages with versions", async () => {
  const lockContent = await readFile("./test-fixtures/vulnerable-flutter-app/pubspec.lock", "utf-8");
  const deps = parsePubspecLock(lockContent);
  const names = deps.map((d) => d.name);
  assert.ok(names.includes("ffmpeg_kit_flutter"));
  assert.ok(names.includes("http"));
  assert.ok(names.includes("shared_preferences"));
  const ffmpeg = deps.find((d) => d.name === "ffmpeg_kit_flutter")!;
  assert.equal(ffmpeg.version, "6.0.3");
  // every parsed dep has name + version
  for (const d of deps) {
    assert.ok(d.name.length > 0);
    assert.ok(/^\d+\.\d+\.\d+/.test(d.version), `unexpected version format '${d.version}'`);
  }
});

test("classifyPubLicenseTags maps copyleft tags correctly and ignores permissive ones", () => {
  assert.equal(classifyPubLicenseTags(["lgpl-3.0"]), "medium");
  assert.equal(classifyPubLicenseTags(["mpl-2.0"]), "medium");
  assert.equal(classifyPubLicenseTags(["gpl-3.0"]), "critical");
  assert.equal(classifyPubLicenseTags(["agpl-3.0"]), "critical");
  // permissive licenses never fire
  assert.equal(classifyPubLicenseTags(["mit"]), null);
  assert.equal(classifyPubLicenseTags(["bsd-3-clause"]), null);
  assert.equal(classifyPubLicenseTags(["apache-2.0"]), null);
  // classification-only tags are not licenses
  assert.equal(classifyPubLicenseTags([]), null);
  assert.equal(classifyPubLicenseTags(["fsf-libre", "osi-approved"]), null);
});

test("unresolvable pub.dev package produces an explicit 'could not be determined' finding", async (t) => {
  // Deterministic offline test: stub fetch to simulate pub.dev being unreachable.
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  globalThis.fetch = (async () => {
    throw new Error("simulated network failure");
  }) as typeof fetch;

  const flutterRoot = "./test-fixtures/vulnerable-flutter-app";
  const files = await fg(["**/*"], { cwd: flutterRoot, dot: true, onlyFiles: true });
  const findings = await licenseCheck({ rootDir: flutterRoot, files });

  assert.ok(findings.length > 0, "network failure must surface findings, not silence");
  for (const f of findings) {
    assert.equal(f.category, "copyleft-license");
    assert.equal(f.severity, "medium");
    assert.match(f.description, /could not be determined/);
  }
});
