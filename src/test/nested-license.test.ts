import { test } from "node:test";
import assert from "node:assert/strict";
import fg from "fast-glob";
import { licenseCheck } from "../detectors/license-check.js";
import type { Finding } from "../types.js";

test("nested package.json dependencies are license-checked (dogfood regression)", async () => {
  // Found dogfooding FounderDive: frontend/package.json with 20 deps was
  // invisible to a root-only check. The fixture mirrors that layout: a root
  // package.json plus a frontend/ one, each with installed fake packages.
  const rootDir = "./test-fixtures/vulnerable-nested-node";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });

  const findings = await licenseCheck({ rootDir, files });
  const filesFlagged = findings.map((f: Finding) => f.file);

  assert.ok(
    filesFlagged.includes("frontend/node_modules/gpl-bundled-lib/package.json"),
    `expected nested GPL dep flagged; got ${JSON.stringify(filesFlagged)}`,
  );
  assert.ok(
    filesFlagged.includes("node_modules/agpl-server-tool/package.json"),
    `expected root AGPL dep flagged; got ${JSON.stringify(filesFlagged)}`,
  );
  assert.equal(findings.find((f: Finding) => f.file.includes("agpl-server-tool"))!.severity, "critical");
  // MIT dep must stay silent
  assert.equal(filesFlagged.filter((f) => f.includes("nice-mit-lib")).length, 0);
});
