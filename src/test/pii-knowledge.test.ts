import { test } from "node:test";
import assert from "node:assert/strict";
import fg from "fast-glob";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { piiConsentCheck } from "../detectors/pii-consent-check.js";

test("modern analytics collectors (PostHog, Meta Pixel, Clarity) fire with no artifact", async () => {
  // Dogfooding found PostHog in a real repo, invisible to the v1 collector list.
  const dir = await mkdtemp(join(tmpdir(), "shipcheck-pii-"));
  try {
    await mkdir(join(dir, "src"), { recursive: true });
    await writeFile(
      join(dir, "src", "analytics.ts"),
      [
        'import posthog from "posthog-js";',
        'posthog.init("phc_test", { api_host: "https://us.i.posthog.com" });',
        "",
        'fbq("init", "1234567890");',
        "",
        'const clr = document.createElement("script");',
        'clr.src = "https://www.clarity.ms/tag/xyz";',
        "",
      ].join("\n"),
    );
    const files = await fg(["**/*"], { cwd: dir, dot: true, onlyFiles: true });
    const findings = await piiConsentCheck({ rootDir: dir, files });

    assert.equal(findings.length, 1);
    for (const name of ["PostHog", "Meta Pixel", "Microsoft Clarity"]) {
      assert.ok(findings[0].description.includes(name), `${name} missing from: ${findings[0].description}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
