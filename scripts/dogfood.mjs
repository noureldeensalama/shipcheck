// Dogfood runner: runs all detectors against a real repo exactly like
// scan_repo does (same file listing, same detectors) and prints JSON.
import fg from "fast-glob";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ignore = require("ignore");

const { secretsScanner } = await import("../dist/detectors/secrets-scanner.js");
const { licenseCheck } = await import("../dist/detectors/license-check.js");
const { unauthEndpoints } = await import("../dist/detectors/unauth-endpoints.js");
const { piiConsentCheck } = await import("../dist/detectors/pii-consent-check.js");
const { paymentHandling } = await import("../dist/detectors/payment-handling.js");

const rootDir = process.argv[2];
if (!rootDir) {
  console.error("usage: node scripts/dogfood.mjs <repo-path>");
  process.exit(1);
}

const DEFAULT_EXCLUDES = [
  "**/.git/**",
  "**/dist/**",
  "**/build/**",
  "**/.next/**",
  "**/coverage/**",
  "**/node_modules/**",
  "**/.venv/**",
  "**/venv/**",
  "**/.tox/**",
];
let gitignoreContent = "";
try {
  gitignoreContent = await readFile(join(rootDir, ".gitignore"), "utf-8");
} catch {}
const ig = ignore().add(gitignoreContent);
const all = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true, ignore: DEFAULT_EXCLUDES });
const files = all.filter((f) => !ig.ignores(f));

const detectors = { secretsScanner, licenseCheck, unauthEndpoints, piiConsentCheck, paymentHandling };
const out = {};
for (const [name, fn] of Object.entries(detectors)) {
  try {
    out[name] = await fn({ rootDir, files });
  } catch (err) {
    out[name] = [{ error: String(err.message ?? err) }];
  }
}
console.log(JSON.stringify(out, null, 2));
