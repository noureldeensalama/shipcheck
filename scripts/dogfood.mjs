// Dogfood runner: runs all detectors against a real repo exactly like
// scan_repo does (same shared file listing, same detectors) and prints JSON.
const { listFiles } = await import("../dist/lib/list-files.js");
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

const files = await listFiles(rootDir);

const detectors = { secretsScanner, licenseCheck, unauthEndpoints, piiConsentCheck, paymentHandling };
const contentCache = new Map();
const out = {};
for (const [name, fn] of Object.entries(detectors)) {
  try {
    out[name] = await fn({ rootDir, files, contentCache });
  } catch (err) {
    out[name] = [{ error: String(err.message ?? err) }];
  }
}
console.log(JSON.stringify(out, null, 2));
