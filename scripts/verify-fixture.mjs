// Acceptance gate for the built-in fixture apps: asserts that each detector
// produces its expected findings — exits non-zero on any mismatch so CI and
// local runs fail loudly instead of printing numbers nobody checks.
import { secretsScanner } from "../dist/detectors/secrets-scanner.js";
import { licenseCheck } from "../dist/detectors/license-check.js";
import { unauthEndpoints } from "../dist/detectors/unauth-endpoints.js";
import { piiConsentCheck } from "../dist/detectors/pii-consent-check.js";
import { paymentHandling } from "../dist/detectors/payment-handling.js";

import fg from "fast-glob";

const detectors = { secretsScanner, licenseCheck, unauthEndpoints, piiConsentCheck, paymentHandling };

/** Minimum findings each detector must produce on the vulnerable fixture. */
const VULNERABLE_APP_MINIMUMS = {
  secretsScanner: 2, // committed .env + key content (+ prefixed env variant)
  licenseCheck: 0,
  unauthEndpoints: 4, // debug route, FastAPI orders, Express user, 2x Next.js
  piiConsentCheck: 1,
  paymentHandling: 2, // checkout.html + mixed redaction/real-input file
};

const FLUTTER_APP_MINIMUMS = {
  secretsScanner: 0,
  licenseCheck: 1, // lgpl ffmpeg_kit_flutter
  unauthEndpoints: 0,
  piiConsentCheck: 0,
  paymentHandling: 0,
};

const EXPECTATIONS = new Map([
  ["./test-fixtures/vulnerable-app", VULNERABLE_APP_MINIMUMS],
  ["./test-fixtures/vulnerable-flutter-app", FLUTTER_APP_MINIMUMS],
]);

let failures = 0;
function check(name, cond) {
  if (cond) console.log(`ok - ${name}`);
  else {
    failures++;
    console.error(`FAIL - ${name}`);
  }
}

for (const [rootDir, minimums] of EXPECTATIONS) {
  console.log(`\n########## ${rootDir} ##########`);
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true, ignore: ["**/.git/**"] });

  const counts = {};
  for (const [name, fn] of Object.entries(detectors)) {
    const findings = await fn({ rootDir, files });
    counts[name] = findings.length;
    console.log(`${name}: ${findings.length} finding(s)`);
    for (const f of findings) {
      console.log(`  [${f.severity}] ${f.file}${f.line ? ":" + f.line : ""} — ${f.description}`);
    }
    check(
      `${rootDir} ${name} >= ${minimums[name]}`,
      counts[name] >= minimums[name],
      `got ${counts[name]}, expected at least ${minimums[name]}`,
    );
  }
}

process.exit(failures > 0 ? 1 : 0);
