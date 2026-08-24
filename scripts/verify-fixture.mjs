import { secretsScanner } from "../dist/detectors/secrets-scanner.js";
import { licenseCheck } from "../dist/detectors/license-check.js";
import { unauthEndpoints } from "../dist/detectors/unauth-endpoints.js";
import { piiConsentCheck } from "../dist/detectors/pii-consent-check.js";
import { paymentHandling } from "../dist/detectors/payment-handling.js";

import fg from "fast-glob";

const detectors = { secretsScanner, licenseCheck, unauthEndpoints, piiConsentCheck, paymentHandling };

for (const rootDir of ["./test-fixtures/vulnerable-app", "./test-fixtures/vulnerable-flutter-app"]) {
  console.log(`\n########## ${rootDir} ##########`);
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true, ignore: ["**/.git/**"] });

  for (const [name, fn] of Object.entries(detectors)) {
    const findings = await fn({ rootDir, files });
    console.log(`\n=== ${name}: ${findings.length} finding(s) ===`);
    for (const f of findings) {
      console.log(`  [${f.severity}] ${f.file}${f.line ? ':' + f.line : ''} — ${f.description}`);
    }
  }
}
