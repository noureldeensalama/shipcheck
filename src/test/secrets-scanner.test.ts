import { test } from "node:test";
import assert from "node:assert/strict";
import fg from "fast-glob";
import { secretsScanner } from "../detectors/secrets-scanner.js";
import type { Finding } from "../types.js";

const rootDir = "./test-fixtures/vulnerable-app";

test("secrets scanner flags committed .env and the key inside it", async () => {
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true, ignore: ["**/.git/**"] });
  const findings = await secretsScanner({ rootDir, files });

  assert.ok(findings.length >= 2, `expected at least 2 findings, got ${findings.length}`);

  const envFileFinding = findings.find((f: Finding) => f.file === ".env" && !f.line);
  assert.ok(envFileFinding, "expected a finding for the committed .env file itself");
  assert.equal(envFileFinding!.severity, "critical");
  assert.equal(envFileFinding!.category, "exposed-secrets");

  const keyFinding = findings.find((f: Finding) => f.file === ".env" && f.line !== undefined);
  assert.ok(keyFinding, "expected a finding for the key content in .env");
  assert.match(keyFinding!.description, /Stripe Secret Key/);
  // shape contract
  for (const f of findings) {
    for (const key of ["category", "severity", "file", "description", "why_it_matters", "suggested_fix"]) {
      assert.ok(key in f, `finding missing field '${key}'`);
    }
  }
});

test(".env.example with placeholder values does not fire (false-positive regression)", async () => {
  const rootDir = "./test-fixtures/clean-app";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });
  const findings = await secretsScanner({ rootDir, files });
  const envExampleFindings = findings.filter((f: Finding) => f.file.includes(".env"));
  assert.deepEqual(
    envExampleFindings,
    [],
    `.env.example must not produce findings; got: ${JSON.stringify(envExampleFindings)}`,
  );
});

test("mock/dummy placeholder keys in test helpers do NOT fire (dogfood regression)", async () => {
  // Found dogfooding FounderDive: ~20 e2e scripts + a mock-provider module
  // used shape-correct but obviously fake keys (rk_test_mock…, ghp_mock0000…,
  // ci-test Supabase JWTs) and every one was flagged as high severity.
  const rootDir = "./test-fixtures/clean-app";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });
  const findings = await secretsScanner({ rootDir, files });
  const mockFindings = findings.filter((f: Finding) => f.file.includes("mock_helpers"));
  assert.deepEqual(
    mockFindings,
    [],
    `placeholder-shaped keys must not produce findings; got: ${JSON.stringify(mockFindings)}`,
  );
});

test("google-services.json Firebase client config does NOT fire (dogfood regression)", async () => {
  // Found dogfooding Fitloom: the committed google-services.json API key is
  // client-config-by-design, not an exposed credential.
  const rootDir = "./test-fixtures/clean-app";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });
  const findings = await secretsScanner({ rootDir, files });
  const fbFindings = findings.filter((f: Finding) => f.file.includes("google-services.json"));
  assert.deepEqual(
    fbFindings,
    [],
    `Firebase client config must not produce findings; got: ${JSON.stringify(fbFindings)}`,
  );
});

test("same credential in multiple files deduplicates into one finding with locations", async () => {
  // .env and src/duplicate_key.py contain the identical Stripe key. Two
  // separate findings would repeat identical prose N times into agent context.
  const rootDir = "./test-fixtures/vulnerable-app";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });

  const findings = await secretsScanner({ rootDir, files });
  const sharedKeyFindings = findings.filter(
    (f: Finding) => f.description.includes("Stripe Secret Key") && f.file === ".env",
  );
  assert.equal(sharedKeyFindings.length, 1);

  const f = sharedKeyFindings[0];
  assert.ok(f.locations, "multi-location finding must carry a locations array");
  assert.equal(f.locations!.length, 2);
  assert.ok(f.locations!.some((l) => l.startsWith("src/duplicate_key.py")), "second location listed");
  assert.match(f.description, /appears in 2 places/);
});

test("project-prefixed env variants (config/backend.env) fire as committed env files", async () => {
  // dotenv conventions like backend.env / config.env are real committed-env
  // leaks; only dot-prefixed names were caught before this fixture existed.
  const rootDir = "./test-fixtures/vulnerable-app";
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });

  const findings = await secretsScanner({ rootDir, files });

  const envFileFinding = findings.find((f: Finding) => f.file === "config/backend.env" && !f.line);
  assert.ok(envFileFinding, "expected a committed-env-file finding for config/backend.env");
  assert.equal(envFileFinding!.severity, "critical");

  // ...plus its own distinct key content
  const keyFinding = findings.find((f: Finding) => f.file === "config/backend.env" && f.line !== undefined);
  assert.ok(keyFinding, "expected the key inside config/backend.env to be flagged");
});
