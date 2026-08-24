import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fg from "fast-glob";
import { parseRequirementsTxt, licenseCheck, clearPypiCache } from "../detectors/license-check.js";
import { isReportableSecret, SECRET_SIGNATURES } from "../detectors/secrets-scanner.js";

const exec = promisify(execFile);

test("parseRequirementsTxt extracts names, skips flags/urls/comments", () => {
  const deps = parseRequirementsTxt(
    [
      "fastapi==0.115.0",
      "# a comment",
      "-r base.txt",
      "-e ./local_pkg",
      "git+https://github.com/x/y.git#egg=y",
      "./wheel.whl",
      "uvicorn[standard]>=0.30,<1.0",
      "requests >= 2.31 # inline comment",
      "",
    ].join("\n"),
  );
  assert.deepEqual(deps, ["fastapi", "requests", "uvicorn"]);
});

test("isReportableSecret filters placeholders and anon JWTs, keeps service_role and real keys", () => {
  const b64url = (o: object) =>
    Buffer.from(JSON.stringify(o)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const jwt = (role: string) =>
    `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${b64url({ iss: "supabase", role })}.Qk7xR2pVwY9sLm3TdF8hJcNzBvAeKu5GiO1qWfEyPZt`;

  assert.equal(isReportableSecret("rk_test_mockexample00000000000000"), false);
  assert.equal(isReportableSecret(jwt("anon")), false);
  assert.equal(isReportableSecret(jwt("service_role")), true);
  assert.equal(isReportableSecret("sk_test_REDACTEDFIXTUREKEY00"), true);
});

test("history scan finds secrets that were committed then removed — but not live ones", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "shipcheck-history-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const git = (...args: string[]) => exec("git", ["-C", dir, ...args]);
  const { scanHistorySecrets } = await import("../detectors/secrets-scanner.js");
  const { listFiles } = await import("../lib/list-files.js");

  // Commit 1: leak a key.
  await git("init", "-q");
  await git("config", "user.email", "t@t");
  await git("config", "user.name", "t");
  const leaked = `STRIPE_KEY=sk_test_REDACTEDFIXTUREKEY00\n`;
  await mkdir(join(dir, "src"), { recursive: true });
  await writeFile(join(dir, "src", "billing.ts"), leaked);
  await git("add", "-A");
  await git("commit", "-qm", "add billing");

  // Commit 2: remove it (the classic 'phew, deleted it' move).
  await writeFile(join(dir, "src", "billing.ts"), "// key removed\n");
  await appendFile(join(dir, ".gitignore"), "\n");
  await git("add", "-A");
  await git("commit", "-qm", "remove key");

  const files = await listFiles(dir);
  const { findings, scannedCommits } = await scanHistorySecrets({ rootDir: dir, files });

  assert.equal(scannedCommits > 0, true);
  const stripeHistory = findings.filter((f) => f.description.includes("Stripe Secret Key"));
  assert.equal(stripeHistory.length, 1, `expected the removed key flagged in history; got ${JSON.stringify(findings.map((f) => f.description))}`);
  assert.match(stripeHistory[0].description, /HISTORY/);

  // A value still live in the tree must NOT produce a duplicate history finding.
  const live = `OPENAI_KEY=sk-projAbCdEfGhIjKlMnOpQrStUvWx1234567890abcd\n`;
  await writeFile(join(dir, "src", "ai.ts"), live);
  await git("add", "-A");
  await git("commit", "-qm", "add ai key");
  const files2 = await listFiles(dir);
  const { findings: findings2 } = await scanHistorySecrets({ rootDir: dir, files: files2 });
  assert.equal(findings2.filter((f) => f.description.includes("OpenAI API Key")).length, 0,
    "live keys belong to the regular scan, not history findings");
});

test("PyPI classifier mapping flags GPL deps and stays silent on permissive ones", async (t) => {
  clearPypiCache();
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
    clearPypiCache();
  });
  const pypiJson = (body: object) =>
    Promise.resolve({ ok: true, json: async () => body } as unknown as Response);
  globalThis.fetch = (async (url: string | URL | Request) => {
    if (String(url).includes("gpl-pkg")) {
      return pypiJson({
        info: { license_expression: null, license: null, classifiers: ["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"] },
      });
    }
    return pypiJson({
      info: { license_expression: "MIT", license: null, classifiers: [] },
    });
  }) as typeof fetch;

  const { mkdtemp, writeFile, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "shipcheck-pylicense-"));
  try {
    await writeFile(join(dir, "requirements.txt"), "gpl-pkg==1.0\nmit-pkg==2.0\n");
    const files = await fg(["**/*"], { cwd: dir, dot: true, onlyFiles: true });
    const findings = await licenseCheck({ rootDir: dir, files });

    assert.equal(findings.length, 1, `got ${JSON.stringify(findings.map((f) => f.description))}`);
    assert.equal(findings[0].severity, "critical");
    assert.match(findings[0].description, /gpl-pkg.*GPL-3\.0/);
    assert.equal(findings[0].file, "requirements.txt (gpl-pkg)");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("database URL signature fires on real-shaped DSN, skips localhost and weak passwords", () => {
  const sig = SECRET_SIGNATURES.find((s) => s.name === "Database URL with embedded password")!;
  const test = (s: string) => {
    sig.pattern.lastIndex = 0;
    const m = sig.pattern.exec(s);
    if (!m) return false;
    // mirror validateMatch logic via public path: run through scanner? keep simple:
    return m ? m[0] : false;
  };
  assert.ok(test('postgres://app_user:S3cretValue@db.prod.example.com:5432/app'));
  assert.ok(test('mongodb+srv://admin:Str0ngPass@cluster0.abc12.mongodb.net/db'));
  assert.ok(!test('postgres://user:pass@localhost/db')); // no dotted host
  assert.ok(!test('postgres://postgres:postgres@db')); // container name, weak pw
});
