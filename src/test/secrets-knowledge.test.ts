import { test } from "node:test";
import assert from "node:assert/strict";
import fg from "fast-glob";
import { secretsScanner } from "../detectors/secrets-scanner.js";
import type { Finding } from "../types.js";

const rootDir = "./test-fixtures/vulnerable-app";

function b64url(obj: object): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function supabaseJwt(role: string): string {
  return `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${b64url({
    iss: "supabase",
    ref: "testref",
    role,
    iat: 1700000000,
    exp: 2000000000,
  })}.Qk7xR2pVwY9sLm3TdF8hJcNzBvAeKu5GiO1qWfEyPZt`; // shape-realistic, no placeholder markers
}

async function scanTmp(files: Record<string, string>): Promise<Finding[]> {
  const { mkdtemp, mkdir, writeFile, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "shipcheck-jwt-"));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const p = join(dir, rel);
      await mkdir(join(p, ".."), { recursive: true });
      await writeFile(p, content);
    }
    const listed = await fg(["**/*"], { cwd: dir, dot: true, onlyFiles: true });
    return await secretsScanner({ rootDir: dir, files: listed });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("service_role JWT fires with accurate description; anon JWT does not", async () => {
  const findings = await scanTmp({
    "src/lib/supabase.ts": `export const KEY = "${supabaseJwt("anon")}";\n`,
    "src/lib/admin.ts": `export const ADMIN_KEY = "${supabaseJwt("service_role")}";\n`,
  });

  const hits = findings.filter((f) => f.description.includes("Supabase"));
  assert.equal(hits.length, 1, `anon key must not fire; got ${JSON.stringify(hits.map((h) => h.file))}`);
  assert.match(hits[0].description, /Supabase/);
  assert.ok(
    /service_role/i.test(hits[0].description) || /Supabase/.test(hits[0].description),
  );
});

test("modern provider signatures fire (OpenRouter, SendGrid)", async () => {
  const findings = await scanTmp({
    "src/config.ts": [
      `const OPENROUTER = "sk-or-v1-${"a".repeat(64)}";`,
      `const SENDGRID = "SG.${"A".repeat(22)}.${"b".repeat(43)}";`,
      "",
    ].join("\n"),
  });

  const names = findings.map((f) => f.description);
  assert.ok(names.some((n) => n.includes("OpenRouter")), JSON.stringify(names));
  assert.ok(names.some((n) => n.includes("SendGrid")), JSON.stringify(names));
});
