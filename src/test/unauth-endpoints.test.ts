import { test } from "node:test";
import assert from "node:assert/strict";
import fg from "fast-glob";
import { unauthEndpoints } from "../detectors/unauth-endpoints.js";
import type { Finding } from "../types.js";

const rootDir = "./test-fixtures/vulnerable-app";

async function scan(rootDir: string) {
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });
  return unauthEndpoints({ rootDir, files });
}

function findByFile(findings: Finding[], suffix: string): Finding | undefined {
  return findings.find((f) => f.file === suffix);
}

test("Express route handling user data without auth fires", async () => {
  const findings = await scan(rootDir);
  const f = findByFile(findings, "src/routes/user.js");
  assert.ok(f, "expected Express user route to fire");
  assert.equal(f!.category, "unauthenticated-endpoint");
  assert.equal(f!.severity, "high");
  assert.match(f!.description, /Express route '\/api\/user\/profile'/);
});

test("FastAPI route handling user data without auth fires", async () => {
  const findings = await scan(rootDir);
  const f = findByFile(findings, "src/routes/orders.py");
  assert.ok(f, "expected FastAPI user orders route to fire");
  assert.match(f!.description, /FastAPI route '\/api\/user\/orders'/);
});

test("Next.js App Router route without auth fires", async () => {
  const findings = await scan(rootDir);
  const f = findByFile(findings, "app/api/user/profile/route.ts");
  assert.ok(f, "expected App Router user profile route to fire");
  assert.match(f!.description, /Next\.js API route '\/api\/user\/profile'/);
});

test("Next.js Pages Router route without auth fires", async () => {
  const findings = await scan(rootDir);
  const f = findByFile(findings, "pages/api/account/settings.ts");
  assert.ok(f, "expected Pages Router account settings route to fire");
  assert.match(f!.description, /Next\.js API route '\/api\/account\/settings'/);
});

test("guarded Next.js routes do NOT fire (false-positive regression)", async () => {
  const findings = await scan(rootDir);
  // getServerSession guard in the handler
  const guardedAppRouter = findByFile(findings, "app/api/admin/stats/route.ts");
  assert.equal(guardedAppRouter, undefined, "guarded App Router route must not be flagged");
  // non-sensitive path
  const publicHealth = findByFile(findings, "pages/api/public/health.ts");
  assert.equal(publicHealth, undefined, "non-sensitive public route must not be flagged");
});

test("guarded FastAPI route does NOT fire (false-positive regression)", async () => {
  const findings = await scan(rootDir);
  const guarded = findByFile(findings, "src/routes/admin_invoices.py");
  assert.equal(guarded, undefined, "Depends(get_current_user) route must not be flagged");
});

test("custom-named guard dependency (Depends(require_admin)) does NOT fire (dogfood regression)", async () => {
  // Found dogfooding FounderDive: every /admin/users route takes
  // admin=Depends(require_admin), which the v1 idiom list didn't recognize,
  // producing ~20 false positives in one repo.
  const findings = await scan(rootDir);
  const guarded = findByFile(findings, "src/routes/admin_users_guarded.py");
  assert.equal(guarded, undefined, "route with Depends(require_admin) must not be flagged");
});

test("unguarded /api/debug route touching user data fires (dogfood recall regression)", async () => {
  // Found dogfooding FounderDive: an unauthenticated debug route queried
  // user_profiles with a service key but wasn't flagged because its path had
  // no sensitive-path keyword. Debug/internal routes are now in scope.
  const findings = await scan(rootDir);
  const f = findByFile(findings, "src/routes/debug_dump.py");
  assert.ok(f, "expected unguarded debug route to fire");
  assert.match(f!.description, /FastAPI route '\/debug\/user-count'/);
});

test("guarded /api/debug route does NOT fire", async () => {
  const findings = await scan(rootDir);
  const guarded = findByFile(findings, "src/routes/debug_guarded.py");
  assert.equal(guarded, undefined, "guarded debug route must not be flagged");
});

test("hand-rolled Authorization-header token guard does NOT fire (dogfood regression)", async () => {
  // Found dogfooding FounderDive: a one-shot migration endpoint guarded by an
  // in-handler bearer-token check on `authorization: str = Header(None)` —
  // no Depends() anywhere — was flagged as unauthenticated.
  const findings = await scan(rootDir);
  const guarded = findByFile(findings, "src/routes/migration_guarded.py");
  assert.equal(guarded, undefined, "header-token-guarded route must not be flagged");
});
