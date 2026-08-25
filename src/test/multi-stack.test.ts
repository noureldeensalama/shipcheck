import { test } from "node:test";
import assert from "node:assert/strict";
import fg from "fast-glob";
import { unauthEndpoints } from "../detectors/unauth-endpoints.js";
import { licenseCheck } from "../detectors/license-check.js";
import { detectProjectTypes } from "../lib/project-types.js";
import type { Finding } from "../types.js";

const rootDir = "./test-fixtures/multi-stack";

async function scan() {
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });
  const findings = await unauthEndpoints({ rootDir, files });
  return { files, findings };
}

test("Go gin routes: unguarded fires, middleware-arg guard does not, group prefix composes", async () => {
  const { findings } = await scan();
  const go = findings.filter((f) => f.file === "go-api/routes.go");
  const descriptions = go.map((f) => f.description);

  assert.ok(descriptions.some((d) => d.includes("/api/users")), JSON.stringify(descriptions));
  assert.ok(!descriptions.some((d) => d.includes("/admin/stats")), "guarded admin route must not fire");
});

test("Laravel: unguarded account route fires, ->middleware('auth') does not", async () => {
  const { findings } = await scan();
  const php = findings.filter((f) => f.file === "laravel-app/routes/web.php");

  assert.equal(php.length, 1);
  assert.match(php[0].description, /\/account\/settings/);
});

test("Spring: class prefix composes; @PreAuthorize route stays silent", async () => {
  const { findings } = await scan();
  const spring = findings.filter((f) => f.file === "spring-app/UserController.java");

  assert.equal(spring.length, 1);
  assert.match(spring[0].description, /\/api\/v1\/profile/);
});

test("Flask: blueprint url_prefix composes; @login_required stays silent", async () => {
  const { findings } = await scan();
  const flask = findings.filter((f) => f.file === "flask-app/app.py");

  assert.equal(flask.length, 1);
  assert.match(flask[0].description, /Flask route '\/api\/user\/export'/);
});

test("composer.lock licenses checked offline; dev packages skipped", async () => {
  const files = await fg(["**/*"], { cwd: rootDir, dot: true, onlyFiles: true });
  const findings = await licenseCheck({ rootDir, files });

  const gpl = findings.find((f: Finding) => f.description.includes("acme/gpl-bundled"));
  assert.ok(gpl, `expected GPL composer dep flagged; got ${JSON.stringify(findings.map((f) => f.file))}`);
  assert.equal(gpl!.severity, "critical");

  const noLicense = findings.find((f: Finding) => f.description.includes("no-license-pkg"));
  assert.ok(noLicense, "empty license array must surface as undetermined");

  assert.ok(
    !findings.some((f: Finding) => f.description.includes("phpunit-thing")),
    "dev packages are out of shipping scope",
  );
  // MIT package silent
  assert.ok(!findings.some((f: Finding) => f.description.includes("http-kit")));
});

test("project types inferred from manifests", () => {
  assert.deepEqual(detectProjectTypes(["pubspec.yaml", "backend/go.mod"]), ["Flutter/Dart", "Go module"]);
  assert.deepEqual(detectProjectTypes(["app/package.json"]), ["Node.js"]);
});
