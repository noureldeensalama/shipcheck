import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolveDiffFiles, getChangedFiles } from "../lib/git-diff.js";

const exec = promisify(execFile);

test("resolveDiffFiles intersects changed paths with available files and drops deletions", () => {
  const files = resolveDiffFiles(
    ["src/app.js", "src/deleted.js", "node_modules/pkg/index.js", ".venv/lib/x.py"],
    ["src/new-file.ts"],
    ["src/app.js", "src/new-file.ts", "src/untouched.js"], // what listFiles returned
  );
  assert.deepEqual(files, ["src/app.js", "src/new-file.ts"]);
});

test("getChangedFiles sees modified + untracked work vs HEAD in a real repo", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "shipcheck-diff-"));
  t.after(() => rm(root, { recursive: true, force: true }));

  const git = (...args: string[]) => exec("git", ["-C", root, ...args]);
  await git("init", "-q");
  await git("config", "user.email", "t@t");
  await git("config", "user.name", "t");

  await writeFile(join(root, "committed.js"), "const a = 1;\n");
  await mkdir(join(root, ".venv"), { recursive: true });
  await writeFile(join(root, ".venv", "lib.py"), "x = 'AKIA1234'\n");
  await writeFile(join(root, ".gitignore"), ".venv/\n");
  await git("add", "-A");
  await git("commit", "-qm", "init");

  // simulate the founder's working tree: edit one file, add one new file,
  // delete nothing, plus an ignored file that must never appear
  await appendFile(join(root, "committed.js"), "const b = 2;\n");
  await writeFile(join(root, "brand-new.js"), "const c = 3;\n");
  await writeFile(join(root, ".venv", "leak.py"), "token='ghp_" + "A".repeat(36) + "'\n");

  const available = (await import("../lib/list-files.js")).listFiles;
  const listed = await available(root);
  const resolution = await getChangedFiles(root, undefined, listed);

  assert.deepEqual(resolution.files, ["brand-new.js", "committed.js"]);
  // 1 modified (committed.js) + 1 untracked (brand-new.js); the .venv leak
  // never reaches this count — git's own exclude-standard filter drops it.
  assert.equal(resolution.reportedChanged, 2);
});

test("getChangedFiles on a repo with zero commits scans untracked files (founder day one)", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "shipcheck-fresh-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const git = (...args: string[]) => exec("git", ["-C", root, ...args]);
  await git("init", "-q");
  await writeFile(join(root, "first-app.js"), "const x = 1;\n");
  await mkdir(join(root, "lib"), { recursive: true });
  await writeFile(join(root, "lib", "util.js"), "export const y = 2;\n");

  const { listFiles } = await import("../lib/list-files.js");
  const listed = await listFiles(root);
  const resolution = await getChangedFiles(root, undefined, listed);

  assert.deepEqual(resolution.files.sort(), ["first-app.js", "lib/util.js"]);
});

test("getChangedFiles throws honest errors for non-repos and bad refs", async (t) => {
  const notARepo = await mkdtemp(join(tmpdir(), "shipcheck-norepo-"));
  t.after(() => rm(notARepo, { recursive: true, force: true }));
  await assert.rejects(
    getChangedFiles(notARepo, undefined, []),
    /not a git repository.*scan_repo/,
  );

  const root = await mkdtemp(join(tmpdir(), "shipcheck-badref-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const git = (...args: string[]) => exec("git", ["-C", root, ...args]);
  await git("init", "-q");
  await git("config", "user.email", "t@t");
  await git("config", "user.name", "t");
  await writeFile(join(root, "a.txt"), "hi\n");
  await git("add", "-A");
  await git("commit", "-qm", "init");

  await assert.rejects(getChangedFiles(root, "no-such-branch", ["a.txt"]), /does not exist/);
});
