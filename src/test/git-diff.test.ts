import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { getChangedFiles } from "../lib/git-diff.js";
import { makePathFilter } from "../lib/list-files.js";

test("path filter applies vendored-dir and gitignore rules per-path (scan_diff fast path)", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "shipcheck-filter-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(join(root, ".gitignore"), "secrets.txt\n");
  await mkdir(join(root, ".venv/lib"), { recursive: true });
  await writeFile(join(root, ".venv", "x.py"), "x\n");
  await writeFile(join(root, "app.js"), "x\n");
  await writeFile(join(root, "secrets.txt"), "x\n");

  const filter = await makePathFilter(root);
  assert.equal(await filter("app.js"), true);
  assert.equal(await filter(".venv/x.py"), false, "vendored dir excluded");
  assert.equal(await filter("secrets.txt"), false, "gitignored excluded");
  assert.equal(await filter("ghost.js"), false, "missing file excluded");
});

const exec = promisify(execFile);

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

    const pathFilter = await makePathFilter(root);
  const resolution = await getChangedFiles(root, undefined, pathFilter);

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

  const { makePathFilter } = await import("../lib/list-files.js");
  const pathFilter = await makePathFilter(root);
  const resolution = await getChangedFiles(root, undefined, pathFilter);

  assert.deepEqual(resolution.files.sort(), ["first-app.js", "lib/util.js"]);
});

test("getChangedFiles throws honest errors for non-repos and bad refs", async (t) => {
  const notARepo = await mkdtemp(join(tmpdir(), "shipcheck-norepo-"));
  t.after(() => rm(notARepo, { recursive: true, force: true }));
  await assert.rejects(
    getChangedFiles(notARepo, undefined, async () => true),
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

  await assert.rejects(getChangedFiles(root, "no-such-branch", async () => true), /does not exist/);
});
