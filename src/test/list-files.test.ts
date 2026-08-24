import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { listFiles } from "../lib/list-files.js";

async function makeTree(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "shipcheck-listfiles-"));
  const write = async (rel: string, content = "x\n") => {
    const p = join(root, rel);
    await mkdir(join(p, ".."), { recursive: true });
    await writeFile(p, content);
  };

  await write("src/app.js");
  await write(".env", "SECRET=1\n");
  await write("node_modules/left-pad/index.js");
  await write(".venv/lib/python3.14/site-packages/ecdsa/keys.py");
  await write("venv/lib/site-packages/foo.py");
  await write(".tox/py310/lib/bar.py");
  await write("dist/bundle.js");
  await write("build/output.js");
  await write("coverage/lcov.info");
  // gitignored path must be dropped even though it's project source
  await write("server/private-keys.txt");

  await writeFile(
    join(root, ".gitignore"),
    "private-keys.txt\n",
  );
  return root;
}

test("listFiles excludes vendored trees and respects .gitignore", async () => {
  const root = await makeTree();
  try {
    const files = await listFiles(root);
    const sorted = files.sort();

    assert.deepEqual(sorted, [".env", ".gitignore", "src/app.js"], `got: ${JSON.stringify(sorted)}`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("listFiles works on a directory with no .gitignore", async () => {
  const root = await mkdtemp(join(tmpdir(), "shipcheck-listfiles2-"));
  try {
    await writeFile(join(root, "only.js"), "x\n");
    await mkdir(join(root, "node_modules"));
    await writeFile(join(root, "node_modules", "dep.js"), "x\n");

    const files = await listFiles(root);
    assert.deepEqual(files.sort(), ["only.js"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
