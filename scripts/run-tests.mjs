#!/usr/bin/env node
// Cross-shell/cross-version test runner: `node --test` behaves differently
// for directory and glob arguments across Node 20/22 and cmd.exe, so we
// enumerate compiled test files ourselves and pass explicit paths.
import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const dir = join("dist", "test");
const files = readdirSync(dir)
  .filter((f) => f.endsWith(".test.js"))
  .map((f) => join(dir, f));

if (files.length === 0) {
  console.error("no compiled test files found in dist/test — did tsc run?");
  process.exit(1);
}

const result = spawnSync(process.execPath, ["--test", ...files], { stdio: "inherit" });
process.exit(result.status ?? 1);
