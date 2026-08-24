import fg from "fast-glob";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { createRequire } from "node:module";

// `ignore` is a CJS package whose type declarations don't interop cleanly
// with NodeNext + esModuleInterop as a default import; requiring it directly
// sidesteps the mismatch rather than fighting the type resolver.
const require = createRequire(import.meta.url);
interface Ignore {
  add(s: string): Ignore;
  ignores(p: string): boolean;
}
const ignore = require("ignore") as (opts?: unknown) => Ignore;

/**
 * Vendored dependency trees are third-party code, not project source.
 * Scanning them produces overwhelming false-positive noise (library test
 * fixtures with example keys, docstring examples) — every detector operates
 * on project-owned files only. license-check reads installed packages'
 * package.json / pubspec data directly from disk and does not need them in
 * the file list.
 */
export const DEFAULT_EXCLUDES = [
  "**/.git/**",
  "**/dist/**",
  "**/build/**",
  "**/.next/**",
  "**/coverage/**",
  "**/node_modules/**",
  "**/.venv/**",
  "**/venv/**",
  "**/.tox/**",
];

/**
 * Lists candidate files for scanning: everything under rootDir minus the
 * default excludes and whatever the repo's own .gitignore ignores.
 * Shared by the MCP server and the dogfood runner so their behavior can't drift.
 */
export async function listFiles(rootDir: string): Promise<string[]> {
  let gitignoreContent = "";
  try {
    gitignoreContent = await readFile(join(rootDir, ".gitignore"), "utf-8");
  } catch {
    // no .gitignore, fine
  }
  const ig = ignore().add(gitignoreContent);

  const all = await fg(["**/*"], {
    cwd: rootDir,
    dot: true,
    onlyFiles: true,
    ignore: DEFAULT_EXCLUDES,
    // A symlink pointing outside the repo (to $HOME, /etc, another project)
    // must not drag external trees into a scan — or leak their contents into
    // findings as if they were project source.
    followSymbolicLinks: false,
  });

  return all.filter((f) => !ig.ignores(f));
}
