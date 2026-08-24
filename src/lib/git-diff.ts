import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);

/**
 * Resolves the set of files a scan_diff should look at, given raw git output:
 * changed paths (from `git diff --name-only --diff-filter=ACMR`) plus
 * untracked-but-not-ignored files (from `git ls-files --others`). Deleted
 * files can't be scanned, and anything not in the available-files list
 * (vendored dirs, gitignored paths) is dropped — identical rules as scan_repo,
 * so a diff scan and a full scan of the same tree can't disagree.
 */
export function resolveDiffFiles(
  changedNames: string[],
  untrackedNames: string[],
  availableFiles: string[],
): string[] {
  const available = new Set(availableFiles);
  const combined = [...changedNames, ...untrackedNames];
  const picked = new Set<string>();
  for (const name of combined) {
    // normalize separators for windows-style output just in case
    const rel = name.split("\\").join("/");
    if (!rel || rel.endsWith("/")) continue;
    if (available.has(rel)) picked.add(rel);
  }
  return [...picked].sort();
}

export interface DiffResolution {
  /** Relative paths to scan (already intersected with availableFiles) */
  files: string[];
  /** Total paths git reported as changed (before availability filtering) */
  reportedChanged: number;
}

/**
 * Asks git at rootDir which files changed vs. `base` (default HEAD: staged +
 * unstaged work) and which are new-untracked, then intersects with
 * availableFiles (the same listing scan_repo uses) so vendored dirs,
 * gitignored paths, and deleted files never reach detectors.
 * Throws with an honest message when rootDir is not a git repository or base
 * doesn't exist.
 */
export async function getChangedFiles(
  rootDir: string,
  base: string | undefined,
  availableFiles: string[],
): Promise<DiffResolution> {
  try {
    await exec("git", ["-C", rootDir, "rev-parse", "--is-inside-work-tree"]);
  } catch {
    throw new Error(
      `'${rootDir}' is not a git repository, so there is no diff to scan. Use scan_repo for a full-repo scan.`,
    );
  }

  const ref = base && base.length > 0 ? base : "HEAD";
  try {
    await exec("git", ["-C", rootDir, "rev-parse", "--verify", "--quiet", `${ref}^{commit}`]);
  } catch {
    throw new Error(`Base ref '${ref}' does not exist in this repository.`);
  }

  // -z: filenames come back NUL-separated so spaces/quotes in paths survive.
  const [{ stdout: diffOut }, { stdout: othersOut }] = await Promise.all([
    exec("git", [
      "-C", rootDir,
      "diff", "--name-only", "--diff-filter=ACMR", "-z",
      ...(ref === "HEAD" ? [] : [ref]),
    ]),
    exec("git", ["-C", rootDir, "ls-files", "--others", "--exclude-standard", "-z"]),
  ]);

  const splitNul = (s: string) => s.split("\0").filter((x) => x.length > 0);
  const changed = splitNul(diffOut);
  const untracked = splitNul(othersOut);

  return {
    files: resolveDiffFiles(changed, untracked, availableFiles),
    reportedChanged: changed.length + untracked.length,
  };
}
