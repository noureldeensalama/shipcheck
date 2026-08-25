import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);

export interface DiffResolution {
  /** Relative paths to scan (already passed through the availability filter) */
  files: string[];
  /** Total paths git reported as changed (before availability filtering) */
  reportedChanged: number;
}

/**
 * Asks git at rootDir which files changed vs. `base` (default HEAD: staged +
 * unstaged work) and which are new-untracked, then keeps only paths that pass
 * pathFilter — the same rules as scan_repo's listing (vendored dirs,
 * gitignored paths, deleted files), applied per-path so no directory walk is
 * needed. Throws with an honest message when rootDir is not a git repository
 * or base doesn't exist.
 */
export async function getChangedFiles(
  rootDir: string,
  base: string | undefined,
  pathFilter: (relPath: string) => Promise<boolean>,
): Promise<DiffResolution> {
  try {
    await exec("git", ["-C", rootDir, "rev-parse", "--is-inside-work-tree"]);
  } catch {
    throw new Error(
      `'${rootDir}' is not a git repository, so there is no diff to scan. Use scan_repo for a full-repo scan.`,
    );
  }

  const ref = base && base.length > 0 ? base : "HEAD";
  let headExists = true;
  try {
    await exec("git", ["-C", rootDir, "rev-parse", "--verify", "--quiet", `${ref}^{commit}`]);
  } catch {
    if (ref !== "HEAD") {
      throw new Error(`Base ref '${ref}' does not exist in this repository.`);
    }
    // A repo with zero commits (founder, day one) has no HEAD. Everything
    // not yet committed is by definition untracked, so the ls-files call
    // below already covers it — don't fail, just skip the diff half.
    headExists = false;
  }

  // -z: filenames come back NUL-separated so spaces/quotes in paths survive.
  const [diffRes, othersRes] = await Promise.all([
    headExists
      ? exec("git", [
          "-C", rootDir,
          "diff", "--name-only", "--diff-filter=ACMR", "-z",
          ...(ref === "HEAD" ? [] : [ref]),
        ])
      : Promise.resolve({ stdout: "" }),
    exec("git", ["-C", rootDir, "ls-files", "--others", "--exclude-standard", "-z"]),
  ]);

  const splitNul = (s: string) => s.split("\0").filter((x) => x.length > 0);
  const changed = splitNul(diffRes.stdout);
  const untracked = splitNul(othersRes.stdout);

  const candidates = [...changed, ...untracked];
  const files: string[] = [];
  for (const name of candidates) {
    const rel = name.split("\\").join("/");
    if (!rel || rel.endsWith("/")) continue;
    if (await pathFilter(rel)) files.push(rel);
  }
  files.sort();

  return { files, reportedChanged: changed.length + untracked.length };
}
