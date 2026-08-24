import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);

/**
 * History scanning: a secret removed from the working tree is still
 * compromised if it ever touched a commit — git history keeps it readable
 * forever, and anyone who clones gets the whole history by default. This
 * module scans recent commit patches for credential signatures so "deleted"
 * secrets still get reported for rotation.
 *
 * Bounded by design: last N commits, +/- lines only, vendored paths excluded
 * via git pathspecs, results deduplicated per value, hard cap on findings.
 */
export const HISTORY_MAX_COMMITS = 200;
const HISTORY_MAX_FINDINGS = 50;

/** Same exclusion rules as listFiles, expressed as git pathspecs. */
const EXCLUDE_PATHSPECS = [
  ":(exclude)node_modules/**",
  ":(exclude).venv/**",
  ":(exclude)venv/**",
  ":(exclude).tox/**",
  ":(exclude)dist/**",
  ":(exclude)build/**",
  ":(exclude)**/node_modules/**",
  ":(exclude)**/.venv/**",
  ":(exclude)**/venv/**",
  ":(exclude)**/.tox/**",
];

export interface HistoryFinding {
  signatureName: string;
  /** The matched secret value itself (needed for live-vs-history dedup). */
  value: string;
  /** Short commit hashes where this value appeared (max 3 examples). */
  commits: string[];
  /** File paths where this value was seen (max 5 examples). */
  files: string[];
}

export interface HistoryScanResult {
  findings: HistoryFinding[];
  scannedCommits: number;
}

const COMMIT_RE = /^commit ([0-9a-f]{40})/;

export async function scanGitHistory(
  rootDir: string,
  patterns: { name: string; pattern: RegExp }[],
  keepValue: (value: string) => boolean,
): Promise<HistoryScanResult> {
  // No history → nothing to do (fresh repo).
  try {
    await exec("git", ["-C", rootDir, "rev-parse", "--verify", "--quiet", "HEAD"]);
  } catch {
    return { findings: [], scannedCommits: 0 };
  }

  let stdout: string;
  try {
    ({ stdout } = await exec(
      "git",
      [
        "-C", rootDir,
        "log",
        "-p",
        "--no-color",
        "--no-ext-diff",
        "--diff-filter=ACMR",
        "-U0",
        "-n", `${HISTORY_MAX_COMMITS}`,
        "--",
        ".",
        ...EXCLUDE_PATHSPECS,
      ],
      { maxBuffer: 256 * 1024 * 1024 },
    ));
  } catch {
    return { findings: [], scannedCommits: 0 };
  }

  const byValue = new Map<string, HistoryFinding>();
  let currentCommit = "";
  let currentFile: string | null = null;

  for (const line of stdout.split("\n")) {
    const cm = line.match(COMMIT_RE);
    if (cm) {
      currentCommit = cm[1].slice(0, 8);
      continue;
    }
    if (line.startsWith("+++ b/")) {
      currentFile = line.slice(6);
      continue;
    }
    if (line.startsWith("+++") || line.startsWith("---")) continue;
    if (!line.startsWith("+") && !line.startsWith("-")) continue;

    for (const sig of patterns) {
      sig.pattern.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = sig.pattern.exec(line)) !== null) {
        const value = m[0];
        if (value.length === 0) {
          sig.pattern.lastIndex++;
          continue;
        }
        if (!keepValue(value)) continue;

        const key = `${sig.name}|${value}`;
        let entry = byValue.get(key);
        if (!entry) {
          entry = { signatureName: sig.name, value, commits: [], files: [] };
          byValue.set(key, entry);
        }
        if (entry.commits.length < 3 && !entry.commits.includes(currentCommit)) {
          entry.commits.push(currentCommit);
        }
        if (currentFile && entry.files.length < 5 && !entry.files.includes(currentFile)) {
          entry.files.push(currentFile);
        }
      }
    }
  }

  return {
    findings: [...byValue.values()].slice(0, HISTORY_MAX_FINDINGS),
    scannedCommits: HISTORY_MAX_COMMITS,
  };
}
