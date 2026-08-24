export type Severity = "critical" | "high" | "medium";

export type Category =
  | "exposed-secrets"
  | "copyleft-license"
  | "unauthenticated-endpoint"
  | "pii-no-consent"
  | "client-side-payment";

export interface Finding {
  category: Category;
  severity: Severity;
  /** Primary location: the first place this pattern was found */
  file: string;
  line?: number;
  /**
   * All locations when the SAME credential/value appears in multiple files
   * (e.g. one leaked key pasted into many scripts). Deduplicating identical
   * values keeps agent context small instead of repeating near-identical
   * findings N times.
   */
  locations?: string[];
  description: string;
  why_it_matters: string;
  suggested_fix: string;
}

export interface DetectorContext {
  /** Absolute path to the repo root being scanned */
  rootDir: string;
  /** Relative file paths (already filtered by .gitignore + common excludes) */
  files: string[];
  /**
   * Per-scan content cache shared by all detectors so each file is read from
   * disk exactly once. Created by the server; detectors go through
   * lib/content.loadFile rather than reading directly.
   */
  contentCache?: Map<string, string | null>;
}

export type Detector = (ctx: DetectorContext) => Promise<Finding[]>;
