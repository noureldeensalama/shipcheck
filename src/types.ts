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
  file: string;
  line?: number;
  description: string;
  why_it_matters: string;
  suggested_fix: string;
}

export interface DetectorContext {
  /** Absolute path to the repo root being scanned */
  rootDir: string;
  /** Relative file paths (already filtered by .gitignore + common excludes) */
  files: string[];
}

export type Detector = (ctx: DetectorContext) => Promise<Finding[]>;
