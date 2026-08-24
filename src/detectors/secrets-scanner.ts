import { join } from "node:path";
import type { Detector, DetectorContext, Finding } from "../types.js";
import { loadFile } from "../lib/content.js";

/**
 * Known secret formats with high-confidence regex signatures.
 * Each pattern targets a specific provider's key format rather than
 * a generic "looks like a secret" heuristic, to keep false positives low.
 */
const SIGNATURES: { name: string; pattern: RegExp }[] = [
  { name: "AWS Access Key ID", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "AWS Secret Access Key (assigned)", pattern: /aws_secret_access_key\s*=\s*['"][A-Za-z0-9/+=]{40}['"]/gi },
  { name: "OpenAI API Key", pattern: /\bsk-[A-Za-z0-9]{20,}\b/g },
  { name: "Anthropic API Key", pattern: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/g },
  { name: "OpenRouter API Key", pattern: /\bsk-or-v1-[a-f0-9]{64}\b/g },
  { name: "Stripe Secret Key", pattern: /\bsk_(live|test)_[A-Za-z0-9]{24,}\b/g },
  { name: "Stripe Restricted Key", pattern: /\brk_(live|test)_[A-Za-z0-9]{24,}\b/g },
  // Supabase-shaped JWTs get role-decoded below before reporting.
  { name: "Supabase Service Role Key (JWT)", pattern: /\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9[A-Za-z0-9._-]{20,}\b/g },
  { name: "Google API Key", pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: "Firebase/Google OAuth Client Secret", pattern: /GOCSPX-[A-Za-z0-9\-_]{20,}/g },
  { name: "GitHub Personal Access Token", pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { name: "Generic private key block", pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { name: "Slack Token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: "SendGrid API Key", pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { name: "Resend API Key", pattern: /\bre_[A-Za-z0-9]{32}\b/g },
  {
    name: "Database URL with embedded password",
    // Requires a dotted hostname (excludes localhost/docker service names)
    // and an 8+ char password segment; extra validation in validateMatch.
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[A-Za-z0-9._%-]+:([^@\s/]{8,})@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/gi,
  },
];

/** Extra per-signature validation beyond the shared value filters. */
const COMMON_WEAK_PASSWORDS = new Set([
  "password", "postgres", "root", "admin", "secret", "test", "test123",
  "changeme", "change-me", "example", "passw0rd", "12345678", "password1",
]);

function validateMatch(name: string, match: RegExpExecArray): boolean {
  if (name === "Database URL with embedded password") {
    const password = match[1];
    const username = match[0].split("://")[1].split(":")[0];
    if (password.toLowerCase() === username.toLowerCase()) return false;
    if (COMMON_WEAK_PASSWORDS.has(password.toLowerCase())) return false;
    if (/^x{4,}$|^0+$|^\*+$|^<{3,}>?$/.test(password)) return false;
  }
  return true;
}

/**
 * Supabase anon keys share the exact same JWT header as service-role keys,
 * but they are public-by-design client identifiers — flagging them is the
 * classic FP. Decode the payload's `role` claim and only report keys that
 * actually bypass row-level security. Unparseable JWTs stay flagged (an
 * unknown token with that header deserves scrutiny).
 */
function decodeSupabaseRole(value: string): string | null {
  const parts = value.split(".");
  if (parts.length < 2) return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = JSON.parse(Buffer.from(b64, "base64").toString("utf-8"));
    return typeof json?.role === "string" ? json.role : null;
  } catch {
    return null;
  }
}

function isServiceRoleJwt(value: string): boolean {
  const role = decodeSupabaseRole(value);
  return role === null || role === "service_role" || role === "service-role";
}

const CLIENT_SIDE_HINT_DIRS = ["src", "app", "lib", "public", "web", "client", "components"];
const SKIP_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".lock", ".min.js"]);

// Firebase client-config filenames are designed to be committed and shipped
// inside client app bundles; the API keys in them are identifiers restricted
// server-side (via App Check / API restrictions), not secret credentials.
// Flagging them every scan drowns real findings. Other signatures (private key
// blocks etc.) cannot legitimately occur in these files either.
const FIREBASE_CLIENT_CONFIG_FILES = new Set(["google-services.json", "GoogleService-Info.plist"]);

/**
 * Values that are obviously placeholders rather than live credentials:
 * mock/dummy fixtures in test helpers, CI placeholder tokens, all-zero runs.
 * A real randomly-generated key essentially never contains these words.
 * Note this deliberately does NOT include the word "test" alone — Stripe
 * `sk_test_…` keys are real credentials against live Stripe test data.
 */
const PLACEHOLDER_VALUE_HINTS = /(mock|dummy|fake|sample|placeholder|example|not[_-]?a[_-]?real|ci[-_]test|x{8,}|0{12,})/i;

function isPlaceholderValue(value: string): boolean {
  return PLACEHOLDER_VALUE_HINTS.test(value);
}

function isBinaryLikely(ext: string): boolean {
  return SKIP_EXTENSIONS.has(ext);
}

// (size guard now lives in lib/content.loadFile — uniform across detectors)

interface SecretHit {
  signatureName: string;
  value: string;
  clientSide: boolean;
  /** Every occurrence, in scan order — made deterministic before emitting. */
  spots: { file: string; line: number }[];
}

/** How many files the secrets scanner reads concurrently. */
const FILE_READ_CONCURRENCY = 12;

export const secretsScanner: Detector = async (ctx) => {
  const findings: Finding[] = [];
  // Same credential pasted into N files = ONE finding with N locations.
  // Repeating a near-identical finding per file wastes the calling agent's
  // context without adding information.
  const byValue = new Map<string, SecretHit>();

  /**
   * Scans one file, pushing env-file findings and accumulating signature hits
   * into byValue. JS runs each worker's sync sections atomically, so the
   * shared Map needs no locking; order of location entries is nondeterministic
   * across workers but content is identical.
   */
  const scanOne = async (relPath: string): Promise<void> => {
    const ext = relPath.slice(relPath.lastIndexOf("."));
    if (isBinaryLikely(ext)) return;

    // Committed .env files are a finding on their own, regardless of content match.
    // Matches the standard dotenv convention in any position: `.env`,
    // `.env.local`, and project-prefixed variants like `backend.env` /
    // `config.env`. Deliberately NOT bare `*.env.example`-suffixed names
    // (handled below) or unrelated words merely containing "env".
    const base = relPath.split("/").pop() ?? "";
    const isEnvFile =
      (/^\.env(\..+)?$/.test(base) || /^[A-Za-z0-9._-]+\.env$/i.test(base)) &&
      base !== ".env.example" &&
      base !== ".env.sample" &&
      !base.endsWith(".env.example") &&
      !base.endsWith(".env.sample");
    const isFirebaseClientConfig = FIREBASE_CLIENT_CONFIG_FILES.has(base);

    if (isEnvFile) {
      findings.push({
        category: "exposed-secrets",
        severity: "critical",
        file: relPath,
        description: `Environment file '${relPath}' is committed to the repository.`,
        why_it_matters:
          "Committed .env files ship real credentials into git history, which is readable by anyone with repo access forever, even after the file is later deleted.",
        suggested_fix:
          `Remove ${relPath} from git tracking (git rm --cached ${relPath}), add it to .gitignore, rotate every credential it contained, and commit only a .env.example with placeholder values.`,
      });
    }
    if (isFirebaseClientConfig) return;

    const loaded = await loadFile(ctx, relPath);
    if (loaded.state === "skipped") return; // too big, vanished, or undecodable
    const content = loaded.content;

    for (const sig of SIGNATURES) {
      sig.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = sig.pattern.exec(content)) !== null) {
        const value = match[0];
        if (value.length === 0) {
          // avoid infinite loop on zero-length matches
          sig.pattern.lastIndex++;
          continue;
        }
        if (isPlaceholderValue(value)) continue;
        // Supabase anon/authenticated JWTs are public-by-design client keys.
        if (sig.name.startsWith("Supabase") && !isServiceRoleJwt(value)) continue;
        if (!validateMatch(sig.name, match)) continue;

        const upToMatch = content.slice(0, match.index);
        const lineNumber = upToMatch.split("\n").length;
        const clientSide = CLIENT_SIDE_HINT_DIRS.some((d) => relPath.startsWith(`${d}/`) || relPath.includes(`/${d}/`));
        const key = `${sig.name}|${value}`;
        const existing = byValue.get(key);
        if (existing) {
          existing.spots.push({ file: relPath, line: lineNumber });
          // escalate severity if any occurrence is client-side
          if (clientSide) existing.clientSide = true;
        } else {
          byValue.set(key, {
            signatureName: sig.name,
            value,
            spots: [{ file: relPath, line: lineNumber }],
            clientSide,
          });
        }
      }
    }
  };

  let next = 0;
  const files = ctx.files;
  await Promise.all(
    Array.from({ length: Math.min(FILE_READ_CONCURRENCY, files.length) }, async () => {
      while (next < files.length) {
        const idx = next++;
        await scanOne(files[idx]);
      }
    }),
  );

  for (const hit of byValue.values()) {
    // Deterministic output regardless of read concurrency: locations sorted,
    // primary = first alphabetically (matches how file listings are ordered).
    const spots = [...hit.spots].sort(
      (a, b) => a.file.localeCompare(b.file) || a.line - b.line,
    );
    const locations = spots.map((s) => `${s.file}:${s.line}`);
    findings.push({
      category: "exposed-secrets",
      severity: hit.clientSide ? "critical" : "high",
      file: spots[0].file,
      line: spots[0].line,
      ...(locations.length > 1 ? { locations } : {}),
      description:
        `Possible ${hit.signatureName} found${hit.clientSide ? " in client-side code" : ""}` +
        (locations.length > 1 ? ` — same value appears in ${locations.length} locations.` : "."),
      why_it_matters: hit.clientSide
        ? "This code ships to end users' browsers or app bundles. Anyone can extract the key from a network request, bundled JS, or the compiled app binary."
        : "Hardcoded secrets in source (even server-side) end up in git history and CI logs, and are easy to leak via an accidental public repo or a misconfigured deploy.",
      suggested_fix:
        "Move this value to an environment variable loaded at runtime, ensure it's never bundled into client code, and rotate the exposed credential immediately — assume it's already compromised.",
    });
  }

  return findings;
};

/** Signatures + value filter, shared with git-history scanning. */
export const SECRET_SIGNATURES = SIGNATURES;

export function isReportableSecret(value: string): boolean {
  if (isPlaceholderValue(value)) return false;
  if (value.startsWith("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")) {
    return isServiceRoleJwt(value); // only service_role JWTs matter
  }
  return true;
}

/**
 * Scans recent git history for secrets that were committed and later removed.
 * Values still present in the working tree are skipped — the regular scan
 * already covers those; this catches "deleted but never rotated."
 */
export async function scanHistorySecrets(
  ctx: DetectorContext,
): Promise<{ findings: Finding[]; scannedCommits: number }> {
  const { scanGitHistory } = await import("../lib/history.js");

  // Values still in the current tree: cheap re-scan over cached contents so
  // history findings don't duplicate live ones.
  const currentValues = new Set<string>();
  for (const relPath of ctx.files) {
    const loaded = await loadFile(ctx, relPath);
    if (loaded.state === "skipped") continue;
    for (const sig of SECRET_SIGNATURES) {
      sig.pattern.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = sig.pattern.exec(loaded.content)) !== null) {
        if (m[0].length === 0) {
          sig.pattern.lastIndex++;
          continue;
        }
        if (!validateMatch(sig.name, m)) continue;
        currentValues.add(`${sig.name}|${m[0]}`);
      }
    }
  }

  const { findings: historyHits, scannedCommits } = await scanGitHistory(ctx.rootDir, SECRET_SIGNATURES, isReportableSecret);

  const out: Finding[] = [];
  for (const hit of historyHits) {
    if (currentValues.has(`${hit.signatureName}|${hit.value}`)) continue; // still live; normal scan covers it
    out.push({      category: "exposed-secrets",
      severity: "high",
      file: hit.files[0] ?? "(git history)",
      ...(hit.files.length > 1 ? { locations: hit.files } : {}),
      description:
        `${hit.signatureName} exists in git HISTORY at commit(s) ${hit.commits.join(", ")}` +
        ` — removed from current code, but still readable to anyone who clones the repo.`,
      why_it_matters:
        "Deleting a credential from the latest commit does not delete it from git history. Anyone with repo access (or anyone at all, once pushed publicly) can check out an old revision and read every secret ever committed.",
      suggested_fix:
        "Rotate this credential immediately — assume compromised. Then purge it from history (git filter-repo or BFG) before considering the repo clean.",
    });
  }
  return { findings: out, scannedCommits };
}
