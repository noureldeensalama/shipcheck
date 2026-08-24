import { readFile, stat as statFile } from "node:fs/promises";
import { join } from "node:path";
import type { Detector, Finding } from "../types.js";

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
  { name: "Stripe Secret Key", pattern: /\bsk_(live|test)_[A-Za-z0-9]{24,}\b/g },
  { name: "Stripe Restricted Key", pattern: /\brk_(live|test)_[A-Za-z0-9]{24,}\b/g },
  { name: "Supabase Service Role Key (JWT)", pattern: /\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9[A-Za-z0-9._-]{20,}\b/g },
  { name: "Google API Key", pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: "Firebase/Google OAuth Client Secret", pattern: /GOCSPX-[A-Za-z0-9\-_]{20,}/g },
  { name: "GitHub Personal Access Token", pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { name: "Generic private key block", pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { name: "Slack Token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
];

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

/** Files larger than this are skipped for content scanning (memory/time guard). */
const MAX_SCAN_BYTES = 2 * 1024 * 1024;

interface SecretHit {
  signatureName: string;
  value: string;
  severity: "critical" | "high";
  firstFile: string;
  firstLine: number;
  locations: string[];
  clientSide: boolean;
}

export const secretsScanner: Detector = async (ctx) => {
  const findings: Finding[] = [];
  // Same credential pasted into N files = ONE finding with N locations.
  // Repeating a near-identical finding per file wastes the calling agent's
  // context without adding information.
  const byValue = new Map<string, SecretHit>();

  for (const relPath of ctx.files) {
    const ext = relPath.slice(relPath.lastIndexOf("."));
    if (isBinaryLikely(ext)) continue;

    // Committed .env files are a finding on their own, regardless of content match.
    const base = relPath.split("/").pop() ?? "";
    const isEnvFile = /^\.env(\..+)?$/.test(base) && base !== ".env.example" && base !== ".env.sample";
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
    if (isFirebaseClientConfig) continue;

    let stat;
    try {
      stat = await statFile(join(ctx.rootDir, relPath));
      if (stat.size > MAX_SCAN_BYTES) continue; // too big to be source; skip content scan
    } catch {
      continue; // unreadable / vanished, skip
    }

    let content: string;
    try {
      content = await readFile(join(ctx.rootDir, relPath), "utf-8");
    } catch {
      continue; // binary / undecodable, skip
    }

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

        const upToMatch = content.slice(0, match.index);
        const lineNumber = upToMatch.split("\n").length;
        const clientSide = CLIENT_SIDE_HINT_DIRS.some((d) => relPath.startsWith(`${d}/`) || relPath.includes(`/${d}/`));
        const key = `${sig.name}|${value}`;
        const existing = byValue.get(key);
        if (existing) {
          existing.locations.push(`${relPath}:${lineNumber}`);
          // escalate severity if any occurrence is client-side
          if (clientSide) existing.clientSide = true;
        } else {
          byValue.set(key, {
            signatureName: sig.name,
            value,
            severity: clientSide ? "critical" : "high",
            firstFile: relPath,
            firstLine: lineNumber,
            locations: [`${relPath}:${lineNumber}`],
            clientSide,
          });
        }
      }
    }
  }

  for (const hit of byValue.values()) {
    findings.push({
      category: "exposed-secrets",
      severity: hit.clientSide ? "critical" : "high",
      file: hit.firstFile,
      line: hit.firstLine,
      ...(hit.locations.length > 1 ? { locations: hit.locations } : {}),
      description:
        `Possible ${hit.signatureName} found${hit.clientSide ? " in client-side code" : ""}` +
        (hit.locations.length > 1 ? ` — same value appears in ${hit.locations.length} locations.` : "."),
      why_it_matters: hit.clientSide
        ? "This code ships to end users' browsers or app bundles. Anyone can extract the key from a network request, bundled JS, or the compiled app binary."
        : "Hardcoded secrets in source (even server-side) end up in git history and CI logs, and are easy to leak via an accidental public repo or a misconfigured deploy.",
      suggested_fix:
        "Move this value to an environment variable loaded at runtime, ensure it's never bundled into client code, and rotate the exposed credential immediately — assume it's already compromised.",
    });
  }

  return findings;
};
