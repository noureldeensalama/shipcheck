import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Detector, Finding } from "../types.js";

const PII_COLLECTORS: { name: string; pattern: RegExp }[] = [
  { name: "Google Analytics", pattern: /(gtag\(|G-[A-Z0-9]{6,}|googletagmanager\.com)/ },
  { name: "Mixpanel", pattern: /mixpanel\.(init|track)/ },
  { name: "Segment", pattern: /analytics\.(identify|track)\s*\(/ },
  { name: "Firebase Analytics", pattern: /firebase\/analytics|logEvent\s*\(/ },
  { name: "Auth provider collecting email/name", pattern: /(signUp|createUserWithEmailAndPassword|supabase\.auth\.signUp)/ },
  { name: "Email input field", pattern: /type=["']email["']/ },
];

const POLICY_ARTIFACT_HINTS = [
  /privacy[-_]?policy/i,
  /terms[-_]?of[-_]?service/i,
  /consent/i,
];

export const piiConsentCheck: Detector = async (ctx) => {
  const findings: Finding[] = [];
  const collectorsFound: { name: string; file: string; line: number }[] = [];
  let policyArtifactFound = false;

  for (const relPath of ctx.files) {
    // Any filename that looks like a privacy policy / ToS page counts as an artifact.
    if (POLICY_ARTIFACT_HINTS.some((p) => p.test(relPath))) {
      policyArtifactFound = true;
    }

    if (!/\.(js|ts|jsx|tsx|dart|py|html)$/.test(relPath)) continue;
    if (relPath.includes("node_modules")) continue;

    let content: string;
    try {
      content = await readFile(join(ctx.rootDir, relPath), "utf-8");
    } catch {
      continue;
    }

    // A link/route to a privacy policy also counts as an artifact.
    if (POLICY_ARTIFACT_HINTS.some((p) => p.test(content))) {
      policyArtifactFound = true;
    }

    for (const collector of PII_COLLECTORS) {
      if (collector.pattern.test(content)) {
        const match = content.match(collector.pattern);
        const idx = match?.index ?? 0;
        const lineNumber = content.slice(0, idx).split("\n").length;
        collectorsFound.push({ name: collector.name, file: relPath, line: lineNumber });
      }
    }
  }

  if (collectorsFound.length > 0 && !policyArtifactFound) {
    // One consolidated finding rather than one per collector call site — a
    // wall of near-duplicate findings for the same missing artifact isn't useful.
    const uniqueCollectors = [...new Set(collectorsFound.map((c) => c.name))];
    const first = collectorsFound[0];
    findings.push({
      category: "pii-no-consent",
      severity: "high",
      file: first.file,
      line: first.line,
      description: `Found data collection (${uniqueCollectors.join(", ")}) with no privacy policy or consent artifact found anywhere in the repo.`,
      why_it_matters:
        "Collecting PII (emails, analytics identifiers, account data) without a disclosed privacy policy is a common App Store/Play Store rejection reason and a regulatory exposure point in most jurisdictions.",
      suggested_fix:
        "Add a privacy policy (even a generated one from a template service to start) and link it from your signup flow and app store listing before launch.",
    });
  }

  return findings;
};
