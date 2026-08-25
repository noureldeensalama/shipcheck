import { join } from "node:path";
import type { Detector, Finding } from "../types.js";
import { loadFile } from "../lib/content.js";

const PII_COLLECTORS: { name: string; pattern: RegExp }[] = [
  { name: "Google Analytics", pattern: /(gtag\(|G-[A-Z0-9]{6,}|googletagmanager\.com)/ },
  { name: "Mixpanel", pattern: /mixpanel\.(init|track)/ },
  { name: "Segment", pattern: /analytics\.(identify|track)\s*\(/ },
  { name: "Firebase Analytics", pattern: /firebase\/analytics|logEvent\s*\(/ },
  // Modern analytics/pixels commonly scaffolded by AI agents (dogfooding
  // found PostHog in a real repo, invisible to the v1 collector list).
  { name: "PostHog", pattern: /posthog\.(init|capture|identify)/ },
  { name: "Meta Pixel", pattern: /\bfbq\s*\(\s*['"]init['"]/ },
  { name: "Hotjar", pattern: /(\bhj\s*\(['"]|hotjar)/i },
  { name: "Microsoft Clarity", pattern: /clarity\.ms/ },
  { name: "Amplitude", pattern: /amplitude\.(init|getInstance|logEvent)/ },
  { name: "Auth provider collecting email/name", pattern: /(signUp|createUserWithEmailAndPassword|supabase\.auth\.signUp)/ },
  { name: "Email input field", pattern: /type=["']email["']/ },
  // Phone numbers are PII in every major regulatory regime.
  { name: "Phone input field", pattern: /(type=["']tel["']|name=["']tele?phone["'])/i },
];

// Filename-level artifact hints: a file whose PATH names a privacy/terms/
// consent document counts, whatever its contents.
const POLICY_ARTIFACT_FILENAME_HINTS = [
  /privac/i,
  /terms[-_]?of[-_]?service/i,
  /consent/i,
];

// Content-level artifact hints require STRUCTURAL evidence — an attribute,
// assignment, or route path pointing at such a page. A bare mention of the
// words ("TODO: add privacy policy") must not suppress the finding.
const POLICY_ARTIFACT_CONTENT_HINTS = [
  // href="/privacy", privacyPolicyUrl: "…", src="…/consent.js"
  /(?:href|src|action|url)\s*[:=]\s*["'][^"']*(?:privac|terms|consent)/i,
  // route/path literals: "/privacy", "/terms-of-service", router.push("/consent")
  /["'`(]\/[a-z0-9\-_/]*(?:privac|terms|consent)/i,
  // Dedicated consent-management integrations ARE consent artifacts
  // (Cookiebot, OneTrust, Osano, react-cookie-consent, Termly…).
  /(react-cookie-consent|cookieconsent|cookie[-_]?bot|onetrust|osano|termly|cookielawinfo)/i,
];

function looksLikePolicyArtifact(relPath: string): boolean {
  return POLICY_ARTIFACT_FILENAME_HINTS.some((p) => p.test(relPath));
}

function contentLooksLikePolicyArtifact(content: string): boolean {
  return POLICY_ARTIFACT_CONTENT_HINTS.some((p) => p.test(content));
}

export const piiConsentCheck: Detector = async (ctx) => {
  const findings: Finding[] = [];
  const collectorsFound: { name: string; file: string; line: number }[] = [];
  let policyArtifactFound = false;

  for (const relPath of ctx.files) {
    // Any filename that looks like a privacy policy / ToS page counts as an artifact.
    if (looksLikePolicyArtifact(relPath)) {
      policyArtifactFound = true;
    }

    if (!/\.(js|ts|jsx|tsx|dart|py|html)$/.test(relPath)) continue;
    if (relPath.includes("node_modules")) continue;

    const loaded = await loadFile(ctx, relPath);
    if (loaded.state === "skipped") continue;
    const content = loaded.content;

    // A link/route to a privacy policy also counts as an artifact.
    if (contentLooksLikePolicyArtifact(content)) {
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
      description: `Your project collects personal info (${uniqueCollectors.join(", ")}) but there's no privacy policy or consent popup anywhere in the project.`,
      why_it_matters:
        "When you collect people's emails or track their activity, you're expected to tell them what happens to that info. App stores can reject apps that don't, and privacy laws in many countries require it — this is one of the easiest launch-blockers to fix.",
      suggested_fix:
        "Write a short privacy policy page (template services can generate one) saying what you collect and why, then link it on your signup screen and app-store listing.",
    });
  }

  return findings;
};
