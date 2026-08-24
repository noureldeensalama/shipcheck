import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import correct from "spdx-correct";
import type { Detector, Finding } from "../types.js";

/**
 * Licenses considered "strong copyleft" for this checker's purposes: pulling
 * one of these into a closed-source commercial app either forces source
 * disclosure or creates real legal exposure. Weak copyleft (MPL, LGPL when
 * only dynamically linked) is flagged at lower severity since it's often fine.
 */
const STRONG_COPYLEFT = new Set(["GPL-2.0", "GPL-3.0", "AGPL-3.0", "AGPL-1.0"]);
const WEAK_COPYLEFT = new Set(["LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-1.0", "EPL-2.0"]);

function normalize(license: string): string {
  const corrected = correct(license);
  return (corrected ?? license).replace(/\+$/, "").replace(/\-only$/, "").replace(/\-or-later$/, "");
}

async function checkNodeDependencies(rootDir: string, findings: Finding[]) {
  const nodeModulesPkgs = new Set<string>();
  try {
    const pkgRaw = await readFile(join(rootDir, "package.json"), "utf-8");
    const pkg = JSON.parse(pkgRaw);
    for (const dep of Object.keys({ ...pkg.dependencies, ...pkg.optionalDependencies })) {
      nodeModulesPkgs.add(dep);
    }
  } catch {
    return; // no package.json, not a Node project (or FastAPI/Flutter only)
  }

  for (const dep of nodeModulesPkgs) {
    try {
      const depPkgRaw = await readFile(join(rootDir, "node_modules", dep, "package.json"), "utf-8");
      const depPkg = JSON.parse(depPkgRaw);
      const rawLicense: string | undefined =
        typeof depPkg.license === "string" ? depPkg.license : depPkg.license?.type ?? depPkg.licenses?.[0]?.type;

      if (!rawLicense) {
        findings.push({
          category: "copyleft-license",
          severity: "medium",
          file: `node_modules/${dep}/package.json`,
          description: `Dependency '${dep}' has no declared license.`,
          why_it_matters: "Undeclared license means you have no legal basis to redistribute or use the package commercially — technically all rights reserved by default.",
          suggested_fix: `Check ${dep}'s repository directly for a LICENSE file, or replace it with a package that declares one clearly.`,
        });
        continue;
      }

      const normalized = normalize(rawLicense);
      if (STRONG_COPYLEFT.has(normalized)) {
        findings.push({
          category: "copyleft-license",
          severity: "critical",
          file: `node_modules/${dep}/package.json`,
          description: `Dependency '${dep}' is licensed under ${rawLicense} (strong copyleft).`,
          why_it_matters:
            "Strong copyleft licenses like GPL/AGPL generally require you to release your application's source code under the same license if you distribute or (for AGPL) even network-serve it. This can force disclosure of your entire proprietary codebase.",
          suggested_fix: `Find a permissively-licensed alternative to '${dep}' (MIT/Apache-2.0/BSD), or consult a lawyer before shipping if it must stay.`,
        });
      } else if (WEAK_COPYLEFT.has(normalized)) {
        findings.push({
          category: "copyleft-license",
          severity: "medium",
          file: `node_modules/${dep}/package.json`,
          description: `Dependency '${dep}' is licensed under ${rawLicense} (weak copyleft).`,
          why_it_matters:
            "Weak copyleft is usually fine if you only dynamically link/import the package without modifying its source, but modifying it or statically bundling it can trigger disclosure requirements.",
          suggested_fix: `Confirm you're using '${dep}' unmodified and as an external dependency, not a forked/vendored copy.`,
        });
      }
    } catch {
      // package not installed / no package.json found in node_modules — skip silently,
      // this just means `npm install` hasn't been run, not a finding worth surfacing.
    }
  }
}

/**
 * pubspec.lock is YAML, but the shape we need (packages.<name>.{source,
 * version}) is flat and regular. We parse it properly with the `yaml` package
 * rather than regexing, since lockfiles are generated output whose exact
 * formatting shouldn't be assumed.
 */
export interface PubDependency {
  name: string;
  version: string;
}

export function parsePubspecLock(content: string): PubDependency[] {
  const doc = parseYaml(content) as
    | { packages?: Record<string, { source?: string; version?: string }> }
    | null;
  if (!doc?.packages) return [];
  const deps: PubDependency[] = [];
  for (const [name, info] of Object.entries(doc.packages)) {
    if (info?.source !== "hosted" || !info.version) continue;
    deps.push({ name, version: info.version });
  }
  return deps.sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * pub.dev exposes machine-readable license classification via the score API's
 * `license:<spdx-lowercase>` tags (verified against the live API — the
 * /api/packages/{name} pubspec block does NOT carry license info). Tags like
 * `license:fsf-libre` / `license:osi-approved` are classifications, not
 * licenses, so they're filtered out here.
 */
const NON_LICENSE_TAGS = new Set(["fsf-libre", "osi-approved", "unknown"]);

export function licenseTagsFromScore(scoreJson: unknown): string[] {
  const tags = (scoreJson as { tags?: string[] })?.tags ?? [];
  return tags
    .filter((t) => t.startsWith("license:"))
    .map((t) => t.slice("license:".length))
    .filter((t) => !NON_LICENSE_TAGS.has(t));
}

async function fetchPackageLicense(name: string): Promise<string[] | null> {
  // null means "could not determine" for any reason: unreachable network,
  // 404, or a response without usable license tags. All three surface to the
  // user as their own finding rather than being silently skipped.
  // One retry: dogfooding showed a single transient timeout among ~90
  // sequential fetches is common, and each one becomes a noisy finding.
  const attempts = [0, 1];
  for (const attempt of attempts) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, 500));
    try {
      const res = await fetch(`https://pub.dev/api/packages/${encodeURIComponent(name)}/score`, {
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) continue;
      const json = (await res.json()) as unknown;
      const tags = licenseTagsFromScore(json);
      if (tags.length > 0) return tags;
    } catch {
      // fall through to next attempt
    }
  }
  return null;
}

function copyleftSeverityFor(licenses: string[]): "critical" | "medium" | null {
  for (const raw of licenses) {
    const normalized = normalize(raw);
    if (STRONG_COPYLEFT.has(normalized.toUpperCase())) return "critical";
    if (WEAK_COPYLEFT.has(normalized.toUpperCase())) return "medium";
  }
  return null;
}

export function classifyPubLicenseTags(tags: string[]): "critical" | "medium" | null {
  return copyleftSeverityFor(tags.map((t) => normalize(t)));
}

async function checkFlutterDependencies(rootDir: string, findings: Finding[]) {
  let lockContent: string;
  try {
    lockContent = await readFile(join(rootDir, "pubspec.lock"), "utf-8");
  } catch {
    return; // not a Flutter project, nothing to do
  }

  const deps = parsePubspecLock(lockContent);

  for (const dep of deps) {
    const licenseTags = await fetchPackageLicense(dep.name);

    if (!licenseTags) {
      findings.push({
        category: "copyleft-license",
        severity: "medium",
        file: `pubspec.lock (${dep.name} ${dep.version})`,
        description: `License for pub.dev dependency '${dep.name}' could not be determined (pub.dev unreachable, package not found, or no license data).`,
        why_it_matters:
          "Undetermined license means you have no confirmed legal basis to use the package commercially — some packages misreport or omit license metadata entirely.",
        suggested_fix: `Check '${dep.name}' directly on pub.dev or its source repository for a LICENSE file, or replace it with a package that declares one clearly.`,
      });
      continue;
    }

    const severity = classifyPubLicenseTags(licenseTags);
    if (severity === "critical") {
      findings.push({
        category: "copyleft-license",
        severity: "critical",
        file: `pubspec.lock (${dep.name} ${dep.version})`,
        description: `pub.dev dependency '${dep.name}' version ${dep.version} is licensed under ${(licenseTags ?? []).join(" OR ")} (strong copyleft) per pub.dev's license data.`,
        why_it_matters:
          "Strong copyleft licenses like GPL/AGPL generally require you to release your application's source code under the same license if you distribute or (for AGPL) even network-serve it. This can force disclosure of your entire proprietary codebase.",
        suggested_fix: `Find a permissively-licensed alternative to '${dep.name}', or consult a lawyer before shipping if it must stay.`,
      });
    } else if (severity === "medium") {
      findings.push({
        category: "copyleft-license",
        severity: "medium",
        file: `pubspec.lock (${dep.name} ${dep.version})`,
        description: `pub.dev dependency '${dep.name}' version ${dep.version} is licensed under ${(licenseTags ?? []).join(" OR ")} (weak copyleft) per pub.dev's license data.`,
        why_it_matters:
          "Weak copyleft is usually fine if you only import the package without modifying its source, but modifying it or vendoring its code can trigger disclosure requirements.",
        suggested_fix: `Confirm you're using '${dep.name}' unmodified and as an external dependency, not a forked/vendored copy.`,
      });
    }
  }
}

export const licenseCheck: Detector = async (ctx) => {
  const findings: Finding[] = [];
  await checkNodeDependencies(ctx.rootDir, findings);
  await checkFlutterDependencies(ctx.rootDir, findings);
  return findings;
};
