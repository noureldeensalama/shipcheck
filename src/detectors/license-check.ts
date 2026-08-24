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

/**
 * Checks every package.json in the repo — not just the root one. AI-built apps
 * are routinely multi-package (frontend/package.json + backend/, workspaces,
 * admin panels); dogfooding found a real repo whose entire 20-dependency
 * frontend tree was invisible to a root-only check. Dependencies are resolved
 * against the node_modules NEXT TO each package.json, mirroring how npm
 * actually resolves them.
 */
async function checkNodeDependencies(rootDir: string, files: string[], findings: Finding[]) {
  const packageJsonFiles = files.filter((f) => f === "package.json" || f.endsWith("/package.json"));
  if (packageJsonFiles.length === 0) return; // not a Node project (or FastAPI/Flutter only)

  for (const pkgPath of packageJsonFiles) {
    const pkgDir = pkgPath.slice(0, pkgPath.length - "package.json".length); // "" for root, "frontend/" etc.
    let deps: string[];
    try {
      const pkgRaw = await readFile(join(rootDir, pkgPath), "utf-8");
      const pkg = JSON.parse(pkgRaw);
      deps = Object.keys({ ...pkg.dependencies, ...pkg.optionalDependencies });
    } catch {
      continue; // malformed/unreadable package.json — not this detector's finding to make
    }

    for (const dep of deps) {
      await checkNodeDependency(rootDir, pkgDir, dep, findings);
    }
  }
}

async function checkNodeDependency(rootDir: string, pkgDir: string, dep: string, findings: Finding[]) {
  // Where the dependency's manifest lives, for honest reporting regardless of nesting.
  const reportPath = `${pkgDir}node_modules/${dep}/package.json`;
  try {
    const depPkgRaw = await readFile(join(rootDir, pkgDir, "node_modules", dep, "package.json"), "utf-8");
    const depPkg = JSON.parse(depPkgRaw);
    const rawLicense: string | undefined =
      typeof depPkg.license === "string" ? depPkg.license : depPkg.license?.type ?? depPkg.licenses?.[0]?.type;

    if (!rawLicense) {
      findings.push({
        category: "copyleft-license",
        severity: "medium",
        file: reportPath,
        description: `Dependency '${dep}' has no declared license.`,
        why_it_matters: "Undeclared license means you have no legal basis to redistribute or use the package commercially — technically all rights reserved by default.",
        suggested_fix: `Check ${dep}'s repository directly for a LICENSE file, or replace it with a package that declares one clearly.`,
      });
      return;
    }

    const normalized = normalize(rawLicense);
    if (STRONG_COPYLEFT.has(normalized)) {
      findings.push({
        category: "copyleft-license",
        severity: "critical",
        file: reportPath,
        description: `Dependency '${dep}' is licensed under ${rawLicense} (strong copyleft).`,
        why_it_matters:
          "Strong copyleft licenses like GPL/AGPL generally require you to release your application's source code under the same license if you distribute or (for AGPL) even network-serve it. This can force disclosure of your entire proprietary codebase.",
        suggested_fix: `Find a permissively-licensed alternative to '${dep}' (MIT/Apache-2.0/BSD), or consult a lawyer before shipping if it must stay.`,
      });
    } else if (WEAK_COPYLEFT.has(normalized)) {
      findings.push({
        category: "copyleft-license",
        severity: "medium",
        file: reportPath,
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

// Session-level cache: an agent may scan the same repo (or several Flutter
// repos) in one session; re-fetching every package's score each time wastes
// seconds of wall-clock and hammers pub.dev for identical answers.
const licenseTagCache = new Map<string, LicenseLookup>();

/** Test hook — clears the module-level pub.dev cache. */
export function clearLicenseCache(): void {
  licenseTagCache.clear();
}

export type LicenseLookup =
  | { ok: true; tags: string[] }
  | { ok: false; reason: "unreachable" | "no-license-tags" };

async function fetchPackageLicense(name: string): Promise<LicenseLookup> {
  const cached = licenseTagCache.get(name);
  if (cached) return cached;
  // Dogfooding showed two distinct failure modes: transient network errors,
  // and pub.dev briefly serving degraded score objects (maxPoints: 0, no
  // license:* tags — verified against the live API). Both are temporary;
  // growing backoff rides out the common window without hammering.
  let result: LicenseLookup = { ok: false, reason: "unreachable" };
  const delays = [0, 300, 1500];
  for (const delay of delays) {
    if (delay > 0) await new Promise((r) => setTimeout(r, delay));
    try {
      const res = await fetch(`https://pub.dev/api/packages/${encodeURIComponent(name)}/score`, {
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) continue;
      const json = (await res.json()) as unknown;
      const tags = licenseTagsFromScore(json);
      if (tags.length > 0) {
        result = { ok: true, tags };
        break;
      }
      result = { ok: false, reason: "no-license-tags" };
    } catch {
      result = { ok: false, reason: "unreachable" };
    }
  }
  licenseTagCache.set(name, result);
  return result;
}

/** How many pub.dev lookups run in parallel. Small enough to stay polite. */
const LICENSE_FETCH_CONCURRENCY = 6;

async function mapWithConcurrency<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const idx = next++;
      results[idx] = await fn(items[idx]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
  return results;
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

/**
 * Checks every pubspec.lock in the repo — Flutter monorepos (melos-style
 * packages/*) have one per package, and each resolves its own dependency set.
 */
async function checkFlutterDependencies(rootDir: string, files: string[], findings: Finding[]) {
  const lockFiles = files.filter((f) => f === "pubspec.lock" || f.endsWith("/pubspec.lock"));
  if (lockFiles.length === 0) return; // not a Flutter project, nothing to do

  for (const lockPath of lockFiles) {
    let lockContent: string;
    try {
      lockContent = await readFile(join(rootDir, lockPath), "utf-8");
    } catch {
      continue;
    }
    await checkPubspecLock(lockPath, lockContent, findings);
  }
}

async function checkPubspecLock(lockPath: string, lockContent: string, findings: Finding[]) {
  const deps = parsePubspecLock(lockContent);
  // Parallel lookups keep a ~90-package lockfile scan in seconds, not minutes;
  // deterministic output order is preserved via indexed results.
  const licenses = await mapWithConcurrency(deps, LICENSE_FETCH_CONCURRENCY, (dep) =>
    fetchPackageLicense(dep.name),
  );

  for (let i = 0; i < deps.length; i++) {
    const dep = deps[i];
    const lookup = licenses[i];
    const reportPath = `${lockPath} (${dep.name} ${dep.version})`;

    if (!lookup.ok) {
      findings.push({
        category: "copyleft-license",
        severity: "medium",
        file: reportPath,
        description:
          lookup.reason === "no-license-tags"
            ? `License for pub.dev dependency '${dep.name}' could not be determined — pub.dev returned score data with no license tags (a transient state on pub.dev's side; re-scanning usually resolves it).`
            : `License for pub.dev dependency '${dep.name}' could not be determined (pub.dev unreachable or package not found).`,
        why_it_matters:
          "Undetermined license means you have no confirmed legal basis to use the package commercially — some packages misreport or omit license metadata entirely.",
        suggested_fix: `Check '${dep.name}' directly on pub.dev or its source repository for a LICENSE file, or replace it with a package that declares one clearly.`,
      });
      continue;
    }

    const licenseTags = lookup.tags;
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

/**
 * Python dependency checking (requirements*.txt). PyPI splits license data
 * across three metadata fields depending on package vintage — PEP 639
 * `license_expression` (new), freeform `license` (older), and trove
 * classifiers (oldest) — so all three are consulted. Like the npm/pub.dev
 * checks, only copyleft families matter here; permissive ambiguity is
 * deliberately not surfaced.
 */

interface PyLicenseLookup {
  ok: boolean;
  /** Copyleft classification result, when the package's metadata was readable. */
  severity: "critical" | "medium" | null;
  label: string;
  /**
   * True when PyPI metadata declared SOME license (permissive ones are
   * silently fine); false only when every license field was empty —
   * which is its own honest finding.
   */
  declared: boolean;
  reason?: "unreachable" | "no-license-data";
}

const pypiCache = new Map<string, PyLicenseLookup>();

/** Test hook — clears the module-level PyPI cache. */
export function clearPypiCache(): void {
  pypiCache.clear();
}

function classifyPythonLicense(haystack: string): { severity: "critical" | "medium" | null; label: string } {
  const has = (re: RegExp) => re.test(haystack);
  // Order matters: AGPL/LGPL contain the string "GPL".
  if (has(/affero general public license|(^|[^a-z])agpl/i)) {
    return { severity: "critical", label: /v\.?\s*3|agpl-?3/i.test(haystack) ? "AGPL-3.0" : "AGPL" };
  }
  if (has(/lesser general public license|(^|[^a-z])lgpl/i)) {
    return {
      severity: "medium",
      label: /v\.?\s*3|lgpl-?3/i.test(haystack) ? "LGPL-3.0" : "LGPL-2.1",
    };
  }
  if (has(/general public license|(^|[^a-z])gpl/i)) {
    return {
      severity: "critical",
      label: /v\.?\s*3|gpl-?3/i.test(haystack) ? "GPL-3.0" : "GPL-2.0",
    };
  }
  if (has(/mozilla public license|(^|[^a-z])mpl/i)) {
    return { severity: "medium", label: "MPL-2.0" };
  }
  if (has(/eclipse public license|(^|[^a-z])epl/i)) {
    return { severity: "medium", label: "EPL-1.0" };
  }
  if (has(/\bcecill-?b\b/i)) {
    return { severity: "critical", label: "CeCILL-B" };
  }
  return { severity: null, label: "" };
}

async function fetchPyLicense(name: string): Promise<PyLicenseLookup> {
  const cached = pypiCache.get(name);
  if (cached) return cached;

  let lookup: PyLicenseLookup = { ok: false, declared: false, severity: null, label: "", reason: "unreachable" };
  for (const delay of [0, 300, 1500]) {
    if (delay > 0) await new Promise((r) => setTimeout(r, delay));
    try {
      const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, {
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) continue;
      const json = (await res.json()) as {
        info?: {
          license_expression?: string | null;
          license?: string | null;
          classifiers?: string[];
        };
      };
      const info = json.info ?? {};
      const classifiers = (info.classifiers ?? []).filter((c) => c.startsWith("License ::")).join(" | ");
      // Freeform `license` is sometimes an entire LICENSE file pasted in —
      // cap it so haystack stays a summary, and skip obviously useless values.
      const freeform =
        info.license && info.license.length <= 120 && !/^unknown$/i.test(info.license.trim())
          ? info.license
          : "";
      const haystack = [info.license_expression ?? "", freeform, classifiers].filter(Boolean).join(" | ");

      if (!haystack.trim()) {
        lookup = { ok: true, declared: false, severity: null, label: "", reason: "no-license-data" };
        break;
      }

      // A License classifier or expression exists — classify against it.
      const { severity, label } = classifyPythonLicense(haystack);
      // Permissive licenses land here with severity null — silent, like npm/pub.dev.
      lookup = { ok: true, declared: true, severity, label };
      break;
    } catch {
      // retry with backoff
    }
  }
  pypiCache.set(name, lookup);
  return lookup;
}

/** Extracts installable PyPI package names from a requirements.txt body. */
export function parseRequirementsTxt(content: string): string[] {
  const names = new Set<string>();
  for (const raw of content.split("\n")) {
    const line = raw.split("#")[0].trim();
    if (!line || line.startsWith("-")) continue; // comments, -r, -e, --hash etc.
    if (/https?:\/\/|^\.|^\/|git\+/.test(line)) continue; // local/VCS deps: nothing to look up
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/);
    if (m && m[1].length > 1) names.add(m[1]);
  }
  return [...names].sort();
}

async function checkPythonDependencies(rootDir: string, files: string[], findings: Finding[]) {
  const reqFiles = files.filter(
    (f) => /^requirements.*\.txt$/.test(f.split("/").pop() ?? "") && !f.includes("node_modules"),
  );
  if (reqFiles.length === 0) return;

  for (const reqPath of reqFiles) {
    let content: string;
    try {
      content = await readFile(join(rootDir, reqPath), "utf-8");
    } catch {
      continue;
    }
    const deps = parseRequirementsTxt(content);
    const lookups = await mapWithConcurrency(deps, LICENSE_FETCH_CONCURRENCY, fetchPyLicense);

    for (let i = 0; i < deps.length; i++) {
      const dep = deps[i];
      const lookup = lookups[i];
      const reportPath = `${reqPath} (${dep})`;

      if (!lookup.ok) {
        findings.push({
          category: "copyleft-license",
          severity: "medium",
          file: reportPath,
          description: `License for PyPI dependency '${dep}' could not be determined (pypi.org unreachable).`,
          why_it_matters:
            "Undetermined license means you have no confirmed legal basis to use the package commercially.",
          suggested_fix: `Check '${dep}' on pypi.org or its source repository for license metadata.`,
        });
        continue;
      }

      if (lookup.severity === "critical") {
        findings.push({
          category: "copyleft-license",
          severity: "critical",
          file: reportPath,
          description: `PyPI dependency '${dep}' is licensed under ${lookup.label} (strong copyleft) per its PyPI metadata.`,
          why_it_matters:
            "Strong copyleft licenses like GPL/AGPL generally require you to release your application's source code under the same license if you distribute or (for AGPL) even network-serve it.",
          suggested_fix: `Find a permissively-licensed alternative to '${dep}', or consult a lawyer before shipping if it must stay.`,
        });
      } else if (lookup.severity === "medium") {
        findings.push({
          category: "copyleft-license",
          severity: "medium",
          file: reportPath,
          description: `PyPI dependency '${dep}' is licensed under ${lookup.label} (weak copyleft) per its PyPI metadata.`,
          why_it_matters:
            "Weak copyleft is usually fine if you import the package unmodified, but modifying or vendoring it can trigger disclosure requirements.",
          suggested_fix: `Confirm you're using '${dep}' unmodified and as an external dependency.`,
        });
      } else if (!lookup.declared) {
        findings.push({
          category: "copyleft-license",
          severity: "medium",
          file: reportPath,
          description: `License for PyPI dependency '${dep}' could not be determined — its metadata declares no license.`,
          why_it_matters:
            "No declared license means all rights remain with the author by default; using it commercially without confirmation is a real risk.",
          suggested_fix: `Verify '${dep}' has a LICENSE file in its source repository, or replace it with a clearly-licensed package.`,
        });
      }
    }
  }
}

export const licenseCheck: Detector = async (ctx) => {
  const findings: Finding[] = [];
  await checkNodeDependencies(ctx.rootDir, ctx.files, findings);
  await checkFlutterDependencies(ctx.rootDir, ctx.files, findings);
  await checkPythonDependencies(ctx.rootDir, ctx.files, findings);
  return findings;
};
