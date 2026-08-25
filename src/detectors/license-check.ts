import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import correct from "spdx-correct";
import { readTextClean } from "../lib/content.js";
import {
  licenseWhyStrong,
  licenseWhyWeak,
  licenseWhyUndeclared,
  licenseWhyLookupFailed,
  licenseFixStrong,
  licenseFixWeak,
  licenseFixUndeclared,
} from "../lib/plain-words.js";
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
      const pkgRaw = await readTextClean(join(rootDir, pkgPath));
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
    const depPkgRaw = await readTextClean(join(rootDir, pkgDir, "node_modules", dep, "package.json"));
    const depPkg = JSON.parse(depPkgRaw);
    const rawLicense: string | undefined =
      typeof depPkg.license === "string" ? depPkg.license : depPkg.license?.type ?? depPkg.licenses?.[0]?.type;

    if (!rawLicense) {
      findings.push({
        category: "copyleft-license",
        severity: "medium",
        file: reportPath,
        description: `Package '${dep}' doesn't say what you're allowed to do with it (no license).`,
        why_it_matters: licenseWhyUndeclared("npm"),
        suggested_fix: licenseFixUndeclared(dep),
      });
      return;
    }

    const normalized = normalize(rawLicense);
    if (STRONG_COPYLEFT.has(normalized)) {
      findings.push({
        category: "copyleft-license",
        severity: "critical",
        file: reportPath,
        description: `Package '${dep}' uses ${rawLicense} — a "share your source" license.`,
        why_it_matters: licenseWhyStrong(rawLicense),
        suggested_fix: licenseFixStrong(dep),
      });
    } else if (WEAK_COPYLEFT.has(normalized)) {
      findings.push({
        category: "copyleft-license",
        severity: "medium",
        file: reportPath,
        description: `Package '${dep}' uses ${rawLicense} — a mild share-your-changes license.`,
        why_it_matters: licenseWhyWeak(),
        suggested_fix: licenseFixWeak(dep),
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
      lockContent = await readTextClean(join(rootDir, lockPath));
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
            ? `We couldn't look up '${dep.name}' because pub.dev sent back incomplete info right now (their side; scanning again usually fixes it).`
            : `We couldn't reach pub.dev to look up '${dep.name}'.`,
        why_it_matters: licenseWhyLookupFailed("pub.dev"),
        suggested_fix: licenseFixUndeclared(dep.name),
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
        description: `Flutter package '${dep.name}' (version ${dep.version}) uses ${licenseTags.join(" OR ")} — a "share your source" license.`,
        why_it_matters: licenseWhyStrong(licenseTags.join(" OR ")),
        suggested_fix: licenseFixStrong(dep.name),
      });
    } else if (severity === "medium") {
      findings.push({
        category: "copyleft-license",
        severity: "medium",
        file: `pubspec.lock (${dep.name} ${dep.version})`,
        description: `Flutter package '${dep.name}' (version ${dep.version}) uses a mild share-your-changes license (${licenseTags.join(" OR ")}).`,
        why_it_matters: licenseWhyWeak(),
        suggested_fix: licenseFixWeak(dep.name),
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
      content = await readTextClean(join(rootDir, reqPath));
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
          description: `We couldn't reach pypi.org to look up '${dep}'.`,
          why_it_matters: licenseWhyLookupFailed("pypi.org"),
          suggested_fix: licenseFixUndeclared(dep),
        });
        continue;
      }

      if (lookup.severity === "critical") {
        findings.push({
          category: "copyleft-license",
          severity: "critical",
          file: reportPath,
          description: `Python package '${dep}' uses ${lookup.label} — a "share your source" license.`,
          why_it_matters: licenseWhyStrong(lookup.label),
          suggested_fix: licenseFixStrong(dep),
        });
      } else if (lookup.severity === "medium") {
        findings.push({
          category: "copyleft-license",
          severity: "medium",
          file: reportPath,
          description: `Python package '${dep}' uses a mild share-your-changes license (${lookup.label}).`,
          why_it_matters: licenseWhyWeak(),
          suggested_fix: licenseFixWeak(dep),
        });
      } else if (!lookup.declared) {
        findings.push({
          category: "copyleft-license",
          severity: "medium",
          file: reportPath,
          description: `Python package '${dep}' doesn't say what you're allowed to do with it (no license listed).`,
          why_it_matters: licenseWhyUndeclared("pypi.org"),
          suggested_fix: licenseFixUndeclared(dep),
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
  await checkCargoDependencies(ctx.rootDir, ctx.files, findings);
  await checkComposerDependencies(ctx.rootDir, ctx.files, findings);
  await checkRubyDependencies(ctx.rootDir, ctx.files, findings);
  return findings;
};

// ── Rust (Cargo.toml → crates.io) ────────────────────────────────────────

const cratesIoCache = new Map<string, PyLicenseLookup>();

/** Test hook — clears the module-level crates.io cache. */
export function clearCratesCache(): void {
  cratesIoCache.clear();
}

async function fetchCrateLicense(name: string): Promise<PyLicenseLookup> {
  const cached = cratesIoCache.get(name);
  if (cached) return cached;

  let lookup: PyLicenseLookup = { ok: false, declared: false, severity: null, label: "", reason: "unreachable" };
  for (const delay of [0, 300]) {
    if (delay > 0) await new Promise((r) => setTimeout(r, delay));
    try {
      // crates.io requires a User-Agent or returns 403.
      const res = await fetch(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`, {
        headers: { "User-Agent": "shipcheck (pre-launch license scanner)" },
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) continue;
      const json = (await res.json()) as { versions?: { license?: string; num?: string }[] };
      const license = json.versions?.[0]?.license ?? "";
      if (!license.trim()) {
        lookup = { ok: true, declared: false, severity: null, label: "", reason: "no-license-data" };
        break;
      }
      const { severity, label } = classifyPythonLicense(license);
      lookup = { ok: true, declared: true, severity, label };
      break;
    } catch {
      // retry
    }
  }
  cratesIoCache.set(name, lookup);
  return lookup;
}

/** Extracts crate names from [dependencies]-style tables; skips path/git/workspace-inherited deps. */
export function parseCargoTomlDependencies(content: string): string[] {
  const names = new Set<string>();
  let inDeps = false;
  for (const raw of content.split("\n")) {
    const line = raw.split("#")[0].trim();
    if (!line) continue;
    if (line.startsWith("[")) {
      inDeps = /\[dependencies\]/.test(line) || /\[.+\.dependencies\]/.test(line);
      continue;
    }
    if (!inDeps) continue;
    // Workspace inheritance comes in two shapes; both mean "resolved by the
    // root manifest", and workspace members are the repo's OWN crates anyway.
    if (/^[A-Za-z0-9_-]+\.workspace\s*=/.test(line)) continue;
    if (/^(workspace\s*=)/.test(line)) continue;
    const nameMatch = line.match(/^([A-Za-z0-9_-]+)\s*=/);
    if (!nameMatch) continue;
    // path = / git = deps are not on crates.io
    if (/(^|[,{]\s*)(path|git)\s*=/.test(line.slice(nameMatch[0].length))) continue;
    names.add(nameMatch[1]);
  }
  return [...names].sort();
}

/** Names of the repo's own crates from a root manifest's [workspace] members. */
export function parseCargoWorkspaceMembers(content: string): string[] {
  const members: string[] = [];
  let inMembers = false;
  for (const raw of content.split("\n")) {
    const line = raw.split("#")[0].trim();
    if (/^\[/.test(line)) { inMembers = false; continue; }
    if (/^members\s*=/.test(line)) { inMembers = true; continue; }
    if (inMembers) {
      const m = line.match(/"([^"]+)"/g);
      if (m) for (const quoted of m) members.push(quoted.slice(1, -1).split("/").pop()!);
      if (line.includes("]")) break;
    }
  }
  return [...new Set(members)].filter(Boolean);
}

async function checkCargoDependencies(rootDir: string, files: string[], findings: Finding[]) {
  const manifests = files.filter((f) => f === "Cargo.toml" || f.endsWith("/Cargo.toml"));
  if (manifests.length === 0) return;

  // The repo's own crates (workspace members) are never crates.io packages.
  let ownCrates = new Set<string>();
  const rootManifest = manifests.find((m) => m === "Cargo.toml");
  if (rootManifest) {
    try {
      ownCrates = new Set(parseCargoWorkspaceMembers(await readTextClean(join(rootDir, rootManifest))));
    } catch {
      // no readable root manifest; per-manifest filtering still applies
    }
  }

  for (const manifestPath of manifests) {
    if (ownCrates.has(manifestPath.split("/").slice(0, -1).pop() ?? "")) continue; // member crate's own manifest
    let content: string;
    try {
      content = await readTextClean(join(rootDir, manifestPath));
    } catch {
      continue;
    }
    const deps = parseCargoTomlDependencies(content).filter((d) => !ownCrates.has(d));
    const lookups = await mapWithConcurrency(deps, LICENSE_FETCH_CONCURRENCY, fetchCrateLicense);

    for (let i = 0; i < deps.length; i++) {
      emitDependencyLicenseFinding({
        findings,
        reportPath: `${manifestPath} (${deps[i]})`,
        depName: deps[i],
        source: "crates.io",
        lookup: lookups[i],
        strongWhy:
          "Strong copyleft licenses like GPL generally require you to release your application's source code under the same license if you distribute binaries built from them.",
      });
    }
  }
}

// ── Shared emitter for API-backed ecosystems ─────────────────────────────

function emitDependencyLicenseFinding(opts: {
  findings: Finding[];
  reportPath: string;
  depName: string;
  source: string;
  lookup: PyLicenseLookup;
  strongWhy: string;
}): void {
  const { findings, reportPath, depName, source, lookup, strongWhy } = opts;

  if (!lookup.ok) {
    findings.push({
      category: "copyleft-license",
      severity: "medium",
      file: reportPath,
      description: `We couldn't reach ${source} to look up '${depName}'.`,
      why_it_matters: licenseWhyLookupFailed(source),
      suggested_fix: licenseFixUndeclared(depName),
    });
    return;
  }
  if (!lookup.declared || lookup.severity === null) {
    if (!lookup.declared) {
      findings.push({
        category: "copyleft-license",
        severity: "medium",
        file: reportPath,
        description: `Package '${depName}' doesn't say what you're allowed to do with it (no license listed).`,
        why_it_matters: licenseWhyUndeclared(source),
        suggested_fix: licenseFixUndeclared(depName),
      });
    }
    return; // declared and permissive → silent
  }

  const strong = lookup.severity === "critical";
  findings.push({
    category: "copyleft-license",
    severity: lookup.severity,
    file: reportPath,
    description: strong
      ? `Package '${depName}' uses ${lookup.label} — a "share your source" license.`
      : `Package '${depName}' uses a mild share-your-changes license (${lookup.label}).`,
    why_it_matters: strong ? licenseWhyStrong(lookup.label) : licenseWhyWeak(),
    suggested_fix: strong ? licenseFixStrong(depName) : licenseFixWeak(depName),
  });
}

// ── PHP (composer.lock — license data is embedded, fully offline) ─────────

interface ComposerPackage {
  name?: string;
  license?: string[];
}

/** Extracts runtime package entries from composer.lock JSON. */
export function parseComposerLockPackages(content: string): { name: string; licenses: string[] }[] {
  let doc: { packages?: ComposerPackage[] };
  try {
    doc = JSON.parse(content);
  } catch {
    return [];
  }
  return (doc.packages ?? [])
    .filter((p) => typeof p.name === "string")
    .map((p) => ({ name: p.name as string, licenses: Array.isArray(p.license) ? p.license : [] }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

async function checkComposerDependencies(rootDir: string, files: string[], findings: Finding[]) {
  const locks = files.filter((f) => f === "composer.lock" || f.endsWith("/composer.lock"));
  for (const lockPath of locks) {
    let content: string;
    try {
      content = await readTextClean(join(rootDir, lockPath));
    } catch {
      continue;
    }
    // packages-dev is deliberately skipped, same shipping-scope rule as npm devDependencies.
    for (const pkg of parseComposerLockPackages(content)) {
      const haystack = pkg.licenses.join(" | ");
      if (!haystack.trim()) {
        findings.push({
          category: "copyleft-license",
          severity: "medium",
          file: `${lockPath} (${pkg.name})`,
          description: `PHP package '${pkg.name}' doesn't say what you're allowed to do with it (no license in composer.lock).`,
          why_it_matters: licenseWhyUndeclared("its listing"),
          suggested_fix: licenseFixUndeclared(pkg.name),
        });
        continue;
      }
      const { severity, label } = classifyPythonLicense(haystack);
      if (severity === null) continue; // permissive → silent
      findings.push({
        category: "copyleft-license",
        severity,
        file: `${lockPath} (${pkg.name})`,
        description: severity === "critical"
          ? `PHP package '${pkg.name}' uses ${label} — a "share your source" license.`
          : `PHP package '${pkg.name}' uses a mild share-your-changes license (${label}).`,
        why_it_matters: severity === "critical" ? licenseWhyStrong(label) : licenseWhyWeak(),
        suggested_fix: severity === "critical" ? licenseFixStrong(pkg.name) : licenseFixWeak(pkg.name),
      });
    }
  }
}

// ── Ruby (Gemfile.lock → rubygems.org) ────────────────────────────────────

const rubygemsCache = new Map<string, PyLicenseLookup>();

/** Test hook — clears the module-level rubygems cache. */
export function clearRubygemsCache(): void {
  rubygemsCache.clear();
}

async function fetchGemLicense(name: string): Promise<PyLicenseLookup> {
  const cached = rubygemsCache.get(name);
  if (cached) return cached;

  let lookup: PyLicenseLookup = { ok: false, declared: false, severity: null, label: "", reason: "unreachable" };
  for (const delay of [0, 300]) {
    if (delay > 0) await new Promise((r) => setTimeout(r, delay));
    try {
      const res = await fetch(`https://rubygems.org/api/v1/gems/${encodeURIComponent(name)}.json`, {
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) continue;
      const json = (await res.json()) as { licenses?: string[] | null };
      const licenses = Array.isArray(json.licenses) ? json.licenses : [];
      if (licenses.length === 0) {
        lookup = { ok: true, declared: false, severity: null, label: "", reason: "no-license-data" };
        break;
      }
      const { severity, label } = classifyPythonLicense(licenses.join(" | "));
      lookup = { ok: true, declared: true, severity, label };
      break;
    } catch {
      // retry
    }
  }
  rubygemsCache.set(name, lookup);
  return lookup;
}

/** Extracts gem names from a Gemfile.lock GEM section's specs list. */
export function parseGemfileLockGems(content: string): string[] {
  const names = new Set<string>();
  let inSpecs = false;
  for (const raw of content.split("\n")) {
    if (raw.trim() === "" ) { if (inSpecs && !raw.startsWith("    ")) inSpecs = false; continue; }
    if (/^  specs:/.test(raw)) { inSpecs = true; continue; }
    if (inSpecs) {
      if (!raw.startsWith("    ")) { inSpecs = false; continue; }
      const m = raw.trim().match(/^([a-zA-Z0-9_.-]+)\s+\(/);
      if (m) names.add(m[1]);
    }
  }
  return [...names].sort();
}

async function checkRubyDependencies(rootDir: string, files: string[], findings: Finding[]) {
  const lockfiles = files.filter((f) => f === "Gemfile.lock" || f.endsWith("/Gemfile.lock"));
  for (const lockPath of lockfiles) {
    let content: string;
    try {
      content = await readTextClean(join(rootDir, lockPath));
    } catch {
      continue;
    }
    const gems = parseGemfileLockGems(content);
    const lookups = await mapWithConcurrency(gems, LICENSE_FETCH_CONCURRENCY, fetchGemLicense);

    for (let i = 0; i < gems.length; i++) {
      emitDependencyLicenseFinding({
        findings,
        reportPath: `${lockPath} (${gems[i]})`,
        depName: gems[i],
        source: "rubygems.org",
        lookup: lookups[i],
        strongWhy:
          "Strong copyleft licenses like GPL generally require you to release your application's source code under the same license when you distribute it.",
      });
    }
  }
}
