/**
 * Infers what kind of project(s) a repo contains, from manifest presence.
 * This is the scanner's self-awareness layer: it lets the summary say
 * "Flutter app + FastAPI backend" so agents and founders know what coverage
 * applied — and, just as importantly, an honest note when a detected stack
 * is one the endpoint detector doesn't cover.
 */

const MANIFESTS: { pattern: RegExp; type: string }[] = [
  { pattern: /(^|\/)pubspec\.yaml$/, type: "Flutter/Dart" },
  { pattern: /(^|\/)go\.mod$/, type: "Go module" },
  { pattern: /(^|\/)Cargo\.toml$/, type: "Rust" },
  { pattern: /(^|\/)composer\.json$/, type: "PHP (Composer)" },
  { pattern: /(^|\/)Gemfile$/, type: "Ruby" },
  { pattern: /(^|\/)pom\.xml$/, type: "Java/Maven" },
  { pattern: /(^|\/)build\.gradle(\.kts)?$/, type: "JVM/Gradle" },
  { pattern: /\.csproj$/, type: ".NET" },
  { pattern: /^requirements.*\.txt$|(^|\/)pyproject\.toml$/, type: "Python" },
  { pattern: /(^|\/)package\.json$/, type: "Node.js" },
];

/** Stacks with NO route-level auth detection in v0.x — surfaced honestly. */
export const ENDPOINT_UNCOVERED_TYPES = new Set([
  "Go module", // only gin/fiber/echo-style routers are covered; net/http is not
  "Ruby",
  "Java/Maven",
  "JVM/Gradle", // Spring Boot IS covered; plain JVM projects are not distinguishable yet
  ".NET",
]);

export function detectProjectTypes(files: string[]): string[] {
  const types = new Set<string>();
  for (const f of files) {
    for (const m of MANIFESTS) {
      if (m.pattern.test(f)) types.add(m.type);
    }
  }
  return [...types].sort();
}

/**
 * Human-readable coverage caveat for the summary when a detected stack has
 * known endpoint-detection gaps. Returns null when everything detected is
 * covered (secrets/licenses apply to all stacks regardless).
 */
export function coverageCaveat(types: string[]): string | null {
  const uncovered = types.filter((t) => ENDPOINT_UNCOVERED_TYPES.has(t));
  if (uncovered.length === 0) return null;
  return (
    `Your project uses ${uncovered.join(" and ")}. Our key and license checks work for every kind of project, ` +
    `but our unlocked-route checker doesn't fully understand these yet — so an empty result there is not proof that everything is locked down.`
  );
}
