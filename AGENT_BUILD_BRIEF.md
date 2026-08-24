# ShipCheck — Agent Build Brief

You are picking up an existing repository, not starting from scratch. Read `PRD.md` in full before
doing anything else — it defines scope, non-goals, and the core design principle (deterministic static
detection; an LLM is only ever used downstream to explain a finding, never to decide whether one exists).
Do not violate that principle anywhere in this work, including in code you write for milestones below.

## Current state (already built and verified — do not redo this)

- MCP server (`src/index.ts`) exposing one tool, `scan_repo`, over stdio transport. Builds clean with
  `npm run build`.
- Five detectors implemented and each independently verified to fire correctly against
  `test-fixtures/vulnerable-app/`: exposed secrets, copyleft license (npm only), unauthenticated
  endpoints (Express + FastAPI only), PII without consent artifact, client-side payment handling.
- Claude Code plugin wrapper: `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`,
  `.mcp.json`, `skills/shipcheck/SKILL.md`.
- Git repo initialized on `main`, one commit, working tree clean.
- Known, documented gaps (do not treat these as bugs to silently patch without following the milestone
  order below — they're intentional v1 scope cuts, see PRD section 10).

Run `npm run verify-fixture` first, before anything else, to confirm the baseline still passes on this
machine. If it doesn't, stop and fix that before starting any milestone — do not build on top of a broken
baseline.

## Milestone 1 — Flutter/pub.dev license coverage

Currently `checkFlutterDependencies` in `src/detectors/license-check.ts` only detects that a Flutter
project exists and emits a "can't check this yet" finding. Replace this with real detection:

- Parse `pubspec.lock` (YAML) to get the full resolved dependency list with versions.
- For each dependency, fetch its license from the pub.dev API (`https://pub.dev/api/packages/{name}`)
  — the response includes a `latest.pubspec` block; license info for pub.dev packages is typically in a
  `LICENSE` file at the package root, not the pubspec itself, so you'll need
  `https://pub.dev/packages/{name}/license` or the package's source repo. Investigate the actual current
  API shape yourself — do not assume the response format without checking a real request first.
- Reuse the existing `STRONG_COPYLEFT` / `WEAK_COPYLEFT` classification sets already defined in the file
  rather than duplicating them.
- Add a fixture: a `pubspec.lock` under a new `test-fixtures/vulnerable-flutter-app/` with at least one
  dependency that resolves to a copyleft license, and confirm the detector fires against it exactly like
  the npm case does.
- Handle the network-failure case explicitly (pub.dev unreachable, package not found) as its own
  medium-severity finding ("license could not be determined"), not a silent skip and not a crash.

**Acceptance:** `npm run verify-fixture` extended to also run against the new Flutter fixture, printing a
non-zero finding count for the copyleft dependency.

## Milestone 2 — Broaden unauthenticated-endpoint coverage

v1 only covers Express and FastAPI route syntax. Add:

- **Flutter/Dart backend patterns are out of scope** — Flutter is a client framework, it doesn't define
  server routes. Do not add Flutter here; this milestone is about server frameworks only.
- Add **Next.js API routes** (`app/api/**/route.ts` handler exports, and the older `pages/api/*.ts`
  pattern) — this is a very common pattern in AI-agent-scaffolded apps and currently produces zero
  findings even when genuinely unauthenticated.
- Add a second fixture file demonstrating a false-positive case that should **not** fire (a route that
  clearly has an auth guard) for each framework you add, so the test suite guards against regressions in
  precision, not just recall.
- Update `PRD.md` section 5's table and `skills/shipcheck/SKILL.md` to reflect the new framework
  coverage honestly — do not leave stale scope claims in either file.

**Acceptance:** New fixtures for Next.js (both router styles) trip the detector; the guarded-route
counterexamples do not.

## Milestone 3 — Automated test suite (not just the manual fixture script)

`scripts/verify-fixture.mjs` is a manual smoke test, not CI-suitable. Build a real test suite:

- Use Node's built-in `node --test` runner (already referenced in `package.json`'s `test` script, but
  unimplemented — no `test/` directory exists yet).
- One test file per detector under `src/test/`, asserting on the `Finding[]` array shape and content
  against the existing fixtures, not just a console-printed count.
- Include at least one explicit false-positive regression test per detector — a fixture snippet that
  looks superficially similar to a risk pattern but should not fire (e.g., a `.env.example` file, which
  the secrets scanner already special-cases — write a test that locks that behavior in).
- Wire `npm test` to actually run these via `node --test`.

**Acceptance:** `npm test` passes and covers all five detectors plus the Milestone 1/2 additions.

## Milestone 4 — CI

Add `.github/workflows/ci.yml`: on every push and PR, run `npm install`, `npm run build`, `npm test`.
Fail the workflow on any test failure or build error. Keep it simple — one job, no matrix builds needed
for v1.

## Milestone 5 — Dogfood against real repositories

This is the milestone that actually matters most and cannot be faked or skipped:

- Run the built scanner (`node dist/index.js` via the MCP inspector, or wired into a real Claude Code
  session) against the user's own FounderDive and Fitloom repositories.
- For every finding produced, manually judge true positive vs. false positive. Log this as a markdown
  file, `DOGFOOD_RESULTS.md`, at the repo root: which repo, which finding, true/false positive, and if
  false, what about the detector's logic caused it.
- If false-positive rate is high on any single detector, narrow that detector's pattern-matching rather
  than leaving it noisy — a detector that cries wolf gets ignored, per the project's own stated design
  principle in `CONTRIBUTING.md`.
- Do not fabricate or guess at this output — this step requires actually running the scanner against
  real code and requires the user's repos to be available to scan. If you do not have access to those
  repositories in this session, stop and say so explicitly rather than inventing plausible-looking
  findings.

**Acceptance:** `DOGFOOD_RESULTS.md` exists with real findings from real repos and an honest
true/false-positive breakdown, including at least one detector that got narrowed as a result.

## Milestone 6 — Publish

Only after Milestones 1–5 are complete and their acceptance criteria are met:

1. Commit all changes with clear, conventional messages (one commit per milestone, not one giant commit).
2. Push to `https://github.com/n0ureldeen/shipcheck` (the user will run the `gh repo create` /
   `git push` step themselves if repo credentials aren't available in this environment — do not attempt
   to authenticate to GitHub on the user's behalf without explicit confirmation).
3. Do not submit to the Claude Code plugin marketplace automatically — that submission form requires the
   user's own account. Prepare the submission by confirming the plugin installs cleanly via
   `claude --plugin-dir` locally, and hand the user the exact URL (claude.ai/settings/plugins/submit) and
   confirmation that local testing passed. Submission itself is the user's action, not yours.

## Guardrails that apply across every milestone

- Never add pass/fail, "compliant," "safe," or "certified" language anywhere in code, output strings, or
  documentation — this is a repeated, explicit requirement from `PRD.md` and `CONTRIBUTING.md`, not a
  suggestion.
- Every new detector or framework addition needs a fixture proving it fires AND a counterexample proving
  it doesn't over-fire. A detector with no false-positive test is not done.
- If a milestone's acceptance criteria can't be met with real verification (e.g., no access to the user's
  real repos for Milestone 5, no network access for Milestone 1's pub.dev calls), say so plainly instead
  of producing output that looks complete but wasn't actually verified. This mirrors the standard already
  set in this repo — every existing detector was built, then actually run against a real fixture with
  printed output, not assumed correct from reading the code.
