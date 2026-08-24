# Contributing to ShipCheck

## Ground rules

1. **Every detector must be deterministic static analysis.** No detector should call out to an LLM to
   *decide* whether something is a risk — LLMs are used downstream (in the consuming agent) to explain
   findings, never inside the detector to produce them. This is the core design principle; PRs that break
   it will be asked to rework, not merged as-is.
2. **No pass/fail language, anywhere.** Findings describe patterns and severity, never "compliant,"
   "safe," "certified," or similar. This project makes no legal claims.
3. **New detector categories need a test fixture.** Add a deliberately-vulnerable example under
   `test-fixtures/` alongside your detector so reviewers (and CI) can verify it actually fires.
4. **False positives are bugs.** If a detector flags something that isn't actually risky, open an issue
   with the offending file/pattern — narrowing a detector's scope to reduce noise is a valid, welcome
   contribution even if it means catching less.

## Adding a new detector

1. Create `src/detectors/your-detector.ts` implementing the `Detector` type from `src/types.ts`.
2. Register it in the `DETECTORS` map and the `categories` enum in `src/index.ts`.
3. Add a fixture under `test-fixtures/` that trips it, and a fixture (or a note) showing what should
   *not* trip it, if the category has an obvious false-positive risk.
4. Update the category table in `README.md`, `PRD.md` section 5, and the skill description in
   `skills/shipcheck/SKILL.md`.

## Development setup

```bash
npm install
npm run dev    # runs the server via tsx against src/ directly
npm run build  # compiles to dist/ for the plugin/production path
```

## Reporting issues

Please include: the file/pattern that produced a false positive or false negative, your framework/stack,
and whether you're running this via the Claude Code plugin or standalone MCP server.
