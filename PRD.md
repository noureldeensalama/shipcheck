# ShipCheck — Product Requirements Document

**Author:** Nour Salama
**Status:** Draft v1.0
**Last updated:** 2026-08-23

---

## 1. Problem Statement

AI coding agents (Claude Code, OpenCode, Cursor, and BYOK setups) let people ship working applications
without traditional engineering experience. This is good for velocity and bad for risk awareness: the
agent optimizes for "does it run," not "will this get you sued, breached, or DMCA'd."

The specific failure mode this project targets: a solo builder ships an app built almost entirely by an
AI agent, and only discovers a critical issue — a leaked API key, a GPL-licensed dependency in a closed
commercial product, an unauthenticated endpoint serving user data, card data touching their own server
instead of a PCI-scoped processor — *after* it's live, indexed, or breached. None of these require deep
security expertise to catch. They require someone to actually look, and vibe coders don't know to look
because they don't know these categories exist.

## 2. Non-Goals (explicitly out of scope, say this out loud)

- This is **not** a legal compliance certification tool. It does not determine GDPR/HIPAA/PCI/ADA
  compliance and must never claim to. It flags *risk patterns*, not legal status.
- This is **not** a general SAST/security scanner (no SQLi/XSS/buffer-overflow detection). Plenty of
  mature tools already do that (Semgrep, CodeQL). We are not competing with them.
- This is **not** a runtime monitoring tool. Static, pre-launch analysis only for v1.
- This is **not** legal advice, and the tool must never use language implying "PASS" or "compliant."

## 3. Target User

Solo developers and small teams shipping apps built substantially with AI coding agents, who have
limited security/legal background — "vibe coders" in the target user's own words — using Claude Code,
OpenCode, Cursor, or any MCP-compatible agent, optionally BYOK.

## 4. Core Principle

**Deterministic detection, LLM explanation.** Every finding starts as a structured, reproducible result
from static analysis (regex, AST parsing, dependency-tree walking, route-table inspection) — never an
LLM's unaided opinion on "is this risky." An LLM (Fable, or whatever model the host agent is running) is
used only downstream, to turn a structured finding into a plain-language explanation and a suggested fix.
This keeps results reproducible, keeps the tool honest about what it can and can't verify, and avoids the
liability of an LLM hallucinating a false "you're fine."

## 5. V1 Scope — Five Risk Categories

Each category below is picked because it is (a) common in AI-agent-generated code, (b) severe when
missed, and (c) mechanically detectable without semantic/legal judgment.

| # | Category | What it detects | Severity if missed |
|---|----------|------------------|---------------------|
| 1 | Exposed secrets | API keys, tokens, private keys committed to the repo or hardcoded client-side | Account takeover, billing abuse, full data breach |
| 2 | Copyleft license contamination | GPL/AGPL/LGPL-licensed dependencies pulled into a closed-source commercial app | Forced disclosure, legal demand letters, forced re-licensing |
| 3 | Unauthenticated data endpoints | Routes/handlers that read or write user data with no auth middleware or RLS-equivalent check (Express, FastAPI, and Next.js API routes — App Router + Pages Router) | Full data exposure, the exact Supabase-RLS class of bug generalized to any backend |
| 4 | PII collection with no privacy policy / consent artifact | Forms, analytics SDKs, or auth providers that collect PII, with no privacy-policy file or consent flow found in the repo | Regulatory exposure, App Store/Play Store rejection, user trust violation |
| 5 | Client-side payment handling | Raw card-number/CVV fields or card data touching the user's own backend instead of a PCI-scoped processor SDK (Stripe Elements, etc.) | PCI violation, processor account termination, fraud liability |

Each finding includes: file + line reference, plain-language "why this matters," a severity tier
(critical / high / medium), and a suggested fix — never a pass/fail verdict for the repo as a whole.

## 6. Architecture

```
Agent (Claude Code / OpenCode / Cursor / BYOK)
        │  MCP (stdio transport)
        ▼
ShipCheck MCP Server (Node.js / TypeScript)
        │
        ├── Detector: secrets-scanner.ts        (regex + entropy check)
        ├── Detector: license-check.ts          (dependency tree + SPDX license DB)
        ├── Detector: unauth-endpoints.ts        (route/handler AST heuristics)
        ├── Detector: pii-consent-check.ts       (form/SDK detection + policy-file check)
        ├── Detector: payment-handling.ts        (card-field pattern + processor SDK check)
        │
        ▼
Structured findings (JSON) ──► returned to the calling agent
        ▼
Agent's LLM turns findings into plain-language report (this is where Fable/Claude does the explaining)
```

Distributed as a **Claude Code plugin**: bundles the MCP server config (`.mcp.json`), a skill
(`skills/shipcheck/SKILL.md`) that teaches the agent when to invoke the scan and how to present results,
and a plugin manifest (`.claude-plugin/plugin.json`). Because it's a standard MCP server underneath, it
also works standalone in OpenCode, Cursor, or any other MCP host via the same `.mcp.json` — the plugin
wrapper is a Claude Code-specific convenience layer, not a hard dependency.

## 7. Tool Interface (MCP Tool Definition)

`scan_repo`
- **Input:** `path` (string, defaults to cwd), `categories` (optional array to limit which of the 5 run)
- **Output:** JSON array of findings: `{ category, severity, file, line, description, suggested_fix }`

`scan_diff` *(shipped in v0.2.0)*
- Same as above but scoped to uncommitted changes (or a branch via `base`) — for inline checking as an
  agent writes new code, not just a one-shot audit.

## 8. Success Criteria for V1

- Correctly flags all 5 categories on a deliberately-vulnerable test fixture app (included in the repo)
  with zero false negatives on the fixture.
- False-positive rate low enough to be usable — validated by running against your own FounderDive and
  Fitloom repos and manually checking every flagged item.
- Installable via `/plugin install shipcheck` in Claude Code, and independently as a standalone MCP
  server via `.mcp.json` in at least one other agent (OpenCode) to prove the agent-agnostic claim isn't
  just a slide.

## 9. Milestones

1. **Week 1:** Secrets scanner + license checker fully working (highest signal-to-effort ratio, no AST
   parsing required). Test fixtures. Basic MCP server wired up, tested locally in Claude Code.
2. **Week 2:** Unauthenticated-endpoint heuristic (start with Express + FastAPI route patterns — the two
   most common in AI-agent-generated backends), PII/consent check, payment-handling check. Plugin
   manifest + skill file. README with install instructions and a demo GIF/recording.
3. **Week 3:** Dogfood on your own repos, fix false positives, write CONTRIBUTING.md, open-source the
   repo publicly, submit to the Claude Code plugin marketplace.

## 10. Risks / Honest Caveats

- Static heuristics for "unauthenticated endpoint" are the hardest of the five to get right without
  false positives — framework conventions vary a lot. Scope this narrowly (Express + FastAPI + Next.js
  API routes only — the three most common in AI-agent-generated apps; Flutter/Dart has no server-route
  concept so it's out of scope here) rather than trying to generalize to every framework.
- The tool must never claim certainty. Every finding is phrased as "this pattern commonly indicates X" —
  legal/security framing discipline matters more than detector count.
- License detection depends on accurate SPDX data per dependency — some packages misreport their license
  in package metadata. Flag "license could not be determined" as its own finding rather than silently
  skipping it.
