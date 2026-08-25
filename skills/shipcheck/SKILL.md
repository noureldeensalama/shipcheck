---
name: shipcheck
description: Use before an app is deployed, published, submitted to an app store, or described as "ready to launch." Also use whenever the user asks about security, compliance, launch-readiness, or "is this safe to ship." Runs the ShipCheck MCP scan_repo tool and presents results as risk flags to review — never as a pass/fail or compliance verdict.
---

# ShipCheck — pre-launch risk scanning

## When to use this

Trigger this skill when:
- The user says something like "is this ready to launch," "can I ship this," "is this secure," or asks
  about compliance/legal risk for an app they're building.
- You (the agent) are about to help the user deploy, publish, or submit an app to an app store, and no
  scan has been run yet in this session.
- You (the agent) are about to commit, push, or hand a batch of changes back to the user — run
  `scan_diff` first and mention anything it flags before proceeding.
- The user explicitly asks to run ShipCheck or scan for security/compliance issues.

Do NOT trigger this for trivial, self-contained edits with no shipping surface (a typo fix in docs,
renaming a variable) — but when in doubt, `scan_diff` is cheap; running it is never wrong.

## How to use it

Two tools are available — pick by scope:

- **`scan_diff`** (default for the daily loop): scans only uncommitted changes (staged + unstaged +
  new files) vs HEAD, or a whole branch via `base`. Use it whenever the agent is about to commit,
  push, or hand work back to the user mid-build — it's fast and only reads what changed. An empty
  diff result says NOTHING about the repo as a whole; don't present it as a clean bill.
- **`scan_repo`**: full-repository audit before launch/app-store submission or on a brand-new
  codebase.

For both:
1. Call the tool with the project root path (default to the current working directory if the user
   doesn't specify one).
2. Read the returned JSON: `summary` (counts, `scanned_files`, inferred `project_types`, a
   `coverage_caveat` when a detected stack lacks endpoint coverage, and for diffs the base ref) and
   `findings` (array of individual issues). The response is already deduplicated and size-capped;
   if a finding has a `locations` array, it is ONE credential/pattern found in several places —
   present it as one issue with all locations, not N issues.
3. Present findings to the user grouped by severity, critical first. For each finding, give:
   - What was found and where (file + line)
   - Why it matters, in plain language — assume the user may not know what PCI, RLS, or copyleft mean
   - The suggested fix
   Keep your own output lean too: don't repeat identical explanations verbatim per finding when one
   shared explanation plus a location list says the same thing with fewer words.
4. **Always** include the tool's own disclaimer near the top of your summary: this is risk-pattern
   detection, not a legal compliance certification, and a zero-findings result means nothing in these
   five categories was detected — not that the app is legally or securely sound.
5. If the tool returns an error (path doesn't exist, not a directory), tell the user plainly — do not
   treat an error as a clean scan.
6. If `summary.truncated` is true, say so and offer a follow-up scan with a `categories` filter to
   retrieve findings beyond the cap.
7. If the user asks "am I compliant" or "is this legal," explicitly say you can't determine that — you can
   only say what risk patterns were or weren't found in these five categories, and point them to an actual
   lawyer for anything with real legal stakes (this matters — do not let the user walk away thinking a
   clean scan is a legal green light).

## Categories this checks (v1)

1. Exposed secrets (API keys, tokens, committed `.env` files) — including secrets deleted from current code but still readable in git history
2. Copyleft-licensed dependencies (GPL/AGPL/LGPL) in what looks like a closed-source app — npm
   dependencies from installed `node_modules`, pub.dev packages via `pubspec.lock`, and Python
   dependencies from `requirements*.txt` via PyPI metadata
3. Unauthenticated endpoints handling user/account data (Express, FastAPI, Flask, Next.js App
   Router + Pages Router, gin/echo/fiber-style Go routers, Laravel, Spring Boot)
4. PII collection (analytics, signup forms, auth) with no privacy policy or consent artifact found
5. Client-side/raw payment card field handling instead of a PCI-scoped processor SDK

## What this does NOT do

Do not imply to the user that this tool checks for SQL injection, XSS, general security vulnerabilities,
or any specific legal framework's compliance (GDPR/HIPAA/PCI/ADA/COPPA). If the user's actual concern is
one of those, say so plainly and suggest a purpose-built tool or a professional instead of stretching
ShipCheck's results to cover it.
