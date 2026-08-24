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
- The user explicitly asks to run ShipCheck or scan for security/compliance issues.

Do NOT trigger this for routine code edits unrelated to shipping — it's a pre-launch check, not a
lint-on-every-save tool in v1.

## How to use it

1. Call the `scan_repo` tool with the project root path (default to the current working directory if the
   user doesn't specify one).
2. Read the returned JSON: `summary` (counts by severity) and `findings` (array of individual issues).
   The response is already deduplicated and size-capped; if a finding has a `locations` array, it is ONE
   credential/pattern found in several places — present it as one issue with all locations, not N issues.
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

1. Exposed secrets (API keys, tokens, committed `.env` files)
2. Copyleft-licensed dependencies (GPL/AGPL/LGPL) in what looks like a closed-source app — npm
   dependencies from installed `node_modules`, and pub.dev packages via `pubspec.lock`
3. Unauthenticated endpoints that appear to handle user/account data (Express, FastAPI, and Next.js API
   routes in both App Router and Pages Router styles)
4. PII collection (analytics, signup forms, auth) with no privacy policy or consent artifact found
5. Client-side/raw payment card field handling instead of a PCI-scoped processor SDK

## What this does NOT do

Do not imply to the user that this tool checks for SQL injection, XSS, general security vulnerabilities,
or any specific legal framework's compliance (GDPR/HIPAA/PCI/ADA/COPPA). If the user's actual concern is
one of those, say so plainly and suggest a purpose-built tool or a professional instead of stretching
ShipCheck's results to cover it.
