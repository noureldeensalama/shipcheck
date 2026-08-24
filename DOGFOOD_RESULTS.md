# Dogfood Results

Scanner run against two real repositories via `node scripts/dogfood.mjs <repo>` (same file
listing and detectors as the `scan_repo` MCP tool). Every finding was judged by hand against
the flagged source. Dates: 2026-08-24.

- **FounderDive AI** — Python/FastAPI backend + Next.js frontend, ~100k LOC
- **Fitloom** — Flutter app (pubspec.lock with ~90 hosted deps)

## Headline numbers

| Repo | v1 findings | v1 false positives | final findings | final false positives |
|---|---|---|---|---|
| FounderDive AI | 101 | ~84 (83%) | 17 | 0 confirmed (1 unverifiable) |
| Fitloom | 5 | 3 (60%) | 2 | 0 |

v-final = after two narrowing rounds driven by specific FP clusters below (round 1 fixed the
vendored-code noise and missed guard idioms; round 2 closed documented recall gaps and tightened
the PII artifact rule without regressing either real repo). The v1 noise was so bad it would have
made the tool unusable on a real repo — exactly the "crying wolf" failure mode CONTRIBUTING.md
warns about.

## FounderDive AI

### unauthenticated-endpoint: 25 → 3 (all true positives)

| Finding | Verdict |
|---|---|
| `backend/main.py:862` — `/api/debug/admin-source` | **True positive.** Live diagnostic returning the first 20 lines of deployed `admin.py` to any caller. |
| `backend/main.py:848` — `/api/debug/deepdive-source` | **True positive**, found after adding `debug`/`internal` to sensitive-path hints (round 2). Same source-disclosure pattern. |
| `backend/main.py:876` — `/api/debug/raw-supabase-count` | **True positive** — this was the recall gap documented in v1 notes; it queries `user_profiles` via the service key with no auth. Now flagged. |
| `backend/routers/admin.py` ×18 and `admin_insights.py` ×2 — `/users…` routes "no auth check nearby" | **False positives.** Every one of these handlers takes `admin=Depends(require_admin)` — a project-specific guard dependency the v1 idiom list didn't recognize (it knew `Depends(get_current_user)` / `Depends(verify…)` only). Fixed: generic recognition of any `Depends(<auth-ish name>)`; regression fixture `src/routes/admin_users_guarded.py`. |
| `backend/routers/admin_migrations.py` — `/api/admin/apply-migration` | **False positive, found in round 2** once router prefixes were included in reported paths. The endpoint IS guarded — by an in-handler bearer-token check on `authorization: str = Header(None)`, with no `Depends()` anywhere. Fixed: header-auth idiom recognition; regression fixture `src/routes/migration_guarded.py`. Also fixed in round 2: FastAPI `APIRouter(prefix=...)` is now prepended to reported paths (`'/users'` → `'/admin/users'`), which is what made this route's `admin` segment visible to hints at all. |
| `backend/.venv/.../fastapi/*.py` ×5 — routes in library docs/examples | **False positives.** A Python virtualenv is third-party code; scanning it at all is wrong. Fixed: file listing now excludes `node_modules/`, `.venv/`, `venv/`, `.tox/`. |

### exposed-secrets: 64 → 14

| Finding | Verdict |
|---|---|
| Supabase service-role JWT ×13 files under `frontend/tests/e2e/_ui/*.mjs` | **True positive — real leaked credential.** The JWT payload decodes to `{"iss":"supabase","ref":"ejpbbqhbjljttrieucdg","role":"service_role",...,"exp":2036}`. A service-role key bypasses RLS entirely; it is hardcoded in 13 committed scripts. **This needs rotation regardless of what this scanner says.** |
| GitHub PAT-shaped token in `frontend/tests/e2e/_gh_probe.js:33` | **Unverifiable, likely true positive.** Shape-valid `ghp_` token posted as an integration credential to a local backend. No placeholder markers; could be a throwaway local test token or a live PAT. Not verified live (deliberately did not use the token). |
| Stripe/GitHub mock keys across ~20 e2e scripts + `_mock_providers.py` (`rk_test_mockfounderdive…`, `ghp_mock0000…`) | **False positives.** Obviously fake values. Fixed: values containing placeholder markers (mock/dummy/fake/ci-test/all-zero runs…) are suppressed; fixtures added. Note: the word "test" alone is deliberately NOT a marker — `sk_test_` Stripe keys are real credentials against live test data. |
| CI dummy JWTs in `backend/tests/conftest.py` | **False positives.** Explicitly labeled CI placeholders (`ci-test-service-key`). Covered by the same suppression. |
| Private-key blocks / JWTs inside `backend/.venv/**` (ecdsa tests, jose/pyjwt docs) ×33 | **False positives.** Vendored library code. Eliminated by the vendored-dir exclusion above. |

### client-side-payment: 11 → 0

| Finding | Verdict |
|---|---|
| `frontend/lib/posthog-client.ts:109` — "raw card field" | **False positive.** The match is the word `card|cvv` inside an analytics redaction regex — there is no card-capture UI. Fixed: card-field hints now require nearby input context (`<input`, `name=`, `TextFormField`, …); fixture added. |
| PIL / pydantic / nltk / joserfc / authlib docstrings ×10 | **False positives.** All inside `backend/.venv`. Eliminated by the vendored-dir exclusion. |

### copyleft-license: 0 both runs — backend is Python; nothing misclassified.

### pii-no-consent: 0 both runs — privacy artifacts present; spot-checked, plausible.

## Fitloom

### exposed-secrets: 1 → 0

| Finding | Verdict |
|---|---|
| `android/app/google-services.json` Google API key, severity critical | **False positive.** This file is Firebase's client config and is *designed* to be committed and shipped inside app bundles; the key is an identifier restricted server-side (App Check / API restrictions), not a secret. Fixed: these filenames are skipped; fixture added. |

### copyleft-license: 3 → 2

| Finding | Verdict |
|---|---|
| `firebase_core_platform_interface` — "license could not be determined" | **False positive (transient).** The pub.dev score API does return `license:bsd-3-clause` for it; the scan hit a transient fetch failure somewhere in ~90 sequential calls. Fixed: one retry with short backoff before emitting the undetermined finding. |
| `dbus 0.7.15` and `gtk 2.2.0` — MPL-2.0 weak copyleft | **True positive as reported**, verified against pub.dev license tags. Practical relevance is low — they're pulled in by Linux-desktop platform plugins, and MPL-2.0 is fine for unmodified external use, which the finding text itself says. Kept: the finding states exactly what is true without overclaiming. |

### Other detectors: 0 findings both runs. Spot-checked plausible (client-side Flutter app).

## Detector changes made as a result of dogfooding

Each change has a fires-on-risk fixture AND a doesn't-over-fire regression test:

1. **File listing** (`src/lib/list-files.ts`, shared by the MCP server and the dogfood runner):
   exclude vendored dependency trees (`node_modules/`, `.venv/`, `venv/`, `.tox/`). License checking
   still works — it reads installed packages directly from disk, not from the scanned file list.
   Covered by unit tests on the shared module.
2. **unauth-endpoints**: recognize custom FastAPI guard dependencies via
   `Depends(<identifier containing auth-ish word>)`; recognize hand-rolled
   `authorization … Header(...)` bearer-token guards; include FastAPI router prefixes in reported
   paths; add `debug`/`internal` to sensitive-path hints.
3. **secrets-scanner**: suppress placeholder-marker values; skip Firebase client-config
   filenames (`google-services.json`, `GoogleService-Info.plist`).
4. **payment-handling**: raw-card hints require input-field context within ±160 chars, checked
   across ALL occurrences in the file (not just the first).
5. **pii-consent-check**: privacy/terms/consent artifacts require structural evidence (dedicated
   filename, link/attribute reference, or route path) — bare mentions like "TODO: add privacy
   policy" no longer suppress the finding.
6. **license-check**: single retry before reporting an undetermined pub.dev license.

## Honest limitations observed while dogfooding

- Duplicate secret findings ARE now deduplicated: the same leaked Supabase key that appeared 13 times
  in v2 output is one finding with a 13-entry `locations` array (this cut FounderDive's MCP response
  from ~11.3KB/~2,800 tokens to ~4.1KB/~1,000 tokens). Per-location detail is preserved.
- Responses are severity-ordered and capped at 100 findings with an explicit `truncated` flag in the
  summary — a pathological repo cannot silently flood agent context, and truncation is never silent.
- A nonexistent or non-directory path returns an explicit tool error instead of a zero-findings
  "clean" result, which would have been misread as "nothing detected."
- Judgment of the `_gh_probe.js` token is unverifiable statically; the finding stands because a
  shape-valid credential with no placeholder markers should be treated as compromised until proven otherwise.
