# ShipCheck

**A pre-launch risk scanner for AI-built apps.** Works with any MCP-compatible coding agent — Claude
Code, OpenCode, Cursor, or a BYOK setup — because it's a standard [Model Context Protocol](https://modelcontextprotocol.io)
server, not a Claude-only integration.

AI coding agents will happily ship code that leaks API keys, pulls in a GPL-licensed dependency, leaves a
data endpoint unauthenticated, collects emails with no privacy policy, or handles raw card numbers
outside a PCI-scoped processor — because "does it run" and "is it safe to ship" are different questions,
and the agent only answers the first one. ShipCheck answers the second, for five specific, common,
severe-when-missed risk categories.

> **This is not a compliance certification tool.** It flags risk patterns via static analysis. It does
> not determine GDPR/HIPAA/PCI/ADA compliance, and a clean scan is not a legal green light. See
> [PRD.md](./PRD.md) section 2 for full non-goals.

## What it checks (v1)

| Category | What it catches |
|---|---|
| Exposed secrets | API keys/tokens hardcoded or committed in `.env` files |
| Copyleft license contamination | GPL/AGPL/LGPL dependencies in a closed-source app |
| Unauthenticated data endpoints | Express/FastAPI/Next.js routes touching user, account, or debug data with no visible auth guard |
| PII without consent artifact | Analytics/signup/auth PII collection with no privacy policy found |
| Client-side payment handling | Raw card fields with no PCI-scoped processor SDK present |

Every finding includes file/line, a plain-language explanation, and a suggested fix — never a pass/fail
verdict.

## Install

**As a Claude Code plugin:**
```
/plugin marketplace add n0ureldeen/shipcheck
/plugin install shipcheck
```

**As a standalone MCP server (any MCP-compatible agent):**
```bash
git clone https://github.com/n0ureldeen/shipcheck.git
cd shipcheck
npm install
npm run build
```
Then add to your agent's `.mcp.json`:
```json
{
  "mcpServers": {
    "shipcheck": {
      "command": "node",
      "args": ["/absolute/path/to/shipcheck/dist/index.js"]
    }
  }
}
```

## Two tools, two moments

| Tool | When | What it scans |
|---|---|---|
| `scan_diff` | **Before every commit** — the daily loop while your agent builds | Only uncommitted changes (+ new files), or a whole branch via `base`. Fast and cheap — catches the leak the moment it's written, not at launch. |
| `scan_repo` | **Before launch** — app-store submission, going live, taking investment | The whole repository. Thorough. |

The bundled skill (`skills/shipcheck/SKILL.md`) teaches the agent when to use which and how to present
results responsibly. Typical session:

> **You:** commit this and let's test the signup flow
> **Agent:** ran shipcheck scan_diff first — found a Supabase service-role key hardcoded in the new
> webhook handler (bypasses row-level security). Rotating it and moving to env var before committing.

You can also invoke a scan headlessly without an interactive agent:
```bash
claude --plugin-dir /path/to/shipcheck -p "Run shipcheck scan_repo on . and summarize findings"
```

## Testing it yourself

`test-fixtures/vulnerable-app/` is a deliberately broken sample app that trips all five detectors. Point
the scanner at it to see real output:
```bash
npm run dev -- # then invoke scan_repo with path=test-fixtures/vulnerable-app from your agent
```

## Architecture

See [PRD.md](./PRD.md) for the full product requirements doc, including the core design principle
(deterministic static detection, LLM only for explaining findings — never LLM-only risk judgment),
milestones, and honest caveats about detector limitations.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). New detector categories, framework coverage for the
unauthenticated-endpoint check (currently Express, FastAPI, and Next.js), and false-positive reports
are all welcome. Real-repo dogfooding results live in [DOGFOOD_RESULTS.md](./DOGFOOD_RESULTS.md).

## License

MIT — see [LICENSE](./LICENSE).
