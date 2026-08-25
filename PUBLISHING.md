# Publishing & Distribution Guide

Everything needed to ship ShipCheck publicly, in order. Steps marked **[you]** require accounts only
you can own; steps marked **[done]** are already in the repo.

## 1. GitHub (the source of truth) — [you]

The repo has no git remote configured and this machine's `GITHUB_TOKEN` is invalid, so run:

```bash
cd /Volumes/DevDrive/Dev/Projects/ShipCheck
gh auth login                      # or: export GITHUB_TOKEN=<a fresh token with repo scope>
gh repo create n0ureldeen/shipcheck --public --source=. --push
```

The CI badge in the README activates the moment the workflow runs on the first push.

## 2. npm — makes it work everywhere via npx — [you]

```bash
npm login
npm publish
```

`package.json` is already prepared: `bin`, `files` (dist, skills, .claude-plugin, .mcp.json),
engines >= 20. After publishing, any MCP host works with zero clone:

```json
{ "mcpServers": { "shipcheck": { "command": "npx", "args": ["-y", "shipcheck-mcp"] } } }
```

Later releases: bump version, `npm publish`. Consider a GitHub Action (e.g. JS-DevRe/npm-publish)
triggered on release tags.

## 3. Claude Code plugin marketplace — [you] · highest-value submission

- URL: https://claude.ai/settings/plugins → **Submit plugin**
- Repo to submit: `n0ureldeen/shipcheck` (the `.claude-plugin/plugin.json` +
  `marketplace.json` + bundled skill are already validated locally via
  `claude --plugin-dir .`)
- This is where Claude Code users browse `/plugin install` — the primary distribution channel.

## 4. Where skill users get skills

Claude Code loads skills from:
- **Bundled**: installing the ShipCheck plugin auto-installs `skills/shipcheck/SKILL.md` — no extra
  step for plugin users.
- **Personal**: `~/.claude/skills/<name>/SKILL.md`
- **Project**: `<repo>/.claude/skills/<name>/SKILL.md`

Directories/lists worth submitting to (PR or form):
- https://github.com/anthropics/skills — Anthropic's official skills collection
- awesome-claude-code lists on GitHub (search "awesome claude code") — most accept PRs adding plugins/skills
- If you later split a standalone skill variant, those same lists are where skill users browse.

## 5. MCP server registries — [you] · after npm publish

Registries that index MCP servers (each has its own submit flow):
- Smithery — https://smithery.ai
- Glama — https://glama.ai/mcp/servers
- PulseMCP — https://pulsemcp.com
- mcp.so

Listing there reaches Cursor/OpenCode/Windsurf users who browse by category.

## 6. Launch channels — [you]

- Show HN: "Show HN: ShipCheck – find what your AI-built app leaks before you ship"
- r/ClaudeAI and r/SideProject — plugin demos do well as short screen recordings
- X/Twitter build-in-public thread using the real dogfood story from DOGFOOD_RESULTS.md
  (live service-role key found → fixed → re-scan verified) — concrete stories travel.

## Pre-flight checklist — [done]

- [x] `npm test` — 53 unit tests
- [x] `npm run e2e` — 21 real-MCP-protocol checks
- [x] `npm run verify-fixture` — acceptance gate
- [x] `claude --plugin-dir .` local install validated repeatedly
- [x] CI matrix: ubuntu/macos/windows × Node 20/22
- [x] npm pack contents verified (dist, skills, .claude-plugin, .mcp.json)
