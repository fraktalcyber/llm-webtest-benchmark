# webagent

A Claude Code harness for OWASP Top 10:2025 web application pentesting.

Runs 10 specialist subagents in parallel (one per OWASP category) against a target web application, pools findings, then runs a PoC/validation agent to weaponize each finding end-to-end.

## The experiment

This harness exists to test a specific hypothesis: **does pentest-specific scaffolding (specialist agents, methodology prompts, structured output) on top of a general-purpose LLM produce meaningfully better results than pointing the raw model at the problem?**

Baseline comparisons:
- Claude Code (single agent, generic prompt) — ~64% detection on HireFlow/OWASP Top 10
- Codex CLI (single agent, generic prompt) — ~45%
- Shannon (purpose-built 5-specialist pipeline) — ~60%

The 10-category OWASP decomposition directly targets the three categories all existing approaches score ~0% on: A03 (Supply Chain), A09 (Logging), A10 (Exceptional Conditions).

## Prerequisites

Required (agents will fail without these):
- **Claude Code CLI** — the harness itself
- **curl** — HTTP testing (preinstalled on macOS/Linux)
- **rg (ripgrep)** — all source searches. `brew install ripgrep` / `apt install ripgrep`
- **jq** — JSON parsing. `brew install jq` / `apt install jq`
- **python3** — crafting JSON payloads, PoC scripts (preinstalled on macOS; `apt install python3` elsewhere)

Optional (unlocks specific techniques; agents degrade gracefully without them):
- **nmap** — port scanning for a02-misconfiguration. `brew install nmap` / `apt install nmap`
- **playwright** — browser-based XSS proof (JWT theft, DOM-XSS confirmation). `npm install -g playwright` + `npx playwright install chromium`
- **sqlmap** — automated SQLi exploitation escalation for the PoC validator. `brew install sqlmap` / `pip install sqlmap`
- **openssl** — TLS/certificate checks (preinstalled on most systems)

Claude Code permissions: the harness uses `Bash` for most specialists. You'll need to allow the following in `.claude/settings.local.json` or accept prompts at runtime:
- `curl`, `rg`, `jq`, `python3`, `nmap` (if used), `base64`, `find`, `dd`, `for`/loops

## Usage

From inside `webagent/`, start Claude Code and use one of the slash commands:

```bash
cd webagent
claude
```

Then at the prompt:

| Command | What it does |
|---|---|
| `/smoke [target_url] [source_dir]` | 3-agent smoke test (a03, a09, a10 only). Validates the harness end-to-end before committing to a full run. ~15 min. |
| `/pentest [target_url] [source_dir]` | Full 10-agent pipeline + PoC validator. ~90 min. |

Arguments:
- `target_url` — base URL of the running application. Defaults to `http://localhost:3000`.
- `source_dir` — absolute path to the target's source tree. Omit for black-box testing.

Examples:
```
/smoke                                          # HireFlow default, black-box
/smoke http://localhost:3000 /tmp/webvulnbench  # custom source path
/pentest https://staging.example.com            # remote target, black-box
/pentest http://localhost:8080 /home/me/myapp   # local with source
```

When using a non-default `source_dir`, also add `Read(<source_dir>/**)` to `.claude/settings.local.json` so the specialists can read source files.

Findings land in `findings/`:
- `_recon.md` — shared recon output (tech stack, routes, tokens)
- `a01.json` through `a10.json` — per-category specialist output
- `poc-report.md` — PoC validator's consolidated findings with working exploits (full run only)
- `pocs/<id>.sh` — standalone reproducible exploit scripts

## Agent roster

| Agent | OWASP | Focus | Tools |
|---|---|---|---|
| `a01-access-control` | A01 | IDOR, missing middleware, role bypass | Read, Grep, Glob, Bash, Write |
| `a02-misconfiguration` | A02 | Headers, CORS, exposed endpoints, defaults | Read, Grep, Glob, Bash, Write |
| `a03-supply-chain` | A03 | CI/CD, dependency pinning, lockfile drift | Read, Grep, Glob, Write |
| `a04-crypto` | A04 | Hardcoded secrets, weak algorithms, bad RNG | Read, Grep, Glob, Bash, Write |
| `a05-injection` | A05 | SQLi, NoSQLi, XSS, cmd, template, log | Read, Grep, Glob, Bash, Write |
| `a06-insecure-design` | A06 | Business logic, workflow bypasses, missing rules | Read, Grep, Glob, Bash, Write |
| `a07-authentication` | A07 | Brute force, session fixation, JWT, password reset | Read, Grep, Glob, Bash, Write |
| `a08-integrity` | A08 | CSRF, file upload types, webhook sig, SRI | Read, Grep, Glob, Bash, Write |
| `a09-logging` | A09 | Missing audit events, log injection, PII in logs | Read, Grep, Glob, Write |
| `a10-exceptional-conditions` | A10 | Races, TOCTOU, error handling, boundary | Read, Grep, Glob, Bash, Write |
| `poc-validator` | — | Reproduce each finding; build end-to-end chains | Read, Write, Bash |

## Design notes

- **Per-category tool shapes differ.** A03/A09 are source-review tasks (no Bash); A01/A05/A07 need curl. Forcing the same tool kit everywhere reproduces Shannon's A03/A09 blind spots.
- **Specialists run in parallel.** Main thread dispatches all 10 in one Agent call block.
- **Findings are structured JSON.** See `prompts/finding-schema.md`. This lets the PoC agent consume them mechanically.
- **PoC agent dedups.** Overlapping finds (e.g., A01↔A07) get merged by endpoint+technique.
- **No cross-agent communication.** Each specialist only sees its own system prompt and the target. The orchestrator is the only synthesizer.
