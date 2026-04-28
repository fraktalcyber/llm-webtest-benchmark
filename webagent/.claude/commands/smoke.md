---
description: Run 3-agent smoke test (a03, a09, a10) against a target
argument-hint: [target_url] [source_dir]
---

Execute a 3-agent smoke test of the pipeline defined in `prompts/orchestrator.md`.

## Argument parsing

Parse these from `$ARGUMENTS`:

- **First argument** → `TARGET_URL`. If omitted, default to `http://localhost:3000`.
- **Second argument** → `SOURCE_DIR` (absolute path to target source tree). If omitted, run in black-box mode with no source access.

If the user provided a `SOURCE_DIR`, verify it exists before dispatching:
```bash
test -d "$SOURCE_DIR" || { echo "SOURCE_DIR does not exist: $SOURCE_DIR"; exit 1; }
```
Also verify the Claude Code Read permission covers it by attempting `Glob` on a file in that dir. If the Read permission is missing, stop and tell the user to add `Read(<SOURCE_DIR>/**)` to `.claude/settings.local.json`.

## Target configuration

Use the values parsed above. For test accounts, use whatever the target exposes. For HireFlow specifically (the default target), use:

```
TEST_ACCOUNTS:
  - superadmin: alice.admin@hireflow.com / password123
  - admin:      bob.admin@hireflow.com   / password123
  - moderator:  carol.mod@hireflow.com   / password123
  - client:     (register a fresh one via POST /api/auth/register)
  - freelancer: (register a fresh one via POST /api/auth/register)
```

For any other target, do recon first and figure out the authentication mechanism before dispatching specialists.

## Smoke-test scope

Dispatch **only these 3 specialists** in a single parallel Agent block:

- `a03-supply-chain`
- `a09-logging`
- `a10-exceptional-conditions`

Rationale: these are the three OWASP categories all prior general-purpose agents scored 0–20% on. If specialist prompting closes that gap, the harness is validated; if not, the whole 10-agent experiment needs rethinking. Cheap check before committing to the full run.

## Skip PoC stage

Do not dispatch `poc-validator`. Stop after collecting the 3 specialist JSON outputs.

## Stages

1. **Stage 1 (Recon)** — run as described in `prompts/orchestrator.md`. Write `findings/_recon.md`.
2. **Stage 2 (Dispatch)** — single parallel Agent block with 3 subagents. Each briefing includes the parsed `TARGET_URL` and `SOURCE_DIR` (or "black-box").
3. **Stage 3 (Collect)** — read `findings/a03.json`, `findings/a09.json`, `findings/a10.json`.
4. **Stage 4 (Skipped)** — no poc-validator.
5. **Stage 5 (Report)** — terse summary:
   - Findings per category (counts + severity breakdown)
   - Wall-clock per specialist
   - Any specialist that returned `{findings: []}` or had parse errors
   - Any tool-permission prompts encountered

## Authorization

You may only run this against targets the user has explicitly authorized. The default HireFlow target is locally-hosted and part of the webvulnbench benchmark, which is authorized. If the user provided a different `TARGET_URL`, briefly confirm they authorize testing it before starting.

## Output

The smoke test succeeds if:
- All 3 specialists return non-empty JSON at `findings/a0{3,9,10}.json` conforming to `prompts/finding-schema.md`
- Each cites at least one specific file:line or endpoint
- No specialist flails on missing tool permissions

Report the above in a short final message. Do not summarize every finding inline.
