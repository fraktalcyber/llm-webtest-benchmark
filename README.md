# LLM Web Application Security Testing Benchmark

A head-to-head comparison of LLM-powered agents performing web application security assessments — single-agent coding CLIs in rounds 1–2 (using the [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/) methodology) and purpose-built multi-agent pentest harnesses in round 3.

This repo contains the raw assessment reports, WSTG checklists, PoC scripts, and prompts from three rounds of testing. Round 3 extends the comparison beyond single-agent CLIs to two purpose-built pentest harnesses: **Shannon** (an external multi-agent pipeline) and **webagent** (our own OWASP Top 10:2025 harness built on Claude Code subagents).

## Blog Posts

- **[Part 1: Black-Box Testing](https://blog.fraktal.fi/how-good-are-ai-agents-at-finding-web-vulnerabilities-part-1-ac6e5e6ab93f)** — agents test HireFlow with no source code access
- **[Part 2: White-Box Testing](https://blog.fraktal.fi/how-good-are-ai-agents-at-finding-web-vulnerabilities-part-2-5a80aa926d10)** — agents test HireFlow with full source code access
- **Part 3: Pentest-Specific Harnesses** — Shannon and webagent test HireFlow with full source access *(coming soon)*

## Agents Tested

| Agent | Description | Rounds |
|-------|-------------|--------|
| **Claude Code** | Anthropic's Claude — autonomous CLI agent | 1, 2 |
| **Codex** | OpenAI's Codex — autonomous CLI agent | 1, 2 |
| **Qwen** | Alibaba's Qwen — autonomous CLI agent | 1, 2 |
| **Shannon** | External purpose-built multi-agent pentest pipeline | 3 |
| **webagent** | Our own Claude Code harness with 10 OWASP-category specialist subagents + PoC validator | 3 |

## Target Application

**HireFlow** — a freelancer marketplace web application (Node.js/Express, React, PostgreSQL + MongoDB, JWT auth) with five test roles and features including gig listings, contracts, escrow payments, messaging, and reviews.

## Repository Structure

```
.
├── README.md
├── round1-wstg.md                            # Round 1 (black-box) prompt
├── round2-wstg-source.md                     # Round 2 (white-box) prompt
├── claude/
│   ├── wstg-assessment-blackbox-claude.md    # Black-box assessment summary
│   ├── wstg-assessment-whitebox-claude.md    # White-box assessment summary
│   ├── blackbox_reports/                     # Round 1 reports + PoCs
│   └── whitebox_reports/                     # Round 2 reports + PoCs
├── codex/
│   ├── wstg-assessment-blackbox-codex.md
│   ├── wstg-assessment-whitebox-codex.md
│   ├── blackbox_reports/
│   └── whitebox_reports/
├── qwen/
│   ├── wstg-assessment-blackbox-qwen.md
│   ├── wstg-assessment-whitebox-qwen.md
│   ├── blackbox_reports/
│   └── whitebox_reports/
├── shannon/                                  # Round 3 — external multi-agent pipeline
│   ├── prompts/                              # Per-phase agent prompts
│   ├── agents/                               # Raw per-attempt execution logs
│   ├── deliverables/                         # Analysis + exploitation evidence
│   ├── session.json                          # Run metadata (cost, duration, phases)
│   └── workflow.log                          # Full workflow trace
└── webagent/                                 # Round 3 — our Claude Code harness
    ├── README.md
    ├── .claude/
    │   ├── agents/                           # 10 OWASP specialist subagents + PoC validator
    │   └── commands/                         # /pentest and /smoke slash commands
    ├── prompts/                              # Orchestrator + finding schema
    └── findings/                             # a01.json–a10.json, PoCs, screenshots, report
```

## Running the PoCs

Rounds 1–2 PoCs are standalone Python scripts; round 3 (`webagent/findings/pocs/`) are standalone bash scripts. All target `http://localhost:3000`:

```bash
# Rounds 1–2 (Python)
pip install requests
python claude/blackbox_reports/pocs/WSTG-CONF-08_cors.py

# Round 3 — webagent (bash + curl)
bash webagent/findings/pocs/poc-chain-A-jwt-superadmin.sh
```

All scripts use the test account `testclient@hireflow.com` / `password123` and will print `[VULNERABLE]` if the finding is confirmed.

## License

This benchmark data is provided for educational and research purposes.
