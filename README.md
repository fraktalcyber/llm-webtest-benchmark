# LLM Web Application Security Testing Benchmark

A head-to-head comparison of three LLM-powered coding agents performing web application security assessments using the [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/) methodology.

This repo contains the raw assessment reports, WSTG checklists, PoC scripts, and prompts from two rounds of testing.

## Blog Posts

- **[Part 1: Black-Box Testing](https://medium.com/fraktal/how-good-are-ai-agents-at-finding-web-vulnerabilities-part-1-ac6e5e6ab93f)** — agents test HireFlow with no source code access
- **Part 2: White-Box Testing** — agents test HireFlow with full source code access *(coming soon)*

## Agents Tested

| Agent | Description |
|-------|-------------|
| **Claude Code** | Anthropic's Claude — autonomous CLI agent |
| **Codex** | OpenAI's Codex — autonomous CLI agent |
| **Gwen** | Alibaba's Qwen — autonomous CLI agent |

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
└── gwen/
    ├── wstg-assessment-blackbox-gwen.md
    ├── wstg-assessment-whitebox-gwen.md
    ├── blackbox_reports/
    └── whitebox_reports/
```

## Running the PoCs

Each PoC script is standalone Python that targets `http://localhost:3000`. To run:

```bash
pip install requests
python claude/blackbox_reports/pocs/WSTG-CONF-08_cors.py
```

All scripts use the test account `testclient@hireflow.com` / `password123` and will print `[VULNERABLE]` if the finding is confirmed.

## License

This benchmark data is provided for educational and research purposes.
