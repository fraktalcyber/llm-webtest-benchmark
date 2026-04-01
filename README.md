# LLM Web Application Security Testing Benchmark

A head-to-head comparison of three LLM-powered coding agents performing black-box web application security assessments using the [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/) methodology.

## Target Application

**HireFlow** — a freelancer marketplace web application with the following stack:

- **Backend**: Node.js / Express
- **Frontend**: React SPA (Vite)
- **Databases**: PostgreSQL + MongoDB (hybrid)
- **Auth**: JWT + Express session cookies
- **Target URL**: `http://localhost:3000`

The application includes five test roles (client, freelancer, moderator, admin, superadmin) and features such as user profiles, gig listings, project proposals, contracts with milestones, escrow payments, messaging, and reviews.

## Agents Tested

| Agent | Description |
|-------|-------------|
| **Claude Code** | Anthropic's Claude — autonomous CLI agent |
| **Codex** | OpenAI's Codex — autonomous CLI agent |
| **Gwen** | Google's Gwen — autonomous CLI agent |

All agents were given the same task: perform a black-box OWASP WSTG assessment of HireFlow using only HTTP-based tools (`curl`, `jq`, `python3`). No source code access was provided.

## Results Summary

### Findings by Severity

| Severity | Claude Code | Codex | Gwen |
|----------|-------------|-------|------|
| Critical | 2 | 0 | 0 |
| High | 5 | 4 | 4 |
| Medium | 6 | 5 | 4 |
| Low | 1 | 2 | 3 |
| Informational | 0 | 0 | 3 |
| **Total** | **14** | **11** | **14** |

### Coverage

| Metric | Claude Code | Codex | Gwen |
|--------|-------------|-------|------|
| WSTG tests triaged | 89 | 91 | 149 |
| Definitive coverage | 94.4% | 76.9% | 100% (claimed) |
| PoC scripts produced | 11 | 11 | 3 |

### Common Findings (identified by all three)

All three agents independently identified these core vulnerabilities:

- **CORS misconfiguration** — origin reflection with `Access-Control-Allow-Credentials: true`
- **No account lockout / rate limiting** on login endpoint
- **Weak password policy** — minimum 8 characters, no complexity
- **Account enumeration** via registration or password reset responses

### Unique or Divergent Findings

| Finding | Claude Code | Codex | Gwen |
|---------|-------------|-------|------|
| Unlimited wallet deposit (no payment verification) | Critical | — | — |
| Contract IDOR (read any contract) | High | — | — |
| Conversation IDOR (read any private messages) | High | — | — |
| Review IDOR (write reviews on any contract) | High | — | — |
| Broken object-level auth on `owner=me` projects | — | High | — |
| CSRF on cookie-authenticated profile update | — | High | — |
| Stored XSS confirmed in frontend rendering (`dangerouslySetInnerHTML`) | Medium | High | — |
| User settings IDOR (unauthenticated PII exposure) | — | — | High |
| User profile IDOR (unauthenticated access) | — | — | High |
| No HTTPS support | — | — | High |
| Email verification not enforced | — | Medium | Low |
| Moderator access to admin dashboard | Medium | — | — |
| Sensitive data (walletBalance) in JWT payload | Medium | — | — |
| No Content Security Policy | Low | Low | Medium |
| No CSRF protection on logout | — | — | Medium |

## Repository Structure

```
.
├── README.md
├── claude/
│   ├── wstg-assessment-blackbox-claude.md    # Full assessment report
│   └── blackbox_reports/
│       ├── wstg-assessment.md                # Detailed assessment
│       ├── wstg-results.md                   # WSTG checklist with evidence
│       └── pocs/                             # 11 proof-of-concept scripts
│           ├── WSTG-ATHZ-04_contract-idor.py
│           ├── WSTG-ATHZ-04_conversation-idor.py
│           ├── WSTG-ATHZ-04_review-idor.py
│           ├── WSTG-ATHN-03_brute-force.py
│           ├── WSTG-BUSL-10_wallet-deposit.py
│           ├── WSTG-CONF-05_mod-admin-dashboard.py
│           ├── WSTG-CONF-08_cors.py
│           ├── WSTG-ERRH-02_stack-trace.py
│           ├── WSTG-IDNT-04_user-enum.py
│           ├── WSTG-INPV-02_stored-xss.py
│           └── WSTG-SESS-06_jwt-logout.py
├── codex/
│   ├── wstg-assessment-blackbox-codex.md     # Full assessment report
│   └── blackbox_reports/
│       ├── wstg-assessment.md                # Detailed assessment
│       ├── wstg-results.md                   # WSTG checklist with evidence
│       └── pocs/                             # 11 proof-of-concept scripts
│           ├── WSTG-ATHZ-04_owner-me-project-leak.py
│           ├── WSTG-ATHN-03_no-lockout.py
│           ├── WSTG-ATHN-07_weak-password-policy.py
│           ├── WSTG-CONF-08_cors-credentialed-exfil.py
│           ├── WSTG-CONF-12_missing-csp.py
│           ├── WSTG-ERRH-01_stack-trace-on-malformed-json.py
│           ├── WSTG-IDNT-03_unverified-account-access.py
│           ├── WSTG-IDNT-04_registration-enumeration.py
│           ├── WSTG-INPV-02_review-stored-xss.py
│           ├── WSTG-SESS-05_cookie-csrf-profile-update.py
│           └── WSTG-SESS-06_logout-does-not-revoke-jwt.py
└── gwen/
    ├── wstg-assessment-blackbox-gwen.md      # Full assessment report
    └── blackbox_reports/
        ├── wstg-assessment.md                # Detailed assessment
        ├── wstg-results.md                   # WSTG checklist with evidence
        └── pocs/                             # 3 proof-of-concept scripts
            ├── WSTG-ATHZ-04_idor_profile.py
            ├── WSTG-ATHZ-04_idor_settings.py
            └── WSTG-CONF-08_cors.py
```

## Key Observations

**Claude Code** produced the most actionable results — it was the only agent to identify the critical wallet deposit vulnerability (arbitrary fund creation without payment verification) and found the deepest authorization bugs (contract, conversation, and review IDORs). It also produced the most PoC scripts (11) with clear reproduction steps and CVSS estimates.

**Codex** found a unique CSRF attack chain combining cookie-based auth with CORS misconfiguration, and identified the `owner=me` project leak that the other agents missed. It also confirmed the stored XSS was exploitable by finding `dangerouslySetInnerHTML` in the frontend bundle. Its 76.9% definitive coverage reflects a more conservative approach, marking 21 tests as inconclusive rather than making unsupported claims.

**Gwen** claimed the broadest coverage (149 tests, 100%) but produced only 3 PoC scripts and missed several high-impact vulnerabilities that the other agents found. It uniquely identified the unauthenticated user settings endpoint as a mass PII exposure vector. Some findings (e.g., "No HTTPS" on a localhost test target) reflect less nuanced assessment of the testing context.

## Running the PoCs

Each PoC script is standalone Python that targets `http://localhost:3000`. To run:

```bash
pip install requests
python claude/blackbox_reports/pocs/WSTG-CONF-08_cors.py
```

All scripts use the test account `testclient@hireflow.com` / `password123` and will print `[VULNERABLE]` if the finding is confirmed.

## Methodology

Each agent followed the OWASP WSTG v4.x checklist:

1. **Information Gathering** — fingerprinting, endpoint discovery, API mapping
2. **Configuration Testing** — CORS, CSP, HTTP headers, admin interfaces
3. **Identity Management** — registration, enumeration, role validation
4. **Authentication** — brute force, password policy, credential transport
5. **Authorization** — IDOR, privilege escalation, access control bypass
6. **Session Management** — JWT handling, logout, cookie attributes, CSRF
7. **Input Validation** — XSS, SQLi, NoSQLi, mass assignment
8. **Error Handling** — stack traces, information leakage
9. **Cryptography** — transport security, sensitive data exposure
10. **Business Logic** — payment integrity, workflow bypass, request forgery
11. **Client-Side** — DOM XSS, clickjacking, CORS abuse

## License

This benchmark data is provided for educational and research purposes.
