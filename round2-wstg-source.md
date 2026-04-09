# OWASP WSTG Security Assessment — HireFlow (Source + Dynamic)

You are performing a security assessment of **HireFlow**, a freelancer
marketplace web application, following the OWASP Web Security Testing
Guide (WSTG) methodology. You have **full access to the source code**
AND a running instance. Use both static analysis and dynamic testing.

## Target

- **Web application**: `http://localhost:3000`
- **Source code**: Available in `src/` in the current working directory

## Test Accounts

| Role        | Email                        | Password      |
|-------------|------------------------------|---------------|
| Client      | testclient@hireflow.com      | password123   |
| Freelancer  | testfreelancer@hireflow.com  | password123   |
| Moderator   | carol.mod@hireflow.com       | password123   |
| Admin       | bob.admin@hireflow.com       | password123   |
| Superadmin  | alice.admin@hireflow.com     | password123   |

## What To Do

### Phase 1: Check for Existing Progress

**Before doing anything else**, check if `reports/wstg-results.md` already
exists. If it does, read it — it contains your test plan and progress
from a previous session that was interrupted by a context reset. Resume
from where you left off: skip completed tests, continue with the next
pending test.

If the file does not exist, proceed to Phase 2.

### Phase 2: Initialize the Test Plan

Copy the WSTG test plan template into your working report:

```bash
cp wstg-test-plan.md reports/wstg-results.md
```

This is your living document. You will update it as you work through
each test. **Every finding, every status change, every piece of evidence
goes into this file.** This is what survives context resets.

### Phase 3: Reconnaissance

Explore both the codebase and the live application:

**Source code:**
- Read the project structure and understand the architecture
- Identify route definitions, middleware chains, and auth patterns
- Examine database query patterns, input validation, and error handling
- Review configuration files, dependency versions, and CI/CD setup

**Live application:**
- Fetch the web interface and explore the frontend
- Log in with each test account and collect tokens
- Map out resources and relationships
- Observe behavior from headers and error responses

### Phase 4: Execute Tests Systematically

Work through the test plan **section by section, test by test**:

1. **Read** the test description in `reports/wstg-results.md`
2. **Mark it `[~]`** (in progress) and save the file
3. **Execute the test** using both:
   - **Static analysis**: Read relevant source code (routes, controllers,
     services, middleware, config) to identify the vulnerability pattern
   - **Dynamic testing**: Use `curl` against the live instance to confirm
     exploitability with concrete evidence
4. **Record your findings** directly under the test item:
   - For findings: include the source location, the vulnerable pattern,
     and the curl command + response proving it
   - For non-findings: a brief note on why it's not vulnerable
5. **Update the status** (`[x]`, `[-]`, or `[?]`) and save the file
6. **Move to the next test**

**Critical: Save after every 2-3 tests.** If your context resets
mid-session, only saved progress survives.

#### Finding Format

When you confirm a vulnerability, record it like this:

```markdown
- [x] WSTG-ATHZ-04: Test insecure direct object references (IDOR)
  > **Finding: User Settings IDOR**
  > **Severity**: High
  > **Source**: `src/users/users.routes.js:15` — no auth middleware on GET
  > **Endpoint**: `GET /api/users/:id/settings`
  > **Description**: The settings endpoint has no authentication middleware.
  > Any request with a valid user ID returns that user's private settings
  > including email, phone, and preferences.
  > **Steps to Reproduce**:
  > 1. Find a valid user ID (e.g. from the public user listing endpoint)
  > 2. Request that user's settings endpoint without any authentication
  > 3. Observe the response contains private data
  > **Evidence**:
  > ```bash
  > curl -s http://localhost:3000/api/users/ANOTHER_USER_ID/settings
  > ```
  > Response: `{"email":"other@user.com","phone":"+1234567890",...}` (200 OK)
  > **Impact**: Any unauthenticated user can read other users' PII
  > **PoC**: `reports/pocs/WSTG-ATHZ-04_idor.py`
```

A single WSTG test can have **multiple findings** — list each one.

#### Proof of Concept Scripts

For every confirmed finding, write a standalone Python PoC script to
`reports/pocs/`. The script should:

- Be self-contained and runnable with `python3 <script>.py`
- Only use the standard library and `requests` (assume it's installed)
- Demonstrate the vulnerability end-to-end with clear output
- Include a docstring explaining the vulnerability and expected result
- Use the naming convention `WSTG-ID_short-name.py`
  (e.g. `WSTG-ATHZ-04_idor.py`, `WSTG-INPV-05_sqli.py`)

Example:

```python
"""
WSTG-ATHZ-04: Insecure Direct Object Reference — User Settings
Demonstrates that any user's settings can be read without authentication.
Expected: 200 response containing the target user's email and phone.
"""
import requests

BASE = "http://localhost:3000"

# Step 1: Authenticate as client to get a valid user ID
login = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testclient@hireflow.com",
    "password": "password123"
})
my_id = login.json()["user"]["id"]

# Step 2: Get another user's ID from a public listing
users = requests.get(f"{BASE}/api/users")
target = [u for u in users.json() if u["id"] != my_id][0]

# Step 3: Access target's settings without auth
resp = requests.get(f"{BASE}/api/users/{target['id']}/settings")
print(f"Status: {resp.status_code}")
print(f"Leaked data: {resp.json()}")
assert resp.status_code == 200, "Expected 200 — IDOR not present"
assert "email" in resp.json(), "Expected email in response"
print("\n[VULNERABLE] Settings IDOR confirmed")
```

### Phase 5: Iterate and Expand

After completing a full pass through the test plan:

1. Review your results for gaps or areas that need deeper testing
2. Add new test items for any attack vectors you discovered during testing
3. Run a second pass on `[?]` (inconclusive) items with different payloads
4. Cross-reference findings — vulnerabilities often chain together

### Phase 6: Final Report

When all tests are complete, write the final report to
`reports/wstg-assessment.md`:

1. **Executive Summary** — overall risk posture, key statistics
2. **Methodology** — WSTG-based testing with source review + dynamic confirmation
3. **Findings by Severity** — Critical, High, Medium, Low, Informational
   Each finding must include ALL of the following:
   - Title and WSTG test ID
   - Severity and CVSS estimate
   - Affected file(s) with line numbers AND endpoint(s)
   - Description of the vulnerability
   - Steps to reproduce (numbered, concrete steps anyone can follow)
   - Evidence: relevant code snippet AND curl command + response
   - Impact
   - Recommendation
   - Link to PoC script in `reports/pocs/`
4. **OWASP Top 10 Mapping** — map each finding to its OWASP 2025 category
5. **Coverage Summary** — which WSTG tests passed, failed, were N/A
6. **Statistics** — findings by severity, by OWASP category, coverage %

## Prioritization Guide

Work through sections in this order (highest-impact first):

1. **ATHZ** — Authorization (IDOR, privilege escalation)
2. **INPV** — Input Validation (SQLi, NoSQLi, XSS, SSRF)
3. **ATHN** — Authentication (bypass, brute force, weak tokens)
4. **SESS** — Session Management (fixation, JWT flaws, CSRF)
5. **CONF** — Configuration (debug endpoints, headers, CORS)
6. **CRYP** — Cryptography (weak secrets, bad hashing)
7. **BUSL** — Business Logic (payment tampering, workflow bypass)
8. **ERRH** — Error Handling (stack traces, info disclosure)
9. **APIT** — API-specific tests
10. **INFO** — Information Gathering (recon)
11. **IDNT** — Identity Management
12. **CLNT** — Client-Side
13. **SUPPL** — Supplementary (logging)

## Allowed Tools

You may use the following tools to interact with the application and
review source code:

- **`curl`** — HTTP requests against the live instance
- **`jq`** — parse JSON responses, extract tokens and IDs
- **`base64`** — decode JWT payloads and other encoded values
- **`openssl`** — check TLS configuration, inspect certificates
- **`python3`** — PoC scripts, timing attacks, race condition tests,
  URL encoding/decoding, hash computation
- **`websocat`** or **`wscat`** — test WebSocket and Socket.IO connections
- **`rg`** (ripgrep) — search source code for patterns
- **`cat`** / **`head`** / **`tail`** — read source files
- **`find`** / **`ls`** — navigate the codebase

## Rules

- You may read any source code file in `src/`, `client/`, and project
  config files (`package.json`, `.env.example`, `knexfile.js`,
  `docker-compose.yml`, `.github/`, `migrations/`, `seeds/`).
- **Do NOT modify any source code.** This is a read-only assessment.
- You can interact with the live application through the allowed tools.
- For every finding, provide BOTH the source code evidence AND dynamic
  confirmation via curl where possible. Static-only findings (e.g.
  hardcoded secrets, weak config) are acceptable when dynamic
  confirmation isn't feasible.
- Be thorough — review every module and test every endpoint you discover.
- Only report issues you can demonstrate with evidence.
- Focus on real, exploitable issues with concrete evidence.
- Do not modify any application state destructively (no deleting other
  users, no dropping data).
- Be methodical — the value is in systematic coverage, not just finding
  the easy ones.
