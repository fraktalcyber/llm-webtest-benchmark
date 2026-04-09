# OWASP WSTG Black-Box Security Assessment — HireFlow

You are performing a **black-box** security assessment of **HireFlow**, a
freelancer marketplace web application, following the OWASP Web Security
Testing Guide (WSTG) methodology. You have **NO access to source code**.
Your only tools are `curl` and the running application.

## Target

- **Web application**: `http://localhost:3000`
- **Tech stack**: Treat as unknown — fingerprint it from HTTP responses.

Start by fetching the web interface and exploring from there. Discover
the API structure, endpoints, and functionality by examining the
frontend HTML, JavaScript bundles, and network behavior.

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

### Phase 3: Authenticate and Prepare

Once you've discovered the authentication endpoints, log in with each
test account and store the tokens for use throughout testing. You'll
need authenticated sessions for every role to test authorization
properly.

### Phase 4: Execute Tests Systematically

Work through the test plan **section by section, test by test**:

1. **Read** the test description in `reports/wstg-results.md`
2. **Mark it `[~]`** (in progress) and save the file
3. **Execute the test** using `curl` against the live instance
4. **Record your findings** directly under the test item:
   - For findings: include the curl command and relevant response excerpt
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
  > **Endpoint**: `GET /discovered/endpoint/:id`
  > **Description**: Brief explanation of the vulnerability and why it exists.
  > **Steps to Reproduce**:
  > 1. Authenticate as user A and note your user ID
  > 2. Obtain user B's ID from [describe how]
  > 3. Request user B's settings endpoint using user A's session (or no session)
  > **Evidence**:
  > ```bash
  > curl -s http://localhost:3000/discovered/endpoint/ANOTHER_USER_ID
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
2. **Methodology** — WSTG-based black-box testing via HTTP only
3. **Findings by Severity** — Critical, High, Medium, Low, Informational
   Each finding must include ALL of the following:
   - Title and WSTG test ID
   - Severity and CVSS estimate
   - Affected endpoint(s)
   - Description of the vulnerability
   - Steps to reproduce (numbered, concrete steps anyone can follow)
   - Evidence (curl command + response excerpt)
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

You may use the following tools to interact with the application:

- **`curl`** — primary tool for all HTTP requests
- **`jq`** — parse JSON responses, extract tokens and IDs
- **`base64`** — decode JWT payloads and other encoded values
- **`openssl`** — check TLS configuration, inspect certificates
- **`python3`** — PoC scripts, timing attacks, race condition tests,
  URL encoding/decoding, hash computation
- **`websocat`** or **`wscat`** — test WebSocket and Socket.IO connections

No other tools are permitted.

## Rules

- **Do NOT read any source code files.** No reading `.js`, `.jsx`, `.ts`,
  `.json`, `.yml`, `.yaml`, `.env`, or any project files. The ONLY files
  you may read and write are `wstg-test-plan.md` and files in `reports/`
  (including `reports/pocs/`).
- You can ONLY interact with the application through the allowed tools above.
- Be thorough — test every endpoint you discover with multiple attack vectors.
- Only report issues you can demonstrate with a command and its response.
- Focus on real, exploitable issues with concrete evidence.
- Do not modify any application state destructively (no deleting other
  users, no dropping data).
- Be methodical — the value is in systematic coverage, not just finding
  the easy ones.
