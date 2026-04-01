# OWASP WSTG Security Assessment Report — HireFlow

**Application**: HireFlow Freelancer Marketplace
**Target**: http://localhost:3000
**Date**: 2026-03-31
**Methodology**: OWASP Web Security Testing Guide (WSTG) — Black-box testing via HTTP
**Assessor**: Automated WSTG Assessment

---

## 1. Executive Summary

HireFlow is a freelancer marketplace web application built with a Node.js/Express backend, React frontend, and a hybrid PostgreSQL + MongoDB database architecture. The assessment identified **14 confirmed vulnerabilities**, including **2 critical**, **5 high**, **6 medium**, and **1 low** severity findings.

The most severe issues are:

- **Critical CORS misconfiguration** that allows any website to perform authenticated API requests on behalf of users
- **Unlimited wallet deposits** without payment verification, allowing users to give themselves unlimited funds
- **Multiple IDOR vulnerabilities** exposing contracts, private conversations, and enabling fake review injection
- **JWT tokens not invalidated on logout**, leaving stolen tokens valid for 7 days
- **No brute force protection** on the login endpoint

The platform's authorization model has significant gaps — while authentication works correctly, resource-level authorization checks are largely missing for contracts, conversations, and reviews.

### Risk Summary

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 5 |
| Medium | 6 |
| Low | 1 |
| **Total** | **14** |

---

## 2. Methodology

Testing followed the OWASP Web Security Testing Guide (WSTG) v4.2 checklist, conducted as a black-box assessment using only HTTP requests via `curl`. The assessment covered 70+ individual test cases across 13 WSTG categories.

**Approach**:
1. Fingerprinted the technology stack from HTTP responses and error messages
2. Mapped the full API surface from frontend JavaScript bundle analysis
3. Authenticated with all 5 test roles (client, freelancer, moderator, admin, superadmin)
4. Systematically tested each WSTG category in priority order (authorization first)
5. Created standalone PoC scripts for each confirmed finding

**Tools used**: `curl`, `jq`, `base64`, `python3`

---

## 3. Findings by Severity

### 3.1 Critical

#### Finding C1: Wildcard Origin Reflection with Credentials (CORS)

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-CONF-08 |
| **Severity** | Critical |
| **CVSS Estimate** | 9.1 (Critical) |
| **Affected Endpoint(s)** | All API endpoints |

**Description**: The server reflects any `Origin` header value in the `Access-Control-Allow-Origin` response header and simultaneously sets `Access-Control-Allow-Credentials: true`. This allows any malicious website to make authenticated cross-origin requests and read the responses, completely bypassing the same-origin policy.

**Steps to Reproduce**:
1. Send any API request with an arbitrary `Origin` header
2. Observe that the exact origin is reflected back with credentials allowed
3. Preflight (OPTIONS) requests also allow all methods (GET, HEAD, PUT, PATCH, POST, DELETE)

**Evidence**:
```bash
curl -si http://localhost:3000/api/auth/me -H "Origin: https://evil.example.com"
```
Response headers:
```
Access-Control-Allow-Origin: https://evil.example.com
Access-Control-Allow-Credentials: true
```

**Impact**: A malicious website can:
- Read any authenticated user's profile, wallet balance, contracts, and messages
- Perform state-changing operations (deposit funds, send messages, create reviews)
- Exfiltrate all user data accessible via the API

**Recommendation**: Configure CORS to only allow specific trusted origins. Never reflect arbitrary origins when `Access-Control-Allow-Credentials` is `true`.

**PoC**: [`reports/pocs/WSTG-CONF-08_cors.py`](pocs/WSTG-CONF-08_cors.py)

---

#### Finding C2: Unlimited Wallet Deposit Without Payment Verification

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-BUSL-10 |
| **Severity** | Critical |
| **CVSS Estimate** | 9.8 (Critical) |
| **Affected Endpoint(s)** | `POST /api/payments/wallet/deposit` |

**Description**: The wallet deposit endpoint directly credits funds to a user's wallet without any payment gateway verification, payment intent confirmation, or external payment processing. Any authenticated user can deposit arbitrary amounts by sending a simple POST request.

**Steps to Reproduce**:
1. Authenticate as any user
2. Send `POST /api/payments/wallet/deposit` with `{"amount": 99999999}`
3. Observe wallet balance increases by $99,999,999.00 without any payment

**Evidence**:
```bash
curl -s http://localhost:3000/api/payments/wallet/deposit \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount":99999999}'
```
Response: `{"wallet":{"balance":"10010001052773",...},"transaction":{"amount":"9999999900","type":"deposit",...}}`

**Impact**: Complete compromise of the platform's financial system. Users can:
- Give themselves unlimited funds
- Fund unlimited escrow payments
- Potentially withdraw funds (if withdrawal is implemented)

**Recommendation**: Wallet deposits must go through a payment gateway (e.g., Stripe) with server-side verification of the payment intent/session. The deposit endpoint should only credit funds after receiving a verified webhook callback from the payment processor.

**PoC**: [`reports/pocs/WSTG-BUSL-10_wallet-deposit.py`](pocs/WSTG-BUSL-10_wallet-deposit.py)

---

### 3.2 High

#### Finding H1: Contract IDOR — Read Any Contract

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-ATHZ-04 |
| **Severity** | High |
| **CVSS Estimate** | 7.5 (High) |
| **Affected Endpoint(s)** | `GET /api/contracts/:id` |

**Description**: Any authenticated user can read any contract's full details by providing the contract UUID, regardless of whether they are a party to that contract. No ownership or participation check is performed.

**Steps to Reproduce**:
1. Login as `testclient@hireflow.com`
2. Obtain a contract ID belonging to other users (e.g., from the reviews listing)
3. Request `GET /api/contracts/{other_contract_id}` with your token

**Evidence**:
```bash
curl -s http://localhost:3000/api/contracts/b713842d-6a95-493d-95ee-66855f1288af \
  -H "Authorization: Bearer $CLIENT_TOKEN"
```
Response: `{"id":"b713842d-...","client_id":"861c73f8-...","freelancer_id":"7c46127e-...","title":"SaaS Dashboard UX Redesign","total_amount":102813,...}` (200 OK)

**Impact**: Exposure of contract financial data, parties, milestones, and deliverables for all contracts on the platform.

**Recommendation**: Add authorization middleware that verifies the requesting user is either the client, freelancer, or an admin before returning contract details.

**PoC**: [`reports/pocs/WSTG-ATHZ-04_contract-idor.py`](pocs/WSTG-ATHZ-04_contract-idor.py)

---

#### Finding H2: Conversation IDOR — Read Any Private Conversation

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-ATHZ-04 |
| **Severity** | High |
| **CVSS Estimate** | 7.5 (High) |
| **Affected Endpoint(s)** | `GET /api/messages/conversations/:id` |

**Description**: Any authenticated user can read any conversation's messages by providing the conversation UUID. No participant check is performed.

**Steps to Reproduce**:
1. Login as `testclient@hireflow.com` and create a conversation with the freelancer
2. Login as `bob.admin@hireflow.com` (not a participant)
3. Access the conversation using its ID — all messages are returned

**Evidence**:
```bash
curl -s http://localhost:3000/api/messages/conversations/$CONV_ID \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
Response: `{"conversation":{...},"messages":[{"content":"This is a private message - IDOR test",...}]}` (200 OK)

**Impact**: Any authenticated user can read all private messages between any users on the platform.

**Recommendation**: Verify the requesting user is a participant of the conversation before returning messages.

**PoC**: [`reports/pocs/WSTG-ATHZ-04_conversation-idor.py`](pocs/WSTG-ATHZ-04_conversation-idor.py)

---

#### Finding H3: Review IDOR — Write Reviews on Any Contract

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-ATHZ-04, WSTG-BUSL-02 |
| **Severity** | High |
| **CVSS Estimate** | 7.1 (High) |
| **Affected Endpoint(s)** | `POST /api/reviews` |

**Description**: Any authenticated user can create reviews on any contract, even if they are not a party to it. The endpoint only checks for duplicate reviews, not contract participation.

**Steps to Reproduce**:
1. Login as `testclient@hireflow.com`
2. Find a contract between other users (e.g., `b713842d`)
3. POST a review targeting that contract and one of its participants

**Evidence**:
```bash
curl -s http://localhost:3000/api/reviews \
  -H "Authorization: Bearer $CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"contract_id":"b713842d-6a95-493d-95ee-66855f1288af","reviewee_id":"7c46127e-222f-4d58-8972-c9ac8659dadd","rating":1,"comment":"Fake review"}'
```
Response: `{"id":"d7559e2a-...","contract_id":"b713842d-...","reviewer_id":"5664b7f1-...","rating":1,...}` (200 OK)

**Impact**: Reputation manipulation — any user can post fake negative or positive reviews on any contract, undermining the trust system.

**Recommendation**: Verify the reviewer is either the client or freelancer on the referenced contract before allowing review creation.

**PoC**: [`reports/pocs/WSTG-ATHZ-04_review-idor.py`](pocs/WSTG-ATHZ-04_review-idor.py)

---

#### Finding H4: JWT Not Invalidated on Logout

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-SESS-06 |
| **Severity** | High |
| **CVSS Estimate** | 7.4 (High) |
| **Affected Endpoint(s)** | `POST /api/auth/logout` |

**Description**: After calling the logout endpoint, the JWT token remains valid and can still authenticate API requests. There is no server-side token blacklist or revocation mechanism. JWT tokens have a 7-day expiry.

**Steps to Reproduce**:
1. Login and obtain JWT token
2. Call `POST /api/auth/logout` with the token
3. Use the same token to access `GET /api/auth/me` — it still works

**Evidence**:
```bash
# After logout, old token still works:
curl -s http://localhost:3000/api/auth/me -H "Authorization: Bearer $OLD_TOKEN"
```
Response: `{"user":{"id":"5664b7f1-...","email":"testclient@hireflow.com",...}}` (200 OK)

**Impact**: If a token is compromised (via XSS, CORS attack, or network interception), the user cannot revoke it by logging out. The attacker retains access for up to 7 days.

**Recommendation**: Implement a server-side token blacklist (e.g., in Redis) that is checked on every request. Add the token to the blacklist on logout.

**PoC**: [`reports/pocs/WSTG-SESS-06_jwt-logout.py`](pocs/WSTG-SESS-06_jwt-logout.py)

---

#### Finding H5: No Account Lockout or Rate Limiting on Login

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-ATHN-03 |
| **Severity** | High |
| **CVSS Estimate** | 7.3 (High) |
| **Affected Endpoint(s)** | `POST /api/auth/login` |

**Description**: The login endpoint has no brute force protection. 25+ consecutive failed login attempts produce no lockout, rate limiting, CAPTCHA, or progressive delay. The account remains fully accessible with the correct password.

**Steps to Reproduce**:
1. Send 25+ failed login attempts for any account
2. Observe all return 401 immediately with no rate limiting
3. Login with the correct password — still works

**Evidence**:
```bash
# All 25 attempts return 401 immediately, then correct password works
for i in $(seq 1 25); do
  curl -s -o /dev/null -w "%{http_code} " http://localhost:3000/api/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"testclient@hireflow.com","password":"wrong"}'
done
# Output: 401 401 401 401 ... (all 401, no lockout)
```

**Impact**: Enables brute force password attacks. Combined with weak password policy (8 chars, no complexity), accounts are at significant risk.

**Recommendation**: Implement progressive rate limiting (e.g., exponential backoff after 5 failures), account lockout after 10 failed attempts, and CAPTCHA after 3 failures.

**PoC**: [`reports/pocs/WSTG-ATHN-03_brute-force.py`](pocs/WSTG-ATHN-03_brute-force.py)

---

### 3.3 Medium

#### Finding M1: Stored XSS in Multiple Fields

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-INPV-02, WSTG-CLNT-03 |
| **Severity** | Medium |
| **CVSS Estimate** | 6.1 (Medium) |
| **Affected Endpoint(s)** | User profiles, messages, reviews, project titles |

**Description**: HTML and JavaScript payloads are stored without sanitization in multiple data fields. Payloads including `<script>`, `<img onerror>`, and other XSS vectors are returned verbatim in API responses.

**Affected fields**:
- User `display_name`: contains `<img src=x onerror=alert(1)>`
- Review `comment`: contains `<img src=x onerror=alert(1)>Great work`
- Message `content`: accepts and stores any HTML
- Project `title`: contains `<script>alert(document.cookie)</script>XSS Test`

**Impact**: If any frontend consumer renders these fields as HTML (e.g., via `dangerouslySetInnerHTML` or a non-React mobile app), XSS executes in the application context, enabling session theft and account takeover. The React SPA likely auto-escapes, reducing client-side risk, but the server should still sanitize input.

**Recommendation**: Sanitize all user input server-side using a library like DOMPurify or sanitize-html. Apply output encoding appropriate to the context.

**PoC**: [`reports/pocs/WSTG-INPV-02_stored-xss.py`](pocs/WSTG-INPV-02_stored-xss.py)

---

#### Finding M2: Stack Traces and SQL Queries in Error Responses

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-ERRH-01, WSTG-ERRH-02 |
| **Severity** | Medium |
| **CVSS Estimate** | 5.3 (Medium) |
| **Affected Endpoint(s)** | Multiple — any endpoint that triggers an error |

**Description**: Error responses expose full PostgreSQL SQL queries, Node.js stack traces with file paths (`/app/node_modules/...`), and dependency information (pg-protocol, body-parser, raw-body).

**Evidence**: Invalid UUID to `/api/contracts/invalid-uuid` returns:
```json
{
  "error": "select * from \"contracts\" where \"id\" = $1 limit $2 - invalid input syntax...",
  "stack": "error: ...at parseErrorMessage (/app/node_modules/pg-protocol/dist/parser.js:305:11)..."
}
```

**Impact**: Reveals database schema, query patterns, file structure, and dependency versions — valuable for targeted attacks.

**Recommendation**: Return generic error messages to clients. Log detailed errors server-side only. Set `NODE_ENV=production` and use proper error handling middleware.

**PoC**: [`reports/pocs/WSTG-ERRH-02_stack-trace.py`](pocs/WSTG-ERRH-02_stack-trace.py)

---

#### Finding M3: Moderator Access to Admin Dashboard

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-ATHZ-02, WSTG-CONF-05 |
| **Severity** | Medium |
| **CVSS Estimate** | 5.3 (Medium) |
| **Affected Endpoint(s)** | `GET /api/admin/dashboard`, `GET /api/admin/disputes` |

**Description**: The moderator role can access the admin dashboard (platform statistics) and admin disputes listing. While admin user management and settings are properly restricted, the dashboard exposes total users, contracts, revenue, and dispute counts.

**PoC**: [`reports/pocs/WSTG-CONF-05_mod-admin-dashboard.py`](pocs/WSTG-CONF-05_mod-admin-dashboard.py)

---

#### Finding M4: Sensitive Data in JWT Payload

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-SESS-04, WSTG-CRYP-03 |
| **Severity** | Medium |
| **CVSS Estimate** | 4.3 (Medium) |
| **Affected Endpoint(s)** | `POST /api/auth/login` |

**Description**: The JWT payload includes `walletBalance` (the user's financial balance) alongside `id`, `email`, and `role`. This sensitive financial data is sent in every API request's Authorization header and may be logged by proxies, CDNs, or application logs.

**Evidence**: JWT decoded payload:
```json
{"id":"5664b7f1-...","email":"testclient@hireflow.com","role":"client","walletBalance":"10000001052873","iat":...,"exp":...}
```

**Recommendation**: Remove `walletBalance` from JWT payload. Fetch wallet data from the server when needed via the `/api/payments/wallet` endpoint.

---

#### Finding M5: Weak Password Policy

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-ATHN-07 |
| **Severity** | Medium |
| **CVSS Estimate** | 5.3 (Medium) |
| **Affected Endpoint(s)** | `POST /api/auth/register` |

**Description**: Password policy only requires 8 characters minimum with no complexity requirements. Passwords like `aaaaaaaa` are accepted. Combined with no brute force protection, this significantly increases account compromise risk.

**Recommendation**: Require at least one uppercase, one lowercase, one digit, and one special character. Consider checking against breached password databases (HIBP).

---

#### Finding M6: Session Cookie Missing Secure and SameSite Attributes

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-SESS-02 |
| **Severity** | Medium |
| **CVSS Estimate** | 4.3 (Medium) |
| **Affected Endpoint(s)** | Session cookie `connect.sid` |

**Description**: The `connect.sid` session cookie has `HttpOnly` but lacks `Secure` and `SameSite` attributes.

**Evidence**: `Set-Cookie: connect.sid=s%3A...; Path=/; HttpOnly` (no Secure, no SameSite)

**Recommendation**: Add `Secure` and `SameSite=Strict` (or `Lax`) attributes to the session cookie.

---

### 3.4 Low

#### Finding L1: Account Enumeration via Password Reset and Registration

| Field | Value |
|-------|-------|
| **WSTG ID** | WSTG-IDNT-04 |
| **Severity** | Low |
| **CVSS Estimate** | 3.7 (Low) |
| **Affected Endpoint(s)** | `POST /api/auth/forgot-password`, `POST /api/auth/register` |

**Description**: The password reset endpoint returns different messages for existing vs non-existing email addresses. The registration endpoint reveals "Email already registered" for existing emails. The login endpoint is properly protected (same error for both).

**Evidence**:
- Existing email: `"Password reset link sent to your email"`
- Non-existing: `"No account found with that email address"`

**Recommendation**: Return the same message regardless of whether the email exists ("If an account exists with that email, a reset link has been sent").

**PoC**: [`reports/pocs/WSTG-IDNT-04_user-enum.py`](pocs/WSTG-IDNT-04_user-enum.py)

---

## 4. OWASP Top 10 (2021) Mapping

| OWASP Category | Findings |
|----------------|----------|
| **A01: Broken Access Control** | C1 (CORS), H1 (Contract IDOR), H2 (Conversation IDOR), H3 (Review IDOR), M3 (Mod Admin Access) |
| **A02: Cryptographic Failures** | M4 (Sensitive JWT Data), M6 (Cookie Attributes) |
| **A03: Injection** | M1 (Stored XSS) |
| **A04: Insecure Design** | C2 (Wallet Deposit), H3 (Review Forgery) |
| **A05: Security Misconfiguration** | M2 (Stack Traces), M3 (Mod Admin Access), L1 (User Enumeration) |
| **A07: Identification & Authentication Failures** | H4 (JWT Logout), H5 (Brute Force), M5 (Weak Password) |
| **A08: Software & Data Integrity Failures** | C2 (Wallet Deposit — no verification) |
| **A09: Security Logging & Monitoring Failures** | H5 (No brute force detection) |

---

## 5. Coverage Summary

| WSTG Section | Tests | Passed | Findings | N/A |
|--------------|-------|--------|----------|-----|
| INFO | 10 | 9 | 1 | 0 |
| CONF | 11 | 7 | 3 | 1 |
| IDNT | 5 | 3 | 2 | 0 |
| ATHN | 9 | 4 | 4 | 1 |
| ATHZ | 5 | 3 | 2 | 0 |
| SESS | 10 | 7 | 3 | 0 |
| INPV | 12 | 11 | 1 | 0 |
| ERRH | 2 | 0 | 2 | 0 |
| CRYP | 3 | 1 | 1 | 1 |
| BUSL | 10 | 8 | 1 | 1 |
| CLNT | 8 | 5 | 2 | 1 |
| APIT | 2 | 1 | 1 | 0 |
| SUPPL | 2 | 2 | 0 | 0 |
| **Total** | **89** | **61** | **23** | **5** |

Note: Some findings map to multiple WSTG tests, so finding count exceeds unique vulnerability count.

---

## 6. Statistics

### Findings by Severity

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 2 | 14.3% |
| High | 5 | 35.7% |
| Medium | 6 | 42.9% |
| Low | 1 | 7.1% |
| **Total** | **14** | 100% |

### Findings by OWASP Top 10

| Category | Count |
|----------|-------|
| A01: Broken Access Control | 5 |
| A07: Identification & Auth Failures | 3 |
| A05: Security Misconfiguration | 3 |
| A02: Cryptographic Failures | 2 |
| A04: Insecure Design | 2 |
| A03: Injection | 1 |

### WSTG Coverage

- **Tests executed**: 89
- **Tests with findings**: 23 (status markers, some overlap)
- **Unique vulnerabilities confirmed**: 14
- **PoC scripts created**: 9
- **Coverage rate**: 94.4% (89 of 89 planned tests completed, 5 N/A)

### PoC Scripts

| File | Finding |
|------|---------|
| `WSTG-CONF-08_cors.py` | Wildcard CORS with credentials |
| `WSTG-ATHZ-04_contract-idor.py` | Contract IDOR |
| `WSTG-ATHZ-04_conversation-idor.py` | Conversation IDOR |
| `WSTG-ATHZ-04_review-idor.py` | Review forgery IDOR |
| `WSTG-SESS-06_jwt-logout.py` | JWT not invalidated on logout |
| `WSTG-BUSL-10_wallet-deposit.py` | Unlimited wallet deposit |
| `WSTG-ATHN-03_brute-force.py` | No brute force protection |
| `WSTG-INPV-02_stored-xss.py` | Stored XSS in multiple fields |
| `WSTG-CONF-05_mod-admin-dashboard.py` | Moderator admin access |
| `WSTG-ERRH-02_stack-trace.py` | Stack trace disclosure |
| `WSTG-IDNT-04_user-enum.py` | Account enumeration |
