# HireFlow Black-Box WSTG Assessment

Assessment date: 2026-03-31

## Executive Summary

HireFlow presents a weak overall security posture from a black-box perspective. The most significant issues are broken access control on owner-scoped project data, credentialed cross-origin data exposure, cookie-authenticated CSRF, and a stored XSS path in public review rendering. Combined, these findings create realistic attack chains that can lead to unauthorized data access and client-side account compromise.

The assessment triaged 91 WSTG checklist items. Of those, 16 produced confirmed finding states in the checklist, 54 were completed with no confirmed issue or were not applicable, and 21 remained inconclusive because the necessary feature surface was absent or could not be fully exercised from the black-box interface. Consolidating duplicate checklist mappings, this report documents 11 unique findings:

- 4 High
- 5 Medium
- 2 Low

## Methodology

Testing followed the OWASP Web Security Testing Guide using HTTP-only black-box interaction with the live application at `http://localhost:3000`. The assessment used:

- `curl` for request/response analysis
- `jq` and `python3` for response parsing, JWT inspection, and reproducible PoCs
- Frontend HTML and downloaded JavaScript bundles for endpoint discovery

No source-code files were read. Findings were only reported when supported by direct request/response evidence.

## Findings By Severity

### High

#### 1. Reflective CORS Allows Credentialed Cross-Origin Reads

- WSTG IDs: `WSTG-CONF-08`, `WSTG-CLNT-07`
- CVSS estimate: 8.6 High
- Affected endpoints: `GET /api/auth/me`, `OPTIONS /api/auth/login`
- Description: The API reflects arbitrary `Origin` values and returns `Access-Control-Allow-Credentials: true`. Because the application also accepts cookie-based authentication, a malicious site can issue credentialed cross-origin requests and read authenticated API responses.
- Steps to reproduce:
  1. Log in and obtain a valid `connect.sid` cookie.
  2. Request `GET /api/auth/me` with `Origin: https://evil.example.com` while sending the cookie.
  3. Observe the reflected origin and returned account data.
- Evidence:
  ```bash
  curl -sS -i --max-time 10 -X OPTIONS http://localhost:3000/api/auth/login \
    -H 'Origin: https://evil.example.com' \
    -H 'Access-Control-Request-Method: POST' \
    -H 'Access-Control-Request-Headers: content-type,authorization'

  curl -sS -i --max-time 10 http://localhost:3000/api/auth/me \
    -H 'Origin: https://evil.example.com' \
    -b cookies.txt
  ```
  Response excerpt:
  ```text
  Access-Control-Allow-Origin: https://evil.example.com
  Access-Control-Allow-Credentials: true
  ```
- Impact: Any third-party website can read authenticated HireFlow API responses from a victim browser.
- Recommendation: Replace origin reflection with a strict allowlist, disable credentialed CORS where not required, and separate public and authenticated API origins where possible.
- PoC: `reports/pocs/WSTG-CONF-08_cors-credentialed-exfil.py`

#### 2. Broken Object-Level Authorization on Owner-Scoped Projects

- WSTG IDs: `WSTG-ATHZ-02`, `WSTG-ATHZ-04`, `WSTG-APIT-02`
- CVSS estimate: 8.1 High
- Affected endpoint: `GET /api/projects?owner=me&status=active&limit=2`
- Description: The application does not bind `owner=me` to the authenticated caller. Unauthenticated requests and unrelated authenticated users receive project data belonging to another user.
- Steps to reproduce:
  1. Note the seed client ID `5664b7f1-dc57-4aac-a3f1-2ec59d7915f9`.
  2. Send `GET /api/projects?owner=me&status=active&limit=2` without authentication or as a different user.
  3. Observe returned projects with `client_id` set to the victim client UUID.
- Evidence:
  ```bash
  curl -sS --max-time 10 'http://localhost:3000/api/projects?owner=me&status=active&limit=2' \
    | jq '{count:(.data|length), first:(.data[0] | {id, client_id, title, status})}'
  ```
  Response excerpt:
  ```json
  {
    "count": 2,
    "first": {
      "id": "4141ce82-a32a-498d-b5cc-aac7f8729edd",
      "client_id": "5664b7f1-dc57-4aac-a3f1-2ec59d7915f9",
      "title": "Mass Assignment Test Project Creation",
      "status": "open"
    }
  }
  ```
- Impact: Attackers can enumerate and retrieve owner-scoped project metadata without authorization.
- Recommendation: Require authentication for owner-scoped resources and derive ownership exclusively from the server-side session/token identity.
- PoC: `reports/pocs/WSTG-ATHZ-04_owner-me-project-leak.py`

#### 3. Cookie-Authenticated Profile Update Is CSRFable

- WSTG IDs: `WSTG-SESS-05`
- CVSS estimate: 8.3 High
- Affected endpoint: `PUT /api/users/:id`
- Description: A session cookie alone is enough to perform state-changing profile updates. No CSRF token or origin check blocks cross-origin requests, and the server still processes the request while reflecting an attacker origin.
- Steps to reproduce:
  1. Register and log in to a disposable account to obtain a `connect.sid` cookie.
  2. Send `PUT /api/users/<your-id>` using only the cookie and no CSRF token.
  3. Include `Origin: https://evil.example.com` and change `display_name`.
  4. Verify the new value through `GET /api/auth/me`.
- Evidence:
  ```bash
  curl -sS -i --max-time 10 -X PUT http://localhost:3000/api/users/<id> \
    -H 'Origin: https://evil.example.com' \
    -H 'Content-Type: application/json' \
    -b cookies.txt \
    --data '{"display_name":"CSRF_UPDATED",...}'
  ```
  Response excerpt:
  ```text
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: https://evil.example.com
  Access-Control-Allow-Credentials: true
  ```
- Impact: Any malicious site can silently perform authenticated state changes for victims with an active session cookie.
- Recommendation: Enforce CSRF protection on all cookie-authenticated state-changing endpoints with synchronizer tokens or equivalent defenses, and use `SameSite` cookies plus strict origin checks.
- PoC: `reports/pocs/WSTG-SESS-05_cookie-csrf-profile-update.py`

#### 4. Stored XSS in Public Review Comments

- WSTG IDs: `WSTG-INPV-02`, `WSTG-CLNT-03`
- CVSS estimate: 8.8 High
- Affected endpoints: `GET /api/reviews?reviewee_id=8a5b0a66-b192-4364-94e5-188a7657c1fa`, `GET /api/gigs/698c5387912d2f005a47a747`
- Description: Public review data contains HTML with an event-handler payload, and the live frontend renders review comments with `dangerouslySetInnerHTML`. This creates a stored XSS condition on seller gig pages.
- Steps to reproduce:
  1. Request gig `698c5387912d2f005a47a747`.
  2. Request `GET /api/reviews?reviewee_id=8a5b0a66-b192-4364-94e5-188a7657c1fa`.
  3. Observe the stored comment `<img src=x onerror=alert(1)>Great work on this project`.
  4. Inspect the frontend bundle and observe `dangerouslySetInnerHTML:{__html:b.comment}`.
- Evidence:
  ```bash
  curl -sS --max-time 10 'http://localhost:3000/api/reviews?reviewee_id=8a5b0a66-b192-4364-94e5-188a7657c1fa'
  curl -sS --max-time 10 http://localhost:3000/assets/index-CtZsj9EZ.js
  ```
- Impact: Viewing the affected seller page can execute attacker-controlled JavaScript in the victim browser.
- Recommendation: Sanitize review HTML on write and on render, or treat review comments as plain text instead of HTML.
- PoC: `reports/pocs/WSTG-INPV-02_review-stored-xss.py`

### Medium

#### 5. Email Verification Not Enforced Before Account Use

- WSTG IDs: `WSTG-IDNT-03`
- CVSS estimate: 6.5 Medium
- Affected endpoints: `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`, `GET /api/payments/wallet`
- Description: Newly registered users receive valid tokens while `email_verified` is `false` and can immediately log in and access protected functionality.
- Steps to reproduce:
  1. Register a new account.
  2. Observe `email_verified: false` and a returned token.
  3. Use that token or log in again.
  4. Access `/api/payments/wallet`.
- Evidence:
  ```json
  {"user":{"email_verified":false,...},"token":"..."}
  ```
- Impact: Attackers can create immediately usable accounts without proving email ownership.
- Recommendation: Block all protected functionality until email verification is complete and do not issue active session tokens before verification.
- PoC: `reports/pocs/WSTG-IDNT-03_unverified-account-access.py`

#### 6. No Account Lockout After Repeated Failed Logins

- WSTG IDs: `WSTG-ATHN-03`
- CVSS estimate: 6.8 Medium
- Affected endpoint: `POST /api/auth/login`
- Description: After 25 consecutive failed login attempts on the same account, the correct password still works immediately.
- Evidence:
  ```text
  failed_attempt_25=401
  HTTP/1.1 200 OK
  ```
- Impact: Password-guessing and credential-stuffing attacks are cheaper and more reliable.
- Recommendation: Add per-account throttling, progressive delays, CAPTCHA/secondary challenges, and lockout controls.
- PoC: `reports/pocs/WSTG-ATHN-03_no-lockout.py`

#### 7. Weak Passwords Are Accepted at Registration

- WSTG IDs: `WSTG-ATHN-07`
- CVSS estimate: 5.9 Medium
- Affected endpoint: `POST /api/auth/register`
- Description: Very short passwords are rejected, but trivial low-entropy values such as `aaaaaaaa` and `password` are accepted.
- Evidence:
  ```text
  HTTP/1.1 400 Bad Request
  HTTP/1.1 201 Created
  HTTP/1.1 201 Created
  ```
- Impact: Users can choose passwords that are highly vulnerable to guessing and stuffing attacks.
- Recommendation: Enforce stronger password controls, including banned-password screening and minimum complexity/length standards aligned with modern guidance.
- PoC: `reports/pocs/WSTG-ATHN-07_weak-password-policy.py`

#### 8. Logout Does Not Revoke Bearer Tokens

- WSTG IDs: `WSTG-SESS-06`
- CVSS estimate: 6.4 Medium
- Affected endpoints: `POST /api/auth/logout`, `GET /api/auth/me`
- Description: Cookie-backed logout invalidates the session cookie, but the JWT issued during login remains valid after logout.
- Evidence:
  ```text
  /api/auth/me with old cookie after logout: HTTP 401
  /api/auth/me with old bearer after logout: HTTP 200
  ```
- Impact: A stolen JWT survives logout and remains usable until expiry.
- Recommendation: Add token revocation/versioning, rotate signing state on logout or password change, and avoid long-lived bearer tokens in browser storage.
- PoC: `reports/pocs/WSTG-SESS-06_logout-does-not-revoke-jwt.py`

#### 9. Stack Trace Disclosure in Error Responses

- WSTG IDs: `WSTG-ERRH-01`, `WSTG-ERRH-02`
- CVSS estimate: 5.3 Medium
- Affected endpoint: `POST /api/auth/login`
- Description: Malformed JSON requests return parser errors and stack traces including module paths under `/app/node_modules/...`.
- Evidence:
  ```json
  {"error":"Expected ',' or '}' after property value in JSON at position 12","stack":"SyntaxError: ... /app/node_modules/body-parser/lib/types/json.js ..."}
  ```
- Impact: Attackers gain precise framework/runtime fingerprinting information that can support later exploitation.
- Recommendation: Return generic client-safe error messages and suppress stack traces from production responses.
- PoC: `reports/pocs/WSTG-ERRH-01_stack-trace-on-malformed-json.py`

### Low

#### 10. Registration Endpoint Enumerates Existing Accounts

- WSTG IDs: `WSTG-IDNT-04`
- CVSS estimate: 3.7 Low
- Affected endpoint: `POST /api/auth/register`
- Description: Existing addresses return `409 Conflict` and `"Email already registered"`, while fresh addresses register successfully.
- Impact: Attackers can verify whether a target email is registered.
- Recommendation: Use generic registration responses and normalize timing/response structure for existing and non-existing accounts.
- PoC: `reports/pocs/WSTG-IDNT-04_registration-enumeration.py`

#### 11. No Content Security Policy

- WSTG IDs: `WSTG-CONF-12`
- CVSS estimate: 3.1 Low
- Affected endpoint: `GET /`
- Description: The SPA entrypoint does not emit a `Content-Security-Policy` header.
- Impact: Browser-side injection issues are easier to exploit and contain poorly.
- Recommendation: Deploy a restrictive CSP with `default-src 'self'`, explicit script/style/font origins, and no inline-script allowances unless strictly necessary.
- PoC: `reports/pocs/WSTG-CONF-12_missing-csp.py`

## OWASP Top 10 2025 Mapping

Mappings use the official OWASP Top 10:2025 category set from OWASP:

- `A01:2025 Broken Access Control`
  - Broken object-level authorization on owner-scoped projects
  - Cookie-authenticated profile update is CSRFable
- `A02:2025 Security Misconfiguration`
  - Reflective credentialed CORS
  - No Content Security Policy
- `A05:2025 Injection`
  - Stored XSS in public review comments
- `A07:2025 Authentication Failures`
  - Email verification not enforced before account use
  - No account lockout after repeated failed logins
  - Weak passwords accepted at registration
  - Logout does not revoke bearer tokens
  - Registration endpoint enumerates existing accounts
- `A10:2025 Mishandling of Exceptional Conditions`
  - Stack trace disclosure in error responses

Reference:

- https://owasp.org/Top10/2025/

## Coverage Summary

- Total WSTG checks triaged: 91
- Confirmed finding states in checklist: 16
- Completed with no confirmed issue / not applicable: 54
- Inconclusive: 21
- Definitive coverage (`[x]` + `[-]`): 70 / 91 = 76.9%
- Checklist triage completion (no pending items): 91 / 91 = 100%

By major area:

- INFO: Completed with partial workflow mapping and no version disclosure
- CONF: Multiple misconfigurations confirmed (`CORS`, missing `CSP`)
- IDNT / ATHN / SESS: Multiple confirmed account/session weaknesses
- ATHZ / APIT: Confirmed broken access control on owner-scoped project data
- INPV / CLNT: Confirmed stored XSS in public review rendering
- ERRH: Confirmed parser/stack-trace disclosure
- BUSL / upload-specific areas: mostly inconclusive due limited reachable feature surface in this pass

## Statistics

### By Severity

- High: 4
- Medium: 5
- Low: 2
- Total unique findings: 11

### By OWASP 2025 Category

- `A01:2025 Broken Access Control`: 2
- `A02:2025 Security Misconfiguration`: 2
- `A05:2025 Injection`: 1
- `A07:2025 Authentication Failures`: 5
- `A10:2025 Mishandling of Exceptional Conditions`: 1

### PoC Inventory

- Total PoC scripts: 11
- Location: `reports/pocs/`
