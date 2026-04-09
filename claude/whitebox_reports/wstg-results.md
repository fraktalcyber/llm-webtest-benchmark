# OWASP WSTG Security Test Plan — HireFlow

This test plan is based on the [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/)
checklist, tailored to a freelancer marketplace web application.

## Status Legend

- `[ ]` = pending
- `[~]` = in progress
- `[x]` = done — finding confirmed
- `[-]` = done — not vulnerable / not applicable
- `[?]` = inconclusive, needs more investigation

When a test produces a finding, record the evidence (curl command and
response excerpt) in a `> Finding:` block directly beneath it.

---

## INFO — Information Gathering

- [x] WSTG-INFO-01: Search engine discovery and reconnaissance
  > No robots.txt or sitemap.xml served (returns React SPA fallback).

- [x] WSTG-INFO-02: Fingerprint web server
  > **Finding: Technology Stack Fingerprinting**
  > **Severity**: Informational
  > Headers reveal: Express.js (via helmet defaults), Node.js. No `Server` or `X-Powered-By` header (helmet removes them).
  > Cookie name `connect.sid` confirms Express session middleware.

- [-] WSTG-INFO-03: Review webserver metafiles for information leakage
  > No robots.txt, sitemap.xml, or .well-known paths exposed. All return SPA fallback.

- [-] WSTG-INFO-04: Enumerate applications on webserver
  > Single application on port 3000. Docker services (postgres:5432, mongodb:27017, redis:6379, minio:9000) are internal.

- [x] WSTG-INFO-05: Review webpage content for information leakage
  > **Finding: Unauthenticated Debug Endpoint**
  > **Severity**: Critical
  > **Source**: `src/index.js:101-113` — `/api/debug/info` has no authentication
  > **Endpoint**: `GET /api/debug/info`
  > **Description**: Exposes database hostnames, MongoDB URI, Redis host, Node version, PID, memory usage, platform info.
  > **Evidence**:
  > ```bash
  > curl -s http://localhost:3000/api/debug/info
  > ```
  > Response: `{"node_version":"v20.20.2","environment":"development","db_host":"postgres","redis_host":"redis","mongo_uri":"mongodb://mongodb:27017/hireflow",...}`
  > **Impact**: Infrastructure details exposed to unauthenticated attackers.
  > **PoC**: `reports/pocs/WSTG-CONF-08_debug-info-leak.py`

- [x] WSTG-INFO-06: Identify application entry points
  > Cataloged all API endpoints across 14 route files. Key entry points:
  > Auth: register, login, logout, forgot-password, reset-password, verify-email
  > Users: CRUD, settings, avatar upload
  > Gigs: CRUD with search (MongoDB)
  > Projects: CRUD with proposals
  > Contracts: milestones, deliverables, invoices
  > Payments: wallet deposit/withdraw, escrow fund/release, transactions
  > Messaging: conversations, messages, link-preview
  > Reviews, Disputes, Notifications, Admin panel
  > Webhooks: payment webhook, test webhook, profile import
  > WebSocket: Socket.IO on /messaging namespace

- [x] WSTG-INFO-07: Map execution paths through application
  > Registration → Gig/Project creation → Proposal → Contract → Milestone funding (escrow) → Work submission → Approval → Escrow release (minus 10% platform fee) → Review
  > Dispute flow: File dispute → Evidence → Moderator assignment → Resolution

- [x] WSTG-INFO-08: Fingerprint web application framework
  > Backend: Express.js 4.17.1 with Node.js v20.20.2
  > Database: PostgreSQL 15 (Knex.js ORM) + MongoDB 7 (Mongoose 5.13.0)
  > Cache/Session: Redis 7 (ioredis + connect-redis)
  > Frontend: React (Vite bundler)
  > Real-time: Socket.IO 4.7.2
  > File storage: MinIO (S3-compatible)
  > Auth: JWT (jsonwebtoken 8.5.1) + express-session

- [-] WSTG-INFO-09: Fingerprint web application
  > No version info in headers or responses. Health endpoint returns only `{"status":"ok"}`.

- [x] WSTG-INFO-10: Map application architecture
  > **Finding: Architecture Details Leaked via Debug Endpoint**
  > Dual auth (session cookies + JWT Bearer tokens). PostgreSQL for relational data, MongoDB for gigs/activity logs, Redis for sessions/cache. MinIO for file storage. MailHog for email in dev.

---

## CONF — Configuration and Deployment Management

- [-] WSTG-CONF-01: Test network/infrastructure configuration
  > Database/cache ports are internal to Docker network. Not externally accessible from app port.

- [x] WSTG-CONF-02: Test application platform configuration
  > **Finding: CSP Disabled, Missing Permissions-Policy**
  > **Severity**: Medium
  > **Source**: `src/index.js:50-53` — `helmet({ contentSecurityPolicy: false })`
  > Most security headers present via helmet (HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy).
  > Missing: Content-Security-Policy (explicitly disabled), Permissions-Policy.

- [-] WSTG-CONF-03: Test file extension handling for sensitive information
  > File uploads use UUID filenames with original extension. Upload filter varies by endpoint.

- [x] WSTG-CONF-04: Review old/backup/unreferenced files
  > **Finding: Upload Directory Listing Enabled**
  > **Severity**: High
  > **Source**: `src/index.js:77` — `app.use('/uploads', serveIndex(...))`
  > **Endpoint**: `GET /uploads/`
  > **Description**: Browsable directory listing of all uploaded files. No authentication required.
  > **Evidence**:
  > ```bash
  > curl -s http://localhost:3000/uploads/ | head -5
  > ```
  > Response: HTML directory listing with all uploaded file UUIDs.
  > **Impact**: All uploaded files (avatars, deliverables, attachments) discoverable and downloadable.

- [-] WSTG-CONF-05: Enumerate admin interfaces
  > Admin endpoints properly protected with RBAC middleware. Client/freelancer get 403. Moderator gets 403 on admin-only routes.

- [-] WSTG-CONF-06: Test HTTP methods
  > Routes defined with specific methods. No method override headers supported.

- [-] WSTG-CONF-07: Test HTTP Strict Transport Security
  > HSTS header present: `max-age=15552000; includeSubDomains`. However, app runs HTTP-only, making HSTS meaningless.

- [x] WSTG-CONF-08: Test cross-domain policy (CORS)
  > **Finding: CORS Allows Any Origin with Credentials**
  > **Severity**: Critical
  > **Source**: `src/index.js:46-49` — `cors({ origin: true, credentials: true })`
  > **Endpoint**: All endpoints
  > **Description**: Any Origin header is reflected back with `Access-Control-Allow-Credentials: true`. This allows any malicious website to make authenticated cross-origin requests.
  > **Evidence**:
  > ```bash
  > curl -sI -H "Origin: https://evil.example.com" http://localhost:3000/api/health
  > ```
  > Response: `Access-Control-Allow-Origin: https://evil.example.com` + `Access-Control-Allow-Credentials: true`
  > **Impact**: Cross-site request forgery from any domain; credential theft.
  > **PoC**: `reports/pocs/WSTG-SESS-05_csrf-cors.py`

- [-] WSTG-CONF-09: Test file permissions
  > Uploaded files served from /uploads/ path. UUID filenames prevent overwriting app files.

- [x] WSTG-CONF-11: Test cloud/object storage
  > **Finding: Upload Path Allows Unauthenticated Access**
  > **Severity**: Medium
  > **Source**: `src/index.js:77-78` — static file serving with directory listing
  > All files at /uploads/ accessible without authentication. Directory listing enabled.

- [x] WSTG-CONF-12: Test Content Security Policy
  > **Finding: CSP Explicitly Disabled**
  > **Severity**: Medium
  > **Source**: `src/index.js:51` — `contentSecurityPolicy: false`
  > No CSP header sent. Inline scripts/styles unrestricted. No XSS mitigations from CSP.

- [-] WSTG-CONF-14: Test other HTTP security header misconfigurations
  > X-Content-Type-Options: nosniff ✓, X-Frame-Options: SAMEORIGIN ✓, Referrer-Policy: no-referrer ✓
  > Missing: Permissions-Policy

---

## IDNT — Identity Management

- [-] WSTG-IDNT-01: Test role definitions
  > Five roles properly defined: guest(0), client(1), freelancer(1), moderator(2), admin(3), superadmin(4).
  > RBAC middleware enforces role hierarchy correctly.

- [-] WSTG-IDNT-02: Test user registration process
  > Mass assignment for role elevation blocked. Duplicate email rejected with 409. Registration requires only email, username (3 chars), password (8 chars).

- [x] WSTG-IDNT-03: Test account provisioning process
  > **Finding: Unverified Accounts Have Full Access**
  > **Severity**: High
  > **Source**: `src/auth/auth.controller.js:52-59` — JWT issued before email verification
  > **Source**: `src/middleware/auth.js` — never checks `email_verified`
  > **Description**: JWT is issued immediately at registration. The authenticate middleware never checks email_verified. Unverified accounts can access all protected endpoints.
  > **Impact**: Email verification is cosmetic; attackers can register with any email and immediately use the platform.

- [x] WSTG-IDNT-04: Test account enumeration
  > **Finding: Account Enumeration via Forgot-Password**
  > **Severity**: Medium
  > **Source**: `src/auth/auth.controller.js:134-138`
  > Valid email: `"Password reset link sent"` (200). Invalid: `"No account found"` (404).
  > Login endpoint correctly returns same message for both cases.

- [-] WSTG-IDNT-05: Test username/email policy
  > Username regex `/^[a-zA-Z0-9_-]+$/` blocks special chars. Email normalized to lowercase.

---

## ATHN — Authentication

- [x] WSTG-ATHN-01: Test credentials over encrypted channel
  > **Finding: No TLS — Credentials Over HTTP**
  > **Severity**: High
  > **Source**: `src/index.js:40` — `http.createServer(app)` (no TLS)
  > All traffic including passwords, JWTs, and session cookies transmitted in cleartext.

- [x] WSTG-ATHN-02: Test for default credentials
  > **Finding: Default Passwords on All Accounts**
  > **Severity**: High
  > All 5 test accounts (including admin/superadmin) use `password123`.

- [x] WSTG-ATHN-03: Test lockout mechanism
  > **Finding: No Account Lockout or Rate Limiting on Login**
  > **Severity**: High
  > **Source**: `src/middleware/rateLimiter.js:13-19` — `authLimiter` defined but never imported/applied
  > **Source**: `src/auth/auth.routes.js` — no rate limiter middleware on auth routes
  > 26+ failed login attempts all returned 401 with no lockout or rate limiting.
  > Login still succeeded with correct password after all failures.

- [x] WSTG-ATHN-04: Test authentication bypass
  > **Finding: Auth Bypass via Error-Swallowing in Middleware**
  > **Severity**: Critical
  > **Source**: `src/middleware/auth.js:32-37` — unexpected errors call `next()` without setting `req.user`
  > If JWT verification succeeds but the database query throws an unexpected error, the middleware calls `next()` (bypassing authentication). The request proceeds unauthenticated.
  >
  > **Finding: Account Enumeration via Forgot-Password**
  > **Severity**: Medium
  > Different messages for existing vs non-existing emails. See IDNT-04.

- [x] WSTG-ATHN-05: Test remember-password / persistent login
  > **Finding: 7-Day JWT Lifetime, No Revocation on Password Change**
  > **Severity**: Medium
  > **Source**: `src/config/index.js:31` — `expiresIn: '7d'`
  > **Source**: `src/auth/auth.service.js:132-140` — `updatePassword()` doesn't invalidate JWTs
  > Old JWT remains valid after password change. No token blacklist exists.
  > **PoC**: `reports/pocs/WSTG-SESS-06_jwt-no-revocation.py`

- [x] WSTG-ATHN-07: Test password policy
  > **Finding: Weak Password Policy and Low Bcrypt Cost**
  > **Severity**: High
  > **Source**: `src/auth/auth.routes.js:18-19` — only `isLength({ min: 8 })` validation
  > **Source**: `src/auth/auth.service.js:8` — `SALT_ROUNDS = 4` (should be 10+)
  > No complexity requirements. `aaaaaaaa`, `password`, `12345678` all accepted.
  > Bcrypt salt rounds of 4 makes brute-forcing ~64x faster than industry-standard 10.

- [x] WSTG-ATHN-09: Test password reset functionality
  > **Finding: Predictable Password Reset Tokens**
  > **Severity**: Critical
  > **Source**: `src/utils/helpers.js:25-29` — `generateResetToken(email)` uses `SHA256(email + base36(timestamp))[:16]`
  > **Description**: Reset token is deterministic. An attacker who knows the email and approximate request time can compute the valid token by enumerating ~1000 millisecond values.
  > No cryptographic randomness used. Token successfully brute-forced in 8-12 attempts.
  > **PoC**: `reports/pocs/WSTG-ATHN-09_predictable-reset-token.py`
  >
  > **Finding: Reset Token Expiry Mismatch**
  > **Severity**: Medium
  > **Source**: `src/auth/auth.service.js:116` — DB sets 1-hour expiry
  > **Source**: `src/auth/auth.controller.js:184` — Code checks 24-hour expiry
  > DB expiry is never enforced in `findByResetToken()`.

- [-] WSTG-ATHN-10: Test alternative auth channels
  > Dual auth (session + JWT) supported. Both mechanisms independently grant access. Increases attack surface.

- [-] WSTG-ATHN-11: Test multi-factor authentication
  > No MFA implementation exists.

---

## ATHZ — Authorization

- [x] WSTG-ATHZ-01: Test directory traversal / file include
  > **Finding: SSRF via Profile Import — No URL Validation**
  > **Severity**: Critical
  > **Source**: `src/integrations/webhook.service.js:196-248` — no protocol/hostname validation
  > **Endpoint**: `GET /api/integrations/import?url=`
  > **Description**: The importProfile() function fetches any URL with zero SSRF protections. Can access internal Docker services, localhost, cloud metadata endpoints.
  > **Evidence**:
  > ```bash
  > curl -s "http://localhost:3000/api/integrations/import?url=http://localhost:3000/api/debug/info" -H "Authorization: Bearer $TOKEN"
  > ```
  > **PoC**: `reports/pocs/WSTG-INPV-19_ssrf-import.py`
  >
  > **Finding: SSRF via Webhook Test — Full Response Returned**
  > **Severity**: Critical
  > **Source**: `src/integrations/webhook.service.js:139-189` — no URL validation, response body returned
  > **Endpoint**: `POST /api/webhooks/test`
  > **Description**: Sends POST to any user-supplied URL and returns HTTP status + response body (up to 500 chars). Full-read SSRF.
  >
  > **Finding: SSRF via Link Preview — Incomplete Blocklist Bypass**
  > **Severity**: High
  > **Source**: `src/messaging/messaging.service.js:367-422` — blocks only `localhost` and `127.0.0.1`
  > **Endpoint**: `POST /api/messages/conversations/:id/link-preview`
  > **Description**: Bypassed via IPv6-mapped addresses, `0.0.0.0`, DNS rebinding (`localtest.me`).
  >
  > **Finding: Upload Directory Listing + Unauthenticated File Access**
  > **Severity**: Medium
  > **Source**: `src/index.js:77-78` — serveIndex + express.static without auth
  > All uploaded files browsable and downloadable without authentication.

- [x] WSTG-ATHZ-02: Test authorization schema bypass
  > **Finding: Payment Webhook Accepts Unsigned Requests**
  > **Severity**: Critical
  > **Source**: `src/integrations/webhook.service.js:18-29` — signature check is conditional: `if (signature) { verify }`
  > **Endpoint**: `POST /api/webhooks/payment`
  > **Description**: When no `x-payment-signature` header is provided, signature verification is skipped entirely. Any unauthenticated caller can inject payment events and credit arbitrary amounts to any user's wallet.
  > **Evidence**:
  > ```bash
  > curl -s -X POST http://localhost:3000/api/webhooks/payment -H "Content-Type: application/json" \
  >   -d '{"event":"payment.completed","data":{"user_id":"TARGET_ID","amount":1000000}}'
  > ```
  > Response: `{"received":true,"result":{"processed":true}}`
  > **PoC**: `reports/pocs/WSTG-ATHZ-02_webhook-bypass.py`
  >
  > **Finding: User List Exposes All Users Including Admins**
  > **Severity**: Medium
  > **Source**: `src/users/users.routes.js:10` — no auth on GET /api/users
  > Role filter (`?role=superadmin`) allows enumerating admin accounts.

- [x] WSTG-ATHZ-03: Test privilege escalation
  > Profile update properly whitelists fields (role not included). Registration properly restricts role to client/freelancer. RBAC middleware correctly enforces role boundaries.
  > No privilege escalation found.

- [x] WSTG-ATHZ-04: Test insecure direct object references (IDOR)
  > **Finding: User Settings IDOR — No Authentication**
  > **Severity**: Critical
  > **Source**: `src/users/users.routes.js:15` — no `authenticate` middleware on GET /:id/settings
  > **Endpoint**: `GET /api/users/:id/settings`
  > **Description**: Returns email, phone, last_login, email_verified status for any user without authentication.
  > **PoC**: `reports/pocs/WSTG-ATHZ-04_user-settings-idor.py`
  >
  > **Finding: Contract IDOR — View/Modify Any Contract**
  > **Severity**: Critical
  > **Source**: `src/contracts/contracts.controller.js:28-38` — no ownership check
  > **Endpoint**: `GET /api/contracts/:id`, `PUT /api/contracts/:id/status`
  > **Description**: Any authenticated user can view any contract's details (milestones, amounts) and change its status (cancel, complete).
  > **PoC**: `reports/pocs/WSTG-ATHZ-04_contract-idor.py`
  >
  > **Finding: Contract Invoice IDOR**
  > **Severity**: High
  > **Source**: `src/contracts/contracts.controller.js:220-237` — no ownership check
  > **Endpoint**: `GET /api/contracts/:id/invoice`
  > Any user can generate and download invoices for any contract.
  >
  > **Finding: Messaging IDOR — Read/Inject Any Conversation**
  > **Severity**: Critical
  > **Source**: `src/messaging/messaging.service.js:187-226` — no participant check
  > **Endpoint**: `GET /api/messages/conversations/:id`, `POST /api/messages/conversations/:id/messages`
  > **Description**: Any authenticated user can read all messages in any conversation and inject messages into any conversation.
  > **PoC**: `reports/pocs/WSTG-ATHZ-04_messaging-idor.py`
  >
  > **Finding: Proposals IDOR — View All Proposals**
  > **Severity**: High
  > **Source**: `src/proposals/proposals.controller.js:9-29` — no ownership filter
  > **Endpoint**: `GET /api/proposals`
  > Any authenticated user can view all proposals (cover letters, bid amounts).

- [-] WSTG-ATHZ-05: Test OAuth weaknesses
  > No OAuth/social login implementation found.

---

## SESS — Session Management

- [x] WSTG-SESS-01: Test session management schema
  > Session cookie `connect.sid` set on login. Sessions stored in Redis. JWT also issued in response body.

- [x] WSTG-SESS-02: Test cookie attributes
  > **Finding: Missing Secure and SameSite Cookie Flags**
  > **Severity**: High
  > **Source**: `src/index.js:68` — `secure: config.env === 'production'` (false in development)
  > Cookie: `connect.sid=s%3A...; Path=/; HttpOnly` — HttpOnly ✓, Secure ✗, SameSite ✗
  > Cookie transmitted over HTTP. No SameSite attribute (defaults to browser Lax in modern browsers).

- [-] WSTG-SESS-03: Test session fixation
  > Session only created on login (not before). However, session is not regenerated on login — `req.session.userId` is set on existing session without `req.session.regenerate()`.

- [x] WSTG-SESS-04: Test exposed session variables
  > **Finding: Sensitive Data in JWT Payload**
  > **Severity**: High
  > **Source**: `src/auth/auth.service.js:68-82` — `walletBalance` and `email` embedded in JWT
  > JWT payload: `{"id":"...","email":"...","role":"client","walletBalance":"10010001052774"}`
  > Financial balance visible in every request header (base64, not encrypted).

- [x] WSTG-SESS-05: Test CSRF protection
  > **Finding: No CSRF Protection**
  > **Severity**: High
  > **Source**: `src/index.js:46-49` — CORS allows all origins with credentials
  > No CSRF tokens. No csurf middleware. No SameSite cookie. CORS reflects any origin.
  > State-changing requests succeed with `Origin: http://evil-attacker.com`.
  > **PoC**: `reports/pocs/WSTG-SESS-05_csrf-cors.py`

- [x] WSTG-SESS-06: Test logout functionality
  > **Finding: JWT Not Invalidated on Logout**
  > **Severity**: High
  > **Source**: `src/auth/auth.controller.js:111-124` — logout only destroys session, no JWT blacklist
  > JWT remains valid for full 7-day lifetime after logout. No revocation mechanism exists.
  > **PoC**: `reports/pocs/WSTG-SESS-06_jwt-no-revocation.py`

- [x] WSTG-SESS-07: Test session timeout
  > **Finding: Excessive JWT Lifetime**
  > **Severity**: Medium
  > **Source**: `src/config/index.js:31` — `expiresIn: '7d'`
  > 7-day JWT lifetime combined with no revocation means compromised tokens are exploitable for a week.

- [-] WSTG-SESS-09: Test session hijacking
  > HttpOnly on session cookie ✓. Secure flag missing (HTTP-only transport). JWT in localStorage vulnerable to XSS.

- [x] WSTG-SESS-10: Test JSON Web Tokens
  > **Finding: Hardcoded JWT Secret Fallback**
  > **Severity**: High
  > **Source**: `src/config/index.js:30` — `secret: process.env.JWT_SECRET || 'hireflow2024api'`
  > Default secret `hireflow2024api` hardcoded in source. If env var unset, any attacker with source access can forge arbitrary JWTs.
  > `alg: none` attack properly rejected by jsonwebtoken library.

- [-] WSTG-SESS-11: Test concurrent sessions
  > Unlimited concurrent sessions allowed. No limit or visibility of active sessions.

---

## INPV — Input Validation

- [x] WSTG-INPV-01: Test reflected XSS
  > **Finding: Input Reflected in Error Messages**
  > **Severity**: Medium
  > **Source**: `src/middleware/errorHandler.js:32-39` — reflects `err.message` in JSON responses
  > User input reflected in CastError messages and validation error details.

- [x] WSTG-INPV-02: Test stored XSS
  > **Finding: Stored XSS in User Profile Bio and Location**
  > **Severity**: High
  > **Source**: `src/users/users.service.js:111-134` — no HTML sanitization on bio/location
  > Script payloads stored and returned verbatim in profile responses.
  >
  > **Finding: Stored XSS in Messages and Conversation Subject**
  > **Severity**: High
  > **Source**: `src/messaging/messaging.service.js:119-181, 232-272` — no sanitization
  > HTML/script payloads stored in messages and subjects without sanitization.
  >
  > **Finding: Stored XSS via dangerouslySetInnerHTML in Reviews**
  > **Severity**: High
  > **Source**: `client/src/pages/GigDetail.jsx:299` — `dangerouslySetInnerHTML={{ __html: review.comment }}`
  > Review comments rendered as raw HTML. Direct XSS vector on the gig detail page.

- [-] WSTG-INPV-03: Test HTTP verb tampering
  > Routes defined with specific methods. Verb changes return 404 or proper 403.

- [-] WSTG-INPV-04: Test HTTP parameter pollution
  > No significant parameter pollution issues found.

- [x] WSTG-INPV-05: Test SQL injection
  > **Finding: SQL Injection in Public User Search**
  > **Severity**: Critical
  > **Source**: `src/users/users.service.js:32-33` — `query += " AND (display_name ILIKE '%${search}%'...)"`
  > **Endpoint**: `GET /api/users?search=`
  > **Description**: Search parameter directly concatenated into SQL. Boolean-based blind SQLi confirmed — extracting password hashes is possible.
  > **Evidence**:
  > ```bash
  > # True condition (returns users):
  > curl -s "http://localhost:3000/api/users?search=%25'+AND+1%3D1+AND+'%25'%3D'"
  > # False condition (returns empty):
  > curl -s "http://localhost:3000/api/users?search=%25'+AND+1%3D2+AND+'%25'%3D'"
  > ```
  > **PoC**: `reports/pocs/WSTG-INPV-05_sqli-users.py`
  >
  > **Finding: SQL Injection in Admin User Search**
  > **Severity**: Critical
  > **Source**: `src/admin/admin.service.js:66` — `whereRaw("display_name ILIKE '%" + search + "%'")`
  > **Endpoint**: `GET /api/admin/users?search=` (requires admin token)
  > Same string concatenation pattern. Tautology injection returns all users.

- [x] WSTG-INPV-06: Test NoSQL injection
  > **Finding: NoSQL Operator Injection in Audit Log**
  > **Severity**: High
  > **Source**: `src/admin/admin.service.js:398-440` — query params passed directly to MongoDB `find()`
  > **Endpoint**: `GET /api/admin/audit-log` (requires superadmin)
  > `$ne` and `$regex` operators injectable via query string, bypassing intended filters.
  > **PoC**: `reports/pocs/WSTG-INPV-06_nosql-injection.py`
  >
  > **Finding: $where Code Injection Pattern in Gig Search**
  > **Severity**: Medium
  > **Source**: `src/gigs/gigs.service.js:41-46` — user input in `$where` JavaScript function
  > **Endpoint**: `GET /api/gigs?tag_filter=`
  > Currently blocked by MongoDB server-side policy, but code vulnerability exists.

- [-] WSTG-INPV-11: Test code injection
  > See NoSQL injection findings above. No other code injection vectors found.

- [-] WSTG-INPV-12: Test command injection
  > File uploads use UUID filenames. No `child_process`/`exec`/`spawn` calls found. PDF uses Puppeteer.

- [-] WSTG-INPV-15: Test HTTP splitting/smuggling
  > No CRLF injection vectors found in response headers.

- [x] WSTG-INPV-17: Test host header injection
  > **Finding: Host Header Used in Password Reset URLs**
  > **Severity**: High
  > **Source**: `src/auth/auth.controller.js:142-143` — `${req.protocol}://${req.get('host')}/reset-password?token=...`
  > **Endpoint**: `POST /api/auth/forgot-password`
  > **Description**: Password reset and email verification URLs use `req.get('host')` which is controlled by the Host header. An attacker can send `Host: evil.com` to generate reset links pointing to their server.
  > **PoC**: `reports/pocs/WSTG-INPV-17_host-header-injection.py`

- [x] WSTG-INPV-18: Test server-side template injection
  > **Finding: HTML Injection in PDF Invoice Generation**
  > **Severity**: High
  > **Source**: `src/utils/pdf.js:32-89` — template literals with unescaped user data
  > **Source**: `src/contracts/contracts.service.js:421-456` — user-controlled data in invoice
  > User-controlled content (display_name, contract title, milestone titles) rendered as raw HTML in Puppeteer PDF. Allows HTML injection, JS execution, and potential SSRF via `<img>` tags.

- [x] WSTG-INPV-19: Test SSRF
  > **Finding: SSRF via Profile Import — No URL Validation**
  > **Severity**: Critical
  > **Source**: `src/integrations/webhook.service.js:196-248`
  > **Endpoint**: `GET /api/integrations/import?url=`
  > No protocol/hostname validation. Successfully accessed localhost, 127.0.0.1, internal Docker hosts.
  > **PoC**: `reports/pocs/WSTG-INPV-19_ssrf-import.py`
  >
  > **Finding: SSRF via Webhook Test**
  > **Severity**: High
  > **Source**: `src/integrations/webhook.service.js:139-189`
  > **Endpoint**: `POST /api/webhooks/test`
  > Full-read SSRF — response body returned to caller.
  >
  > **Finding: SSRF via Link Preview — Blocklist Bypass**
  > **Severity**: High
  > **Source**: `src/messaging/messaging.service.js:367-422`
  > Incomplete blocklist bypassed via IPv6-mapped addresses and DNS rebinding.

- [x] WSTG-INPV-20: Test mass assignment
  > Registration and profile update properly use whitelists. Role elevation blocked.
  > No mass assignment vulnerabilities found.

---

## ERRH — Error Handling

- [x] WSTG-ERRH-01: Test improper error handling
  > **Finding: SQL Query Structure Leaked in Error Messages**
  > **Severity**: Medium
  > Invalid UUIDs trigger: `"select * from \"contracts\" where \"id\" = $1 limit $2 - invalid input syntax for type uuid: \"not-a-uuid\""`
  > Malformed JSON reveals parser error details.

- [x] WSTG-ERRH-02: Test stack traces
  > **Finding: Stack Traces Always Leaked Due to Case-Sensitivity Bug**
  > **Severity**: High
  > **Source**: `src/middleware/errorHandler.js:35` — `process.env.NODE_ENV !== 'Production'` (capital P)
  > Node.js convention is `'production'` (lowercase). Stack traces included in all non-`Production` environments, which is always.
  > Leaked info: internal file paths, node_modules structure, library versions.
  > **PoC**: `reports/pocs/WSTG-ERRH-02_stack-trace-leak.py`

---

## CRYP — Cryptography

- [x] WSTG-CRYP-01: Test weak transport layer security
  > **Finding: Application Runs HTTP Only**
  > **Severity**: High
  > **Source**: `src/index.js:40` — `http.createServer(app)`
  > No TLS. All data in cleartext.

- [x] WSTG-CRYP-03: Test sensitive data sent via unencrypted channels
  > **Finding: Wallet Balance in JWT Payload**
  > **Severity**: High
  > **Source**: `src/auth/auth.service.js:68-82`
  > JWT contains `walletBalance` field — financial data visible in every request.

- [x] WSTG-CRYP-04: Test weak cryptographic primitives
  > **Finding: Bcrypt Salt Rounds = 4**
  > **Severity**: Critical
  > **Source**: `src/auth/auth.service.js:8` — `const SALT_ROUNDS = 4`
  > Industry minimum is 10. Makes brute-forcing ~64x faster.
  >
  > **Finding: Hardcoded JWT/Session Secrets**
  > **Severity**: Critical
  > **Source**: `src/config/index.js:25,30` — `'hireflow-session-key-change-in-production'`, `'hireflow2024api'`
  > Default secrets hardcoded in source code.
  >
  > **Finding: Deterministic Password Reset Tokens**
  > **Severity**: Critical
  > **Source**: `src/utils/helpers.js:25-29` — `SHA256(email + base36(timestamp))[:16]`
  > No cryptographic randomness. Brute-forceable with known email + approximate time.

---

## BUSL — Business Logic

- [x] WSTG-BUSL-01: Test business logic data validation
  > **Finding: No Maximum Deposit Amount**
  > **Severity**: High
  > **Source**: `src/payments/payments.controller.js:15-16` — only checks `amount <= 0`
  > Deposits of $999,999,999,999 accepted without validation.
  > **PoC**: `reports/pocs/WSTG-BUSL-01_negative-deposit.py`

- [x] WSTG-BUSL-02: Test ability to forge requests
  > **Finding: Escrow Release Amount Override**
  > **Severity**: High
  > **Source**: `src/payments/payments.service.js:204,228` — `const amount = overrideAmount || milestone.amount`
  > Client can specify arbitrary release amount via `req.body.amount`, potentially extracting more from escrow than deposited.

- [x] WSTG-BUSL-03: Test integrity checks
  > **Finding: Webhook Signature Bypass**
  > **Severity**: Critical
  > **Source**: `src/integrations/webhook.service.js:18-29` — `if (signature) { verify }` (conditional check)
  > Without `x-payment-signature` header, any payment event is processed. Arbitrary wallet credits possible.
  > **PoC**: `reports/pocs/WSTG-ATHZ-02_webhook-bypass.py`

- [x] WSTG-BUSL-04: Test process timing
  > **Finding: Race Condition in Wallet Withdrawals**
  > **Severity**: High
  > **Source**: `src/payments/payments.service.js:79-109` — read-then-write without transaction/lock
  > Balance check and update are not atomic. Concurrent withdrawals can overdraft.

- [-] WSTG-BUSL-05: Test function usage limits
  > No limits on proposals, password resets, or transactions per time period. Rate limiting defined but not applied to auth routes.

- [x] WSTG-BUSL-06: Test workflow circumvention
  > See BUSL-02 (escrow override). Withdrawal properly checks balance (though race condition exists).

- [-] WSTG-BUSL-07: Test defenses against application misuse
  > `authLimiter` defined but never applied. `apiLimiter` (1000 req/15min in dev) is the only rate limit.

- [x] WSTG-BUSL-08: Test upload of unexpected file types
  > **Finding: HTML/SVG Files Served with Original Content-Type**
  > **Severity**: Critical
  > **Source**: `src/middleware/upload.js:50-52` — deliverable upload has no file filter
  > **Source**: `src/index.js:77-78` — files served via express.static (content-type from extension)
  > HTML files uploaded and served as `text/html`. Combined with directory listing, creates stored XSS.
  > **PoC**: `reports/pocs/WSTG-BUSL-08_upload-xss.py`

- [-] WSTG-BUSL-09: Test upload of malicious files
  > No file size limit on general/deliverable uploads. Only avatar (5MB) and gig images (10MB) have limits.

- [x] WSTG-BUSL-10: Test payment functionality
  > See BUSL-01 (no deposit ceiling), BUSL-02 (escrow override), BUSL-03 (webhook bypass), BUSL-04 (race condition).

---

## CLNT — Client-Side Testing

- [x] WSTG-CLNT-01: Test DOM-based XSS
  > **Finding: dangerouslySetInnerHTML in Review Rendering**
  > **Severity**: High
  > **Source**: `client/src/pages/GigDetail.jsx:299`
  > Review comments rendered as raw HTML via `dangerouslySetInnerHTML`.

- [x] WSTG-CLNT-03: Test HTML injection
  > Backend stores HTML payloads unsanitized in profiles, messages, reviews. See INPV-02.

- [-] WSTG-CLNT-04: Test client-side URL redirect
  > No open redirect vectors found. Client-side navigation only.

- [x] WSTG-CLNT-07: Test CORS
  > See CONF-08. CORS reflects any origin with credentials.

- [-] WSTG-CLNT-09: Test clickjacking
  > X-Frame-Options: SAMEORIGIN set by helmet. No CSP frame-ancestors (CSP disabled).

- [x] WSTG-CLNT-10: Test WebSockets
  > **Finding: Socket.IO Connections Lack Authentication**
  > **Severity**: Critical
  > **Source**: `src/config/socket.js:17-19` — accepts any `userId` from query without token verification
  > **Source**: `src/messaging/messaging.gateway.js:13-14` — no authentication check
  > Any user can connect as any other user by setting `userId` in query params. Can join any conversation room, receive all messages/notifications, and send messages impersonating any user.

- [x] WSTG-CLNT-12: Test browser storage
  > **Finding: JWT Stored in localStorage**
  > **Severity**: Medium
  > **Source**: `client/src/api/client.js:10-13` — `localStorage.setItem('hf_token', token)`
  > JWT accessible to any JavaScript on the page. Vulnerable to XSS-based theft.

- [-] WSTG-CLNT-14: Test reverse tabnabbing
  > External links properly use `rel="noopener noreferrer"`.

---

## APIT — API Testing

- [x] WSTG-APIT-01: API reconnaissance
  > **Finding: Unauthenticated Debug Endpoint** — See INFO-05.
  > No Swagger/OpenAPI docs. No API versioning. All routes under `/api/`.

- [x] WSTG-APIT-02: Test broken object-level authorization (BOLA)
  > **Finding: Multiple BOLA/IDOR Vulnerabilities** — See ATHZ-04.
  > Contracts, messages, proposals, invoices: no ownership checks.
  > Wallet, transactions, notifications, disputes: properly scoped.

---

## SUPPL — Log Injection & Monitoring (supplementary)

- [-] WSTG-SUPPL-01: Test log injection
  > Login email validated before reaching log statements. JSON-structured logging mitigates plain-text injection.

- [x] WSTG-SUPPL-02: Test sensitive data in logs
  > **Finding: Request Body Logged in Error Handler**
  > **Severity**: Medium
  > **Source**: `src/middleware/errorHandler.js:3-9` — `logger.error(err.message, { body: req.body })`
  > Passwords and tokens may be logged when errors occur on auth endpoints.
