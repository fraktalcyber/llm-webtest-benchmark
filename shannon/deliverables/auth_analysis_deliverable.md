# Authentication Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Target:** HireFlow Freelancer Marketplace — `http://host.docker.internal:3000`
- **Key Outcome:** Twelve (12) authentication vulnerabilities were identified spanning all major methodology categories: transport exposure, hardcoded cryptographic secrets enabling full JWT/session forgery, absent auth-specific rate limiting, a broken reset token design, and unauthenticated WebSocket impersonation. The most critical finding is a hardcoded JWT secret (`hireflow2024api`) that allows an external attacker to forge valid JWTs for any user — including superadmin — without possessing any credential.
- **Purpose of this Document:** This report provides strategic context on the application's authentication mechanisms, dominant flaw patterns, and key architectural details necessary to effectively exploit the vulnerabilities listed in the exploitation queue.

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: Hardcoded Cryptographic Secrets (Critical)
- **Description:** Both the JWT signing secret (`hireflow2024api`, `src/config/index.js:30`) and the Express session secret (`hireflow-session-key-change-in-production`, `src/config/index.js:25`) are committed directly in source code as fallback default values. The `||` pattern means these secrets are active whenever the corresponding environment variable is not explicitly set — a condition that is true in the observed deployment.
- **Implication:** Any attacker with access to the source code (or who discovers these values through reconnaissance) can forge a JWT for any user ID and any role, or sign arbitrary `connect.sid` session cookies. This is a complete authentication bypass without requiring any credential.
- **Representative Findings:** `AUTH-VULN-01`, `AUTH-VULN-02`.

### Pattern 2: Missing Auth-Specific Rate Limiting
- **Description:** A dedicated `authLimiter` (15 req/15 min) is defined in `src/middleware/rateLimiter.js` but is **never imported or applied** to any auth route. The only active limiter on `/api/auth/*` is the general `apiLimiter` (200 req/15 min in production, 1000 in development), applied globally via `app.use('/api', apiLimiter)` in `src/index.js:74`. No CAPTCHA, account lockout, or per-account backoff exists.
- **Implication:** Login, forgot-password, and reset-password endpoints can be brute-forced freely. Combined with the user-enumeration flaw on forgot-password, attackers can mount targeted credential attacks.
- **Representative Findings:** `AUTH-VULN-03`.

### Pattern 3: Broken Reset Token Design
- **Description:** Two independent flaws compound to make the password reset flow exploitable: (1) `generateResetToken()` produces a deterministic, low-entropy token (`timestamp_base36 + sha256(email+timestamp)[:16]`) rather than using `crypto.randomBytes()`; and (2) `updatePassword()` never clears the `reset_token` column, leaving used tokens reusable for up to 24 hours.
- **Implication:** Tokens can be guessed offline against a known email. Used tokens remain active, enabling an attacker who intercepts or observes a reset link to take over the account hours after the legitimate user already reset their password.
- **Representative Findings:** `AUTH-VULN-07`, `AUTH-VULN-08`.

### Pattern 4: Incomplete Session Lifecycle Management
- **Description:** Multiple session lifecycle controls are absent or incorrectly implemented: (a) Logout destroys only the server-side session — the JWT remains valid for its full 7-day lifetime with no blacklist; (b) The session cookie lacks a `SameSite` attribute and the `secure` flag is conditional on `NODE_ENV === 'production'`, making it inactive in the observed environment; (c) No session ID rotation occurs post-login; (d) No idle or absolute session timeout is configured for Redis sessions.
- **Implication:** A stolen or leaked JWT allows account access for up to 7 days post-logout. HTTP-only cookies without the `secure` flag are transmitted over plaintext HTTP, exposing them to network interception.
- **Representative Findings:** `AUTH-VULN-04`, `AUTH-VULN-05`.

---

## 3. Strategic Intelligence for Exploitation

- **Authentication Methods:** Dual-path authentication — Express session cookie (`connect.sid`, Redis-backed) checked first, then JWT Bearer token. Both paths ultimately load the user record fresh from PostgreSQL, so role is authoritative from the DB (not the JWT payload) for session-based requests. JWT-authenticated requests do the same: decode to get `id`, then `SELECT * FROM users WHERE id = decoded.id`.
- **JWT Details:** Signed with `HS256` (jsonwebtoken default). Secret: `hireflow2024api` (hardcoded). 7-day expiry. Payload: `{ id, email, role, walletBalance }`. No `jti` (JWT ID), no revocation list.
- **Session Details:** Cookie name `connect.sid`, `httpOnly: true`, `secure: false` (non-production env), no `sameSite` attribute set. Session secret: `hireflow-session-key-change-in-production`. Redis backend with no TTL configured (sessions persist until Redis eviction).
- **Reset Token Format:** `${Date.now().toString(36)}-${crypto.createHash('sha256').update(email+timestamp).digest('hex').slice(0,16)}` — deterministic, timestamp-seeded, 16-char hash component. Stored as plaintext in `users.reset_token`. DB expiry field stored but **never queried** — expiry is checked only client-side via timestamp extracted from the token string itself.
- **Password Policy:** Server-side minimum 8 characters (enforced in `resetPassword` controller); registration uses express-validator `isLength({ min: 8 })`. No complexity requirements. bcrypt with **4 salt rounds** (industry minimum is 10-12), making offline cracking significantly faster.
- **Transport:** HTTP only. No TLS configured on Nginx (port 80) or the direct Express listener (port 3000). No HSTS. All credentials, cookies, and tokens transmitted in cleartext.
- **Socket.IO Auth:** The default namespace accepts any `userId` from the WebSocket handshake query parameter (`socket.handshake.query.userId`) with no session or JWT validation. Any actor can declare themselves as any user ID and receive presence/typing events attributed to that user.
- **MailHog Exposure:** All outbound email (including password reset links) is captured by MailHog at port 8025, which is publicly accessible with no authentication. Reset tokens are directly readable by anyone who can reach this port.
- **Auth Middleware Bypass (Conditional):** `src/middleware/auth.js:36` — if a non-JWT error occurs during Bearer token processing (e.g., a DB connection error), `next()` is called without setting `req.user` and without returning 401. Downstream handlers that dereference `req.user` without null-checking could panic or inadvertently process unauthenticated requests.
- **Role Hierarchy:** `guest(0) < client(1) = freelancer(1) < moderator(2) < admin(3) < superadmin(4)`. `superadmin` bypasses ALL `requireRole` checks unconditionally (`rbac.js:22`). Forging a JWT and creating a session with `superadmin` role grants complete platform access.

---

## 4. Detailed Findings

### AUTH-VULN-01: Hardcoded JWT Secret — JWT Forgery / Vertical Privilege Escalation
- **File:** `src/config/index.js:30`
- **Code:** `secret: process.env.JWT_SECRET || 'hireflow2024api'`
- **Flaw:** The JWT HMAC secret is a hardcoded, trivially guessable string. An attacker can sign arbitrary JWT payloads with `HS256` using this secret. The `authenticate` middleware at `src/middleware/auth.js:25-29` calls `jwt.verify(token, config.jwt.secret)` and then loads the user from DB by `decoded.id`. By forging a JWT with a valid user `id` (obtainable from public `/api/users/:id` endpoints), an attacker fully authenticates as that user.
- **Methodology Check:** Token/session properties — secret not cryptographically random/secret.
- **Verdict:** VULNERABLE

### AUTH-VULN-02: Hardcoded Session Secret — Session Cookie Forgery
- **File:** `src/config/index.js:25`
- **Code:** `secret: process.env.SESSION_SECRET || 'hireflow-session-key-change-in-production'`
- **Flaw:** Express session cookies (`connect.sid`) are HMAC-signed with this known secret. Using `cookie-signature` (the library express uses internally), an attacker can forge a valid signed session cookie for any `sessionId` they choose to insert into Redis (possible given Redis has no authentication and is directly exposed on port 6379) or to replay a previously observed session.
- **Methodology Check:** Session management — session secret is public.
- **Verdict:** VULNERABLE

### AUTH-VULN-03: No Auth-Specific Rate Limit on Login / Reset Endpoints
- **File:** `src/auth/auth.routes.js` (no `authLimiter` import), `src/middleware/rateLimiter.js:13-19` (defined but unused on auth routes)
- **Flaw:** `authLimiter` is defined but never applied. The active limit is 200 requests per 15 minutes per IP (global), or 1000 in development. An attacker can submit ~13 login attempts per minute before even approaching the general limit. No lockout, no backoff, no CAPTCHA.
- **Methodology Check:** Rate limiting — auth endpoints lack per-endpoint limits.
- **Verdict:** VULNERABLE

### AUTH-VULN-04: JWT Not Invalidated on Logout
- **File:** `src/auth/auth.controller.js:111-124`
- **Flaw:** `logout()` calls `req.session.destroy()` only. The JWT token issued at login persists for its full 7-day TTL. No JWT blacklist or token family tracking exists. An attacker who steals a JWT (e.g., from HTTP traffic, logs, or client storage) retains full account access for up to 7 days after the victim logs out.
- **Methodology Check:** Session management — logout does not invalidate all authentication tokens.
- **Verdict:** VULNERABLE

### AUTH-VULN-05: Session Cookie Missing `secure` Flag and `SameSite` Attribute
- **File:** `src/index.js:67-70`
- **Code:** `cookie: { secure: config.env === 'production', httpOnly: true }` — no `sameSite`
- **Flaw:** `config.env` evaluates to `'development'` (or undefined), so `secure: false` is the active setting. Session cookies are transmitted over plaintext HTTP. No `SameSite` attribute is set, leaving the cookie's cross-site behavior at the browser's default (varies; some browsers default to `Lax`, but server-side SameSite enforcement is absent).
- **Methodology Check:** Session management — cookie `secure` and `SameSite` flags.
- **Verdict:** VULNERABLE (compounded by HTTP-only deployment — AUTH-VULN-09)

### AUTH-VULN-06: Session Fixation — No Session ID Rotation Post-Login
- **File:** `src/auth/auth.controller.js:94-97`
- **Code:** `req.session.userId = user.id;` — assigns userId to existing session without regenerating session ID
- **Flaw:** The login handler sets `req.session.userId` on the existing session without calling `req.session.regenerate()`. If an attacker can supply a pre-known session ID (e.g., by injecting a `connect.sid` via a cross-site mechanism), they can fixate the session and gain access after the victim logs in.
- **Methodology Check:** Session fixation — session ID must be rotated after authentication.
- **Verdict:** VULNERABLE

### AUTH-VULN-07: Predictable/Weak Password Reset Token
- **File:** `src/utils/helpers.js:25-29`
- **Code:** `return \`${timestamp}-${hash}\`` where `hash = crypto.createHash('sha256').update(email + timestamp).digest('hex').slice(0, 16)`
- **Flaw:** The token is deterministic — it is derived from two values that are either known (email) or encoded directly in the token itself (timestamp in base36). The hash component is only 16 hex characters (8 bytes, 64 bits). More critically, since the timestamp is embedded in the public-facing token, the only "secret" component is `sha256(email + known_timestamp)[:16]`. This can be computed by anyone who knows the target email and has the token (defeating its purpose), or brute-forced offline. NIST SP 800-63B requires at least 20 bytes of cryptographically random data.
- **Methodology Check:** Recovery — token must be cryptographically random, not derived.
- **Verdict:** VULNERABLE

### AUTH-VULN-08: Password Reset Token Not Invalidated After Use
- **File:** `src/auth/auth.service.js:128-135` (`updatePassword` function)
- **Flaw:** `updatePassword()` updates only `password_hash` and `updated_at`. It does NOT clear `reset_token` or `reset_token_expires`. The token therefore remains in the database and is usable for up to 24 hours after the legitimate password reset completes. A token observed once (e.g., intercepted from MailHog, HTTP traffic, or email logs) can be replayed.
- **Methodology Check:** Recovery — reset tokens must be single-use.
- **Verdict:** VULNERABLE

### AUTH-VULN-09: No HTTPS — Plaintext Transport of All Auth Material
- **Infrastructure:** Nginx on port 80 (HTTP only), Express directly on port 3000 (HTTP only). No TLS certificates. No HSTS headers.
- **Flaw:** All authentication material (credentials in POST body, session cookies, JWT Bearer tokens, password reset links in emails) is transmitted over cleartext HTTP. A network-level observer (MitM, shared network, rogue proxy) can capture all of this passively.
- **Methodology Check:** Transport — HTTPS not enforced, no HSTS.
- **Verdict:** VULNERABLE

### AUTH-VULN-10: User Enumeration via Forgot-Password Endpoint
- **File:** `src/auth/auth.controller.js:136-138`
- **Code:** `return res.status(404).json({ message: 'No account found with that email address' })`
- **Flaw:** The forgot-password handler returns HTTP 404 with a distinct message when the email is not registered. A registered email receives HTTP 200 with a success message. This allows an attacker to enumerate valid email addresses systematically.
- **Methodology Check:** Login/signup responses — error messages must not reveal account existence.
- **Verdict:** VULNERABLE

### AUTH-VULN-11: bcrypt Work Factor Too Low (4 Rounds)
- **File:** `src/auth/auth.service.js:8`
- **Code:** `const SALT_ROUNDS = 4;`
- **Flaw:** bcrypt with 4 rounds is approximately 64× weaker than the recommended 10 rounds and ~4096× weaker than 12 rounds. If the PostgreSQL database is exfiltrated (possible via SQLi sinks identified in recon), passwords can be cracked offline at a dramatically higher rate than with a proper work factor.
- **Methodology Check:** Password policy — passwords must use strong one-way hashing.
- **Verdict:** VULNERABLE

### AUTH-VULN-12: Socket.IO Authentication Bypass — User Impersonation
- **File:** `src/config/socket.js:18`
- **Code:** `const userId = socket.handshake.query.userId;`
- **Flaw:** The Socket.IO default namespace accepts the `userId` value directly from the WebSocket handshake query string with no session validation, JWT verification, or any server-side identity check. Any client can impersonate any user by supplying an arbitrary `userId` in the WebSocket connection URL. This user ID is then used for presence tracking (`user:online` / `user:offline` broadcasts) and for joining conversation rooms.
- **Methodology Check:** Session management / authentication — identity in real-time channel not verified.
- **Verdict:** VULNERABLE

---

## 5. Secure by Design: Validated Components

These components were analyzed and found to have adequate defenses. They are low-priority for further authentication testing.

| Component/Flow | Endpoint/File Location | Defense Mechanism Implemented | Verdict |
|---|---|---|---|
| Password Hashing Algorithm | `src/auth/auth.service.js:56-58` | Uses `bcrypt.compare()` for constant-time password verification. Correct algorithm (bcrypt). | SAFE (work factor is weak — see AUTH-VULN-11) |
| JWT Signature Algorithm | `src/auth/auth.service.js:75` | Signs with `config.jwt.secret` using default HS256; `jwt.verify()` used (not `jwt.decode()`). No `alg: 'none'` bypass possible with this library version. | SAFE |
| Role Stored in Database | `src/middleware/auth.js:26-28` | Despite role being embedded in JWT payload, the `authenticate` middleware re-fetches the full user record from PostgreSQL for every request. Privilege is authoritative from DB, not JWT payload. | SAFE |
| Registration Role Coercion | `src/auth/auth.controller.js:28` | Only `client` or `freelancer` can be self-assigned at registration. Any non-`freelancer` value is coerced to `client`. | SAFE |
| Login Error Messages (Login Endpoint) | `src/auth/auth.controller.js:77-88` | Login returns a generic `'Invalid email or password'` for both non-existent accounts and wrong passwords — no user enumeration via the login endpoint. | SAFE |
| Active User Check | `src/middleware/auth.js:11, 27` | Both session and JWT auth paths verify `user.is_active` before granting access. Deactivated accounts are correctly rejected. | SAFE |
| SSO/OAuth | N/A | No SSO, OAuth, or OIDC flows are implemented. | N/A |
