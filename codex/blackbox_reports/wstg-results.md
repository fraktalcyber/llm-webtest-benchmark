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

## Session Notes

- 2026-03-31 15:16:53 EEST: Initialized this working report from `wstg-test-plan.md`.
- 2026-03-31 15:16:53 EEST: Initial reconnaissance blocked because the target was not listening on `http://localhost:3000`.
  Evidence:
  ```bash
  curl -sS -i --max-time 3 http://localhost:3000/
  ```
  Result:
  ```text
  curl: (7) Failed to connect to localhost port 3000 after 0 ms: Couldn't connect to server
  ```
- 2026-03-31 15:18:26 EEST: Retried from outside the sandbox and confirmed the target is reachable on `http://localhost:3000`.

---

## INFO — Information Gathering

- [-] WSTG-INFO-01: Search engine discovery and reconnaissance
  - Check robots.txt, sitemap.xml for exposed paths
  - Probe for information leakage in publicly accessible resources
  - `GET /robots.txt`, `GET /sitemap.xml`, and `GET /.well-known/security.txt` all returned the SPA entrypoint HTML rather than dedicated metadata files.
  - No crawler directives or search-engine metadata were exposed during this pass.
  - Evidence:
    ```bash
    curl -sS -i --max-time 5 http://localhost:3000/robots.txt
    curl -sS -i --max-time 5 http://localhost:3000/sitemap.xml
    curl -sS -i --max-time 5 http://localhost:3000/.well-known/security.txt
    ```
    Response excerpt:
    ```html
    <title>HireFlow - Freelancer Marketplace</title>
    <script type="module" crossorigin src="/assets/index-CtZsj9EZ.js"></script>
    ```

- [-] WSTG-INFO-02: Fingerprint web server
  - Check `Server`, `X-Powered-By`, and other headers from responses
  - Identify technology stack from response characteristics
  - `Server` and `X-Powered-By` are not disclosed.
  - Response headers match an Express/Helmet-style deployment and include rate-limiting headers on `/api/*`.
  - Fingerprints observed:
    - `Set-Cookie: connect.sid=...; Path=/; HttpOnly`
    - `RateLimit-Policy`, `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`
    - `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Strict-Transport-Security`
  - Evidence:
    ```bash
    curl -sS -i --max-time 5 http://localhost:3000/
    curl -sS -i --max-time 5 http://localhost:3000/api/health
    ```
    Response excerpt:
    ```text
    Strict-Transport-Security: max-age=15552000; includeSubDomains
    X-Frame-Options: SAMEORIGIN
    RateLimit-Policy: 1000;w=900
    ```

- [-] WSTG-INFO-03: Review webserver metafiles for information leakage
  - Check `/robots.txt`, `/sitemap.xml`, `/.well-known/` paths
  - Probe for exposed config files at web root (`.env`, `package.json`, etc.)
  - No dedicated metafiles were exposed; known metadata paths routed to the SPA shell.
  - Further exposed-file checks are still pending under `WSTG-CONF-04`.
  - Evidence:
    ```bash
    curl -sS -i --max-time 5 http://localhost:3000/.well-known/security.txt
    ```
    Response excerpt:
    ```html
    <div id="root"></div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>
    ```

- [?] WSTG-INFO-04: Enumerate applications on webserver
  - Probe common ports and paths for additional services
  - Check for management consoles or infrastructure services exposed alongside the app
  - No additional web applications or management consoles were discovered from the HTTP application surface.
  - Broader network-service enumeration was outside the exercised black-box workflow.

- [-] WSTG-INFO-05: Review webpage content for information leakage
  - Inspect HTML source, JS bundles, and inline comments for secrets
  - Check for API keys, internal URLs, or debug info in client code
  - Probe for diagnostic, debug, or health-check endpoints
  - The HTML and frontend bundle exposed route structure and the `hf_token` browser-storage key, but no API keys, credentials, or internal hostnames were disclosed.
  - `/api/health` returned only a basic status/timestamp object.

- [-] WSTG-INFO-06: Identify application entry points
  - Examine frontend JavaScript to discover API routes and endpoints
  - Catalog request methods, parameters, and auth requirements per endpoint
  - Identify file upload endpoints, webhook receivers, WebSocket endpoints
  - Confirmed static API routes from the live frontend bundle:
    - `POST /api/auth/login`, `POST /api/auth/register`, `POST /api/auth/logout`
    - `GET /api/auth/me`
    - `GET /api/admin/dashboard`, `GET /api/admin/disputes`, `GET|PUT /api/admin/settings`
    - `GET /api/gigs?limit=8&sort=rating`, `GET /api/gigs?seller=me&status=active&limit=5`, `POST /api/gigs`
    - `GET /api/projects?owner=me&status=active&limit=5`, `POST /api/projects`
    - `GET /api/proposals?sent=true&limit=5`, `GET /api/proposals?received=true&limit=5`, `POST /api/proposals`
    - `GET /api/contracts?role=client&status=active&limit=5`, `GET /api/contracts?role=freelancer&status=active&limit=5`, `POST /api/contracts`
    - `GET /api/messages/conversations`
    - `GET /api/notifications/unread-count`
    - `GET /api/payments/wallet`
  - Confirmed dynamic object-route patterns from the bundle:
    - `/api/users/${id}`
    - `/api/projects/${id}`
    - `/api/contracts/${id}`
    - `/api/reviews?reviewee_id=${id}`
    - `/api/messages/conversations/${id}`
    - `POST /api/messages/conversations/${id}/messages`
    - `POST /api/messages/conversations/${id}/read`
  - No concrete WebSocket endpoint has been identified yet.
  - Evidence:
    ```bash
    curl -sS --max-time 10 http://localhost:3000/assets/index-CtZsj9EZ.js
    ```

- [?] WSTG-INFO-07: Map execution paths through application
  - Trace key user workflows: registration -> gig creation -> proposal -> contract -> payment -> review
  - Map the escrow lifecycle: deposit -> milestone funding -> release
  - Identify dispute resolution flow
  - Partial flows mapped: registration/login, dashboard/resource listing, project creation, proposal/contract route discovery, and messaging conversations.
  - Full escrow, milestone, and dispute workflows were not fully exercised.

- [-] WSTG-INFO-08: Fingerprint web application framework
  - Identify framework from headers, error response formats, cookie names
  - Detect session store type from cookie behavior
  - Identify frontend framework from JS bundles
  - Frontend fingerprint:
    - Vite-style asset names (`/assets/index-CtZsj9EZ.js`, `/assets/index-CFEQRVFS.css`)
    - React/React Router patterns in the fetched bundle
    - Token handling in bundle stores `hf_token` in `localStorage`
  - Backend fingerprint:
    - Express disclosed on `OPTIONS` responses (`X-Powered-By: Express`)
    - `connect.sid` cookie indicates server-side session support
    - API served under `/api` on the same origin as the SPA
  - Evidence:
    ```bash
    curl -sS -i --max-time 10 -X OPTIONS http://localhost:3000/api/auth/login
    curl -sS --max-time 10 http://localhost:3000/assets/index-CtZsj9EZ.js
    ```

- [-] WSTG-INFO-09: Fingerprint web application
  - Determine application version from headers, responses, or exposed files
  - Check health or status endpoints for version info
  - No version string was exposed in headers, HTML, asset names, or `/api/health`.

- [-] WSTG-INFO-10: Map application architecture
  - Identify backend services from error messages or debug endpoints
  - Map internal hostnames if disclosed anywhere
  - Document the auth architecture (look for both session cookies and JWT tokens)
  - Architecture mapped so far:
    - Single-page application on `/` backed by a same-origin JSON API under `/api`
    - Hybrid authentication model: JWT bearer tokens plus `connect.sid` session cookies
    - Both auth artifacts independently authorize `/api/auth/me`
    - Public and authenticated API routes are mixed under the same origin
  - Evidence:
    ```bash
    curl -sS -i --max-time 10 http://localhost:3000/api/auth/me
    curl -sS -i --max-time 10 http://localhost:3000/api/auth/me -b /tmp/hf_client.cookies
    curl -sS -i --max-time 10 http://localhost:3000/api/auth/me -H "Authorization: Bearer <token>"
    ```

---

## CONF — Configuration and Deployment Management

- [?] WSTG-CONF-01: Test network/infrastructure configuration
  - Check if database or cache ports are externally accessible
  - Probe for exposed infrastructure services (object storage consoles, mail servers)
  - No infrastructure service interfaces were discoverable from the assessed HTTP surface.
  - Direct port/service enumeration was not part of the exercised web-only testing flow.

- [-] WSTG-CONF-02: Test application platform configuration
  - Observe error response behavior to infer environment settings
  - Check security header configuration (CSP, HSTS, X-Frame-Options)
  - Security headers were largely present.
  - Platform weaknesses are captured separately under `WSTG-CONF-12` and `WSTG-ERRH-*`.

- [?] WSTG-CONF-03: Test file extension handling for sensitive information
  - Upload and request files with various extensions (`.html`, `.svg`, `.js`, `.exe`)
  - Check if uploaded files are served with their original content-type
  - Upload endpoints were not fully exercised during this pass, so extension handling remains inconclusive.

- [-] WSTG-CONF-04: Review old/backup/unreferenced files
  - Check for `.env`, `.env.example`, `.env.backup` at web root
  - Probe for common backup extensions: `.bak`, `.old`, `.swp`, `~`
  - Check for exposed git metadata (`/.git/config`, `/.git/HEAD`)
  - Probed `/.env`, `/.env.example`, `/.env.backup`, `/package.json`, `/package-lock.json`, `/.git/HEAD`, `/.git/config`, `/backup.zip`, and `/app.bak`.
  - All tested paths returned the SPA shell (`Content-Type: text/html; charset=UTF-8`) rather than sensitive file contents.
  - Evidence:
    ```bash
    curl -sS -i --max-time 10 http://localhost:3000/.env
    curl -sS -i --max-time 10 http://localhost:3000/.git/HEAD
    ```
    Response excerpt:
    ```html
    <title>HireFlow - Freelancer Marketplace</title>
    <script type="module" crossorigin src="/assets/index-CtZsj9EZ.js"></script>
    ```

- [-] WSTG-CONF-05: Enumerate admin interfaces
  - Discover admin endpoints by examining frontend JS and probing common paths
  - Test admin endpoint access with different role tokens
  - Check if admin-only functionality is accessible to lower-privilege roles
  - `/api/admin/dashboard`, `/api/admin/disputes`, and `/api/admin/settings` were enumerated and tested across roles.
  - No lower-privilege bypass to admin-only settings was found.

- [-] WSTG-CONF-06: Test HTTP methods
  - Send OPTIONS requests to key endpoints and review allowed methods
  - Test unexpected methods (PUT, DELETE, PATCH) on read-only endpoints
  - Check for method override headers (`X-HTTP-Method-Override`)
  - `OPTIONS /api/auth/login` advertises `GET,HEAD,PUT,PATCH,POST,DELETE`.
  - On `GET /api/health`, direct `POST` and `DELETE` requests returned `404`, and `X-HTTP-Method-Override: DELETE` on a `GET` request did not alter routing.
  - No method-based authorization bypass was confirmed on the exercised routes.

- [-] WSTG-CONF-07: Test HTTP Strict Transport Security
  - Check for `Strict-Transport-Security` header in responses
  - Verify HSTS max-age and includeSubDomains settings
  - `Strict-Transport-Security: max-age=15552000; includeSubDomains` was present on observed responses.

- [x] WSTG-CONF-08: Test cross-domain policy (CORS)
  - Send requests with `Origin: https://evil.example.com` and check reflection
  - Test CORS with credentials (`Access-Control-Allow-Credentials`)
  - Check preflight (OPTIONS) responses for overly permissive headers
  > **Finding: Reflective CORS Allows Credentialed Cross-Origin Reads**
  > **Severity**: High
  > **Endpoint**: `GET /api/auth/me`, `OPTIONS /api/auth/login`
  > **Description**: The API reflects arbitrary `Origin` values and sets `Access-Control-Allow-Credentials: true`. Because the application also accepts session cookies for authenticated API access, a malicious site can issue credentialed cross-origin requests and read the victim's API responses from the browser.
  > **Steps to Reproduce**:
  > 1. Log in to HireFlow and capture a valid `connect.sid` session cookie.
  > 2. Send a cross-origin request with `Origin: https://evil.example.com` to an authenticated endpoint while presenting that cookie.
  > 3. Observe that the response includes both `Access-Control-Allow-Origin: https://evil.example.com` and `Access-Control-Allow-Credentials: true` along with private account data.
  > **Evidence**:
  > ```bash
  > curl -sS -i --max-time 10 -X OPTIONS http://localhost:3000/api/auth/login \
  >   -H 'Origin: https://evil.example.com' \
  >   -H 'Access-Control-Request-Method: POST' \
  >   -H 'Access-Control-Request-Headers: content-type,authorization'
  > 
  > curl -sS -i --max-time 10 http://localhost:3000/api/auth/me \
  >   -H 'Origin: https://evil.example.com' \
  >   -b /tmp/hf_client.cookies
  > ```
  > Response excerpt:
  > ```text
  > Access-Control-Allow-Origin: https://evil.example.com
  > Access-Control-Allow-Credentials: true
  > ```
  > ```json
  > {"user":{"id":"5664b7f1-dc57-4aac-a3f1-2ec59d7915f9","email":"testclient@hireflow.com","role":"client",...}}
  > ```
  > **Impact**: Any website can read authenticated API responses from a victim's browser if the victim has an active HireFlow session cookie.
  > **PoC**: `reports/pocs/WSTG-CONF-08_cors-credentialed-exfil.py`

- [?] WSTG-CONF-09: Test file permissions
  - Check if uploaded files are served from a path within the application origin
  - Verify uploaded files cannot overwrite application files
  - Upload/file-serving behavior was not fully exercised, so this remains inconclusive.

- [?] WSTG-CONF-11: Test cloud/object storage
  - Check for publicly accessible storage buckets
  - Test if upload paths allow unauthenticated access
  - Check for directory listing on file-serving paths
  - No cloud/object-storage endpoints or bucket URLs were discovered from the assessed surface.

- [x] WSTG-CONF-12: Test Content Security Policy
  - Check for CSP header presence and directives
  - Verify if inline scripts/styles are allowed
  - Check for `unsafe-eval`, `unsafe-inline`, or overly broad source lists
  > **Finding: No Content Security Policy**
  > **Severity**: Low
  > **Endpoint**: `GET /`
  > **Description**: The SPA entrypoint does not return a `Content-Security-Policy` header. Because the application also has a confirmed stored XSS issue in review rendering, the absence of CSP materially increases exploit reliability and post-exploitation impact.
  > **Steps to Reproduce**:
  > 1. Request `GET /`.
  > 2. Inspect the response headers.
  > 3. Observe that no `Content-Security-Policy` header is present.
  > **Evidence**:
  > ```bash
  > curl -sS -i --max-time 10 http://localhost:3000/
  > ```
  > Response excerpt:
  > ```text
  > X-Frame-Options: SAMEORIGIN
  > X-Content-Type-Options: nosniff
  > ```
  > No `Content-Security-Policy` header is returned.
  > **Impact**: Browser-side injection issues such as the confirmed stored XSS are easier to exploit and harder to contain.
  > **PoC**: `reports/pocs/WSTG-CONF-12_missing-csp.py`

- [-] WSTG-CONF-14: Test other HTTP security header misconfigurations
  - Check `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`
  - Check `Referrer-Policy`, `Permissions-Policy` headers
  - `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` were present.
  - No standalone exploitable header misconfiguration beyond CORS/CSP was confirmed.

---

## IDNT — Identity Management

- [-] WSTG-IDNT-01: Test role definitions
  - Map all user roles by logging in with different accounts
  - Test each endpoint with each role to verify RBAC enforcement
  - Check for role hierarchy bypass (e.g. moderator accessing admin endpoints)
  - Roles confirmed from login responses:
    - `client`: `testclient@hireflow.com`
    - `freelancer`: `testfreelancer@hireflow.com`
    - `moderator`: `carol.mod@hireflow.com`
    - `admin`: `bob.admin@hireflow.com`
    - `superadmin`: `alice.admin@hireflow.com`
  - Admin endpoint matrix observed so far:
    - unauthenticated: `401` on `/api/admin/dashboard`, `/api/admin/disputes`, `/api/admin/settings`
    - client/freelancer: `403` on the same endpoints
    - moderator: `200` on `/api/admin/dashboard` and `/api/admin/disputes`, `403` on `/api/admin/settings`
    - admin/superadmin: `200` on all three
  - Object-level authorization issues are tracked separately under `WSTG-ATHZ-04` / `WSTG-APIT-02`.

- [-] WSTG-IDNT-02: Test user registration process
  - Register with minimal data and verify what's required vs optional
  - Register with duplicate email/username and observe behavior
  - Check if role can be set during registration (mass assignment)
  - Minimal registration succeeded with `email`, `password`, `username`, and `display_name`.
  - Registration does not allow arbitrary privilege assignment: `role=admin` and `role=superadmin` were rejected with validation errors.
  - Evidence:
    ```bash
    curl -sS -i --max-time 10 -X POST http://localhost:3000/api/auth/register \
      -H 'Content-Type: application/json' \
      --data '{"email":"wstg_admin_20260331_1224@proton.test","password":"password123","username":"wstg_admin_1224","display_name":"WSTG Admin","role":"admin"}'
    ```
    Response excerpt:
    ```json
    {"errors":[{"msg":"Role must be client or freelancer","path":"role"}]}
    ```

- [x] WSTG-IDNT-03: Test account provisioning process
  - Check if email verification is required before account activation
  - Test if unverified accounts can access protected functionality
  > **Finding: Email Verification Not Enforced Before Account Use**
  > **Severity**: Medium
  > **Endpoint**: `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`, `GET /api/payments/wallet`
  > **Description**: Newly registered users are provisioned as active accounts immediately. The registration response returns a valid bearer token while `email_verified` is `false`, and the same unverified account can both log in normally and access protected API endpoints.
  > **Steps to Reproduce**:
  > 1. Register a new account with a unique email address.
  > 2. Observe that the JSON response includes both `token` and `"email_verified": false`.
  > 3. Use the returned token, or log in again with the same credentials.
  > 4. Request `/api/auth/me` or `/api/payments/wallet`.
  > **Evidence**:
  > ```bash
  > curl -sS -i --max-time 10 -X POST http://localhost:3000/api/auth/register \
  >   -H 'Content-Type: application/json' \
  >   --data '{"email":"wstg_unverified_20260331_1227@proton.test","password":"password123","username":"wstg_unverified_1227","display_name":"WSTG Unverified"}'
  > 
  > curl -sS -i --max-time 10 -X POST http://localhost:3000/api/auth/login \
  >   -H 'Content-Type: application/json' \
  >   --data '{"email":"wstg_unverified_20260331_1227@proton.test","password":"password123"}'
  > 
  > curl -sS -i --max-time 10 http://localhost:3000/api/payments/wallet \
  >   -H 'Authorization: Bearer <token-from-register-or-login>'
  > ```
  > Response excerpt:
  > ```json
  > {"user":{"email":"wstg_unverified_20260331_1227@proton.test","role":"client","is_active":true,"email_verified":false,...}}
  > ```
  > ```json
  > {"id":"7724c2cf-8cc4-4f59-9b0e-24ef685984ba","user_id":"29bdff15-df24-4ddf-ad6e-f7d01d1936c0","balance":"0",...}
  > ```
  > **Impact**: Attackers can create immediately usable accounts without proving control of the registered email address, enabling spam, abuse, and workflow access that should be gated by verification.
  > **PoC**: `reports/pocs/WSTG-IDNT-03_unverified-account-access.py`

- [x] WSTG-IDNT-04: Test account enumeration
  - Compare registration responses for existing vs new emails
  - Compare login error messages for valid vs invalid usernames
  - Compare forgot-password responses for existing vs non-existing emails
  - Test user search endpoints with known and unknown usernames
  > **Finding: Registration Endpoint Enumerates Existing Accounts**
  > **Severity**: Low
  > **Endpoint**: `POST /api/auth/register`
  > **Description**: Registration responses differ clearly for existing and non-existing email addresses. Existing addresses return `409 Conflict` and the explicit message `"Email already registered"`, which allows an attacker to verify whether an account exists.
  > **Steps to Reproduce**:
  > 1. Submit a registration request using a known existing email such as `testclient@hireflow.com`.
  > 2. Submit the same request pattern with a fresh email address.
  > 3. Compare the status codes and response bodies.
  > **Evidence**:
  > ```bash
  > curl -sS -i --max-time 10 -X POST http://localhost:3000/api/auth/register \
  >   -H 'Content-Type: application/json' \
  >   --data '{"email":"testclient@hireflow.com","password":"password123","username":"wstg_enum_existing","display_name":"WSTG Enum"}'
  > 
  > curl -sS -i --max-time 10 -X POST http://localhost:3000/api/auth/register \
  >   -H 'Content-Type: application/json' \
  >   --data '{"email":"wstg_enum_fresh@proton.test","password":"password123","username":"wstg_enum_fresh","display_name":"WSTG Enum"}'
  > ```
  > Response excerpt:
  > ```json
  > {"error":"Email already registered"}
  > ```
  > **Impact**: Attackers can enumerate valid email addresses for credential-stuffing, phishing, or password-reset abuse.
  > **PoC**: `reports/pocs/WSTG-IDNT-04_registration-enumeration.py`

- [-] WSTG-IDNT-05: Test username/email policy
  - Register with special characters in username/email
  - Test for case sensitivity issues (User@Email.com vs user@email.com)
  - Test maximum length enforcement
  - Email uniqueness is case-insensitive: `TESTFREELANCER@HIREFLOW.COM` returned the same duplicate-email behavior as the lowercase address.
  - A dotted username (`wstg.user-...`) was rejected with `400 Bad Request`.
  - No policy weakness was confirmed in this pass.

---

## ATHN — Authentication

- [-] WSTG-ATHN-01: Test credentials over encrypted channel
  - Check if login endpoint is accessible over HTTP (not just HTTPS)
  - Verify auth tokens are not transmitted in URL parameters
  - The assessed lab target is exposed over `http://localhost:3000`.
  - Tokens were observed in JSON bodies and authorization headers, not in URL query parameters.

- [-] WSTG-ATHN-02: Test for default credentials
  - Try common default passwords against discovered accounts
  - Check if admin accounts use weak or predictable passwords
  - The documented lab accounts authenticated with the supplied test credentials.
  - No separate default-credential issue beyond the intentionally provided assessment accounts was confirmed.

- [x] WSTG-ATHN-03: Test lockout mechanism
  - Send 25+ failed login attempts for the same account
  - Check if the account is locked or if rate limiting kicks in
  - Test if lockout can be bypassed by changing IP headers (X-Forwarded-For)
  > **Finding: No Account Lockout After Repeated Failed Logins**
  > **Severity**: Medium
  > **Endpoint**: `POST /api/auth/login`
  > **Description**: A disposable account remained fully usable after 25 consecutive failed login attempts. No account lockout, CAPTCHA, or per-account throttle was triggered before a successful login with the correct password.
  > **Steps to Reproduce**:
  > 1. Register a new disposable account.
  > 2. Send 25 login attempts with the correct email and a wrong password.
  > 3. Immediately retry with the correct password.
  > 4. Observe that login succeeds normally.
  > **Evidence**:
  > ```bash
  > # Failed attempts 1..25
  > curl -sS -o /dev/null -w '%{http_code}\n' --max-time 10 -X POST http://localhost:3000/api/auth/login \
  >   -H 'Content-Type: application/json' \
  >   --data '{"email":"wstg_lockout_1774960509_fe4242@proton.test","password":"wrongpassword"}'
  > 
  > # Correct password still works immediately afterward
  > curl -sS -i --max-time 10 -X POST http://localhost:3000/api/auth/login \
  >   -H 'Content-Type: application/json' \
  >   --data '{"email":"wstg_lockout_1774960509_fe4242@proton.test","password":"password123"}'
  > ```
  > Response excerpt:
  > ```text
  > failed_attempt_25=401
  > HTTP/1.1 200 OK
  > ```
  > **Impact**: The absence of lockout or per-account throttling materially lowers the cost of password guessing and credential-stuffing attacks.
  > **PoC**: `reports/pocs/WSTG-ATHN-03_no-lockout.py`

- [-] WSTG-ATHN-04: Test authentication bypass
  - Access protected endpoints without any auth token
  - Send requests with an empty `Authorization` header
  - Send requests with `Authorization: Bearer null` or `Bearer undefined`
  - Send malformed tokens and observe whether requests are rejected or fall through
  - Tested `GET /api/auth/me` with no header, an empty `Authorization` header, `Bearer null`, `Bearer undefined`, and a malformed bearer token.
  - All tested variants returned `401 Unauthorized`.
  - Evidence:
    ```bash
    curl -sS -i --max-time 10 http://localhost:3000/api/auth/me
    curl -sS -i --max-time 10 http://localhost:3000/api/auth/me -H 'Authorization: Bearer null'
    curl -sS -i --max-time 10 http://localhost:3000/api/auth/me -H 'Authorization: Bearer undefined'
    curl -sS -i --max-time 10 http://localhost:3000/api/auth/me -H 'Authorization: Bearer not-a-jwt'
    ```

- [-] WSTG-ATHN-05: Test remember-password / persistent login
  - Check if JWT tokens have reasonable expiry (not 30d+)
  - Verify session cookies have appropriate MaxAge
  - Check if tokens survive password changes
  - JWT lifetime observed was 7 days, not 30+ days.
  - Session cookies were non-persistent.
  - Token survival after logout is captured separately under `WSTG-SESS-06`.

- [x] WSTG-ATHN-07: Test password policy
  - Register with password `a` (too short)
  - Register with password `aaaaaaaa` (meets length, no complexity)
  - Register with password `password` (dictionary word)
  - Check if password is validated on change as well as registration
  > **Finding: Weak Passwords Are Accepted at Registration**
  > **Severity**: Medium
  > **Endpoint**: `POST /api/auth/register`
  > **Description**: The application rejects very short passwords such as `a`, but accepts trivial low-entropy choices including `aaaaaaaa` and the dictionary password `password`. This indicates a length-only password policy without basic banned-password controls.
  > **Steps to Reproduce**:
  > 1. Register a new account with password `a` and note the validation failure.
  > 2. Register new accounts with passwords `aaaaaaaa` and `password`.
  > 3. Observe that both weak passwords are accepted and accounts are created.
  > **Evidence**:
  > ```bash
  > curl -sS -i --max-time 10 -X POST http://localhost:3000/api/auth/register \
  >   -H 'Content-Type: application/json' \
  >   --data '{"email":"wstg_pw_short@proton.test","password":"a","username":"wstg_pw_short","display_name":"WSTG Password"}'
  > 
  > curl -sS -i --max-time 10 -X POST http://localhost:3000/api/auth/register \
  >   -H 'Content-Type: application/json' \
  >   --data '{"email":"wstg_pw_repeat@proton.test","password":"aaaaaaaa","username":"wstg_pw_repeat","display_name":"WSTG Password"}'
  > 
  > curl -sS -i --max-time 10 -X POST http://localhost:3000/api/auth/register \
  >   -H 'Content-Type: application/json' \
  >   --data '{"email":"wstg_pw_dict@proton.test","password":"password","username":"wstg_pw_dict","display_name":"WSTG Password"}'
  > ```
  > Response excerpt:
  > ```text
  > HTTP/1.1 400 Bad Request
  > HTTP/1.1 201 Created
  > HTTP/1.1 201 Created
  > ```
  > **Impact**: Users can choose passwords that are highly vulnerable to guessing and credential-stuffing attacks.
  > **PoC**: `reports/pocs/WSTG-ATHN-07_weak-password-policy.py`

- [-] WSTG-ATHN-09: Test password reset functionality
  - Request a reset and analyze the token format/entropy
  - Test if reset tokens are time-limited
  - Test if reset tokens are single-use (use same token twice)
  - Check if the old password is still valid after a reset
  - No password-reset flow or reset endpoint was discovered in the assessed surface.

- [-] WSTG-ATHN-10: Test alternative auth channels
  - Check if the app supports both session-based and token-based auth
  - Compare security controls between auth mechanisms
  - Test if webhook/integration endpoints have proper authentication
  - Both session-cookie and bearer-token auth were confirmed.
  - Security-control differences are already captured under `WSTG-CONF-08`, `WSTG-SESS-05`, and `WSTG-SESS-06`.
  - No additional integration/webhook auth channel was discovered.

- [-] WSTG-ATHN-11: Test multi-factor authentication
  - Check if MFA is available for any accounts
  - If present, test bypass techniques
  - No MFA prompt, route, or bundle reference was discovered.

---

## ATHZ — Authorization

- [-] WSTG-ATHZ-01: Test directory traversal / file include
  - Test file download/serving endpoints with `../` sequences
  - Test avatar and deliverable paths for path traversal
  - Test any URL-fetching features for `file://` protocol support
  - No dedicated file-download or server-side URL-fetching feature was confirmed from the assessed surface.
  - No traversal/file-include issue was demonstrated in this pass.

- [x] WSTG-ATHZ-02: Test authorization schema bypass
  - Access admin endpoints with non-admin tokens
  - Access moderator endpoints with client/freelancer tokens
  - Check if any endpoints are accessible without any authentication
  > **Finding: Owner-Scoped Project Endpoint Is Accessible Without Authorization**
  > **Severity**: High
  > **Endpoint / Evidence / Impact / PoC**: See the confirmed finding under `WSTG-ATHZ-04` and PoC `reports/pocs/WSTG-ATHZ-04_owner-me-project-leak.py`.

- [-] WSTG-ATHZ-03: Test privilege escalation
  - Test if a user can modify their role via profile update
  - Test if one role can access another role's exclusive endpoints
  - Test user management endpoints for self-elevation
  - Self role escalation via `PUT /api/users/{id}` was tested and the `role` field remained `client`.
  - Cross-user profile updates were rejected with `403`.
  - Admin-only settings remained inaccessible to non-admin roles.

- [x] WSTG-ATHZ-04: Test insecure direct object references (IDOR)
  - Access other users' settings, profiles, and account details
  - Access other users' contracts and financial data
  - Access other users' messages and conversations
  - Access other users' proposals, payment history, and notifications
  - Test UUID enumeration vs sequential ID guessing
  > **Finding: `owner=me` Project Listing Leaks Another User's Projects**
  > **Severity**: High
  > **Endpoint**: `GET /api/projects?owner=me&status=active&limit=2`
  > **Description**: The owner-scoped projects endpoint does not bind `owner=me` to the authenticated principal. It returns the same active projects belonging to `testclient@hireflow.com` to unauthenticated requests and to an unrelated newly registered user.
  > **Steps to Reproduce**:
  > 1. Authenticate as `testclient@hireflow.com` and note the client ID `5664b7f1-dc57-4aac-a3f1-2ec59d7915f9`.
  > 2. Register or log in as a different account, or send no authentication at all.
  > 3. Request `GET /api/projects?owner=me&status=active&limit=2`.
  > 4. Observe that the response contains projects with `client_id` set to the victim client's UUID instead of the caller's identity.
  > **Evidence**:
  > ```bash
  > curl -sS --max-time 10 'http://localhost:3000/api/projects?owner=me&status=active&limit=2' | jq '{count:(.data|length), first:(.data[0] | {id, client_id, title, status})}'
  > 
  > curl -sS --max-time 10 'http://localhost:3000/api/projects?owner=me&status=active&limit=2' \
  >   -H 'Authorization: Bearer <token-for-wstg_unverified_20260331_1227@proton.test>' \
  >   | jq '{count:(.data|length), first:(.data[0] | {id, client_id, title, status})}'
  > ```
  > Response excerpt:
  > ```json
  > {
  >   "count": 2,
  >   "first": {
  >     "id": "4141ce82-a32a-498d-b5cc-aac7f8729edd",
  >     "client_id": "5664b7f1-dc57-4aac-a3f1-2ec59d7915f9",
  >     "title": "Mass Assignment Test Project Creation",
  >     "status": "open"
  >   }
  > }
  > ```
  > **Impact**: Unauthenticated and unrelated users can retrieve another user's owner-scoped project data, undermining dashboard privacy and enabling enumeration of project metadata tied to specific user IDs.
  > **PoC**: `reports/pocs/WSTG-ATHZ-04_owner-me-project-leak.py`

- [-] WSTG-ATHZ-05: Test OAuth weaknesses
  - Check if any OAuth/social login flows exist
  - If present, test for redirect_uri manipulation, token leakage
  - No OAuth or social-login flow was discovered in the assessed surface.

---

## SESS — Session Management

- [-] WSTG-SESS-01: Test session management schema
  - Analyze session cookie attributes (name, domain, path)
  - Check session ID entropy and randomness
  - Determine if sessions are stored server-side or client-side
  - Hybrid auth model mapped: `connect.sid` server-side session cookie plus HS256 JWT bearer tokens.
  - No additional standalone schema flaw beyond the documented CSRF/CORS/logout issues was confirmed.

- [?] WSTG-SESS-02: Test cookie attributes
  - Check `HttpOnly` flag on session cookie
  - Check `Secure` flag on session cookie
  - Check `SameSite` attribute on session cookie
  - Check cookie `Path` and `Domain` scope
  - `connect.sid` is issued with `HttpOnly` and `Path=/`.
  - No `SameSite`, `Secure`, `Expires`, or `Max-Age` attributes were observed on the session cookie captured from `POST /api/auth/login`.
  - These attributes materially contribute to the confirmed CSRF/cross-origin session abuse risk, but were not raised as a separate standalone finding in this report.

- [-] WSTG-SESS-03: Test session fixation
  - Set a known session cookie before login and check if it persists after auth
  - Test if pre-auth session ID is reused post-auth
  - Supplied a pre-auth cookie value (`connect.sid=s%3Aattackercontrolled.fixationvalue`) before login.
  - The server issued a fresh `Set-Cookie: connect.sid=...` on successful login, replacing the attacker-chosen value.
  - Evidence:
    ```bash
    curl -sS -i --max-time 10 -X POST http://localhost:3000/api/auth/login \
      -H 'Cookie: connect.sid=s%3Aattackercontrolled.fixationvalue' \
      -H 'Content-Type: application/json' \
      --data '{"email":"testclient@hireflow.com","password":"password123"}'
    ```

- [-] WSTG-SESS-04: Test exposed session variables
  - Check if session data leaks in responses, headers, or URL params
  - Decode JWT payload and check for sensitive data (email, balance, etc.)
  - Verify tokens are not included in error responses
  - Decoded JWT payload includes `id`, `email`, `role`, and `walletBalance`.
  - Example decoded payload:
    ```json
    {
      "email": "testclient@hireflow.com",
      "id": "5664b7f1-dc57-4aac-a3f1-2ec59d7915f9",
      "role": "client",
      "walletBalance": "10010001052774"
    }
    ```
  - No additional standalone issue was raised beyond the broader browser-storage and token-lifecycle findings already documented.

- [x] WSTG-SESS-05: Test CSRF protection
  - Check for CSRF tokens in state-changing requests
  - Test state-changing endpoints (POST/PUT/DELETE) without CSRF token
  - Verify session-based auth endpoints are protected against CSRF
  > **Finding: Cookie-Authenticated Profile Update Is CSRFable**
  > **Severity**: High
  > **Endpoint**: `PUT /api/users/:id`
  > **Description**: A session cookie alone is sufficient to perform state-changing profile updates, and no CSRF token or origin validation blocks cross-origin requests. When the request includes `Origin: https://evil.example.com`, the server still processes the update and reflects the origin with `Access-Control-Allow-Credentials: true`.
  > **Steps to Reproduce**:
  > 1. Register and log in to a disposable account, capturing the `connect.sid` cookie.
  > 2. Send `PUT /api/users/<your-id>` using only the cookie for authentication, without a bearer token or CSRF token.
  > 3. Include `Origin: https://evil.example.com` and change a profile field such as `display_name`.
  > 4. Request `GET /api/auth/me` with the same cookie and confirm the change persisted.
  > **Evidence**:
  > ```bash
  > curl -sS --max-time 10 -c cookies.txt -X POST http://localhost:3000/api/auth/login \
  >   -H 'Content-Type: application/json' \
  >   --data '{"email":"wstg_csrf_1774960920_faccbf@proton.test","password":"password123"}'
  > 
  > curl -sS -i --max-time 10 -X PUT http://localhost:3000/api/users/fc1a2d68-fc96-44b2-ae00-ac7d239f775a \
  >   -H 'Origin: https://evil.example.com' \
  >   -H 'Content-Type: application/json' \
  >   -b cookies.txt \
  >   --data '{"display_name":"CSRF_UPDATED",...}'
  > 
  > curl -sS --max-time 10 http://localhost:3000/api/auth/me -b cookies.txt
  > ```
  > Response excerpt:
  > ```text
  > HTTP/1.1 200 OK
  > Access-Control-Allow-Origin: https://evil.example.com
  > Access-Control-Allow-Credentials: true
  > ```
  > ```json
  > {"user":{"id":"fc1a2d68-fc96-44b2-ae00-ac7d239f775a","display_name":"CSRF_UPDATED",...}}
  > ```
  > **Impact**: Any malicious site can silently perform authenticated state changes for victims who have an active cookie-backed session, including account/profile modification and potentially other state-changing actions that rely on the same session mechanism.
  > **PoC**: `reports/pocs/WSTG-SESS-05_cookie-csrf-profile-update.py`

- [x] WSTG-SESS-06: Test logout functionality
  - Log out and verify the session is invalidated server-side
  - Test if the JWT token is still accepted after logout
  - Check if the session cookie is cleared on logout
  > **Finding: Logout Does Not Revoke Bearer Tokens**
  > **Severity**: Medium
  > **Endpoint**: `POST /api/auth/logout`, `GET /api/auth/me`
  > **Description**: Logging out a cookie-backed session invalidates the `connect.sid` session as expected, but the JWT issued at login remains valid after logout and continues to authorize `GET /api/auth/me`. This means a stolen or cached bearer token survives logout.
  > **Steps to Reproduce**:
  > 1. Log in and capture both the bearer token and the `connect.sid` cookie.
  > 2. Call `POST /api/auth/logout` with the session cookie.
  > 3. Retry `GET /api/auth/me` once with the same cookie and once with the original bearer token.
  > 4. Observe that the cookie is rejected but the bearer token still returns `200 OK`.
  > **Evidence**:
  > ```bash
  > curl -sS --max-time 10 -c cookies.txt -X POST http://localhost:3000/api/auth/login \
  >   -H 'Content-Type: application/json' \
  >   --data '{"email":"testclient@hireflow.com","password":"password123"}'
  > 
  > curl -sS -i --max-time 10 -X POST http://localhost:3000/api/auth/logout -b cookies.txt
  > curl -sS -i --max-time 10 http://localhost:3000/api/auth/me -b cookies.txt
  > curl -sS -i --max-time 10 http://localhost:3000/api/auth/me -H 'Authorization: Bearer <login-token>'
  > ```
  > Response excerpt:
  > ```text
  > HTTP/1.1 401 Unauthorized
  > HTTP/1.1 200 OK
  > ```
  > **Impact**: Logout does not terminate all active auth artifacts. If a JWT is stolen from browser storage, logs, or another channel, the user cannot invalidate it by logging out.
  > **PoC**: `reports/pocs/WSTG-SESS-06_logout-does-not-revoke-jwt.py`

- [?] WSTG-SESS-07: Test session timeout
  - Check if session cookie has a `Max-Age` or `Expires`
  - Decode JWT and verify `exp` claim duration
  - Test if idle sessions are terminated
  - Session cookie is non-persistent in observed responses (`connect.sid` without `Max-Age` or `Expires`).
  - Decoded JWT lifetime is `604800` seconds (7 days) between `iat` and `exp`.
  - Idle timeout behavior was not fully exercised with live wait-based testing, so this remains inconclusive.

- [?] WSTG-SESS-09: Test session hijacking
  - Check if session cookie lacks `HttpOnly` (accessible to JS)
  - Check if session cookie lacks `Secure` (sent over HTTP)
  - Verify the session is tied to the user and not transferable
  - `HttpOnly` was present and `Secure` was absent on the HTTP-served lab instance.
  - No dedicated network-path/session-theft simulation was performed beyond the confirmed CSRF/CORS session abuse findings.

- [-] WSTG-SESS-10: Test JSON Web Tokens
  - Decode JWT payload and review all claims
  - Test JWT with `alg: none` to bypass signature verification
  - Test JWT with `alg: HS256` using common/default secrets
  - Check for `aud`, `iss` claim validation
  - Test expired JWT handling
  - Test malformed JWT handling and error responses
  - JWT claims were decoded and reviewed.
  - `alg: none` tokens were rejected with `401`.
  - A small common-secret wordlist did not match the HS256 signing key.
  - Malformed tokens were rejected as described under `WSTG-ATHN-04`.

- [-] WSTG-SESS-11: Test concurrent sessions
  - Log in from two sessions and verify both remain active
  - Check if there's a limit on concurrent sessions per user
  - Two concurrent bearer tokens for the same account remained valid simultaneously.
  - No standalone security issue was confirmed from concurrent-session behavior alone.

---

## INPV — Input Validation

- [-] WSTG-INPV-01: Test reflected XSS
  - Test search parameters on user and gig listing endpoints
  - Test error messages that reflect user input
  - Test URL parameters reflected in responses
  - XSS-style payloads in `search` did not produce reflected HTML/DOM execution in this pass.

- [x] WSTG-INPV-02: Test stored XSS
  - Submit gig descriptions/titles with HTML/script payloads
  - Submit review comments with script payloads
  - Submit profile bio with HTML/script content
  - Submit messages with HTML/script payloads
  - Test project descriptions for stored XSS
  > **Finding: Stored XSS in Public Review Comments**
  > **Severity**: High
  > **Endpoint**: `GET /api/reviews?reviewee_id=<seller-id>`, `GET /api/gigs/<gig-id>`
  > **Description**: Public review data contains HTML with an event-handler payload (`<img src=x onerror=alert(1)>...`). The live frontend bundle renders review comments using `dangerouslySetInnerHTML:{__html:b.comment}`, which means this review content is inserted into the DOM as HTML on gig detail pages for the reviewed seller.
  > **Steps to Reproduce**:
  > 1. Request the public gig for seller `8a5b0a66-b192-4364-94e5-188a7657c1fa` (for example gig `698c5387912d2f005a47a747`).
  > 2. Request `GET /api/reviews?reviewee_id=8a5b0a66-b192-4364-94e5-188a7657c1fa`.
  > 3. Observe the stored review comment `<img src=x onerror=alert(1)>Great work on this project`.
  > 4. Fetch the frontend bundle and observe that review comments are rendered with `dangerouslySetInnerHTML`.
  > **Evidence**:
  > ```bash
  > curl -sS --max-time 10 http://localhost:3000/api/gigs/698c5387912d2f005a47a747
  > curl -sS --max-time 10 'http://localhost:3000/api/reviews?reviewee_id=8a5b0a66-b192-4364-94e5-188a7657c1fa'
  > curl -sS --max-time 10 http://localhost:3000/assets/index-CtZsj9EZ.js
  > ```
  > Response excerpt:
  > ```json
  > {"id":"49fe77e5-f11a-45c4-baae-c5da8d83188e","reviewee_id":"8a5b0a66-b192-4364-94e5-188a7657c1fa","comment":"<img src=x onerror=alert(1)>Great work on this project",...}
  > ```
  > Bundle excerpt:
  > ```text
  > review-text",dangerouslySetInnerHTML:{__html:b.comment}
  > ```
  > **Impact**: Any user who views a gig detail page for the affected seller can have arbitrary JavaScript executed in their browser, enabling session theft, CSRF chaining, or account takeover.
  > **PoC**: `reports/pocs/WSTG-INPV-02_review-stored-xss.py`

- [-] WSTG-INPV-03: Test HTTP verb tampering
  - Send POST to GET-only endpoints and vice versa
  - Test PATCH on endpoints that only expect PUT
  - Check if verb changes bypass authorization checks
  - `POST /api/health` and `DELETE /api/health` returned `404`.
  - `X-HTTP-Method-Override: DELETE` on `GET /api/health` did not alter routing or bypass controls.

- [?] WSTG-INPV-04: Test HTTP parameter pollution
  - Send duplicate parameters (`?search=a&search=b`) and observe behavior
  - Test parameter pollution on auth endpoints
  - Test array parameters vs scalar parameters
  - Duplicate-parameter checks on `/api/gigs` hit rate limiting and remain inconclusive.

- [-] WSTG-INPV-05: Test SQL injection
  - Test user search endpoints with `' OR 1=1--`
  - Test admin search endpoints with SQL metacharacters
  - Test ORDER BY injection in listing endpoints
  - Test UNION-based injection for data exfiltration
  - Test time-based blind injection on filterable endpoints
  - Generic SQLi payloads in `/api/gigs?search=...` did not produce SQL errors, timing behavior, or differential responses in this pass.

- [-] WSTG-INPV-06: Test NoSQL injection
  - Test gig search/filter parameters with MongoDB operator injection
  - Test activity/report endpoints with JSON-breaking payloads
  - Test query operator injection (`$gt`, `$ne`, `$regex`) in filters
  - Simple operator-style payloads did not produce a demonstrable NoSQL injection effect in this pass.

- [-] WSTG-INPV-11: Test code injection
  - Test any server-side JavaScript evaluation vectors (e.g. MongoDB `$where`)
  - Test JSON import features for prototype pollution
  - Test webhook payloads for injection in data processing
  - No server-side evaluation/import/webhook-processing surface was confirmed from the assessed routes.

- [-] WSTG-INPV-12: Test command injection
  - Test file upload filenames for command injection
  - Test any image/document processing features with crafted inputs
  - Test PDF generation features for injection in rendered content
  - No command-execution or server-side file-processing surface was confirmed from the assessed routes.

- [-] WSTG-INPV-15: Test HTTP splitting/smuggling
  - Test for CRLF injection in response headers via user input
  - Test header injection through controllable values
  - No CRLF/header-injection vector was demonstrated in this pass.

- [-] WSTG-INPV-17: Test host header injection
  - Send requests with modified `Host` header
  - Check if Host header is used in password reset link generation
  - Test `X-Forwarded-Host` injection
  - Modified `Host` and `X-Forwarded-Host` headers on `/api/health` did not affect the response.
  - No reset-link generation flow was exposed.

- [-] WSTG-INPV-18: Test server-side template injection
  - Test PDF generation with template syntax payloads (`{{7*7}}`, `${7*7}`)
  - Test notification and email content for SSTI
  - No PDF/template-rendering surface was confirmed from the assessed routes.

- [-] WSTG-INPV-19: Test SSRF
  - Test any URL-fetching features (link previews, profile import, webhooks)
    with internal addresses: `http://localhost`, `http://127.0.0.1`,
    `http://169.254.169.254/`, internal Docker hostnames
  - Test `file://` and `gopher://` protocol handlers
  - Test SSRF bypass: decimal IP, IPv6, DNS rebinding, URL encoding
  - No confirmed server-side URL-fetching feature was discovered from the assessed surface.
  - Suspicious URL-like profile fields existed in data, but no server-side fetch behavior was demonstrated.

- [-] WSTG-INPV-20: Test mass assignment
  - Register a new user and include extra fields like `role: "admin"`
  - Update user profile and include `role`, `is_verified`, `wallet_balance`
  - Test resource creation endpoints with extra privileged fields
  - Registration rejected invalid privileged roles.
  - `PUT /api/users/{id}` ignored `role`, `email_verified`, `is_active`, and `walletBalance` overrides.
  - `POST /api/projects` ignored attacker-supplied `client_id`, `status`, and `proposal_count`, binding them to server-side values.

---

## ERRH — Error Handling

- [x] WSTG-ERRH-01: Test improper error handling
  - Send malformed JSON bodies and analyze error responses
  - Send invalid IDs/UUIDs in path parameters
  - Send requests to non-existent endpoints
  - Trigger database errors and check what's exposed
  - Check if different error types leak different levels of detail
  > **Finding: Malformed JSON Errors Expose Parser Details**
  > **Severity**: Medium
  > **Endpoint**: `POST /api/auth/login`
  > **Description**: Sending malformed JSON returns a verbose parser error and stack trace in the response body, exposing dependency paths and runtime internals.
  > **Evidence**:
  > ```bash
  > curl -sS -i --max-time 10 -X POST http://localhost:3000/api/auth/login \
  >   -H 'Content-Type: application/json' \
  >   --data '{"email":"a"'
  > ```
  > Response excerpt:
  > ```json
  > {"error":"Expected ',' or '}' after property value in JSON at position 12","stack":"SyntaxError: ... /app/node_modules/body-parser/lib/types/json.js ..."}
  > ```
  > **Impact**: Detailed parser/runtime disclosures help attackers fingerprint the stack and tune follow-on payloads.
  > **PoC**: `reports/pocs/WSTG-ERRH-01_stack-trace-on-malformed-json.py`

- [x] WSTG-ERRH-02: Test stack traces
  - Trigger 500 errors and check for stack traces in responses
  - Check if stack traces include file paths, line numbers, dependency versions
  - Test error responses across multiple endpoints for consistency
  > **Finding: Stack Trace Disclosure in Error Responses**
  > **Severity**: Medium
  > **Endpoint / Evidence / Impact / PoC**: See the confirmed finding under `WSTG-ERRH-01` and PoC `reports/pocs/WSTG-ERRH-01_stack-trace-on-malformed-json.py`.

---

## CRYP — Cryptography

- [-] WSTG-CRYP-01: Test weak transport layer security
  - Check if the application is accessible over plain HTTP
  - Verify TLS configuration if HTTPS is enabled
  - Check for mixed content issues
  - The assessed lab target is exposed over plain HTTP on localhost.
  - No HTTPS listener was part of the tested surface, so TLS configuration was not applicable here.

- [-] WSTG-CRYP-03: Test sensitive data sent via unencrypted channels
  - Check if auth tokens are ever sent in URL query parameters
  - Decode JWT payloads and check for sensitive PII or financial data
  - Check if any API responses include secrets or credentials
  - Tokens were not observed in URLs.
  - JWT payloads include email and wallet balance, which is noted under `WSTG-SESS-04`, but no cryptographic secret exposure was confirmed.

- [-] WSTG-CRYP-04: Test weak cryptographic primitives
  - Time login/registration requests to estimate hashing cost factor
  - Analyze password reset token format for predictability
  - Test JWT with known weak secrets (common wordlists)
  - Check if any responses contain weakly hashed values
  - `alg: none` tokens were rejected.
  - A small common-secret wordlist did not match the JWT signing key.
  - No reset-token flow or leaked hashes were exposed.

---

## BUSL — Business Logic

- [?] WSTG-BUSL-01: Test business logic data validation
  - Create a gig with negative price or zero price
  - Submit a proposal with bid amount exceeding project budget
  - Deposit negative or zero amount into wallet
  - Test boundary values on financial fields

- [?] WSTG-BUSL-02: Test ability to forge requests
  - Attempt to override escrow release amounts via request body
  - Submit a proposal on your own project
  - Approve your own milestone
  - Review yourself

- [?] WSTG-BUSL-03: Test integrity checks
  - Send webhook payloads without any signature header
  - Send webhook payloads with an invalid signature
  - Test if payment amounts can be tampered between steps

- [?] WSTG-BUSL-04: Test process timing
  - Check for race conditions in wallet deposit/withdrawal
  - Test double-spending by sending two rapid escrow release requests
  - Test concurrent proposal submissions

- [?] WSTG-BUSL-05: Test function usage limits
  - Test if a user can submit unlimited proposals
  - Test if password reset can be requested unlimited times
  - Test if there's a limit on wallet transactions per time period

- [?] WSTG-BUSL-06: Test workflow circumvention
  - Try to release escrow without funding the milestone first
  - Try to leave a review without completing a contract
  - Try to withdraw more money than wallet balance
  - Skip expected steps in multi-step workflows

- [?] WSTG-BUSL-07: Test defenses against application misuse
  - Test rate limiting on all state-changing endpoints
  - Verify login endpoint rate limiting (brute force protection)
  - Test for abuse of messaging system (mass send)

- [?] WSTG-BUSL-08: Test upload of unexpected file types
  - Upload `.html`, `.svg`, `.exe`, `.php`, `.jsp` files
  - Check if files are served with original content-type
  - Test if uploaded HTML executes in application origin context

- [?] WSTG-BUSL-09: Test upload of malicious files
  - Upload files exceeding expected size limits
  - Upload polyglot files (e.g., GIF header + JS body)
  - Upload SVG with embedded JavaScript

- [?] WSTG-BUSL-10: Test payment functionality
  - Test wallet deposit/withdrawal with extreme amounts (no ceiling?)
  - Test escrow release amount override
  - Test partial payment edge cases
  - Verify financial calculations handle decimals correctly
  - Test for integer overflow in large transactions

---

## CLNT — Client-Side Testing

- [-] WSTG-CLNT-01: Test DOM-based XSS
  - Check if URL fragments or query params are inserted into DOM unsafely
  - Test search results page for DOM-based injection
  - No DOM-based sink was confirmed for the tested query-string payloads in this pass.

- [x] WSTG-CLNT-03: Test HTML injection
  - Submit HTML in profile fields and check rendering
  - Submit HTML in gig descriptions and titles
  - Submit HTML in messages and review rendering
  > **Finding: HTML Injection Reaches a Dangerous Client-Side Sink**
  > **Severity / Evidence / Impact / PoC**: See the confirmed stored-XSS finding under `WSTG-INPV-02` and PoC `reports/pocs/WSTG-INPV-02_review-stored-xss.py`.

- [-] WSTG-CLNT-04: Test client-side URL redirect
  - Check for open redirects in login flow (`?redirect=` or `?next=` params)
  - Test callback URLs for redirect manipulation
  - No `redirect`, `next`, callback, or OAuth return-URL surface was discovered in the live bundle.

- [x] WSTG-CLNT-07: Test CORS
  - Verify CORS policy with various Origin headers
  - Test if credentials are allowed with wildcard or reflected origin
  - Check preflight responses for dangerous allowed methods/headers
  > **Finding: Reflective Credentialed CORS**
  > **Severity / Evidence / Impact / PoC**: See the confirmed finding under `WSTG-CONF-08` and PoC `reports/pocs/WSTG-CONF-08_cors-credentialed-exfil.py`.

- [-] WSTG-CLNT-09: Test clickjacking
  - Check `X-Frame-Options` header
  - Check CSP `frame-ancestors` directive
  - Verify the application cannot be embedded in an iframe
  - `X-Frame-Options: SAMEORIGIN` was present.
  - No clickjacking bypass was confirmed in this pass.

- [-] WSTG-CLNT-10: Test WebSockets
  - Check if Socket.IO connections require authentication
  - Test if a user can listen on other users' notification channels
  - Test if WebSocket messages are validated server-side
  - Check for injection in real-time message content
  - No concrete WebSocket/Socket.IO endpoint was discovered from the assessed surface.

- [-] WSTG-CLNT-12: Test browser storage
  - Check what's stored in localStorage (JWT tokens? sensitive data?)
  - Check sessionStorage for sensitive information
  - Verify tokens are cleared on logout
  - The live frontend bundle reads `hf_token` from `localStorage`, confirming browser storage of bearer tokens.
  - This was not raised as a standalone finding because the stronger exploit chains are already covered by `WSTG-INPV-02` and `WSTG-SESS-06`.

- [-] WSTG-CLNT-14: Test reverse tabnabbing
  - Check if external links use `rel="noopener noreferrer"`
  - Test link preview feature for tabnabbing vectors
  - No target=`_blank` external-navigation surface or link-preview feature was confirmed in this pass.

---

## APIT — API Testing

- [-] WSTG-APIT-01: API reconnaissance
  - Enumerate all API endpoints and document request/response formats
  - Check for API documentation endpoints (Swagger, OpenAPI, etc.)
  - Test for undocumented or debug endpoints
  - Check API versioning and deprecated endpoint access
  - Core API routes were enumerated from the live frontend bundle and exercised directly over HTTP.
  - No Swagger/OpenAPI/debug-doc surface was discovered.

- [x] WSTG-APIT-02: Test broken object-level authorization (BOLA)
  - Test every resource endpoint with another user's resource IDs
  - Check contracts, messages, proposals, reviews, payments, disputes
  - Verify that listing endpoints only return the current user's resources
  - Test batch/bulk endpoints for IDOR
  > **Finding: Broken Object-Level Authorization on Owner-Scoped Project Resources**
  > **Severity / Evidence / Impact / PoC**: See the confirmed finding under `WSTG-ATHZ-04` and PoC `reports/pocs/WSTG-ATHZ-04_owner-me-project-leak.py`.

---

## SUPPL — Log Injection & Monitoring (supplementary)

- [?] WSTG-SUPPL-01: Test log injection
  - Submit login attempts with newlines/CRLF in email field
  - Observe if manipulated inputs cause anomalous server behavior
  - Log backends were not observable from the black-box surface, so log-injection impact remains inconclusive.

- [-] WSTG-SUPPL-02: Test sensitive data in logs
  - Trigger errors on auth endpoints and observe if error responses
    contain submitted credentials
  - Check if error responses include request body contents
  - Error responses did not echo submitted passwords or whole credential bodies.
  - Stack-trace exposure is tracked separately under `WSTG-ERRH-01` / `WSTG-ERRH-02`.
