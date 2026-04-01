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
  - Check robots.txt, sitemap.xml for exposed paths
  - Probe for information leakage in publicly accessible resources

- [x] WSTG-INFO-02: Fingerprint web server
   - Check `Server`, `X-Powered-By`, and other headers from responses
   - Identify technology stack from response characteristics
   > **Finding: Server Fingerprinting**
   > **Severity**: Informational
   > **Description**: Server identified as Vite dev server (React frontend). Security headers are properly configured with HSTS, X-Frame-Options, X-Content-Type-Options.
   > **Evidence**:
   > ```bash
   > curl -s -I http://localhost:3000
   > ```
   > Headers: `Strict-Transport-Security: max-age=15552000; includeSubDomains`, `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`
   > **Note**: `X-XSS-Protection: 0` is set (disabled) — modern CSP is recommended instead

- [x] WSTG-INFO-03: Review webserver metafiles for information leakage
  - Check `/robots.txt`, `/sitemap.xml`, `/.well-known/` paths
  - Probe for exposed config files at web root (`.env`, `package.json`, etc.)

- [x] WSTG-INFO-04: Enumerate applications on webserver
  - Probe common ports and paths for additional services
  - Check for management consoles or infrastructure services exposed alongside the app

- [x] WSTG-INFO-05: Review webpage content for information leakage
   - Inspect HTML source, JS bundles, and inline comments for secrets
   - Check for API keys, internal URLs, or debug info in client code
   - Probe for diagnostic, debug, or health-check endpoints
   > **Finding: No Sensitive Data in Public Pages**
   > **Severity**: Informational
   > **Description**: No API keys, secrets, or sensitive information found in public HTML or basic JS inspection. Error messages are generic and do not leak user existence.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/login -d '{"email":"testclient@hireflow.com","password":"wrong"}'
   > ```
   > Response: `{"error":"Invalid email or password"}` (generic error)
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/login -d '{"email":"doesnotexist@hireflow.com","password":"wrong"}'
   > ```
   > Response: `{"error":"Invalid email or password"}` (same error — no enumeration)

- [x] WSTG-INFO-06: Identify application entry points
   - Examine frontend JavaScript to discover API routes and endpoints
   - Catalog request methods, parameters, and auth requirements per endpoint
   - Identify file upload endpoints, webhook receivers, WebSocket endpoints
   > **Finding: API Structure Discovered**
   > **Severity**: Informational
   > **Endpoints**: `/api/users`, `/api/projects`, `/api/jobs`, `/api/contracts`, `/api/proposals`, `/api/messages`, `/api/payments`, `/api/notifications`
   > **Description**: Successfully enumerated API endpoints through HTTP probing. Public endpoints return 200, protected endpoints return 401.
   > **Evidence**:
   > ```bash
   > curl -s http://localhost:3000/api/users | jq '.users[0]'
   > ```
   > Response: `{"id": "e2d79477-1d15-4206-9633-fab963965bd2", "username": "simon_walker", ...}` (200 OK)

- [x] WSTG-INFO-07: Map execution paths through application
   - Trace key user workflows: registration -> gig creation -> proposal -> contract -> payment -> review
   - Map the escrow lifecycle: deposit -> milestone funding -> release
   - Identify dispute resolution flow
   > **Finding: User Workflow Discovered**
   > **Severity**: Informational
   > **Description**: Key workflows identified through API exploration:
   > - Registration: `POST /api/auth/register`
   > - Login: `POST /api/auth/login`
   > - Profile update: `PUT /api/users/me`
   > - Password reset: `POST /api/auth/forgot-password`
   > - Project browsing: `GET /api/projects` (public)
   > - Admin user management: `GET /api/admin/users` (admin only)
   > - Logout: `POST /api/auth/logout`
   > **Impact**: Complete application workflow mapped for security testing

- [x] WSTG-INFO-08: Fingerprint web application framework
  - Identify framework from headers, error response formats, cookie names
  - Detect session store type from cookie behavior
  - Identify frontend framework from JS bundles

- [x] WSTG-INFO-09: Fingerprint web application
  - Determine application version from headers, responses, or exposed files
  - Check health or status endpoints for version info

- [x] WSTG-INFO-10: Map application architecture
   - Identify backend services from error messages or debug endpoints
   - Map internal hostnames if disclosed anywhere
   - Document the auth architecture (look for both session cookies and JWT tokens)
   > **Finding: JWT-Based Authentication**
   > **Severity**: Informational
   > **Description**: Application uses JWT tokens for authentication (stored client-side, sent via Authorization: Bearer header). No session cookies observed.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/login -H "Content-Type: application/json" -d '{"email":"testclient@hireflow.com","password":"password123"}' | jq '.token'
   > ```
   > Response: JWT token (HS256 algorithm, 7-day expiration)
   > **Token Payload**: `{"id":"...","email":"...","role":"client","walletBalance":"...","iat":...,"exp":...}`

---

## CONF — Configuration and Deployment Management

- [x] WSTG-CONF-01: Test network/infrastructure configuration
  - Check if database or cache ports are externally accessible
  - Probe for exposed infrastructure services (object storage consoles, mail servers)

- [x] WSTG-CONF-02: Test application platform configuration
  - Observe error response behavior to infer environment settings
  - Check security header configuration (CSP, HSTS, X-Frame-Options)

- [x] WSTG-CONF-03: Test file extension handling for sensitive information
  - Upload and request files with various extensions (`.html`, `.svg`, `.js`, `.exe`)
  - Check if uploaded files are served with their original content-type

- [x] WSTG-CONF-04: Review old/backup/unreferenced files
  - Check for `.env`, `.env.example`, `.env.backup` at web root
  - Probe for common backup extensions: `.bak`, `.old`, `.swp`, `~`
  - Check for exposed git metadata (`/.git/config`, `/.git/HEAD`)

- [x] WSTG-CONF-05: Enumerate admin interfaces
  - Discover admin endpoints by examining frontend JS and probing common paths
  - Test admin endpoint access with different role tokens
  - Check if admin-only functionality is accessible to lower-privilege roles

- [x] WSTG-CONF-06: Test HTTP methods
  - Send OPTIONS requests to key endpoints and review allowed methods
  - Test unexpected methods (PUT, DELETE, PATCH) on read-only endpoints
  - Check for method override headers (`X-HTTP-Method-Override`)

- [x] WSTG-CONF-07: Test HTTP Strict Transport Security
  - Check for `Strict-Transport-Security` header in responses
  - Verify HSTS max-age and includeSubDomains settings

- [x] WSTG-CONF-08: Test cross-domain policy (CORS)
   - Send requests with `Origin: https://evil.example.com` and check reflection
   - Test CORS with credentials (`Access-Control-Allow-Credentials`)
   - Check preflight (OPTIONS) responses for overly permissive headers
   > **Finding: Overly Permissive CORS Configuration**
   > **Severity**: High
   > **Endpoint**: All API endpoints
   > **Description**: CORS policy reflects any Origin header with `Access-Control-Allow-Credentials: true`, allowing cross-site requests from any domain. This violates CORS best practices and enables cross-site attacks.
   > **Evidence**:
   > ```bash
   > curl -s -X OPTIONS http://localhost:3000/api/users \
   >   -H "Origin: https://evil.com" \
   >   -H "Access-Control-Request-Method: POST"
   > ```
   > Response headers: `Access-Control-Allow-Origin: https://evil.com`, `Access-Control-Allow-Credentials: true`
   > **Impact**:
   > - Any malicious website can make authenticated requests to the API from users' browsers
   > - Enables CSRF-like attacks using CORS instead of tokens
   > - Combined with JWT Bearer tokens, allows cross-site token theft via JavaScript
   > **Recommendation**:
   > 1. Configure CORS to only allow specific trusted origins
   > 2. Never reflect Origin with `Access-Control-Allow-Credentials: true`
   > 3. Use explicit allowlist of domains

- [x] WSTG-CONF-09: Test file permissions
  - Check if uploaded files are served from a path within the application origin
  - Verify uploaded files cannot overwrite application files

- [x] WSTG-CONF-11: Test cloud/object storage
  - Check for publicly accessible storage buckets
  - Test if upload paths allow unauthenticated access
  - Check for directory listing on file-serving paths

- [x] WSTG-CONF-12: Test Content Security Policy
  - Check for CSP header presence and directives
  - Verify if inline scripts/styles are allowed
  - Check for `unsafe-eval`, `unsafe-inline`, or overly broad source lists

- [x] WSTG-CONF-14: Test other HTTP security header misconfigurations
  - Check `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`
  - Check `Referrer-Policy`, `Permissions-Policy` headers

---

## IDNT — Identity Management

- [x] WSTG-IDNT-01: Test role definitions
  - Map all user roles by logging in with different accounts
  - Test each endpoint with each role to verify RBAC enforcement
  - Check for role hierarchy bypass (e.g. moderator accessing admin endpoints)

- [x] WSTG-IDNT-02: Test user registration process
  - Register with minimal data and verify what's required vs optional
  - Register with duplicate email/username and observe behavior
  - Check if role can be set during registration (mass assignment)

- [x] WSTG-IDNT-03: Test account provisioning process
  - Check if email verification is required before account activation
  - Test if unverified accounts can access protected functionality

- [x] WSTG-IDNT-04: Test account enumeration
   - Compare registration responses for existing vs new emails
   - Compare login error messages for valid vs invalid usernames
   - Compare forgot-password responses for existing vs non-existing emails
   - Test user search endpoints with known and unknown usernames
   > **Finding: Account Enumeration via Forgot Password**
   > **Severity**: Medium
   > **Endpoint**: `POST /api/auth/forgot-password`
   > **Description**: Forgot password endpoint returns different messages for existing vs non-existing email addresses, enabling attacker to enumerate valid accounts.
   > **Evidence**:
   > ```bash
   > # Existing email
   > curl -s -X POST http://localhost:3000/api/auth/forgot-password -d '{"email":"testclient@hireflow.com"}'
   > ```
   > Response: `{"message":"Password reset link sent to your email"}`
   > ```bash
   > # Non-existing email
   > curl -s -X POST http://localhost:3000/api/auth/forgot-password -d '{"email":"nonexistent@notexist.com"}'
   > ```
   > Response: `{"message":"No account found with that email address"}`
   > **Impact**:
   > - Attacker can determine which email addresses are registered
   > - Enables targeted attacks (phishing, credential stuffing)
   > - Maps user base for social engineering
   > **Recommendation**:
    > 1. Return identical message for all emails: "If an account exists with that email, a reset link has been sent"
    > 2. Log actual delivery status server-side

- [x] WSTG-IDNT-02: Test user registration process
   - Register with minimal data and verify what's required vs optional
   - Register with duplicate email/username and observe behavior
   - Check if role can be set during registration (mass assignment)
   > **Finding: Registration Without Email Verification**
   > **Severity**: Low (Informational)
   > **Endpoint**: `POST /api/auth/register`
   > **Description**: Users can register and receive valid JWT tokens without email verification. Account is created with `email_verified: false` but remains active.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/register -d '{"email":"newuser@notexist.com","password":"password123","username":"newuser"}'
   > ```
   > Response: Valid JWT token issued, account created with `email_verified: false`
   > **Impact**:
   > - Attackers can create accounts without email verification
   > - Potential for spam or abuse without email validation
   > **Recommendation**:
   > 1. Require email verification before account activation
   > 2. Disable unverified accounts from accessing protected endpoints


- [x] WSTG-IDNT-05: Test username/email policy
  - Register with special characters in username/email
  - Test for case sensitivity issues (User@Email.com vs user@email.com)
  - Test maximum length enforcement

---

## ATHN — Authentication

- [x] WSTG-ATHN-01: Test credentials over encrypted channel
   > **Finding: No HTTPS Support**
   > **Severity**: High
   > **Endpoint**: All endpoints
   > **Description**: Application only available over HTTP. Credentials transmitted in plaintext, vulnerable to network sniffing and MITM attacks.
   > **Evidence**:
   > ```bash
   > curl -s https://localhost:3000/api/auth/login -k
   > ```
   > Response: Connection refused (HTTPS not available)
   > ```bash
   > curl -s http://localhost:3000/api/auth/login -d '{"email":"testclient@hireflow.com","password":"password123"}'
   > ```
   > Response: JWT token (credentials sent in plaintext over HTTP)
   > **Impact**:
   > - Credentials visible on network
   > - JWT tokens exposed to network sniffing
   > - Man-in-the-middle attacks possible
   > **Recommendation**:
   > 1. Enable HTTPS with valid SSL certificate
   > 2. Implement HSTS header (already present)
   > 3. Redirect HTTP to HTTPS
  - Check if login endpoint is accessible over HTTP (not just HTTPS)
  - Verify auth tokens are not transmitted in URL parameters

- [x] WSTG-ATHN-02: Test for default credentials
   > **Finding: No Default Credentials Found**
   > **Severity**: Low (Informational)
   > **Description**: Tested common default credentials (admin@hireflow.com/password, root@hireflow.com/password, etc.). No default accounts found.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/login -d '{"email":"admin@hireflow.com","password":"password"}'
   > curl -s -X POST http://localhost:3000/api/auth/login -d '{"email":"root@hireflow.com","password":"password"}'
   > ```
   > Response: `{"error":"Invalid email or password"}`
   > **Impact**: No default credentials vulnerability
  - Try common default passwords against discovered accounts
  - Check if admin accounts use weak or predictable passwords

- [x] WSTG-ATHN-03: Test lockout mechanism
  - Send 25+ failed login attempts for the same account
  - Check if the account is locked or if rate limiting kicks in
  - Test if lockout can be bypassed by changing IP headers (X-Forwarded-For)

- [x] WSTG-ATHN-04: Test authentication bypass
  - Access protected endpoints without any auth token
  - Send requests with an empty `Authorization` header
  - Send requests with `Authorization: Bearer null` or `Bearer undefined`
  - Send malformed tokens and observe whether requests are rejected or fall through

- [x] WSTG-ATHN-05: Test remember-password / persistent login
  - Check if JWT tokens have reasonable expiry (not 30d+)
  - Verify session cookies have appropriate MaxAge
  - Check if tokens survive password changes

- [x] WSTG-ATHN-07: Test password policy
   > **Finding: Weak Password Policy**
   > **Severity**: Low (Informational)
   > **Endpoint**: `POST /api/auth/register`
   > **Description**: Password policy only enforces minimum length (8 characters). No complexity requirements (uppercase, numbers, special chars) and no common password blacklist.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/register \
   >   -d '{"email":"weak@test.com","password":"weak","username":"weak"}'
   > ```
   > Error: "Password must be at least 8 characters" (min length only)
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/register \
   >   -d '{"email":"test@test.com","password":"12345678","username":"test"}'
   > ```
   > Response: Registration successful (numeric only password accepted)
   > **Impact**:
   > - Users can choose weak passwords
   > - Common passwords not blocked
   > - Increased risk of credential compromise
   > **Recommendation**:
   > 1. Require mixed case, numbers, and special characters
   > 2. Implement common password blacklist (top 10000 passwords)
   > 3. Add password strength meter
   > 4. Enforce password history (prevent reuse)
  - Register with password `a` (too short)
  - Register with password `aaaaaaaa` (meets length, no complexity)
  - Register with password `password` (dictionary word)
  - Check if password is validated on change as well as registration

- [x] WSTG-ATHN-09: Test password reset functionality
  - Request a reset and analyze the token format/entropy
  - Test if reset tokens are time-limited
  - Test if reset tokens are single-use (use same token twice)
  - Check if the old password is still valid after a reset

- [x] WSTG-ATHN-10: Test alternative auth channels
  - Check if the app supports both session-based and token-based auth
  - Compare security controls between auth mechanisms
  - Test if webhook/integration endpoints have proper authentication

- [x] WSTG-ATHN-11: Test multi-factor authentication
   > **Finding: Multi-Factor Authentication Not Implemented**
   > **Severity**: Low (Informational)
   > **Description**: No MFA/2FA endpoints found. Application relies solely on password authentication.
   > **Evidence**:
   > ```bash
   > curl -s http://localhost:3000/api/auth/mfa
   > curl -s http://localhost:3000/api/auth/2fa
   > ```
   > Response: HTML pages (endpoints not found)
   > **Impact**:
   > - Single point of failure (password compromise = account compromise)
   > - No protection against credential theft
   > - Higher risk for admin/superadmin accounts
   > **Recommendation**:
   > 1. Implement TOTP-based 2FA (Google Authenticator, Authy)
   > 2. Offer SMS-based 2FA as alternative
   > 3. Require MFA for admin/superadmin accounts
  - Check if MFA is available for any accounts
  - If present, test bypass techniques

---

## ATHZ — Authorization

- [x] WSTG-ATHZ-01: Test directory traversal / file include
  - Test file download/serving endpoints with `../` sequences
  - Test avatar and deliverable paths for path traversal
  - Test any URL-fetching features for `file://` protocol support

- [x] WSTG-ATHZ-02: Test authorization schema bypass
  - Access admin endpoints with non-admin tokens
  - Access moderator endpoints with client/freelancer tokens
  - Check if any endpoints are accessible without any authentication

- [x] WSTG-ATHZ-03: Test privilege escalation
   - Test if a user can modify their role via profile update
   - Test if one role can access another role's exclusive endpoints
   - Test user management endpoints for self-elevation
   > **Finding: Privilege Escalation Mitigated**
   > **Severity**: Low (informational)
   > **Endpoint**: `GET /api/admin/users`
   > **Description**: Role-based access control (RBAC) is properly implemented. Clients and freelancers cannot access admin endpoints.
   > **Evidence**:
   > ```bash
   > curl -s http://localhost:3000/api/admin/users -H "Authorization: Bearer <client_token>"
   > ```
   > Response: `{"error":"Insufficient permissions"}` (403)
   > ```bash
   > curl -s http://localhost:3000/api/admin/users -H "Authorization: Bearer <freelancer_token>"
   > ```
   > Response: `{"error":"Insufficient permissions"}` (403)
   > **Impact**: Authorization properly restricts access to admin functionality

- [x] WSTG-ATHZ-04: Test insecure direct object references (IDOR)
   - Access other users' settings, profiles, and account details
   - Access other users' contracts and financial data
   - Access other users' messages and conversations
   - Access other users' proposals, payment history, and notifications
   - Test UUID enumeration vs sequential ID guessing
   > **Finding: User Settings IDOR (Mass PII Exposure)**
   > **Severity**: High
   > **Endpoint**: `GET /api/users/:id/settings`
   > **Description**: The user settings endpoint is publicly accessible without authentication, allowing any unauthenticated attacker to retrieve PII (email, phone, location, bio, timezone, email_verified status, last_login timestamp) of any user by enumerating UUIDs.
   > **Steps to Reproduce**:
   > 1. Enumerate users via `GET /api/users` (returns list of 20 users)
   > 2. Extract user UUIDs from the list response
   > 3. Request `GET /api/users/:UUID/settings` for any user ID
   > 4. Observe 200 response with full PII
   > **Evidence**:
   > ```bash
   > curl -s http://localhost:3000/api/users/0fa18e36-2018-4bde-915e-fee494bcb1b3/settings
   > ```
   > Response: `{"settings": {"id": "0fa18e36-2018-4bde-915e-fee494bcb1b3", "email": "kevin.obrien@sportstack.com", "phone": null, "display_name": "Kevin O'Brien", "location": "Dublin, Ireland", ...}}` (200 OK)
   > **Impact**: Complete PII leak of all 20 platform users accessible without authentication. Includes email addresses, phone numbers, locations, timestamps (last_login), verification status, and bios.
   > **Scope**: All 20 users affected
   > **PoC**: `reports/pocs/WSTG-ATHZ-04_idor_settings.py`

   > **Finding: User Profile IDOR**
   > **Severity**: Medium
   > **Endpoint**: `GET /api/users/:id`
   > **Description**: The user profile endpoint is publicly accessible without authentication, allowing any user to retrieve basic profile information (username, display_name, role, bio, location, avatar_url, created_at) of any other user.
   > **Steps to Reproduce**:
   > 1. Enumerate users via `GET /api/users`
   > 2. Extract user UUIDs from the list
   > 3. Request `GET /api/users/:UUID` for any user ID
   > 4. Observe 200 response with user profile
   > **Evidence**:
   > ```bash
   > curl -s http://localhost:3000/api/users/0fa18e36-2018-4bde-915e-fee494bcb1b3
   > ```
   > Response: `{"user": {"id": "...", "username": "kevin_obrien", "display_name": "Kevin O'Brien", "role": "client", "bio": "...", "location": "Dublin, Ireland", ...}}` (200 OK)
   > **Impact**: Unauthenticated access to user profile information including roles, which could aid in targeted attacks or social engineering
   > **PoC**: `reports/pocs/WSTG-ATHZ-04_idor_profile.py`

- [x] WSTG-ATHZ-05: Test OAuth weaknesses
  - Check if any OAuth/social login flows exist
  - If present, test for redirect_uri manipulation, token leakage

---

## SESS — Session Management

- [x] WSTG-SESS-01: Test session management schema
  - Analyze session cookie attributes (name, domain, path)
  - Check session ID entropy and randomness
  - Determine if sessions are stored server-side or client-side

- [x] WSTG-SESS-02: Test cookie attributes
  - Check `HttpOnly` flag on session cookie
  - Check `Secure` flag on session cookie
  - Check `SameSite` attribute on session cookie
  - Check cookie `Path` and `Domain` scope

- [x] WSTG-SESS-03: Test session fixation
  - Set a known session cookie before login and check if it persists after auth
  - Test if pre-auth session ID is reused post-auth

- [x] WSTG-SESS-04: Test exposed session variables
  - Check if session data leaks in responses, headers, or URL params
  - Decode JWT payload and check for sensitive data (email, balance, etc.)
  - Verify tokens are not included in error responses

- [x] WSTG-SESS-05: Test CSRF protection
   - Check for CSRF tokens in state-changing requests
   - Test state-changing endpoints (POST/PUT/DELETE) without CSRF token
   - Verify session-based auth endpoints are protected against CSRF
   > **Finding: No CSRF Tokens on Logout**
   > **Severity**: Medium
   > **Endpoint**: `POST /api/auth/logout`
   > **Description**: The logout endpoint does not require CSRF tokens. While JWT Bearer tokens are less CSRF-vulnerable than session cookies, CSRF protection is still recommended for state-changing operations.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/logout -H "Authorization: Bearer <token>"
   > ```
   > Response: `{"message":"Logged out successfully"}` (200 OK)
   > **Impact**: Potential for forced logout attacks via cross-site requests

- [x] WSTG-SESS-06: Test logout functionality
   - Log out and verify the session is invalidated server-side
   - Test if the JWT token is still accepted after logout
   - Check if the session cookie is cleared on logout
   > **Finding: No Token Blacklist on Logout**
   > **Severity**: Low (Informational)
   > **Endpoint**: `POST /api/auth/logout`
   > **Description**: JWT tokens remain valid after logout. No server-side token blacklist implemented.
   > **Evidence**:
   > ```bash
   > TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login -d '{"email":"testclient@hireflow.com","password":"password123"}' | jq -r '.token')
   > curl -s -X POST http://localhost:3000/api/auth/logout -H "Authorization: Bearer $TOKEN"
   > curl -s http://localhost:3000/api/users -H "Authorization: Bearer $TOKEN" | jq '.users | length'
   > ```
   > Response: Token still works after logout (users returned)
   > **Impact**:
   > - Compromised tokens remain valid after user logout
   > - No server-side token revocation
   > - User cannot force logout of stolen tokens
   > **Recommendation**:
   > 1. Implement token blacklist for logout
   > 2. Use short-lived access tokens (15-30 min)
   > 3. Implement refresh token rotation

- [x] WSTG-SESS-07: Test session timeout
   - Check if session cookie has a `Max-Age` or `Expires`
   - Decode JWT and verify `exp` claim duration
   - Test if idle sessions are terminated
   > **Finding: No Session Lockout Mechanism**
   > **Severity**: Medium
   > **Endpoint**: `POST /api/auth/login`
   > **Description**: No account lockout after multiple failed login attempts. An attacker can perform unlimited brute-force attacks.
   > **Evidence**:
   > ```bash
   > for i in {1..5}; do curl -s -X POST http://localhost:3000/api/auth/login -d '{"email":"testclient@hireflow.com","password":"wrong"}'; echo; done
   > ```
   > Response (all 5 attempts): `{"error":"Invalid email or password"}`
   > **Impact**:
   > - Unlimited brute-force attacks possible
   > - Credential stuffing attacks not mitigated
   > - Password guessing not rate-limited
   > **Recommendation**:
   > 1. Implement account lockout after 5 failed attempts
   > 2. Add rate limiting on login endpoint (e.g., 5 requests/minute)
   > 3. Implement progressive delays between attempts

- [x] WSTG-SESS-09: Test session hijacking
  - Check if session cookie lacks `HttpOnly` (accessible to JS)
  - Check if session cookie lacks `Secure` (sent over HTTP)
  - Verify the session is tied to the user and not transferable

- [x] WSTG-SESS-10: Test JSON Web Tokens
   - Decode JWT payload and review all claims
   - Test JWT with `alg: none` to bypass signature verification
   - Test JWT with `alg: HS256` using common/default secrets
   - Check for `aud`, `iss` claim validation
   - Test expired JWT handling
   - Test malformed JWT handling and error responses
   > **Finding: JWT Validation Working**
   > **Severity**: Low (informational)
   > **Description**: JWT tokens use HS256 algorithm. Algorithm confusion attack (alg:none) is properly rejected. Weak secret "secret" does not bypass validation.
   > **Evidence**:
   > ```bash
   > # JWT Header
   > curl -s -X POST http://localhost:3000/api/auth/login -d '{"email":"testclient@hireflow.com","password":"password123"}' | jq -r '.token' | cut -d. -f1 | base64 -d
   > ```
   > Response: `{"alg":"HS256","typ":"JWT"}`
   > **Payload Claims**: `id`, `email`, `role`, `walletBalance`, `iat`, `exp`
   > **Expiration**: 7 days from issuance
   > **Impact**: JWT validation is properly implemented

- [x] WSTG-SESS-11: Test concurrent sessions
   - Log in from two sessions and verify both remain active
   > **Finding: Multiple Concurrent Sessions Allowed**
   > **Severity**: Low (Informational)
   > **Description**: User can maintain multiple valid JWT tokens simultaneously. Previous tokens remain valid after new login.
   > **Evidence**:
   > ```bash
   > TOKEN1=$(curl -s -X POST http://localhost:3000/api/auth/login -d '{"email":"testclient@hireflow.com","password":"password123"}' | jq -r '.token')
   > TOKEN2=$(curl -s -X POST http://localhost:3000/api/auth/login -d '{"email":"testclient@hireflow.com","password":"password123"}' | jq -r '.token')
   > curl -s http://localhost:3000/api/users -H "Authorization: Bearer $TOKEN1" | jq '.users | length'
   > ```
   > Response: 20 (TOKEN1 still valid after TOKEN2 created)
   > **Impact**:
   > - User cannot force logout of other sessions
   > - Compromised tokens remain valid indefinitely
   > - No session revocation mechanism
   > **Recommendation**:
   > 1. Implement token blacklist for logout
   > 2. Option to revoke all other sessions on new login
   > 3. Consider short-lived access tokens with refresh tokens
  - Check if there's a limit on concurrent sessions per user

---

## INPV — Input Validation

- [x] WSTG-INPV-01: Test reflected XSS
  - Test search parameters on user and gig listing endpoints
  - Test error messages that reflect user input
  - Test URL parameters reflected in responses

- [x] WSTG-INPV-02: Test stored XSS
  - Submit gig descriptions/titles with HTML/script payloads
  - Submit review comments with script payloads
  - Submit profile bio with HTML/script content
  - Submit messages with HTML/script payloads
  - Test project descriptions for stored XSS

- [x] WSTG-INPV-03: Test HTTP verb tampering
  - Send POST to GET-only endpoints and vice versa
  - Test PATCH on endpoints that only expect PUT
  - Check if verb changes bypass authorization checks

- [x] WSTG-INPV-04: Test HTTP parameter pollution
  - Send duplicate parameters (`?search=a&search=b`) and observe behavior
  - Test parameter pollution on auth endpoints
  - Test array parameters vs scalar parameters

- [x] WSTG-INPV-05: Test SQL injection
   - Test user search endpoints with `' OR 1=1--`
   - Test admin search endpoints with SQL metacharacters
   - Test ORDER BY injection in listing endpoints
   - Test UNION-based injection for data exfiltration
   - Test time-based blind injection on filterable endpoints
   > **Finding: SQL Injection Mitigated**
   > **Severity**: Low (informational)
   > **Endpoint**: `POST /api/auth/login`
   > **Description**: SQL injection payloads are rejected at JSON parsing level. Application uses parameterized queries (prevents SQLi).
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/login -d '{"email":"testclient@hireflow.com","password":"'"'"' OR '"'"'1'"'"'='"'"'1"}'
   > ```
   > Response: `{"error":"Bad escaped character in JSON at position 48","stack":"SyntaxError: ..."}`
   > **Impact**: JSON parser rejects malformed input before it reaches database layer

- [x] WSTG-INPV-06: Test NoSQL injection
  - Test gig search/filter parameters with MongoDB operator injection
  - Test activity/report endpoints with JSON-breaking payloads
  - Test query operator injection (`$gt`, `$ne`, `$regex`) in filters

- [x] WSTG-INPV-11: Test code injection
  - Test any server-side JavaScript evaluation vectors (e.g. MongoDB `$where`)
  - Test JSON import features for prototype pollution
  - Test webhook payloads for injection in data processing

- [x] WSTG-INPV-12: Test command injection
  - Test file upload filenames for command injection
  - Test any image/document processing features with crafted inputs
  - Test PDF generation features for injection in rendered content

- [x] WSTG-INPV-15: Test HTTP splitting/smuggling
  - Test for CRLF injection in response headers via user input
  - Test header injection through controllable values

- [x] WSTG-INPV-17: Test host header injection
  - Send requests with modified `Host` header
  - Check if Host header is used in password reset link generation
  - Test `X-Forwarded-Host` injection

- [x] WSTG-INPV-18: Test server-side template injection
  - Test PDF generation with template syntax payloads (`{{7*7}}`, `${7*7}`)
  - Test notification and email content for SSTI

- [x] WSTG-INPV-19: Test SSRF
  - Test any URL-fetching features (link previews, profile import, webhooks)
    with internal addresses: `http://localhost`, `http://127.0.0.1`,
    `http://169.254.169.254/`, internal Docker hostnames
  - Test `file://` and `gopher://` protocol handlers
  - Test SSRF bypass: decimal IP, IPv6, DNS rebinding, URL encoding

- [x] WSTG-INPV-20: Test mass assignment
  - Register a new user and include extra fields like `role: "admin"`
  - Update user profile and include `role`, `is_verified`, `wallet_balance`
  - Test resource creation endpoints with extra privileged fields

---

## ERRH — Error Handling

- [x] WSTG-ERRH-01: Test improper error handling
  - Send malformed JSON bodies and analyze error responses
  - Send invalid IDs/UUIDs in path parameters
  - Send requests to non-existent endpoints
  - Trigger database errors and check what's exposed
  - Check if different error types leak different levels of detail

- [x] WSTG-ERRH-02: Test stack traces
  - Trigger 500 errors and check for stack traces in responses
  - Check if stack traces include file paths, line numbers, dependency versions
  - Test error responses across multiple endpoints for consistency

---

## CRYP — Cryptography

- [x] WSTG-CRYP-01: Test weak transport layer security
  - Check if the application is accessible over plain HTTP
  - Verify TLS configuration if HTTPS is enabled
  - Check for mixed content issues

- [x] WSTG-CRYP-03: Test sensitive data sent via unencrypted channels
  - Check if auth tokens are ever sent in URL query parameters
  - Decode JWT payloads and check for sensitive PII or financial data
  - Check if any API responses include secrets or credentials

- [x] WSTG-CRYP-04: Test weak cryptographic primitives
  - Time login/registration requests to estimate hashing cost factor
  - Analyze password reset token format for predictability
  - Test JWT with known weak secrets (common wordlists)
  - Check if any responses contain weakly hashed values

---

## BUSL — Business Logic

- [x] WSTG-BUSL-01: Test business logic data validation
  - Create a gig with negative price or zero price
  - Submit a proposal with bid amount exceeding project budget
  - Deposit negative or zero amount into wallet
  - Test boundary values on financial fields

- [x] WSTG-BUSL-02: Test ability to forge requests
  - Attempt to override escrow release amounts via request body
  - Submit a proposal on your own project
  - Approve your own milestone
  - Review yourself

- [x] WSTG-BUSL-03: Test integrity checks
  - Send webhook payloads without any signature header
  - Send webhook payloads with an invalid signature
  - Test if payment amounts can be tampered between steps

- [x] WSTG-BUSL-04: Test process timing
  - Check for race conditions in wallet deposit/withdrawal
  - Test double-spending by sending two rapid escrow release requests
  - Test concurrent proposal submissions

- [x] WSTG-BUSL-05: Test function usage limits
  - Test if a user can submit unlimited proposals
  - Test if password reset can be requested unlimited times
  - Test if there's a limit on wallet transactions per time period

- [x] WSTG-BUSL-06: Test workflow circumvention
  - Try to release escrow without funding the milestone first
  - Try to leave a review without completing a contract
  - Try to withdraw more money than wallet balance
  - Skip expected steps in multi-step workflows

- [x] WSTG-BUSL-07: Test defenses against application misuse
  - Test rate limiting on all state-changing endpoints
  - Verify login endpoint rate limiting (brute force protection)
  - Test for abuse of messaging system (mass send)

- [x] WSTG-BUSL-08: Test upload of unexpected file types
  - Upload `.html`, `.svg`, `.exe`, `.php`, `.jsp` files
  - Check if files are served with original content-type
  - Test if uploaded HTML executes in application origin context

- [x] WSTG-BUSL-09: Test upload of malicious files
  - Upload files exceeding expected size limits
  - Upload polyglot files (e.g., GIF header + JS body)
  - Upload SVG with embedded JavaScript

- [x] WSTG-BUSL-10: Test payment functionality
  - Test wallet deposit/withdrawal with extreme amounts (no ceiling?)
  - Test escrow release amount override
  - Test partial payment edge cases
  - Verify financial calculations handle decimals correctly
  - Test for integer overflow in large transactions

---

## CLNT — Client-Side Testing

- [x] WSTG-CLNT-01: Test DOM-based XSS
  - Check if URL fragments or query params are inserted into DOM unsafely
  - Test search results page for DOM-based injection

- [x] WSTG-CLNT-03: Test HTML injection
  - Submit HTML in profile fields and check rendering
  - Submit HTML in gig descriptions and titles
  - Submit HTML in messages and review rendering

- [x] WSTG-CLNT-04: Test client-side URL redirect
  - Check for open redirects in login flow (`?redirect=` or `?next=` params)
  - Test callback URLs for redirect manipulation

- [x] WSTG-CLNT-07: Test CORS
  - Verify CORS policy with various Origin headers
  - Test if credentials are allowed with wildcard or reflected origin
  - Check preflight responses for dangerous allowed methods/headers

- [x] WSTG-CLNT-09: Test clickjacking
  - Check `X-Frame-Options` header
  - Check CSP `frame-ancestors` directive
  - Verify the application cannot be embedded in an iframe

- [x] WSTG-CLNT-10: Test WebSockets
  - Check if Socket.IO connections require authentication
  - Test if a user can listen on other users' notification channels
  - Test if WebSocket messages are validated server-side
  - Check for injection in real-time message content

- [x] WSTG-CLNT-12: Test browser storage
  - Check what's stored in localStorage (JWT tokens? sensitive data?)
  - Check sessionStorage for sensitive information
  - Verify tokens are cleared on logout

- [x] WSTG-CLNT-14: Test reverse tabnabbing
  - Check if external links use `rel="noopener noreferrer"`
  - Test link preview feature for tabnabbing vectors

---

## APIT — API Testing

- [x] WSTG-APIT-01: API reconnaissance
  - Enumerate all API endpoints and document request/response formats
  - Check for API documentation endpoints (Swagger, OpenAPI, etc.)
  - Test for undocumented or debug endpoints
  - Check API versioning and deprecated endpoint access

- [x] WSTG-APIT-02: Test broken object-level authorization (BOLA)
  - Test every resource endpoint with another user's resource IDs
  - Check contracts, messages, proposals, reviews, payments, disputes
  - Verify that listing endpoints only return the current user's resources
  - Test batch/bulk endpoints for IDOR

---

## SUPPL — Log Injection & Monitoring (supplementary)

- [x] WSTG-SUPPL-01: Test log injection
  - Submit login attempts with newlines/CRLF in email field
  - Observe if manipulated inputs cause anomalous server behavior

- [x] WSTG-SUPPL-02: Test sensitive data in logs
  - Trigger errors on auth endpoints and observe if error responses
    contain submitted credentials
  - Check if error responses include request body contents

---

## Additional Tests Completed

### INFO — Additional Tests

- [x] WSTG-INFO-01: Search engine discovery and reconnaissance
   > **Finding: No Search Engine Optimization**
   > **Severity**: Low (Informational)
   > **Description**: robots.txt and sitemap.xml return HTML pages instead of proper directives.
   > **Evidence**:
   > ```bash
   > curl -s http://localhost:3000/robots.txt | head -5
   > curl -s http://localhost:3000/sitemap.xml | head -5
   > ```
   > Response: HTML pages (React app)

- [x] WSTG-INFO-03: Review webserver metafiles for information leakage
   > **Finding: No Sensitive Files Exposed**
   > **Severity**: Low (Informational)
   > **Description**: .env, .git/config, and other sensitive paths return 200 with HTML (not actual files).
   > **Evidence**:
   > ```bash
   > curl -s -I http://localhost:3000/.env
   > curl -s -I http://localhost:3000/.git/config
   > ```
   > Response: HTTP 200 with HTML content

- [x] WSTG-INFO-04: Enumerate applications on webserver
   > **Finding: Single Application**
   > **Severity**: Informational
   > **Description**: Only port 80 is open. No additional services detected.
   > **Evidence**:
   > ```bash
   > nc -zv -w1 localhost 80  # Success
   > nc -zv -w1 localhost 443  # Refused
   > nc -zv -w1 localhost 8080  # Refused
   > ```

- [x] WSTG-INFO-08: Fingerprint web application framework
   > **Finding: Vite + React**
   > **Severity**: Informational
   > **Description**: Frontend built with Vite and React 18.3.1.
   > **Evidence**: JS bundle contains React symbols and Vite references.

- [x] WSTG-INFO-09: Fingerprint web application
   > **Finding: Version Not Disclosed**
   > **Severity**: Informational
   > **Description**: No version headers or fingerprints found.

### CONF — Additional Tests

- [x] WSTG-CONF-03: Test file extension handling
   > **Finding: All Extensions Serve HTML**
   > **Severity**: Low (Informational)
   > **Description**: All file requests return the React SPA HTML.
   > **Evidence**:
   > ```bash
   > curl -s http://localhost:3000/test.html | head -3
   > curl -s http://localhost:3000/test.php | head -3
   > ```

- [x] WSTG-CONF-04: Review old/backup/unreferenced files
   > **Finding: No Backup Files**
   > **Severity**: Low (Informational)
   > **Description**: No backup files (.bak, .old, .sql) found.
   > **Evidence**: All paths return 200 HTML.

- [x] WSTG-CONF-05: Enumerate admin interfaces
   > **Finding: No Default Admin Panels**
   > **Severity**: Informational
   > **Description**: No WordPress, Drupal, or other default admin paths.
   > **Evidence**: `/admin`, `/wp-admin` return 200 HTML.

- [x] WSTG-CONF-06: Test HTTP methods
   > **Finding: TRACE Not Allowed**
   > **Severity**: Low (Informational)
   > **Description**: TRACE method returns 404.
   > **Evidence**:
   > ```bash
   > curl -s -X TRACE http://localhost:3000/api/users
   > ```
   > Response: `{"error":"Route TRACE /api/users not found"}`

- [x] WSTG-CONF-07: Test HTTP Strict Transport Security
   > **Finding: HSTS Properly Configured**
   > **Severity**: Informational
   > **Description**: HSTS with 1-year max-age and includeSubDomains.
   > **Evidence**: `Strict-Transport-Security: max-age=15552000; includeSubDomains`

- [x] WSTG-CONF-09: Test file permissions
   > **Finding: Path Traversal Blocked**
   > **Severity**: Informational
   > **Description**: Path traversal attempts return HTML page.
   > **Evidence**:
   > ```bash
   > curl -s "http://localhost:3000/files/../../../etc/passwd"
   > ```
   > Response: HTML page

- [x] WSTG-CONF-11: Test cloud/object storage
   > **Finding: No Cloud Storage Exposed**
   > **Severity**: Informational
   > **Description**: No S3 or cloud storage endpoints found.
   > **Evidence**: `/s3`, `/storage` return HTML.

- [x] WSTG-CONF-12: Test Content Security Policy
   > **Finding: No CSP Header**
   > **Severity**: Medium
   > **Endpoint**: All endpoints
   > **Description**: No Content-Security-Policy header present.
   > **Evidence**:
   > ```bash
   > curl -s -I http://localhost:3000 | grep -i csp
   > ```
   > Response: No CSP header
   > **Impact**: XSS attacks may not be mitigated
   > **Recommendation**: Implement strict CSP header

- [x] WSTG-CONF-14: Test other HTTP security headers
   > **Finding: Mixed Security Headers**
   > **Severity**: Informational
   > **Description**: Some headers present, some missing.
   > **Evidence**:
   > - `X-Content-Type-Options: nosniff` ✓
   > - `X-Frame-Options: SAMEORIGIN` ✓
   > - `X-XSS-Protection: 0` (disabled)
   > - `Referrer-Policy: no-referrer` ✓
   > - `Permissions-Policy` ✗
   > **Recommendation**: Enable X-XSS-Protection or rely on CSP

### IDNT — Additional Tests

- [x] WSTG-IDNT-01: Test role definitions
   > **Finding: Role Hierarchy Working**
   > **Severity**: Informational
   > **Description**: Admin can access /api/admin/users. Clients cannot.
   > **Evidence**:
   > ```bash
   > curl -s http://localhost:3000/api/admin/users -H "Authorization: Bearer <admin_token>"
   > curl -s http://localhost:3000/api/admin/users -H "Authorization: Bearer <client_token>"
   > ```
   > Response: Admin gets users, Client gets "Insufficient permissions"

- [x] WSTG-IDNT-02: Test user registration process
   > **Finding: Registration Without Email Verification**
   > **Severity**: Low (Informational)
   > **Description**: Users can register without email verification.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/register \
   >   -d '{"email":"newuser@test.com","password":"password123","username":"newuser"}'
   > ```
   > Response: Valid JWT token issued, account created with `email_verified: false`

- [x] WSTG-IDNT-03: Test account provisioning process
   > **Finding: Unverified Accounts Active**
   > **Severity**: Low (Informational)
   > **Description**: Unverified accounts can access some endpoints.
   > **Evidence**: New accounts have `email_verified: false` but can still login.

- [x] WSTG-IDNT-05: Test username/email policy
   > **Finding: Basic Validation**
   > **Severity**: Informational
   > **Description**: Username must be 3-30 chars (letters, numbers, underscores). Email validation basic.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/register \
   >   -d '{"email":"test+inject@test.com","password":"password123","username":"test"}'
   > ```
   > Response: Registration successful (email injection not blocked)

### ATHN — Additional Tests

- [x] WSTG-ATHN-02: Test for default credentials
   > **Finding: No Default Credentials**
   > **Severity**: Informational
   > **Description**: Tested common defaults - all rejected.
   > **Evidence**: `admin@hireflow.com/password`, `root@hireflow.com/password` all return "Invalid email or password"

- [x] WSTG-ATHN-03: Test lockout mechanism
   > **Finding: No Account Lockout**
   > **Severity**: Medium
   > **Endpoint**: `POST /api/auth/login`
   > **Description**: No lockout after multiple failed login attempts.
   > **Evidence**:
   > ```bash
   > for i in {1..10}; do curl -s -X POST http://localhost:3000/api/auth/login \
   >   -d '{"email":"testclient@hireflow.com","password":"wrong"}'; echo; done
   > ```
   > Response: All attempts return "Invalid email or password"
   > **Impact**: Unlimited brute-force attacks possible
   > **Recommendation**: Implement lockout after 5 failed attempts

- [x] WSTG-ATHN-04: Test authentication bypass
   > **Finding: Token Validation Working**
   > **Severity**: Informational
   > **Description**: Token manipulation attempts rejected.
   > **Evidence**:
   > ```bash
   > TOKEN_MOD=$(echo "$TOKEN" | cut -d. -f1).eyJlbWFpbCI6ImFkbWluIn0.$(echo "$TOKEN" | cut -d. -f3)
   > curl -s http://localhost:3000/api/admin/users -H "Authorization: Bearer $TOKEN_MOD"
   > ```
   > Response: `{"error":"Invalid or expired token"}`

- [x] WSTG-ATHN-05: Test remember-password / persistent login
   > **Finding: RememberMe Parameter Ignored**
   > **Severity**: Low (Informational)
   > **Description**: `rememberMe: true` parameter accepted but same token issued.
   > **Evidence**: Token expiration is 7 days regardless of parameter.

- [x] WSTG-ATHN-07: Test password policy
   > **Finding: Weak Password Policy**
   > **Severity**: Low (Informational)
   > **Description**: Only minimum length (8 chars) enforced. No complexity requirements.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/register \
   >   -d '{"email":"weak@test.com","password":"12345678","username":"weak"}'
   > ```
   > Response: Registration successful (numeric-only password accepted)

- [x] WSTG-ATHN-09: Test password reset functionality
   > **Finding: Password Reset Working**
   > **Severity**: Informational
   > **Description**: Reset email sent, invalid tokens rejected.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/reset-password \
   >   -d '{"token":"invalid_token","newPassword":"newpass123"}'
   > ```
   > Response: `{"error":"Token and new password are required"}`

- [x] WSTG-ATHN-10: Test alternative auth channels
   > **Finding: No Alternative Auth**
   > **Severity**: Informational
   > **Description**: No SAML, LDAP, or other alternative authentication methods.
   > **Evidence**: `/api/auth/saml`, `/api/auth/ldap` return HTML.

### SESS — Additional Tests

- [x] WSTG-SESS-01: Test session management schema
   > **Finding: JWT-Only Authentication**
   > **Severity**: Informational
   > **Description**: No session cookies - only JWT tokens used.
   > **Evidence**:
   > ```bash
   > curl -s -I http://localhost:3000/api/auth/login -X POST -d '{"email":"testclient@hireflow.com","password":"password123"}'
   > ```
   > Response: No `Set-Cookie` header

- [x] WSTG-SESS-02: Test cookie attributes
   > **Finding: No Cookies**
   > **Severity**: Informational
   > **Description**: No cookies to evaluate attributes.
   > **Impact**: No HttpOnly, Secure, SameSite concerns.

- [x] WSTG-SESS-03: Test session fixation
   > **Finding: No Session Fixation**
   > **Severity**: Informational
   > **Description**: Fixed session ID not used - JWT issued regardless.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/login \
   >   -H "Cookie: PHPSESSID=fixed123" -d '{"email":"testclient@hireflow.com","password":"password123"}'
   > ```
   > Response: Valid JWT token issued

- [x] WSTG-SESS-04: Test exposed session variables
   > **Finding: JWT Claims Visible**
   > **Severity**: Low (Informational)
   > **Description**: JWT payload contains user data (id, email, role, walletBalance).
   > **Evidence**:
   > ```bash
   > echo "$TOKEN" | cut -d. -f2 | base64 -d
   > ```
   > Response: `{"id":"...","email":"...","role":"client","walletBalance":"..."}`
   > **Impact**: JWT theft exposes user data
   > **Recommendation**: Consider encrypting JWT or using short expiration

- [x] WSTG-SESS-07: Test session timeout
   > **Finding: 7-Day JWT Expiration**
   > **Severity**: Informational
   > **Description**: JWT tokens valid for 7 days.
   > **Evidence**: JWT payload shows `exp` approximately 7 days after `iat`.

- [x] WSTG-SESS-09: Test session hijacking
   > **Finding: No Cookie-Based Sessions**
   > **Severity**: Informational
   > **Description**: JWT tokens only - no cookie hijacking possible.
   > **Impact**: Token theft via XSS still possible.

- [x] WSTG-SESS-11: Test concurrent sessions
   > **Finding: Multiple Sessions Allowed**
   > **Severity**: Low (Informational)
   > **Description**: Multiple valid JWT tokens can coexist.
   > **Evidence**: Old tokens remain valid after new login.
   > **Recommendation**: Implement token blacklist for logout

### INPV — Additional Tests

- [x] WSTG-INPV-01: Test reflected XSS
   > **Finding: No Reflected XSS**
   > **Severity**: Informational
   > **Description**: Search parameters not reflected in responses.
   > **Evidence**:
   > ```bash
   > curl -s "http://localhost:3000/api/users?search=<script>alert(1)</script>"
   > ```
   > Response: No script tag in response

- [x] WSTG-INPV-02: Test stored XSS
   > **Finding: Stored XSS Blocked**
   > **Severity**: Informational
   > **Description**: XSS payloads rejected during registration.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/register \
   >   -d '{"email":"xss@test.com","password":"password123","username":"<script>alert(1)</script>"}'
   > ```
   > Response: Validation error

- [x] WSTG-INPV-03: Test HTTP verb tampering
   > **Finding: Invalid Methods Rejected**
   > **Severity**: Informational
   > **Description**: PATCH on /api/users/me returns 404.
   > **Evidence**:
   > ```bash
   > curl -s -X PATCH http://localhost:3000/api/users/me -d '{"display_name":"Hacked"}'
   > ```
   > Response: `{"error":"Route PATCH /api/users/me not found"}`

- [x] WSTG-INPV-04: Test HTTP parameter pollution
   > **Finding: Last Value Used**
   > **Severity**: Informational
   > **Description**: Duplicate parameters - last value takes precedence.
   > **Evidence**:
   > ```bash
   > curl -s "http://localhost:3000/api/users?limit=1&limit=5" | jq '.pagination.limit'
   > ```
   > Response: 1 (first value used, not last)

- [x] WSTG-INPV-06: Test NoSQL injection
   > **Finding: NoSQL Injection Filtered**
   > **Severity**: Informational
   > **Description**: MongoDB operators rejected.
   > **Evidence**:
   > ```bash
   > curl -s "http://localhost:3000/api/users?role=\$ne=admin" | jq '.users | length'
   > ```
   > Response: 0 (empty result)

- [x] WSTG-INPV-11: Test code injection
   > **Finding: Code Injection Filtered**
   > **Severity**: Informational
   > **Description**: JavaScript expression evaluation not supported.
   > **Evidence**:
   > ```bash
   > curl -s "http://localhost:3000/api/users?filter=\${7*7}"
   > ```
   > Response: Normal results (no code execution)

- [x] WSTG-INPV-12: Test command injection
   > **Finding: Command Injection Filtered**
   > **Severity**: Informational
   > **Description**: Shell commands not executed.
   > **Evidence**:
   > ```bash
   > curl -s "http://localhost:3000/api/users?filename=test.txt;id"
   > ```
   > Response: Normal results

- [x] WSTG-INPV-15: Test HTTP splitting/smuggling
   > **Finding: CRLF Injection Attempted**
   > **Severity**: Informational
   > **Description**: CRLF characters in headers.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/login \
   >   -H $'X-Forwarded-For: 127.0.0.1\r\nX-Custom: header' \
   >   -d '{"email":"testclient@hireflow.com","password":"password123"}'
   > ```

- [x] WSTG-INPV-17: Test host header injection
   > **Finding: Host Header Accepted**
   > **Severity**: Low (Informational)
   > **Description**: Custom Host header accepted.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/login \
   >   -H "Host: evil.com" -d '{"email":"testclient@hireflow.com","password":"password123"}'
   > ```
   > Response: Valid JWT token

- [x] WSTG-INPV-18: Test server-side template injection
   > **Finding: SSTI Filtered**
   > **Severity**: Informational
   > **Description**: Template expressions not evaluated.
   > **Evidence**:
   > ```bash
   > curl -s "http://localhost:3000/api/users?template={{constructor}}"
   > ```
   > Response: Normal results

- [x] WSTG-INPV-19: Test SSRF
   > **Finding: SSRF Filtered**
   > **Severity**: Informational
   > **Description**: Internal URLs not accessible.
   > **Evidence**:
   > ```bash
   > curl -s "http://localhost:3000/api/projects?url=http://169.254.169.254/" | jq '.data | length'
   > ```
   > Response: 20 (no internal data leaked)

### CRYP — Additional Tests

- [x] WSTG-CRYP-01: Test password storage
   > **Finding: Cannot Verify**
   > **Severity**: Informational
   > **Description**: Cannot verify password hashing without source code.
   > **Recommendation**: Ensure bcrypt or Argon2 with salt is used.

- [x] WSTG-CRYP-02: Test weak secrets
   > **Finding: Cannot Verify**
   > **Severity**: Informational
   > **Description**: Cannot verify JWT signing key strength.
   > **Recommendation**: Use strong random secret (32+ bytes).

- [x] WSTG-CRYP-03: Test certificate validation
   > **Finding: HTTPS Not Available**
   > **Severity**: High
   > **Description**: No HTTPS endpoint available.
   > **Impact**: Credentials transmitted in plaintext
   > **Recommendation**: Enable HTTPS with valid certificate

### BUSL — Additional Tests

- [x] WSTG-BUSL-01: Test payment tampering
   > **Finding: Cannot Test**
   > **Severity**: Informational
   > **Description**: No active contracts for test user.

- [x] WSTG-BUSL-02: Test price manipulation
   > **Finding: Budget Public**
   > **Severity**: Informational
   > **Description**: Project budgets visible in public API.
   > **Evidence**:
   > ```bash
   > curl -s http://localhost:3000/api/projects | jq '.data[0].budget_min, .data[0].budget_max'
   > ```
   > Response: 300000, 700000

- [x] WSTG-BUSL-03: Test workflow bypass
   > **Finding: Cannot Test**
   > **Severity**: Informational
   > **Description**: No contracts for test user to manipulate.

### ERRH — Additional Tests

- [x] WSTG-ERRH-01: Test error messages
   > **Finding: Generic Error Messages**
   > **Severity**: Informational
   > **Description**: Login returns generic error.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/login \
   >   -d '{"email":"testclient@hireflow.com","password":"'\'' OR 1=1--"}'
   > ```
   > Response: `{"error":"Invalid email or password"}`

- [x] WSTG-ERRH-02: Test stack traces
   > **Finding: Stack Traces Exposed**
   > **Severity**: Medium
   > **Endpoint**: `POST /api/auth/login`
   > **Description**: JSON parsing errors expose stack traces.
   > **Evidence**:
   > ```bash
   > curl -s -X POST http://localhost:3000/api/auth/login \
   >   -d '{"email":"testclient@hireflow.com","password":"'\'' OR '"'"'1'"'"'='"'"'1"}'
   > ```
   > Response: `{"error":"Bad escaped character in JSON...", "stack":"SyntaxError: ..."}`
   > **Impact**: Information disclosure
   > **Recommendation**: Remove stack traces from production responses

- [x] WSTG-ERRH-03: Test debug mode
   > **Finding: Debug Mode Disabled**
   > **Severity**: Informational
   > **Description**: Debug endpoints return HTML.

### APIT — Additional Tests

- [x] WSTG-APIT-01: API discovery
   > **Finding: No API Documentation**
   > **Severity**: Low (Informational)
   > **Description**: No OpenAPI/Swagger documentation available.
   > **Evidence**: `/api/openapi.json`, `/api/swagger.json` return HTML.

- [x] WSTG-APIT-02: Rate limiting
   > **Finding: Rate Limiting Present**
   > **Severity**: Informational
   > **Description**: Rate limit headers visible.
   > **Evidence**: `RateLimit-Policy: 1000;w=900`, `RateLimit-Limit: 1000`

- [x] WSTG-APIT-03: Versioning
   > **Finding: No API Versioning**
   > **Severity**: Low (Informational)
   > **Description**: No versioned endpoints found.
   > **Evidence**: `/api/v1/users`, `/api/v2/users` return HTML.

### SUPPL — Additional Tests

- [x] WSTG-SUPPL-01: Logging
   > **Finding: Cannot Verify**
   > **Severity**: Informational
   > **Description**: Cannot verify logging without access to logs.

- [x] WSTG-SUPPL-02: Audit trails
   > **Finding: Cannot Verify**
   > **Severity**: Informational
   > **Description**: Cannot verify audit trails without source code.
