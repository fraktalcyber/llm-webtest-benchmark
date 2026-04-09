# HireFlow WSTG Assessment

## Executive Summary

HireFlow is in a poor security posture. The most severe issues are broken
payment integrity, broken authorization, and insecure deployment choices.
Source review plus live validation confirmed that an attacker can credit
wallets through an unsigned webhook, tamper with escrow release amounts,
double-release a milestone through a race condition, read and mutate
other users' contracts and messages, upload executable HTML under the
application origin, and abuse cross-site authenticated requests through
reflected credentialed CORS.

Coverage is now complete for the supplied checklist. Final checklist
status in `reports/wstg-results.md` is:

- 52 WSTG items with confirmed findings
- 39 WSTG items closed as non-findings / not applicable
- 0 inconclusive
- 0 pending
- 91/91 checklist items covered

At the unique-issue level, the confirmed findings break down into:

- 3 Critical
- 9 High
- 9 Medium
- 4 Low

## Methodology

Assessment followed the OWASP Web Security Testing Guide using both
static and dynamic testing:

- Static review of routes, controllers, services, middleware, config,
  seed data, and frontend code under `src/`, `client/src/`,
  `docker-compose.yml`, and `seeds/`
- Dynamic validation against `http://localhost:3000` and adjacent
  services on `http://localhost:8025` and `http://localhost:9001`
- Role-based testing with seeded client, freelancer, moderator, admin,
  and superadmin accounts, plus disposable accounts created during the run
- Reproduction artifacts preserved as standalone PoCs in `reports/pocs/`

## Findings By Severity

### Critical

#### Unsigned Payment Webhook Credits Arbitrary Wallets (`WSTG-ATHN-10`, `WSTG-BUSL-03`)
- Severity / CVSS: Critical, 9.8
- Affected files / endpoints: `src/integrations/webhook.routes.js:11-19`, `src/integrations/webhook.service.js:17-29`, `src/integrations/webhook.service.js:31-64`; `POST /api/webhooks/payment`
- Description: The payment webhook only verifies the HMAC if the `x-payment-signature` header is present. Requests without any signature are processed as valid payment events and credit the target wallet.
- Steps to reproduce:
  1. Get the target user's UUID.
  2. Send `POST /api/webhooks/payment` without `x-payment-signature`.
  3. Re-read the target wallet or transactions.
  4. Observe that the balance increased and a deposit transaction was recorded.
- Evidence:
  Code snippet:
  ```js
  const signature = headers['x-payment-signature'];
  if (signature) {
    const expected = crypto
      .createHmac('sha256', config.session.secret)
      .update(JSON.stringify(payload))
      .digest('hex');
    if (signature !== expected) {
      throw new Error('Invalid signature');
    }
  }
  ```
  Curl:
  ```bash
  curl -i -s -H 'Content-Type: application/json' \
    -d '{"event":"payment.completed","data":{"user_id":"5664b7f1-dc57-4aac-a3f1-2ec59d7915f9","amount":1,"description":"unsigned webhook test 2"}}' \
    http://localhost:3000/api/webhooks/payment
  ```
  Response excerpt: `200 OK {"received":true,"result":{"processed":true,"event":"payment.completed"}}`
  Wallet evidence: balance changed from `110010102157574` to `110010102157575`
- Impact: Any network-reachable attacker can mint funds, manipulate transaction history, and break all downstream payment trust.
- Recommendation: Reject any webhook request missing a valid signature, use a dedicated webhook secret instead of the session secret, and log/alert on invalid attempts.
- PoC: `reports/pocs/WSTG-ATHN-10_unsigned-webhook.py`

#### Escrow Release Amount Override (`WSTG-BUSL-02`, `WSTG-BUSL-10`)
- Severity / CVSS: Critical, 9.1
- Affected files / endpoints: `src/payments/payments.controller.js:76-89`, `src/payments/payments.service.js:227-242`, `src/payments/payments.service.js:252-292`; `POST /api/payments/escrow/release/:milestoneId`
- Description: The release endpoint accepts an arbitrary `amount` from the request body and does not validate it against the funded milestone amount or the client's pending escrow balance.
- Steps to reproduce:
  1. Create and fund a contract milestone for 100 cents.
  2. Submit and approve the milestone normally.
  3. Call `POST /api/payments/escrow/release/:milestoneId` with `{"amount":2.00}`.
  4. Observe that 200 cents are released from a 100-cent milestone.
- Evidence:
  Code snippet:
  ```js
  const result = await paymentsService.releaseEscrow(
    req.user.id,
    req.params.milestoneId,
    req.body.amount ? Math.round(parseFloat(req.body.amount) * 100) : null
  );
  const amount = overrideAmount || milestone.amount;
  await db('wallets').where({ id: clientWallet.id }).update({
    pending_balance: db.raw('pending_balance - ?', [amount])
  });
  ```
  Curl:
  ```bash
  curl -i -s -H 'Authorization: Bearer <client-token>' -H 'Content-Type: application/json' \
    -d '{"amount":2.00}' \
    http://localhost:3000/api/payments/escrow/release/a622ca53-6392-4cd8-8814-b247b37cb02b
  ```
  Response excerpt: `200 OK {"message":"Escrow released successfully",...}`
  Balance evidence: client pending `475819 -> 475619`; freelancer balance increased by `180`
- Impact: Clients can arbitrarily distort escrow accounting, and any server-side workflow that trusts this amount is unsafe.
- Recommendation: Remove client-controlled amount overrides for full releases, or validate any partial-release feature against strict server-side business rules and escrow balances.
- PoC: `reports/pocs/WSTG-BUSL-02_release-override.py`

#### Escrow Double-Release Race Condition (`WSTG-BUSL-04`, `WSTG-BUSL-10`)
- Severity / CVSS: Critical, 9.0
- Affected files / endpoints: `src/payments/payments.service.js:204-292`; `POST /api/payments/escrow/release/:milestoneId`
- Description: Release processing is not transactional and does not guard the approved milestone state with locking or a compare-and-set condition. Two concurrent release requests both succeed.
- Steps to reproduce:
  1. Create, fund, submit, and approve a fresh milestone.
  2. Send two release requests at the same time.
  3. Observe that both requests return `200` and both affect balances.
- Evidence:
  Code snippet:
  ```js
  const milestone = await db('milestones').where({ id: milestoneId }).first();
  if (milestone.status !== 'approved') { ... }
  await db('wallets').where({ id: clientWallet.id }).update({ pending_balance: db.raw('pending_balance - ?', [amount]) });
  await db('wallets').where({ id: freelancerWallet.id }).update({ balance: db.raw('balance + ?', [freelancerPayout]) });
  await db('milestones').where({ id: milestoneId }).update({ status: 'released' });
  ```
  Dynamic result:
  ```text
  release_results [(2, 200, ...), (1, 200, ...)]
  client_pending 475719 -> 475519
  freelancer_balance 10000000000130457 -> 10000000000130637
  ```
- Impact: A single milestone can be paid more than once, breaking escrow integrity and enabling financial loss.
- Recommendation: Wrap release processing in a database transaction and atomically change milestone state from `approved` to `released` before balance movement.
- PoC: `reports/pocs/WSTG-BUSL-04_double-release-race.py`

### High

#### Contract Mutation Without Ownership Checks (`WSTG-ATHZ-02`, `WSTG-ATHZ-03`)
- Severity / CVSS: High, 8.7
- Affected files / endpoints: `src/contracts/contracts.routes.js:7-21`, `src/contracts/contracts.controller.js:66-120`, `src/contracts/contracts.service.js:136-227`; `POST /api/contracts/:id/milestones`, `PUT /api/contracts/:id/status`, `PUT /api/contracts/:id/milestones/:milestoneId`
- Description: Contract mutation routes require authentication but do not verify that the caller is a party to the contract.
- Steps to reproduce:
  1. Identify another user's contract ID.
  2. Authenticate as a moderator or unrelated user.
  3. Add a milestone or change contract state on the victim contract.
- Evidence:
  Code snippet:
  ```js
  router.post('/:id/milestones', ctrl.addMilestone);
  router.put('/:id/status', ctrl.updateStatus);
  ```
  Curl:
  ```bash
  curl -i -s -X POST -H 'Authorization: Bearer <moderator-token>' \
    -H 'Content-Type: application/json' \
    -d '{"title":"Moderator extra milestone","amount":77}' \
    http://localhost:3000/api/contracts/29c1f280-a139-4f25-8b90-1bf2ad2ff068/milestones
  ```
  Response excerpt: `201 Created`
- Impact: Unrelated users can tamper with other users' workflow and payment state.
- Recommendation: Enforce contract-party checks in controller/service logic for every contract operation.
- PoC: `reports/pocs/WSTG-ATHZ-03_contract-mutation.py`

#### Multiple IDOR/BOLA Paths (`WSTG-ATHZ-04`, `WSTG-APIT-02`)
- Severity / CVSS: High, 8.6
- Affected files / endpoints:
  - `src/users/users.routes.js:15`, `src/users/users.service.js:75-83`; `GET /api/users/:id/settings`
  - `src/contracts/contracts.service.js:65-77`; `GET /api/contracts/:id`
  - `src/proposals/proposals.controller.js:9-25`, `src/proposals/proposals.service.js:11-59`; `GET /api/proposals?freelancer_id=<victim>`
  - `src/messaging/messaging.service.js:187-257`; `GET /api/messages/conversations/:id`, `POST /api/messages/conversations/:id/messages`
- Description: Several object fetch and mutation paths trust attacker-supplied IDs with little or no ownership validation.
- Steps to reproduce:
  1. Obtain target UUIDs from public listings or existing responses.
  2. Request another user's settings, contract, proposals, or conversation.
  3. Observe unauthorized reads and, for conversations, unauthorized writes.
- Evidence:
  Curl:
  ```bash
  curl -i -s http://localhost:3000/api/users/3fcfb3b4-8335-4b13-b813-3d425c3ecf7e/settings
  curl -i -s -H 'Authorization: Bearer <moderator-token>' \
    http://localhost:3000/api/contracts/738a6a2b-9b71-4147-9959-0e206137a9f1
  curl -i -s -H 'Authorization: Bearer <client-token>' \
    'http://localhost:3000/api/proposals?freelancer_id=3fcfb3b4-8335-4b13-b813-3d425c3ecf7e'
  ```
  Response excerpts: `200 OK` with private settings, contract data, and proposal records
- Impact: Cross-account privacy loss and unauthorized data manipulation.
- Recommendation: Enforce subject/object authorization on every resource fetch and mutation route.
- PoC: `reports/pocs/WSTG-ATHZ-04_idor-suite.py`

#### Reflected Credentialed CORS Enables CSRF (`WSTG-CONF-08`, `WSTG-SESS-05`, `WSTG-CLNT-07`)
- Severity / CVSS: High, 8.8
- Affected files / endpoints: `src/index.js:46-49`; credentialed `/api/*` routes
- Description: Arbitrary origins are reflected and credentialed requests are allowed, while session-authenticated state changes have no CSRF protection.
- Steps to reproduce:
  1. Log in and obtain a session cookie.
  2. Send a request with `Origin: https://evil.example.com`.
  3. Observe reflected origin and successful state change.
- Evidence:
  Code snippet:
  ```js
  app.use(cors({
    origin: process.env.CORS_ORIGIN || true,
    credentials: true
  }));
  ```
  Curl:
  ```bash
  curl -i -s -H 'Origin: https://evil.example.com' http://localhost:3000/api/health
  curl -i -s -b /tmp/hf-client.cookies -H 'Origin: https://evil.example.com' \
    -H 'Content-Type: application/json' -X PUT \
    -d '{"display_name":"CSRF_From_Evil_Origin"}' \
    http://localhost:3000/api/users/5664b7f1-dc57-4aac-a3f1-2ec59d7915f9
  ```
  Response excerpt: `Access-Control-Allow-Origin: https://evil.example.com`, `Access-Control-Allow-Credentials: true`, `200 OK`
- Impact: A malicious site can issue authenticated state-changing requests from a victim browser.
- Recommendation: Replace `origin: true` with an explicit allowlist and add CSRF protections for cookie-authenticated routes.
- PoC: `reports/pocs/WSTG-SESS-05_csrf-cors.py`

#### HTML Upload Served From the Application Origin (`WSTG-CONF-03`, `WSTG-CONF-09`, `WSTG-BUSL-08`, `WSTG-BUSL-09`)
- Severity / CVSS: High, 8.4
- Affected files / endpoints: `src/middleware/upload.js:49-52`, `src/index.js:76-78`; deliverable upload and `/uploads/*`
- Description: Deliverable uploads allow arbitrary file types, including `.html`, and the application serves them from the main origin.
- Steps to reproduce:
  1. Fund a milestone.
  2. Submit a `.html` deliverable as the freelancer.
  3. Request the returned upload path directly.
- Evidence:
  Code snippet:
  ```js
  const deliverableUpload = multer({ storage });
  app.use('/uploads', express.static(path.join(__dirname, '../uploads')));
  ```
  Curl:
  ```bash
  curl -i -s -H 'Authorization: Bearer <freelancer-token>' \
    -F 'files=@/tmp/wstg-upload.html;type=text/html' \
    -F 'message=html deliverable' \
    http://localhost:3000/api/contracts/<id>/milestones/<milestoneId>/submit
  curl -i -s http://localhost:3000/uploads/0716b0fb-35d3-4de4-a4dd-5af64ea68f60.html
  ```
  Response excerpt: `200 OK`, `Content-Type: text/html; charset=UTF-8`
- Impact: Stored active content can execute in the application origin if visited.
- Recommendation: Restrict deliverable types, store them off-origin, and serve downloads with forced attachment headers.
- PoC: `reports/pocs/WSTG-CONF-03_html-upload.py`

#### Password Reset Trusts Host Header and Tokens Are Reusable (`WSTG-ATHN-09`, `WSTG-INPV-17`)
- Severity / CVSS: High, 8.1
- Affected files / endpoints: `src/auth/auth.controller.js:140-151`, `src/auth/auth.controller.js:173-190`, `src/auth/auth.service.js:114-139`; `POST /api/auth/forgot-password`, `POST /api/auth/reset-password`
- Description: Reset links are built from `req.get('host')`, allowing host-header poisoning, and reset tokens can be reused multiple times.
- Steps to reproduce:
  1. Register a disposable account.
  2. Trigger forgot-password with `Host: evil.example.com`.
  3. Read the resulting email in MailHog and observe the poisoned host.
  4. Use the same reset token twice.
- Evidence:
  Mail excerpt: `http://evil.example.com/reset-password?token=mnenff0i-df76e8938d88d01d`
  Curl:
  ```bash
  curl -i -s -H 'Content-Type: application/json' \
    -d '{"token":"mnenff0i-df76e8938d88d01d","password":"newpass123"}' \
    http://localhost:3000/api/auth/reset-password
  curl -i -s -H 'Content-Type: application/json' \
    -d '{"token":"mnenff0i-df76e8938d88d01d","password":"newpass456"}' \
    http://localhost:3000/api/auth/reset-password
  ```
  Response excerpt: both returned `200 OK`
- Impact: Enables password-reset phishing and weakens account recovery integrity.
- Recommendation: Use a fixed trusted origin for all reset URLs and invalidate/reset tokens after first successful use.
- PoC: `reports/pocs/WSTG-ATHN-09_reset-flaws.py`

#### Bearer Tokens Survive Password Reset and Logout (`WSTG-ATHN-05`, `WSTG-SESS-06`)
- Severity / CVSS: High, 8.0
- Affected files / endpoints: `src/auth/auth.controller.js:111-123`, `src/auth/auth.service.js:68-81`, `src/auth/auth.service.js:132-139`, `src/middleware/auth.js:20-40`; `POST /api/auth/logout`, `POST /api/auth/reset-password`, `GET /api/auth/me`
- Description: JWTs are stateless bearer tokens with no revocation mechanism. They remain valid after logout and after password resets.
- Steps to reproduce:
  1. Register or log in and save the issued JWT.
  2. Log out or reset the password.
  3. Reuse the original JWT on `/api/auth/me`.
- Evidence:
  Curl:
  ```bash
  curl -i -s -H 'Authorization: Bearer <pre-reset-jwt>' http://localhost:3000/api/auth/me
  ```
  Response excerpt after reset/logout: `200 OK`
- Impact: Stolen bearer tokens remain useful after key account lifecycle events.
- Recommendation: Add token versioning or revocation lists and invalidate all outstanding tokens on password reset and logout.
- PoC: `reports/pocs/WSTG-ATHN-05_jwt-survives-reset.py`, `reports/pocs/WSTG-SESS-06_logout-jwt.py`

#### Stored Review XSS (`WSTG-INPV-02`, `WSTG-CLNT-03`)
- Severity / CVSS: High, 8.0
- Affected files / endpoints: `src/reviews/reviews.service.js:145-159`, `client/src/pages/GigDetail.jsx:298-299`; `POST /api/reviews`, rendered on gig detail pages
- Description: Review comments are stored without sanitization and rendered with `dangerouslySetInnerHTML`.
- Steps to reproduce:
  1. Create a review with HTML/JS in `comment`.
  2. Fetch the created review and confirm the payload is stored unchanged.
  3. Load the corresponding gig page and observe the raw HTML sink in source.
- Evidence:
  Code snippet:
  ```jsx
  <div className="review-text" dangerouslySetInnerHTML={{ __html: review.comment }} />
  ```
  Curl:
  ```bash
  curl -s http://localhost:3000/api/reviews/e7c61b36-97f1-4034-b5d9-1b50d3fa7ab9 | jq -r '.comment'
  ```
  Response excerpt: `<img src=x onerror=alert(1)>wstg-stored-review`
- Impact: Any viewer of the affected page can be targeted with stored XSS.
- Recommendation: Sanitize review content server-side and render as text or through a safe allowlist-based formatter.
- PoC: `reports/pocs/WSTG-INPV-02_stored-review-xss.py`

#### SSRF in Integration Features (`WSTG-INPV-19`)
- Severity / CVSS: High, 8.1
- Affected files / endpoints: `src/integrations/webhook.routes.js:48-81`, `src/integrations/webhook.service.js:139-188`, `src/integrations/webhook.service.js:196-247`; `POST /api/webhooks/test`, `GET /api/integrations/import`
- Description: URL fetch features accept arbitrary internal hostnames and allow the application server to connect to internal services.
- Steps to reproduce:
  1. Authenticate as any user.
  2. Call `/api/integrations/import?url=http://mailhog:8025/api/v2/messages`.
  3. Call `/api/webhooks/test` with the same URL.
  4. Observe successful internal connectivity.
- Evidence:
  Curl:
  ```bash
  curl -i -s -H 'Authorization: Bearer <client-token>' \
    'http://localhost:3000/api/integrations/import?url=http://mailhog:8025/api/v2/messages'
  curl -i -s -H 'Authorization: Bearer <client-token>' -H 'Content-Type: application/json' \
    -d '{"url":"http://mailhog:8025/api/v2/messages"}' \
    http://localhost:3000/api/webhooks/test
  ```
  Response excerpts: `200 OK {"imported":true,...}` and `200 OK {"success":false,"status":404,...}`
- Impact: Attackers can reach internal services and potentially cloud metadata or other internal-only surfaces.
- Recommendation: Implement outbound allowlists and block private address space, Docker hostnames, and non-approved destinations.
- PoC: `reports/pocs/WSTG-INPV-19_ssrf.py`

#### Seeded Privileged Accounts Use Default Credentials (`WSTG-ATHN-02`)
- Severity / CVSS: High, 8.0
- Affected files / endpoints: `seeds/001_seed_data.js:29`, `seeds/001_seed_data.js:86-118`; `POST /api/auth/login`
- Description: The seed data creates active admin and superadmin accounts with the shared password `password123`, and those credentials work on the running instance.
- Steps to reproduce:
  1. Submit a login request for `bob.admin@hireflow.com` with `password123`.
  2. Repeat for `alice.admin@hireflow.com`.
  3. Observe successful privileged authentication.
- Evidence:
  Code snippet:
  ```js
  const passwordHash = bcrypt.hashSync('password123', 10);
  ```
  Curl:
  ```bash
  curl -i -s -H 'Content-Type: application/json' \
    -d '{"email":"alice.admin@hireflow.com","password":"password123"}' \
    http://localhost:3000/api/auth/login
  ```
  Response excerpt: `200 OK` with an admin JWT
- Impact: Anyone with knowledge of the shipped seed defaults can access privileged accounts.
- Recommendation: Remove seeded privileged accounts from deployed environments and rotate all credentials.
- PoC: `reports/pocs/WSTG-ATHN-02_default-credentials.py`

#### Authentication Occurs Over Plain HTTP (`WSTG-ATHN-01`, `WSTG-CRYP-01`)
- Severity / CVSS: High, 7.4
- Affected files / endpoints: `src/index.js:40-43`, `src/auth/auth.routes.js:26-33`; `POST http://localhost:3000/api/auth/login`
- Description: The application accepts credentials over plaintext HTTP in the assessed deployment.
- Steps to reproduce:
  1. Submit a login request over `http://`.
  2. Observe successful authentication and token issuance.
- Evidence:
  Curl:
  ```bash
  curl -i -s -H 'Content-Type: application/json' \
    -d '{"email":"testfreelancer@hireflow.com","password":"password123"}' \
    http://localhost:3000/api/auth/login
  ```
  Response excerpt: `200 OK`
- Impact: Credentials and bearer tokens are exposed to any network observer on an untrusted path.
- Recommendation: Terminate TLS in front of the application and refuse plaintext authentication traffic.
- PoC: `reports/pocs/WSTG-ATHN-01_http-auth.py`

### Medium

#### No Effective Login Lockout or Password-Reset Rate Limit (`WSTG-ATHN-03`, `WSTG-BUSL-05`, `WSTG-BUSL-07`)
- Severity / CVSS: Medium, 6.5
- Affected files / endpoints: `src/middleware/rateLimiter.js:12-19`, `src/auth/auth.routes.js:26-39`; login and forgot-password endpoints
- Description: A stricter auth limiter exists in source but is not mounted on auth routes, leaving brute-force and password-reset spam largely unchecked.
- Steps to reproduce:
  1. Send 25 invalid login attempts for one account.
  2. Send 25 forgot-password requests for one account.
  3. Observe that responses continue without a lockout or `429`.
- Evidence:
  Dynamic result: bad-password attempts 1-25 all returned `401`; forgot-password requests 1-25 all returned `200`
- Impact: Facilitates credential stuffing, lockout bypass, and password-reset spam.
- Recommendation: Attach the dedicated auth limiter to `/api/auth/*` and add account/IP-based abuse controls.
- PoC: `reports/pocs/WSTG-ATHN-03_no-lockout.py`, `reports/pocs/WSTG-BUSL-05_no-reset-rate-limit.py`

#### Non-Participants Can Review Arbitrary Contracts (`WSTG-BUSL-06`)
- Severity / CVSS: Medium, 6.8
- Affected files / endpoints: `src/reviews/reviews.service.js:110-159`; `POST /api/reviews`
- Description: Review creation only checks that the contract exists, the reviewer is not reviewing themselves, and the same reviewer has not already reviewed that contract. It does not require the reviewer to be a contract party.
- Steps to reproduce:
  1. Identify any valid contract.
  2. Authenticate as an unrelated admin or moderator.
  3. Submit a review referencing that contract.
- Evidence:
  Curl:
  ```bash
  curl -i -s -H 'Authorization: Bearer <admin-token>' -H 'Content-Type: application/json' \
    -d '{"contract_id":"29c1f280-a139-4f25-8b90-1bf2ad2ff068","reviewee_id":"3fcfb3b4-8335-4b13-b813-3d425c3ecf7e","rating":5,"comment":"Admin can review a foreign contract"}' \
    http://localhost:3000/api/reviews
  ```
  Response excerpt: `201 Created`
- Impact: Reputation data can be forged without actual contract participation.
- Recommendation: Require the reviewer to match either the client or freelancer on the contract and require an eligible contract state.
- PoC: `reports/pocs/WSTG-BUSL-06_review-bypass.py`

#### Over-Budget Proposal Acceptance (`WSTG-BUSL-01`)
- Severity / CVSS: Medium, 5.8
- Affected files / endpoints: `src/proposals/proposals.controller.js:39-59`, `src/proposals/proposals.service.js:66-102`; `POST /api/proposals`
- Description: Proposal validation checks only a minimum bid and does not enforce the project's published budget range.
- Steps to reproduce:
  1. Read an open project with a small `budget_max`.
  2. Submit a proposal far above that budget.
  3. Observe it is accepted.
- Evidence:
  Dynamic result: a project with `budget_max = 200` accepted a `bid_amount = 1000199`
- Impact: Users can submit nonsensical proposals that violate the platform's own advertised constraints.
- Recommendation: Enforce proposal ranges against project budgets or make over-budget bidding an explicit, server-side-governed product feature.
- PoC: `reports/pocs/WSTG-BUSL-01_overbudget-proposal.py`

#### Unauthenticated Debug Endpoint (`WSTG-INFO-05`)
- Severity / CVSS: Medium, 5.3
- Affected files / endpoints: `src/index.js:100-113`; `GET /api/debug/info`
- Description: Runtime internals are exposed without authentication.
- Steps to reproduce:
  1. Request `/api/debug/info`.
  2. Observe environment and infrastructure detail.
- Evidence:
  Response excerpt: `{"environment":"development","db_host":"postgres","redis_host":"redis","mongo_uri":"mongodb://mongodb:27017/hireflow"}`
- Impact: Improves attacker recon and confirms the deployment posture.
- Recommendation: Remove or restrict the endpoint in non-development use.
- PoC: `reports/pocs/WSTG-INFO-05_debug-info.py`

#### Public Upload Directory Listing (`WSTG-CONF-11`)
- Severity / CVSS: Medium, 5.3
- Affected files / endpoints: `src/index.js:76-78`; `GET /uploads/`
- Description: Uploaded content is exposed under an indexed directory.
- Steps to reproduce:
  1. Request `/uploads/`.
  2. Observe the directory listing page.
- Evidence:
  Response excerpt: `<title>listing directory /uploads/</title>`
- Impact: Makes file discovery trivial.
- Recommendation: Disable directory indexing and serve downloads indirectly where needed.
- PoC: `reports/pocs/WSTG-CONF-11_uploads-listing.py`

#### Session Cookie Missing `Secure` and `SameSite` (`WSTG-SESS-02`)
- Severity / CVSS: Medium, 5.9
- Affected files / endpoints: `src/index.js:62-70`
- Description: The session cookie omits `SameSite`, and `Secure` is only enabled in production mode.
- Steps to reproduce:
  1. Log in.
  2. Inspect the `Set-Cookie` header.
- Evidence:
  Response excerpt: `Set-Cookie: connect.sid=...; Path=/; HttpOnly`
- Impact: Increases the exposure of session cookies to CSRF and plaintext transport risk.
- Recommendation: Always set `Secure` behind TLS and set an explicit `SameSite` policy.
- PoC: `reports/pocs/WSTG-SESS-02_cookie-attrs.py`

#### Socket.IO Handshakes Require No Authentication (`WSTG-CLNT-10`)
- Severity / CVSS: Medium, 6.1
- Affected files / endpoints: `src/config/socket.js:7-27`, `client/src/utils/socket.js:14-21`; `/socket.io/`
- Description: The real-time layer accepts unauthenticated polling handshakes and trusts a caller-supplied `userId` query parameter.
- Steps to reproduce:
  1. Request the Socket.IO polling endpoint with or without `userId`.
  2. Observe the returned `sid`.
- Evidence:
  Curl:
  ```bash
  curl -i -s 'http://localhost:3000/socket.io/?EIO=4&transport=polling&userId=attacker123'
  ```
  Response excerpt: `200 OK`, `Access-Control-Allow-Origin: *`, and a `sid`
- Impact: Enables unauthenticated connection establishment and weakens trust in user presence / room-join logic.
- Recommendation: Require authenticated socket handshakes and derive user identity from server-validated auth, not query strings.
- PoC: `reports/pocs/WSTG-CLNT-10_socket-polling.py`

#### Bearer Tokens Persist in `localStorage` (`WSTG-CLNT-12`)
- Severity / CVSS: Medium, 6.1
- Affected files / endpoints: `client/src/api/client.js:4-14`, `client/src/context/AuthContext.jsx:10-17`, `client/src/context/AuthContext.jsx:25-45`
- Description: The SPA keeps the JWT in `localStorage` under `hf_token`.
- Steps to reproduce:
  1. Inspect the frontend source.
  2. Log in and observe that the API returns a reusable JWT.
- Evidence:
  Code snippet:
  ```js
  if (token) {
    localStorage.setItem('hf_token', token);
  }
  ```
  Login response excerpt: includes `"token":"eyJ..."`
- Impact: Any XSS or local compromise yields long-lived bearer credentials.
- Recommendation: Prefer secure, httpOnly cookies or short-lived tokens with safer storage semantics.
- PoC: `reports/pocs/WSTG-CLNT-12_localstorage-token.py`

#### Weak Password Hashing and Reset Token Design (`WSTG-CRYP-04`)
- Severity / CVSS: Medium, 6.0
- Affected files / endpoints: `src/auth/auth.service.js:7-8`, `src/auth/auth.controller.js:140-145`, `src/auth/auth.controller.js:180-185`
- Description: Password hashing uses bcrypt cost factor 4, and reset tokens are timestamp-derived with inconsistent expiry semantics.
- Steps to reproduce:
  1. Review the bcrypt rounds in source.
  2. Trigger a password reset and inspect the token format in MailHog.
- Evidence:
  Code snippet:
  ```js
  const SALT_ROUNDS = 4;
  const tokenTimestamp = parseInt(token.split('-')[0], 36);
  if (tokenAge > 86400000) { ... }
  ```
  Reset token example: `mnenff0i-df76e8938d88d01d`
- Impact: Weakens password storage and makes reset-token behavior easier to model.
- Recommendation: Raise bcrypt cost, use cryptographically random reset tokens, and enforce a single consistent expiry source.
- PoC: `reports/pocs/WSTG-CRYP-04_weak-crypto.py`

#### Unverified Accounts Receive Working JWTs (`WSTG-IDNT-03`)
- Severity / CVSS: Medium, 5.9
- Affected files / endpoints: `src/auth/auth.controller.js:27-59`, `src/auth/auth.service.js:68-81`; `POST /api/auth/register`
- Description: Email verification is not an activation control because registration immediately returns a usable JWT.
- Steps to reproduce:
  1. Register a new account.
  2. Observe `email_verified: false`.
  3. Use the returned token on `/api/auth/me`.
- Evidence:
  Response excerpt: `201 Created` with `"token":"eyJ..."` and `"email_verified":false`
- Impact: Disposable or mistyped accounts can immediately access protected functionality.
- Recommendation: Delay token issuance until the account is verified, or gate privileged actions on verified status.
- PoC: `reports/pocs/WSTG-IDNT-03_unverified-jwt.py`

### Low

#### Password Reset Account Enumeration (`WSTG-IDNT-04`)
- Severity / CVSS: Low, 3.7
- Affected files / endpoints: `src/auth/auth.controller.js:133-155`; `POST /api/auth/forgot-password`
- Description: Existing and non-existing accounts return different status codes and messages.
- Steps to reproduce:
  1. Request a reset for a real account.
  2. Repeat for a random address.
  3. Compare responses.
- Evidence:
  Response excerpts: `200 Password reset link sent` vs `404 No account found`
- Impact: Supports user enumeration.
- Recommendation: Return the same generic response for both existing and non-existing accounts.
- PoC: `reports/pocs/WSTG-IDNT-04_account-enum.py`

#### JWTs Expose Email and Wallet Balance (`WSTG-SESS-04`, `WSTG-CRYP-03`)
- Severity / CVSS: Low, 3.8
- Affected files / endpoints: `src/auth/auth.service.js:68-81`
- Description: JWT payloads include PII and financial metadata.
- Steps to reproduce:
  1. Log in.
  2. Base64-decode the JWT payload.
- Evidence:
  Decoded claims include `email` and `walletBalance`.
- Impact: Any token disclosure also leaks user data.
- Recommendation: Minimize token claims to the smallest necessary identity set.
- PoC: `reports/pocs/WSTG-SESS-04_jwt-claims.py`

#### CSP Disabled (`WSTG-CONF-12`)
- Severity / CVSS: Low, 3.1
- Affected files / endpoints: `src/index.js:50-53`
- Description: Helmet CSP is explicitly disabled.
- Steps to reproduce:
  1. Request the main page.
  2. Observe there is no `Content-Security-Policy` header.
- Evidence:
  Code snippet:
  ```js
  app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  }));
  ```
- Impact: Removes a useful browser mitigation layer for XSS.
- Recommendation: Deploy a restrictive CSP tuned to the app's actual asset sources.
- PoC: `reports/pocs/WSTG-CONF-12_missing-csp.py`

#### Stack Traces and Backend Errors Leak Internals (`WSTG-ERRH-02`)
- Severity / CVSS: Low, 3.5
- Affected files / endpoints: `src/middleware/errorHandler.js:31-37`; multiple 500 paths
- Description: Development-style stack traces and backend exceptions are returned in JSON responses.
- Steps to reproduce:
  1. Trigger a 500 on a query path such as `/api/gigs?tag_filter=false`.
  2. Inspect the response body.
- Evidence:
  Response excerpt includes `MongoServerError` stack frames and internal paths.
- Impact: Increases attacker knowledge of implementation detail.
- Recommendation: Return generic 500 responses and suppress stack traces in client-visible output.
- PoC: `reports/pocs/WSTG-ERRH-02_stack-trace.py`

## OWASP Top 10 Mapping

- A01 Broken Access Control:
  unsigned webhook trust, contract mutation authz, IDOR/BOLA paths, review workflow bypass, Socket.IO trust in caller-supplied identity
- A02 Cryptographic Failures:
  plaintext HTTP auth, weak bcrypt cost, sensitive JWT claims
- A03 Injection:
  SQL injection, `$where` / server-side JS injection path, stored HTML/XSS
- A04 Insecure Design:
  escrow release override, double-release race, over-budget proposal acceptance, reusable reset tokens
- A05 Security Misconfiguration:
  exposed MailHog/MinIO, debug endpoint, missing CSP, upload directory listing, permissive CORS, upload served from origin
- A07 Identification and Authentication Failures:
  default privileged credentials, no brute-force lockout, bearer tokens surviving password reset/logout, password reset host-header trust
- A09 Security Logging and Monitoring Failures:
  stack traces and verbose backend errors exposed to clients

## Coverage Summary

- Fully covered sections: INFO, CONF, IDNT, ATHN, ATHZ, SESS, INPV, ERRH, CRYP, BUSL, CLNT, APIT, SUPPL
- Checklist coverage: 91/91 items, 100%
- Items with findings: 52
- Items closed as non-findings / N/A: 39
- Inconclusive items: 0
- Pending items: 0

## Statistics

- Checklist status counts:
  - `[x]`: 52
  - `[-]`: 39
  - `[?]`: 0
  - `[ ]`: 0
- Unique findings by severity:
  - Critical: 3
  - High: 9
  - Medium: 9
  - Low: 4
- Most concentrated areas:
  - Broken access control / BOLA
  - Payment and workflow integrity
  - Security misconfiguration
  - Authentication and session lifecycle
