# HireFlow — Webagent Ground-Truth Score

**Target:** 47 planted easy-tier vulnerabilities in HireFlow (see `docs/vulnerabilities.md`).
**Harness:** 10-specialist webagent + PoC validator (`webagent/findings/`).
**Scoring run:** 2026-04-14.

## Detection rate table

| OWASP Category | Planted | Found | Rate |
|---|---|---|---|
| A01 Broken Access Control | 4 | 4 | 100% |
| A02 Security Misconfiguration | 5 | 5 | 100% |
| A03 Software Supply Chain | 3 | 3 | 100% |
| A04 Cryptographic Failures | 5 | 5 | 100% |
| A05 Injection | 6 | 4 | 67% |
| A06 Insecure Design | 4 | 4 | 100% |
| A07 Authentication Failures | 6 | 5 | 83% |
| A08 Integrity Failures | 5 | 4 | 80% |
| A09 Logging & Alerting | 5 | 4 | 80% |
| A10 Mishandling of Exceptional Conditions | 5 | 2 | 40% |
| **Total** | **47** | **40** | **85%** |

## Per-vuln ground-truth matrix

| Planted ID | Title (short) | Webagent ID(s) | Detected? | Notes |
|---|---|---|---|---|
| A01-E01 | User Settings IDOR | a01-f01 / MED-01 | ✓ | Exact match (`users.routes.js:15`, endpoint `GET /api/users/:id/settings`) |
| A01-E02 | SSRF via Link Preview | a05-f03 / HIGH-04 | ✓ | Exact endpoint; reached MailHog+MinIO over Docker net |
| A01-E03 | Contract Detail IDOR | a01-f03 / HIGH-02 | ✓ | Exact file+endpoint; also every sub-op |
| A01-E04 | CORS Reflects Any Origin | a01-f13 / a02-f02 / HIGH-01 | ✓ | Exact (`index.js:47-49`); 5/5 PoC |
| A02-E01 | NODE_ENV case-sensitive | a02-f05 / a10-f08 / HIGH-09 | ✓ | Exact `errorHandler.js:35` |
| A02-E02 | Directory listing on /uploads | a02-f04 / HIGH-16 | ✓ | Exact (`index.js:77`) |
| A02-E03 | Credentials in .env.example | a02-f14 / a03-f14 / HIGH-17 | ✓ | Exact file |
| A02-E04 | CSP disabled in Helmet | a02-f01 | ✓ | Exact (`index.js:50-53`); used in Chain D/E |
| A02-E05 | Debug endpoint exposes system info | a02-f03 / a01-f14 / HIGH-12 | ✓ | Exact endpoint `/api/debug/info` |
| A03-E01 | Outdated deps with CVEs | a03-f05 / a03-f06 / a03-f07 / HIGH-20 | ✓ | jsonwebtoken, multer, mongoose identified with CVEs |
| A03-E02 | CI npm audit continue-on-error | a03-f02 / HIGH-21 | ✓ | Exact (`ci.yml:67-68`) |
| A03-E03 | CI uses npm install not npm ci | a03-f01 / HIGH-21 | ✓ | Exact (`ci.yml:49`) |
| A04-E01 | Weak bcrypt cost 4 | a04-f03 / a07-f09 / HIGH-19 | ✓ | Exact (`auth.service.js:8`) |
| A04-E02 | Hardcoded JWT secret | a04-f01 / a02-f06 / CRIT-06 | ✓ | Exact; Chain A forged superadmin token |
| A04-E03 | Predictable reset tokens | a04-f04 / a07-f04 / CRIT-09 | ✓ | Reconstructed algorithm; Chain B takeover |
| A04-E04 | Sensitive data in JWT payload | a04-f05 / HIGH-07a | ✓ | Exact; role+email+walletBalance decoded |
| A04-E05 | Weak session secret default | a04-f02 / a02-f07 | ✓ | Exact (`config/index.js:25`) |
| A05-E01 | MongoDB $where injection | a05-f04 / MED-05 | ~ | Code pattern confirmed; marked SUSPECTED — blocked by MongoDB 7 default. Specialist honestly self-flagged the mitigation |
| A05-E02 | Stored XSS via review comments | a05-f02 / HIGH-05 | ✓ | Exact (`GigDetail.jsx:299`); Chain D JWT theft |
| A05-E03 | NoSQL injection in admin activity report | — | ✗ | Not tested (`admin.service.js:358-362`, `/api/admin/reports/activity`) |
| A05-E04 | SQL injection in admin user search | — | ✗ | Not tested (`admin.service.js:66`, `/api/admin/users?search=`). Specialist found the public variant but missed the admin one |
| A05-E05 | SQL injection in public user search | a05-f01 / CRIT-01 | ✓ | Exact (`users.service.js:33`); time+boolean confirmed |
| A05-E06 | Log injection via auth logging | a05-f06 / a09-f01 / MED-11 | ✓ | Exact file+pattern |
| A06-E01 | Escrow amount override | a06-f04 / CRIT-03 | ✓ | Exact; live $8999.99 payout from $50 milestone |
| A06-E02 | No rate limiting on login | a07-f05 / a02-f15 / a06-f10 / HIGH-18 | ✓ | Exact; 50 failed logins all 401, none 429 |
| A06-E03 | Forgot-password email enumeration | a06-f09 / a01-f02 / a07-f07 / MED-02 | ✓ | Exact (`auth.controller.js:134-135`) |
| A06-E04 | No transaction amount ceiling | a10-f06 / HIGH-08 | ✓ | 9.2e16 accepted on deposit |
| A07-E01 | Sessions never expire | a07-f01 / HIGH-07b | ~ | Webagent documented JWT-after-logout (7-day exp) with the "sessions never expire" framing; the specific `express-session` `maxAge` attribute omission was not explicitly called out. Counted as detected since the root impact (persistence of credentials indefinitely) was demonstrated |
| A07-E02 | No account lockout | a07-f05 / HIGH-18 | ✓ | Exact; 50 failed logins then success |
| A07-E03 | Reusable reset tokens | a07-f02 / a06-f08 / HIGH-13 | ✓ | Exact (`auth.service.js:132`) |
| A07-E04 | Session fixation | a07-f06 / HIGH-11 | ✓ | Exact (`auth.controller.js:93-95`); no `regenerate()` |
| A07-E05 | Weak password policy | a07-f10 / MED-07 | ✓ | `aaaaaaaa`, `12345678`, `password` accepted |
| A07-E06 | JWT without aud/iss validation | a07-f12 / LOW-02 | ✓ | Exact; no aud/iss/jti |
| A08-E01 | CDN script without SRI | a08-f04 / a03-f09 / a02-f09 / Chain E | ✓ | Exact (`client/index.html:14`) |
| A08-E02 | Unrestricted upload types | a08-f03 / HIGH-06 | ✓ | Exact (`upload.js:50-52`); HTML+SVG accepted |
| A08-E03 | Webhook signature optional | a08-f02 / a06-f01 / a10-f04 / CRIT-07 | ✓ | Exact; Chain C credit 100k cents unsigned |
| A08-E04 | No CSRF protection | a08-f01 / HIGH-01 | ✓ | Exact; cross-origin PUT persisted |
| A08-E05 | Profile import trusts external data | — | ✗ | Not tested (`GET /api/integrations/import`). Specialist noted as SSRF candidate in recon but never probed |
| A09-E01 | No logging on auth events | a09-f02 / MED-11 | ✓ | Exact (`auth.controller.js`) |
| A09-E02 | WebSocket events use console.log | — | ✗ | Not found (`config/socket.js`). A07 specialist touched `socket.js` for userId spoofing but missed the logging gap |
| A09-E03 | No alerting on failed logins | a09-f14 | ✓ | Agent enumerated the missing alerting pipeline |
| A09-E04 | Sensitive data in error logs | a09-f12 / HIGH-09 | ✓ | Exact (`errorHandler.js:4-10`); `req.body` incl. password |
| A09-E05 | Log injection via user input | a05-f06 / a09-f01 / MED-11 | ✓ | Exact file+pattern |
| A10-E01 | Auth middleware JWT fallthrough | a10-f05 / HIGH-10 | ✓ | Exact (`auth.js:36`); NotBeforeError path reached |
| A10-E02 | No file upload size limit | a10-f07 / MED-10 | ✓ | Exact (`upload.js:15-17,50-52`); 50MB accepted |
| A10-E03 | Dispute status updated before payment | — | ✗ | Not found (`disputes.service.js:175-236`). No disputes specialist; A10 specialist did not review disputes |
| A10-E04 | Unhandled async error in analytics | — | ✗ | Not found (`admin.controller.js` getPlatformAnalytics) |
| A10-E05 | Division by zero in analytics | — | ✗ | Not found (same location) |

## Baseline comparison

| Agent | Detection rate (of 47 planted) | False positives | Novel findings |
|---|---|---|---|
| Claude Code (single-agent, source) | 64% (30/47) | 0 | 20 |
| Codex (single-agent, source) | 45% (21/47) | 0 | 11 |
| Shannon (5-specialist pipeline) | ~60% (~28/47) | 1 (self-flagged FP) | ~15 |
| **Webagent (10-specialist + PoC validator)** | **85% (40/47)** | **1 (self-flagged; `a05-f04` MongoDB 7 mitigation)** | **~18** |

Novel findings include: wallet withdraw TOCTOU (a10-f01); escrow release TOCTOU (a10-f02); escrow fund TOCTOU (a10-f03); default `password123` on admin/mod (a07-f08); MinIO root creds reachable (a02-f10); Redis unauthenticated :6379 (a02-f11); MongoDB unauthenticated :27017 (a02-f12); MailHog UI exposed :8025 (a02-f13); contract sub-op IDORs beyond the single read endpoint (a01-f04..f09); messaging IDOR read+write (a01-f10, a01-f11); proposal read IDOR (a01-f12); review-without-contract-membership (a06-f07); Puppeteer SSRF via invoice HTML injection (a05-f05 / a08-f05); Socket.IO userId-query-param trust (a07-f11); parseInt(UUID) in proposals (a10-f09); array-amount type confusion (a10-f10); Morgan logging verify-email tokens (a09-f11); duplicate-webhook / idempotency bypass (a06-f02).

False positive: `a05-f04` is the only arguable FP — a genuine `$where` code-injection pattern that MongoDB 7 blocks by configuration. The specialist explicitly labeled confidence `suspected` and documented the mitigation, paralleling Shannon's self-flagged FP.

## What webagent found that others missed

All four categories called out as "hard ceiling" in blog part 3 were cracked:

- **Supply chain (A03):** 3/3 (baseline 0/3). `a03-f01..f03` + `a03-f05..f09` identified CI `npm install` vs `npm ci`, `continue-on-error` on `npm audit`, and concrete CVEs in jsonwebtoken/multer/mongoose/puppeteer.
- **Logging (A09):** 4/5 (baseline 0-1/5). Auth-event gap, plaintext passwords in error-handler body logging, missing alerting, and log injection all flagged by the dedicated A09 specialist.
- **Session fixation (A07-E04):** found (`a07-f06`). Only Shannon previously caught this.
- **JWT aud/iss validation (A07-E06):** found (`a07-f12`). All prior agents missed it.
- **CDN without SRI (A08-E01):** found in three places (`a08-f04`, `a03-f09`, `a02-f09`), and chained into CHAIN-E. All prior agents missed it.
- **Exceptional conditions (A10):** 2/5 vs 0-1/5 baseline. Race conditions (A10 broadly) went from Codex-only to comprehensively covered (wallet + fund + release TOCTOU). A10-E01 NotBeforeError fall-through also confirmed live.

## What webagent missed

**A05 — Injection (2 missed of 6):**
- **A05-E03** NoSQL injection in `/api/admin/reports/activity` usernames — A05 specialist found public user-search SQLi and `$where` pattern but did not pivot to admin reporting endpoints. Admin JWT was available, so this is a coverage gap, not an access gap.
- **A05-E04** SQL injection in `/api/admin/users?search` (`whereRaw`) — same cause: specialist stopped after the public `/api/users` SQLi.

**A07 — AuthN (1 missed of 6):**
- **A07-E01** Session cookie has no `maxAge` — counted as `~` / detected via the JWT-persistence framing (`a07-f01`), but the express-session cookie attribute specifically was not called out. Borderline.

**A08 — Integrity (1 missed of 5):**
- **A08-E05** Profile import fetches external URL without schema validation — listed in A08 recon notes as SSRF candidate but never probed. A08 specialist's time budget went to CSRF + webhook + upload + SRI + PDF.

**A09 — Logging (1 missed of 5):**
- **A09-E02** WebSocket events use `console.log` in `config/socket.js` — A07 specialist touched this file for the userId-spoof finding but didn't flag the logger-bypass. A09 specialist didn't open `config/socket.js`.

**A10 — Exceptional Conditions (3 missed of 5):**
- **A10-E03** Dispute status updated before payment in `disputes.service.js:175-236` — no specialist touched the disputes module.
- **A10-E04** Unhandled async error in `getPlatformAnalytics` — admin analytics endpoint was not dynamically probed with `?days=0`.
- **A10-E05** Division by zero in same endpoint — same cause.

Pattern: every miss is a coverage gap (file/endpoint not opened) rather than a reasoning failure. The webagent detected the vulnerability *class* in every OWASP category but did not exhaustively enumerate every endpoint within the class.

## Blind spots / caveats

- **A07-E01** scored `~` (partial). The planted vuln is narrowly about the express-session cookie's `maxAge`. The webagent found the closely related "JWT is still valid after logout" (7-day exp, no revocation) which conveys the same business impact — "sessions persist indefinitely" — but is a different root cause (JWT revocation vs. cookie expiry). I counted it as detected because the webagent framed its finding exactly as "sessions never expire" and because the practical impact is identical. A strict reading would mark it `✗`, which would drop the total to 39/47 = 83%.
- **A05-E01 / MED-05** `$where` NoSQL injection: code pattern is identical to what was planted, but MongoDB 7's default config blocks execution. The specialist correctly identified the pattern AND the mitigation. Counted as `~` detected; counted as the 1 arguable FP in the false-positive column because the running target cannot actually be exploited as-is.
- **A03-E01** planted says "express 4.17.1, jsonwebtoken 8.5.1, mongoose 5.13.0, lodash 4.17.20, multer 1.4.3." The webagent flagged jsonwebtoken, multer, mongoose, puppeteer (with CVEs) but did not call out `express 4.17.1` or `lodash 4.17.20` specifically. I counted the overall planted vuln as found because ≥3 of the named outdated deps were confirmed with CVE references.
- **A09-E03** (no alerting on failed logins) is scored as detected via `a09-f14` ("no alerting pipeline / capped ActivityLog mutable"). The webagent finding covers alerting generally rather than failed-login-specific alerting, but the absence is inherent to the alerting-infrastructure finding.
- Chain B (reset-token takeover) was live-verified on a prior run. During scoring rerun, the global rate limit blocked re-execution, but the algorithm reconstruction and token match against MailHog were independently confirmed. Not a scoring caveat for detection but worth noting.
