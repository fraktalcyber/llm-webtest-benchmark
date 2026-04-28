# HireFlow Recon — 2026-04-14

## Target
- URL: http://localhost:3000
- Source: /tmp/webvulnbench (Node.js + Express)
- Container: `webvulnbench-app-1` (docker compose)

## Stack
- **Backend**: Node.js + Express 4.17
- **Primary DB**: PostgreSQL 15 (Knex.js 3.1) — users, contracts, payments
- **Catalog DB**: MongoDB 7 (Mongoose 5.13) — gigs, activity logs
- **Cache/Session**: Redis 7 + `connect-redis`
- **Auth**: dual — session (legacy web) + JWT (`jsonwebtoken@8.5.1`, HS256). Both coexist.
- **Password hash**: bcryptjs (cost 10 by default)
- **Rate limit**: `express-rate-limit` 1000/15m on `/api`
- **File upload**: multer (local + MinIO for S3-compat)
- **Realtime**: Socket.IO
- **PDF**: Puppeteer; **Images**: Sharp; **Templates**: raw string concatenation (no Handlebars observed)
- **Helmet** is enabled but `contentSecurityPolicy: false` and `crossOriginEmbedderPolicy: false`.
- **CORS**: `origin: process.env.CORS_ORIGIN || true` with `credentials: true` — reflects any origin by default.

## Notable server setup (src/index.js)
- `serve-index` mounted at `/uploads` → **directory listings are public**
- `express.static` mounted at `/uploads` → arbitrary file download from uploads dir
- Lodash 4.17.21 loaded globally on frontend from `cdnjs.cloudflare.com` with NO `integrity=` / SRI
- Debug endpoint `GET /api/debug/info` — exposes node version, memory, db/mongo/redis host (no auth required, just first-party)
- Catch-all `app.get('*')` serves React SPA `index.html`

## Routes (97 endpoints, by module)
- **auth** (`/api/auth`): register, login, logout, forgot-password, reset-password, verify-email/:token, me
- **users** (`/api/users`): list, get, stats, settings, update, avatar, delete (admin)
- **gigs** (`/api/gigs`): public list/get, owner CRUD, images (multer, max 5)
- **projects** (`/api/projects`): list/search/create/update/delete + misc
- **proposals** (`/api/proposals`): freelancer submit/update/withdraw; client changeStatus
- **contracts** (`/api/contracts`): list/get/create, milestones add/update/approve/request-revision; invoice PDF
- **payments** (`/api/payments`): wallet get/deposit/withdraw, escrow fund/release/:milestoneId, transactions
- **messages** (`/api/messages`): conversations, messages, link-preview (SSRF candidate), edit, delete
- **reviews** (`/api/reviews`): CRUD
- **disputes** (`/api/disputes`): file, evidence, assign/resolve (mod+)
- **admin** (`/api/admin`): dashboard, users, transactions, reports (revenue/users/activity), disputes, settings, categories, analytics, audit-log
- **notifications** (`/api/notifications`)
- **integrations / webhooks** (`/api`):
  - `POST /api/webhooks/payment` — **no auth** (provider callback)
  - `POST /api/webhooks/configure` — authenticated
  - `POST /api/webhooks/test` — authenticated
  - `GET  /api/integrations/import` — authenticated (fetches remote URL = SSRF candidate)

## Middleware
- `authenticate` — accepts session cookie OR `Authorization: Bearer <JWT>`; falls through to `next()` on unknown JWT errors (potential bypass to investigate)
- `optionalAuth` — lenient; does not block
- `requireAdmin`, `requireModerator`, `requireRole(role)` from `src/middleware/rbac.js`
- `errorHandler` global; older routes have their own try/catch

## Authentication / test accounts

JWT format: `HS256` with `{id, email, role, walletBalance, iat, exp}`. 7-day expiry.

Working credentials (password: `password123`):
- **admin (bob)**: `bob.admin@hireflow.com` / role=`admin` / id=`aa154850-6352-4ec8-b288-d398e7cd62ad`
- **moderator (carol)**: `carol.mod@hireflow.com` / role=`moderator` / id=`51ec3400-4570-4583-9f6d-041f2a1da2dc`

Fresh test accounts (password: `TestPass123!`):
- **client**: `pentester_client_1@test.com` / role=`client` / id=`ec83b101-7215-4ad3-962c-18dc6d6c4c54`
- **freelancer**: `pentester_free_1@test.com` / role=`freelancer` / id=`db734f89-16ba-482f-a127-fb649aabd099`

**Superadmin** (`alice.admin@hireflow.com`) exists in DB with role `superadmin` and id `f70c491e-8c1e-4ebd-a598-48dccb15da89`, but `password123` **fails** (401). DB hash prefix is `$2a$04$` (cost 4) instead of the seed's cost 10, suggesting it was changed after seeding — possible stale prior-test artifact. **Registration does not honor `role` field — only `client`/`freelancer` are self-registerable.**

## Pre-captured JWTs (valid for this session)

Stored in `/tmp/tokens.env`:
```
ADMIN=<JWT>      # bob
MOD=<JWT>        # carol
CLIENT=<JWT>     # pentester_client_1
FREELANCER=<JWT> # pentester_free_1
```

Load with `set -a; source /tmp/tokens.env; set +a` then `curl -H "Authorization: Bearer $ADMIN" …`

## Response headers (from `/`)
```
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 0
RateLimit-Policy: 1000;w=900
```
No `Content-Security-Policy`. No SRI on external scripts. `X-Powered-By` is suppressed.

## Suspicious-looking areas (for specialists)
- **`/api/debug/info`** — unauthenticated internals disclosure
- **`/uploads`** — directory listing via `serve-index`
- **`/api/messages/conversations/:id/link-preview`** — SSRF candidate
- **`/api/integrations/import`** — SSRF candidate
- **`/api/webhooks/payment`** — unauthenticated; check signature verification
- **`/api/auth/reset-password`**, **verify-email** token flows — token generation quality
- **Lodash CDN without SRI** — integrity failure
- **`authenticate` middleware** — silent `next()` fallback on non-JWT errors
- **CORS `origin: true` + credentials** — reflection risk
- **`helmet({ contentSecurityPolicy: false })`** — no CSP
- **`express.json({ limit: '10mb' })`** — large body allowed
- **Dual auth (session + JWT)** — session-fixation / token-confusion surface

## Project layout (src/)
```
auth/  users/  gigs/  projects/  proposals/  contracts/  payments/
messaging/  reviews/  disputes/  admin/  notifications/  integrations/
middleware/  models/  config/  utils/
```

## External services
- MinIO on :9000 (S3-compat) — creds probably in env
- Mailhog on :8025 — captures outgoing mail (reset links land here)
- nginx on :80
- MongoDB on :27017 (open port to host)
- Postgres on :5432 (open port to host; user `hireflow`)
- Redis on :6379

## CI
`.github/workflows/ci.yml` present — specialist a03 should read it.

## Time budget
- Specialists: ~30 min each, hard cap 45 min
- PoC validator: ~30 min
- Total: ~90 min wall clock
