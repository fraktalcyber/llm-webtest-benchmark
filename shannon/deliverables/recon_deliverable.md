# Reconnaissance Deliverable: HireFlow Freelancer Marketplace

## 0) HOW TO READ THIS

This reconnaissance report provides a comprehensive map of the application's attack surface for the HireFlow freelance marketplace, with special emphasis on authorization and privilege escalation opportunities for all downstream specialists.

**Key Sections for Authorization Analysis:**
- **Section 4 (API Endpoint Inventory):** Contains authorization details for each endpoint — focus on "Required Role" and "Object ID Parameters" columns to identify IDOR candidates.
- **Section 6.4 (Guards Directory):** Catalog of authorization controls — understand what each guard means before analyzing vulnerabilities.
- **Section 7 (Role & Privilege Architecture):** Complete role hierarchy and privilege mapping — use this to understand the privilege lattice and identify escalation targets.
- **Section 8 (Authorization Vulnerability Candidates):** Pre-prioritized lists of endpoints for horizontal, vertical, and context-based authorization testing.

**How to Use the Network Mapping (Section 6):** The entity/flow mapping shows system boundaries and data sensitivity levels. Pay special attention to flows marked with authorization guards and entities handling PII/sensitive data.

**Priority Order for Testing:** Start with Section 8's High-priority horizontal candidates (contracts, messaging IDORs), then vertical escalation endpoints (JWT secret forgery to admin), finally context-based workflow bypasses (dispute resolution without role).

---

## 1. Executive Summary

HireFlow is a full-stack Node.js freelance marketplace where clients post projects, freelancers submit proposals, and work is managed through milestone-based contracts with an integrated escrow wallet system. The application also offers gig browsing (MongoDB-backed), real-time messaging via Socket.IO, dispute resolution, and admin/moderation panels.

**Core Technology Stack:** Node.js 20 / Express 4.17.1 backend, React 18 SPA frontend (Vite), PostgreSQL 15 (relational data), MongoDB 7 (gigs/activity logs), Redis 7 (sessions), MinIO (file storage), Socket.IO 4.7.2 (real-time), Nginx (reverse proxy), Puppeteer 21.6.1 (PDF generation).

**Attack Surface Overview:**
- 77 unique HTTP API endpoints across 13 route modules
- 2 Socket.IO namespaces (default `/` and `/messaging`)
- 1 publicly accessible upload directory with directory listing
- 1 unauthenticated infrastructure disclosure endpoint (`/api/debug/info`)
- 1 unauthenticated financial webhook (`/api/webhooks/payment`)
- A dual authentication model (session + JWT) with hardcoded fallback secrets

The application has a critically weak security posture with multiple unauthenticated injection points, pervasive IDOR vulnerabilities, an open CORS policy, and financial operations without transaction safety.

---

## 2. Technology & Service Map

- **Frontend:** React 18.2.0 SPA, React Router v6, Vite 5.0.8 build tooling. Client communicates via `fetch()` with `credentials: 'include'`. `dangerouslySetInnerHTML` used in `GigDetail.jsx` (XSS sink).
- **Backend:** Node.js 20 (Alpine), Express 4.17.1, Socket.IO 4.7.2, Multer 1.4.3 (file uploads), Puppeteer 21.6.1 (PDF via Chromium `--no-sandbox`), sharp 0.33.1 (image processing), Nodemailer 6.9.7 (email via MailHog), jsonwebtoken 8.5.1, bcryptjs 2.4.3 (4 rounds), express-session with connect-redis, express-validator (partial), express-rate-limit (partially applied)
- **Infrastructure:** Docker Compose v3.8, Nginx (HTTP port 80, no TLS), Express directly on port 3000 (Nginx bypass possible). All internal services also exposed on host ports.
- **Databases:** PostgreSQL 15 (port 5432, no SSL, no auth separation), MongoDB 7 (port 27017, no auth, no TLS), Redis 7 (port 6379, no auth, no TLS)
- **Object Storage:** MinIO (ports 9000/9001), buckets `avatars` and `gig-images` configured with anonymous download access
- **Email:** MailHog SMTP relay (port 1025, port 8025 web UI) — development relay, captures all outbound email
- **Identified Subdomains:** None discovered (single-host deployment, `host.docker.internal:3000`)
- **Open Ports & Services:**
  - 80/tcp — Nginx reverse proxy (HTTP ingress)
  - 3000/tcp — Express app directly (Nginx bypass)
  - 5432/tcp — PostgreSQL (directly exposed)
  - 27017/tcp — MongoDB (directly exposed)
  - 6379/tcp — Redis (directly exposed)
  - 9000/tcp — MinIO S3 API (directly exposed)
  - 9001/tcp — MinIO Web UI (directly exposed)
  - 1025/tcp — MailHog SMTP (directly exposed)
  - 8025/tcp — MailHog Web UI (directly exposed)

---

## 3. Authentication & Session Management Flow

### Entry Points
- `POST /api/auth/register` — Public user registration (roles: client, freelancer only)
- `POST /api/auth/login` — Credential submission, returns both session cookie and JWT
- `POST /api/auth/logout` — Destroys server-side session (JWT remains valid until expiry)
- `POST /api/auth/forgot-password` — Initiates password reset (user enumerable)
- `POST /api/auth/reset-password` — Completes password reset via token
- `GET /api/auth/verify-email/:token` — Email verification via token
- `GET /api/auth/me` — Returns current authenticated user profile

### Mechanism
1. **Registration** (`src/auth/auth.controller.js:7-64`): User submits email, username, password, role (only `client`/`freelancer` accepted via forced coercion at line 28). Password hashed with bcrypt (4 rounds — far too low). User record created in PostgreSQL. Verification token generated and stored. JWT returned immediately (email verification not required for JWT use).
2. **Login** (`src/auth/auth.controller.js:66-110`): Credentials validated against PostgreSQL. Both a `connect.sid` session cookie AND a JWT bearer token are returned. The session stores `req.session.userId`. The JWT payload contains `{ id, email, role, walletBalance }`.
3. **Request Authentication** (`src/middleware/auth.js:6-41`): Checks session first (line 8-18), falls back to JWT Bearer header (line 21-38). **Auth bypass on unexpected errors**: line 36 calls `next()` (without 401) when a non-JWT error occurs during token processing, passing the request through unauthenticated with `req.user` undefined.
4. **Logout** (`src/auth/auth.controller.js:111-124`): Destroys the server-side session only. JWT token remains valid for its full 7-day lifetime. No token blacklist exists.

### Code Pointers
- Auth middleware: `src/middleware/auth.js`
- Auth service: `src/auth/auth.service.js`
- Auth controller: `src/auth/auth.controller.js`
- Session setup: `src/index.js:60-71`
- JWT config: `src/config/index.js:28-32`

### 3.1 Role Assignment Process
- **Role Determination:** At registration, user submits desired role. Controller coerces any non-`freelancer` value to `client` (`auth.controller.js:28`). Role is stored in PostgreSQL `users.role` column. JWT is signed with this role embedded.
- **Default Role:** `client` (anything except `freelancer` submitted becomes `client`)
- **Role Upgrade Path:** Only via admin endpoint `PUT /api/admin/users/:id` (requires `admin` role or higher). A regular `admin` can upgrade any user to `moderator` or `admin`. Only `superadmin` can assign `superadmin` role. No self-service role escalation path exists for public users.
- **Code Implementation:** `src/auth/auth.controller.js:28` (registration), `src/admin/admin.controller.js:33-60` (admin upgrade)

### 3.2 Privilege Storage & Validation
- **Storage Location:** Role stored in PostgreSQL `users.role` VARCHAR column. Also embedded in JWT payload `{ role }` and implicitly in Redis session (user object loaded from DB on each session request).
- **Validation Points:**
  - `src/middleware/auth.js` — loads user from DB, attaches as `req.user`
  - `src/middleware/rbac.js` — `requireRole()`, `requireAdmin()`, `requireModerator()` middleware functions check `req.user.role`
  - Inline checks: various controllers (e.g., `req.user.id !== userId` for ownership)
- **Cache/Session Persistence:** Session stored in Redis (no expiry configured — persists until Redis eviction). JWT tokens live 7 days with no refresh or revocation mechanism. Role changes in the database do NOT invalidate existing JWTs — an admin-demoted user retains admin-level JWT until expiry.
- **Code Pointers:** `src/middleware/rbac.js`, `src/middleware/auth.js`, `src/config/index.js:25-31`

### 3.3 Role Switching & Impersonation
- **Impersonation Features:** None implemented.
- **Role Switching:** None implemented.
- **Audit Trail:** Admin user updates are logged to MongoDB `ActivityLog` collection (`admin.controller.js:54-57`).
- **Code Implementation:** N/A

---

## 4. API Endpoint Inventory

**Network Surface Focus:** All endpoints below are accessible through the deployed application via HTTP requests to `http://host.docker.internal:3000` (direct) or port 80 (via Nginx).

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|---|---|---|---|---|---|
| GET | `/api/health` | anon | None | None | Health check. `src/index.js:96` |
| GET | `/api/debug/info` | anon | None | None | **CRITICAL: No auth** — leaks db_host, redis_host, mongo_uri, PID, memory. `src/index.js:101` |
| GET | `/uploads/` | anon | None | None | **Directory listing** — browse all uploaded files via serve-index. `src/index.js` |
| POST | `/api/auth/register` | anon | None | None | User registration; role coerced to client/freelancer. `src/auth/auth.routes.js:8` |
| POST | `/api/auth/login` | anon | None | None | Login; returns session cookie + JWT. `src/auth/auth.routes.js:26` |
| POST | `/api/auth/logout` | anon | None | None | Destroys session only (JWT unaffected). `src/auth/auth.routes.js:35` |
| POST | `/api/auth/forgot-password` | anon | None | None | Password reset initiation; user enumerable via 404. `src/auth/auth.routes.js:37` |
| POST | `/api/auth/reset-password` | anon | None | None | Completes reset via token; token reusable, 24h effective window. `src/auth/auth.routes.js:39` |
| GET | `/api/auth/verify-email/:token` | anon | token | None | Email verification. `src/auth/auth.routes.js:41` |
| GET | `/api/auth/me` | user | None | Bearer Token / Session + `authenticate` | Current user profile. `src/auth/auth.routes.js:43` |
| GET | `/api/users` | anon | None | None | **SQLi sink** — `?search=` interpolated into raw SQL. `src/users/users.routes.js:10` |
| GET | `/api/users/:id` | anon | user_id | None | Public user profile. `src/users/users.routes.js:11` |
| GET | `/api/users/:id/stats` | anon | user_id | None | User statistics. `src/users/users.routes.js:12` |
| GET | `/api/users/:id/settings` | anon | user_id | **None (IDOR)** | **No auth** — exposes email, phone, last_login for any user. `src/users/users.routes.js:15` |
| PUT | `/api/users/:id/settings` | user | user_id | Bearer/Session + ownership check (`req.user.id !== userId`) | Update own settings. `src/users/users.routes.js:16` |
| PUT | `/api/users/:id` | user | user_id | Bearer/Session + ownership check or admin | Update user profile. `src/users/users.routes.js:19` |
| PUT | `/api/users/:id/avatar` | user | user_id | Bearer/Session + ownership check | Upload avatar. `src/users/users.routes.js:20` |
| DELETE | `/api/users/:id` | admin | user_id | Bearer/Session + `requireAdmin` | Delete user. `src/users/users.routes.js:23` |
| GET | `/api/gigs` | anon | None | None (optionalAuth) | **NoSQL injection** — `?tag_filter=` injected into MongoDB `$where` (blocked by MongoDB 7 config). `src/gigs/gigs.routes.js:8` |
| GET | `/api/gigs/user/:userId` | anon | userId | None | All gigs for a user. `src/gigs/gigs.routes.js:9` |
| GET | `/api/gigs/:id` | anon | gig_id | None (optionalAuth) | Single gig detail. `src/gigs/gigs.routes.js:10` |
| POST | `/api/gigs` | freelancer | None | Bearer/Session + `requireRole('freelancer')` | Create gig. `src/gigs/gigs.routes.js:13` |
| PUT | `/api/gigs/:id` | freelancer | gig_id | Bearer/Session + `requireRole('freelancer')` + ownership check | Update own gig. `src/gigs/gigs.routes.js:14` |
| DELETE | `/api/gigs/:id` | freelancer | gig_id | Bearer/Session + `requireRole('freelancer')` + ownership check | Delete own gig. `src/gigs/gigs.routes.js:15` |
| GET | `/api/projects` | anon | None | None (validators only) | List projects. `src/projects/projects.routes.js:90` |
| GET | `/api/projects/:id` | anon | project_id (UUID) | Validation only (UUID check) | Single project. `src/projects/projects.routes.js:97` |
| POST | `/api/projects` | client | None | Bearer/Session + `requireRole('client')` | Create project. `src/projects/projects.routes.js:105` |
| PUT | `/api/projects/:id` | client | project_id | Bearer/Session + `requireRole('client')` | Update project. `src/projects/projects.routes.js:114` |
| DELETE | `/api/projects/:id` | client | project_id | Bearer/Session + `requireRole('client')` | Cancel project. `src/projects/projects.routes.js:124` |
| GET | `/api/projects/:id/proposals` | user | project_id | Bearer/Session + `authenticate` | List proposals for project. `src/projects/projects.routes.js:134` |
| GET | `/api/proposals` | user | None | Bearer/Session + `authenticate` | **IDOR** — any authenticated user can query `?freelancer_id=<any>` to read any freelancer's proposals. `src/proposals/proposals.routes.js:10` |
| POST | `/api/proposals` | freelancer | None | Bearer/Session + `requireRole('freelancer')` | Submit proposal. `src/proposals/proposals.routes.js:13` |
| PUT | `/api/proposals/:id` | freelancer | proposal_id | Bearer/Session + `requireRole('freelancer')` + ownership check | Update own proposal. `src/proposals/proposals.routes.js:16` |
| PUT | `/api/proposals/:id/status` | client | proposal_id | Bearer/Session + `requireRole('client')` | Accept/reject proposal. `src/proposals/proposals.routes.js:19` |
| DELETE | `/api/proposals/:id` | freelancer | proposal_id | Bearer/Session + `requireRole('freelancer')` + ownership check | Withdraw proposal. `src/proposals/proposals.routes.js:22` |
| GET | `/api/contracts` | user | None | Bearer/Session + `authenticate` | List user's contracts. `src/contracts/contracts.routes.js:10` |
| GET | `/api/contracts/:id` | user | contract_id | Bearer/Session + `authenticate` (NO party check — IDOR) | **IDOR** — any auth user reads any contract. `src/contracts/contracts.routes.js:11` |
| POST | `/api/contracts` | user | None | Bearer/Session + `authenticate` | Create contract. `src/contracts/contracts.routes.js:14` |
| PUT | `/api/contracts/:id/status` | user | contract_id | Bearer/Session + `authenticate` (NO party check — IDOR) | **IDOR** — any auth user can cancel/complete any contract. `src/contracts/contracts.routes.js:17` |
| POST | `/api/contracts/:id/milestones` | user | contract_id | Bearer/Session + `authenticate` (NO party check — IDOR) | **IDOR** — any auth user adds milestones to any contract. `src/contracts/contracts.routes.js:20` |
| PUT | `/api/contracts/:id/milestones/:milestoneId` | user | contract_id, milestoneId | Bearer/Session + `authenticate` (NO party check — IDOR) | **IDOR** — any auth user modifies any milestone. `src/contracts/contracts.routes.js:21` |
| POST | `/api/contracts/:id/milestones/:milestoneId/submit` | user | contract_id, milestoneId | Bearer/Session + `authenticate` (NO party check — IDOR) | **IDOR** — any auth user submits deliverables. `src/contracts/contracts.routes.js:24` |
| PUT | `/api/contracts/:id/milestones/:milestoneId/approve` | user | contract_id, milestoneId | Bearer/Session + `authenticate` (NO party check — IDOR) | **IDOR** — any auth user approves any milestone. `src/contracts/contracts.routes.js:31` |
| PUT | `/api/contracts/:id/milestones/:milestoneId/request-revision` | user | contract_id, milestoneId | Bearer/Session + `authenticate` (NO party check — IDOR) | **IDOR** — any auth user requests revision. `src/contracts/contracts.routes.js:32` |
| GET | `/api/contracts/:id/invoice` | user | contract_id | Bearer/Session + `authenticate` (NO party check — IDOR) | **IDOR** — any auth user downloads PDF invoice with both parties' emails + financials. `src/contracts/contracts.routes.js:35` |
| GET | `/api/payments/wallet` | user | None | Bearer/Session + `authenticate` | Own wallet balance. `src/payments/payments.routes.js:8` |
| POST | `/api/payments/wallet/deposit` | user | None | Bearer/Session + `authenticate` | Deposit to own wallet. `src/payments/payments.routes.js:9` |
| POST | `/api/payments/wallet/withdraw` | user | None | Bearer/Session + `authenticate` | Withdraw from own wallet (race condition). `src/payments/payments.routes.js:10` |
| POST | `/api/payments/escrow/fund/:milestoneId` | user (client) | milestoneId | Bearer/Session + client ownership check | Fund escrow for milestone. `src/payments/payments.routes.js:13` |
| POST | `/api/payments/escrow/release/:milestoneId` | user | milestoneId | Bearer/Session + client ownership check | Release escrow. `src/payments/payments.routes.js:14` |
| GET | `/api/payments/transactions` | user | None | Bearer/Session + `authenticate` | Own transaction history. `src/payments/payments.routes.js:17` |
| GET | `/api/payments/transactions/:id` | user | transaction_id | Bearer/Session + wallet ownership check | Single transaction. `src/payments/payments.routes.js:18` |
| GET | `/api/messages/conversations` | user | None | Bearer/Session + `authenticate` | List own conversations. `src/messaging/messaging.routes.js:10` |
| POST | `/api/messages/conversations` | user | None | Bearer/Session + `authenticate` | Create conversation. `src/messaging/messaging.routes.js:11` |
| GET | `/api/messages/conversations/:id` | user | conversation_id | Bearer/Session + `authenticate` (NO participant check — IDOR) | **IDOR** — any auth user reads any conversation's messages. `src/messaging/messaging.routes.js:12` |
| POST | `/api/messages/conversations/:id/messages` | user | conversation_id | Bearer/Session + `authenticate` (NO participant check — IDOR) | **IDOR** — any auth user injects messages into any conversation. `src/messaging/messaging.routes.js:13` |
| POST | `/api/messages/conversations/:id/link-preview` | user | conversation_id | Bearer/Session + `authenticate` | SSRF — fetches user-supplied URL with partial blocklist. `src/messaging/messaging.routes.js:14` |
| PUT | `/api/messages/conversations/:id/read` | user | conversation_id | Bearer/Session + `authenticate` | Mark conversation read. `src/messaging/messaging.routes.js:15` |
| PUT | `/api/messages/messages/:id` | user | message_id | Bearer/Session + sender ownership check | Edit own message. `src/messaging/messaging.routes.js:18` |
| DELETE | `/api/messages/messages/:id` | user | message_id | Bearer/Session + sender ownership check | Delete own message. `src/messaging/messaging.routes.js:19` |
| GET | `/api/reviews` | anon | None | None | List reviews. `src/reviews/reviews.routes.js:7` |
| GET | `/api/reviews/user/:userId/summary` | anon | userId | None | User review summary. `src/reviews/reviews.routes.js:8` |
| GET | `/api/reviews/:id` | anon | review_id | None | **Info disclosure** — private reviews readable by anyone with ID. `src/reviews/reviews.routes.js:9` |
| POST | `/api/reviews` | user | None | Bearer/Session + `authenticate` (no contract party check) | **Logic flaw** — any user can submit a review for any contract. `src/reviews/reviews.routes.js:12` |
| PUT | `/api/reviews/:id` | user | review_id | Bearer/Session + reviewer ownership check | Update own review. `src/reviews/reviews.routes.js:13` |
| DELETE | `/api/reviews/:id` | admin | review_id | Bearer/Session + `requireAdmin` | Delete review (admin only). `src/reviews/reviews.routes.js:14` |
| GET | `/api/disputes` | user | None | Bearer/Session + `authenticate` | List disputes (scoped to user). `src/disputes/disputes.routes.js:11` |
| GET | `/api/disputes/:id` | user | dispute_id | Bearer/Session + party/moderator check | Get dispute (party check present). `src/disputes/disputes.routes.js:14` |
| POST | `/api/disputes` | user | None | Bearer/Session + `authenticate` + party check in service | File dispute. `src/disputes/disputes.routes.js:17` |
| POST | `/api/disputes/:id/evidence` | user | dispute_id | Bearer/Session + party check | Add evidence. `src/disputes/disputes.routes.js:20` |
| PUT | `/api/disputes/:id/assign` | moderator | dispute_id | Bearer/Session + `requireModerator` at route BUT controller has no role recheck | Assign moderator. `src/disputes/disputes.routes.js:23` |
| PUT | `/api/disputes/:id/resolve` | moderator | dispute_id | Bearer/Session + `requireModerator` at route | Resolve dispute (triggers financial ops). `src/disputes/disputes.routes.js:24` |
| GET | `/api/admin/dashboard` | moderator | None | Bearer/Session + `authenticate` + `requireModerator` | Admin dashboard stats. `src/admin/admin.routes.js:12` |
| GET | `/api/admin/users` | admin | None | Bearer/Session + `authenticate` + `requireAdmin` | **SQLi sink** — `?search=` concatenated in whereRaw. `src/admin/admin.routes.js:15` |
| PUT | `/api/admin/users/:id` | admin | user_id | Bearer/Session + `authenticate` + `requireAdmin` | Admin update user/role. `src/admin/admin.routes.js:16` |
| DELETE | `/api/admin/users/:id` | admin | user_id | Bearer/Session + `authenticate` + `requireAdmin` | Admin deactivate user. `src/admin/admin.routes.js:17` |
| GET | `/api/admin/transactions` | admin | None | Bearer/Session + `authenticate` + `requireAdmin` | All transactions. `src/admin/admin.routes.js:20` |
| GET | `/api/admin/reports/revenue` | admin | None | Bearer/Session + `authenticate` + `requireAdmin` | Revenue reports. `src/admin/admin.routes.js:23` |
| GET | `/api/admin/reports/users` | admin | None | Bearer/Session + `authenticate` + `requireAdmin` | User growth report. `src/admin/admin.routes.js:24` |
| GET | `/api/admin/reports/activity` | admin | None | Bearer/Session + `authenticate` + `requireAdmin` | **NoSQL injection** — `?usernames[]=` injected into MongoDB query. `src/admin/admin.routes.js:25` |
| GET | `/api/admin/reports` | admin | None | Bearer/Session + `authenticate` + `requireAdmin` | All reports. `src/admin/admin.routes.js:28` |
| GET | `/api/admin/disputes` | moderator | None | Bearer/Session + `authenticate` + `requireModerator` | Admin dispute list. `src/admin/admin.routes.js:31` |
| GET | `/api/admin/disputes/:id` | moderator | dispute_id | Bearer/Session + `authenticate` + `requireModerator` | Admin dispute detail. `src/admin/admin.routes.js:32` |
| PUT | `/api/admin/disputes/:id/resolve` | moderator | dispute_id | Bearer/Session + `authenticate` + `requireModerator` | Admin resolve dispute. `src/admin/admin.routes.js:33` |
| GET | `/api/admin/settings` | admin | None | Bearer/Session + `authenticate` + `requireAdmin` | Read platform settings. `src/admin/admin.routes.js:36` |
| PUT | `/api/admin/settings` | superadmin | None | Bearer/Session + `authenticate` + `requireRole('superadmin')` | Update platform settings. `src/admin/admin.routes.js:37` |
| GET | `/api/admin/categories` | admin | None | Bearer/Session + `authenticate` + `requireAdmin` | List categories. `src/admin/admin.routes.js:40` |
| POST | `/api/admin/categories` | admin | None | Bearer/Session + `authenticate` + `requireAdmin` | Create category. `src/admin/admin.routes.js:41` |
| PUT | `/api/admin/categories/:id` | admin | category_id | Bearer/Session + `authenticate` + `requireAdmin` | Update category. `src/admin/admin.routes.js:42` |
| GET | `/api/admin/analytics/platform` | admin | None | Bearer/Session + `authenticate` + `requireAdmin` | Platform analytics. `src/admin/admin.routes.js:45` |
| GET | `/api/admin/audit-log` | superadmin | None | Bearer/Session + `authenticate` + `requireRole('superadmin')` | Audit log. `src/admin/admin.routes.js:48` |
| GET | `/api/notifications` | user | None | Bearer/Session + `authenticate` | Own notifications. `src/notifications/notifications.routes.js:8` |
| GET | `/api/notifications/unread-count` | user | None | Bearer/Session + `authenticate` | Unread count. `src/notifications/notifications.routes.js:9` |
| PUT | `/api/notifications/read-all` | user | None | Bearer/Session + `authenticate` | Mark all read. `src/notifications/notifications.routes.js:10` |
| PUT | `/api/notifications/:id/read` | user | notification_id | Bearer/Session + ownership via service | Mark notification read. `src/notifications/notifications.routes.js:11` |
| DELETE | `/api/notifications/:id` | user | notification_id | Bearer/Session + ownership via service | Delete notification. `src/notifications/notifications.routes.js:12` |
| POST | `/api/webhooks/payment` | **anon** | None | **None (signature verification optional)** | **CRITICAL** — unauthenticated financial webhook; credits arbitrary wallet amounts. `src/integrations/webhook.routes.js:11` |
| POST | `/api/webhooks/configure` | user | None | Bearer/Session + `authenticate` | Configure webhook. `src/integrations/webhook.routes.js:27` |
| POST | `/api/webhooks/test` | user | None | Bearer/Session + `authenticate` | **SSRF** — POST to any URL, no validation. `src/integrations/webhook.routes.js:48` |
| GET | `/api/integrations/import` | user | None | Bearer/Session + `authenticate` | **SSRF** — GET any URL, response returned. `src/integrations/webhook.routes.js:69` |

**WebSocket Endpoints (Socket.IO):**
- `ws://host.docker.internal:3000/socket.io` — Default namespace. No authentication. `userId` is a plain URL query parameter (`?userId=`). Any client can impersonate any user. Events: `join:conversation`, `leave:conversation`, `typing`, `disconnect`. `src/config/socket.js`
- `ws://host.docker.internal:3000/messaging` — Messaging namespace (NOTE: `setupMessagingGateway()` is never called from `src/index.js` — this namespace may be unreachable in the deployed app). When active: same `userId` query param auth, events: `join_conversation`, `send_message`, `edit_message`, `delete_message`, `mark_read`. `src/messaging/messaging.gateway.js`

---

## 5. Potential Input Vectors for Vulnerability Analysis

### URL Parameters (Query String)
- `GET /api/users?search=` — **SQL injection sink** (`src/users/users.service.js:33`) — interpolated into raw SQL `ILIKE` clause
- `GET /api/gigs?tag_filter=` — **NoSQL injection sink** (`src/gigs/gigs.service.js:41-45`) — injected into MongoDB `$where` JavaScript expression (blocked by MongoDB 7 security policy in this deployment, but code is vulnerable)
- `GET /api/gigs?category=&min_price=&max_price=&skills=&sort=&page=&limit=` — various filter parameters passed to MongoDB query
- `GET /api/admin/users?search=` — **SQL injection sink** (`src/admin/admin.service.js:66`) — concatenated into `whereRaw()`
- `GET /api/admin/reports/activity?usernames[]=` — **NoSQL injection sink** (`src/admin/admin.service.js:358-364`) — array items concatenated into JSON MongoDB query
- `GET /api/integrations/import?url=` — **SSRF sink** (`src/integrations/webhook.service.js:196-248`) — full URL fetched server-side, response returned
- `GET /api/users?page=&limit=&role=&skills=` — additional filter parameters
- `GET /api/proposals?freelancer_id=&project_id=&status=` — IDOR on `freelancer_id` parameter (no ownership check)
- `GET /api/reviews?reviewee_id=&contract_id=&type=` — review filter parameters
- `GET /api/auth/verify-email/:token` — token in URL path

### POST Body Fields (JSON)
- `POST /api/auth/register`: `email`, `username`, `password`, `role`, `display_name` — role coerced but still user-controlled
- `POST /api/auth/login`: `email`, `password`
- `POST /api/auth/forgot-password`: `email`
- `POST /api/auth/reset-password`: `token`, `password`
- `POST /api/gigs`: `title`, `description`, `category`, `tags[]`, `packages[]`, `requirements`
- `POST /api/projects`: `title`, `description`, `budget_min`, `budget_max`, `skills[]`, `category`
- `POST /api/proposals`: `project_id`, `cover_letter`, `bid_amount`, `estimated_days`
- `POST /api/contracts`: `project_id`, `proposal_id`, `milestones[]`
- `POST /api/contracts/:id/milestones`: `title`, `description`, `amount`, `due_date`
- `PUT /api/contracts/:id/milestones/:id`: `title`, `description`, `amount`, `due_date`
- `POST /api/contracts/:id/milestones/:id/submit`: `notes` (plus file uploads)
- `PUT /api/contracts/:id/milestones/:id/request-revision`: `reason` — **HTML injection sink** (`src/contracts/contracts.service.js:386-387`) — interpolated into email HTML
- `POST /api/payments/wallet/deposit`: `amount`
- `POST /api/payments/wallet/withdraw`: `amount`
- `POST /api/payments/escrow/fund/:id`: (milestone identified by URL param)
- `POST /api/payments/escrow/release/:id`: `overrideAmount` — no validation for positivity or bounds (`src/payments/payments.service.js`)
- `POST /api/messages/conversations`: `participant_id`
- `POST /api/messages/conversations/:id/messages`: `content`, `type` (plus file attachments)
- `POST /api/messages/conversations/:id/link-preview`: `url` — **SSRF sink** (`src/messaging/messaging.service.js:367-421`) — fetched server-side with partial blocklist
- `PUT /api/messages/messages/:id`: `content`
- `POST /api/reviews`: `contract_id`, `reviewee_id`, `rating`, `comment` — comment is **stored XSS sink** (`client/src/pages/GigDetail.jsx:299` — `dangerouslySetInnerHTML`)
- `PUT /api/reviews/:id`: `rating`, `comment`, **and any other fields** (mass assignment — `src/reviews/reviews.service.js:213`)
- `POST /api/disputes`: `contract_id`, `reason`, `description`
- `POST /api/disputes/:id/evidence`: `description`, `evidence_url`
- `PUT /api/disputes/:id/resolve`: `resolution`, `refund_amount`
- `POST /api/webhooks/payment`: `event`, `data.user_id`, `data.amount`, `data.transaction_id` — **unauthenticated financial input**
- `POST /api/webhooks/configure`: `url`, `events[]`, `secret`
- `POST /api/webhooks/test`: `url` — **SSRF sink** (`src/integrations/webhook.service.js:139-188`) — full POST SSRF, no validation
- `PUT /api/users/:id`: `display_name`, `bio`, `location`, `website`, `skills[]`, `phone`, `timezone` — `display_name` flows into **PDF/Puppeteer SSRF sink** (`src/utils/pdf.js:55-76`)
- `PUT /api/admin/users/:id`: `role`, `is_active`
- `PUT /api/admin/settings`: various platform configuration fields

### File Uploads (Multipart)
- `PUT /api/users/:id/avatar`: `avatar` (image file) — processed with `sharp`, stored in MinIO. Uses `avatarUpload` multer config with `fileFilter` for image types.
- `POST /api/gigs`: `images[]` (up to 5) — uses `gigImageUpload` multer config
- `POST /api/contracts/:id/milestones/:id/submit`: `files[]` (up to 10) — uses `deliverableUpload` multer config with **NO fileFilter** — arbitrary file types accepted (`src/middleware/upload.js:50-52`)
- `POST /api/messages/conversations/:id/messages`: `attachments[]` (up to 5) — uses messaging `upload` multer config with **NO fileFilter** — arbitrary file types accepted (`src/middleware/upload.js`)

### HTTP Headers
- `Authorization: Bearer <token>` — JWT token; validated by `authenticate` middleware; auth bypass possible if unexpected errors occur (`src/middleware/auth.js:36`)
- `Cookie: connect.sid` — Session cookie; `httpOnly: true`, no `sameSite` attribute set (CSRF exposure); `secure` conditional on `NODE_ENV === 'production'` (not always set)
- `X-Payment-Signature` — Optional webhook signature; if **omitted**, signature verification is **skipped** entirely (`src/integrations/webhook.service.js:14-29`)
- `Content-Type` — Used by Multer file upload parsing; no MIME type enforcement for deliverable uploads
- `Origin` — CORS reflects any origin with credentials (`Access-Control-Allow-Origin: <any>` + `Access-Control-Allow-Credentials: true`)

### Cookie Values
- `connect.sid` — Express session ID (Redis-backed). Session secret fallback: `hireflow-session-key-change-in-production`. No `sameSite` attribute.

### WebSocket Event Payloads (Socket.IO)
- `socket.handshake.query.userId` — **User impersonation vector** — no server-side verification
- `join:conversation` / `join_conversation` event: `conversationId` — no membership validation
- `send_message` event: `conversationId`, `content`, `type`, `attachments` — no participant check
- `typing` event: `{ userId }` from client payload (NOT from session) — spoofable
- `edit_message` event: `messageId`, `content`
- `delete_message` event: `messageId`, `conversationId`

---

## 6. Network & Interaction Map

### 6.1 Entities

| Title | Type | Zone | Tech | Data | Notes |
|---|---|---|---|---|---|
| UserBrowser | Identity | Internet | Browser/React 18 SPA | Public | End user; communicates via HTTP to Nginx/Express |
| Nginx | ExternAsset | Edge | Nginx HTTP | Public | Reverse proxy on port 80; HTTP only, no TLS, no security headers, 50MB body limit |
| HireFlowApp | Service | App | Node.js 20 / Express 4.17.1 | PII, Tokens, Payments, Secrets | Main application backend; also directly accessible on port 3000 (Nginx bypass) |
| PostgreSQL | DataStore | Data | PostgreSQL 15 | PII, Tokens, Payments, Secrets | Users, wallets, transactions, contracts, messages, reviews, disputes; no SSL; all ports exposed |
| MongoDB | DataStore | Data | MongoDB 7 | Public | Gig catalog, activity logs; no auth, no TLS; port 27017 exposed |
| Redis | DataStore | Data | Redis 7 | Tokens, Secrets | Session storage; no auth, no TLS; port 6379 exposed |
| MinIO | DataStore | Data | MinIO (S3-compatible) | PII | Avatar/gig image storage; anonymous download on buckets; ports 9000/9001 exposed |
| MailHog | ThirdParty | App | MailHog SMTP relay | PII | Captures all outbound email (dev relay); port 1025 SMTP, port 8025 web UI exposed |
| PuppeteerChromium | Service | App | Chromium (--no-sandbox) | PII, Secrets | Headless PDF generation; triggered by invoice API; vulnerable to SSRF via HTML injection |
| SocketIO | Service | App | Socket.IO 4.7.2 | PII | Real-time messaging/presence; no auth on default namespace; wildcard CORS |

### 6.2 Entity Metadata

| Title | Metadata Key: Value |
|---|---|
| HireFlowApp | Hosts: `http://host.docker.internal:3000`, `http://host.docker.internal:80` (via Nginx); Routes: `/api/*`, `/uploads/*`, `/socket.io`; Auth: Session Cookie (`connect.sid`), Bearer JWT; JWT Secret: `hireflow2024api` (default); Session Secret: `hireflow-session-key-change-in-production` (default); CORS: `origin: true, credentials: true`; CSP: disabled |
| PostgreSQL | Engine: PostgreSQL 15; Exposure: host port 5432 (directly accessible); Credentials: `PG_PASSWORD` env var or fallback `hireflow_dev_2024`; SSL: none; Consumers: HireFlowApp |
| MongoDB | Engine: MongoDB 7; Exposure: host port 27017 (directly accessible); Auth: none; SSL: none; URI: `mongodb://mongodb:27017/hireflow` (leaked by `/api/debug/info`); Consumers: HireFlowApp |
| Redis | Engine: Redis 7; Exposure: host port 6379 (directly accessible); Auth: none; SSL: none; Stores: express-session data; Consumers: HireFlowApp |
| MinIO | Engine: MinIO S3-compatible; Exposure: ports 9000 (API), 9001 (Web UI) directly accessible; Access Key: `MINIO_ACCESS_KEY` env or `hireflow`; Secret Key: `MINIO_SECRET_KEY` env or `hireflow123`; Buckets: `avatars`, `gig-images` (both anonymous download) |
| MailHog | Engine: MailHog; Exposure: port 1025 (SMTP, unauthenticated), port 8025 (web UI, unauthenticated); Receives: all application email including password reset links, contract notifications |
| PuppeteerChromium | Flags: `--no-sandbox`; Trigger: `GET /api/contracts/:id/invoice`; Input: `display_name`, `milestone.title` (unsanitized HTML interpolation); Risk: SSRF/local file read via HTML injection |
| SocketIO | CORS: `origin: '*'`; Auth: none on default namespace; Identity: `userId` query parameter (client-asserted); Namespaces: `/` (active), `/messaging` (dead code — not initialized) |

### 6.3 Flows (Connections)

| FROM → TO | Channel | Path/Port | Guards | Touches |
|---|---|---|---|---|
| UserBrowser → Nginx | HTTP | `:80 /api/*`, `/uploads/*`, `/socket.io` | None | Public, PII, Tokens, Payments |
| UserBrowser → HireFlowApp | HTTP | `:3000 /api/*` (Nginx bypass) | None | Public, PII, Tokens, Payments |
| Nginx → HireFlowApp | HTTP | `proxy_pass :3000` | None | Public, PII, Tokens, Payments |
| UserBrowser → HireFlowApp | HTTP | `:3000 POST /api/auth/login` | None | PII (credentials) |
| UserBrowser → HireFlowApp | HTTP | `:3000 GET /api/users?search=` | None (public) | PII — **SQLi sink** |
| UserBrowser → HireFlowApp | HTTP | `:3000 GET /api/gigs?tag_filter=` | None (public) | Public — **NoSQLi sink** |
| UserBrowser → HireFlowApp | HTTP | `:3000 GET /api/debug/info` | None (public) | **Secrets** (mongo_uri, db_host, redis_host) |
| UserBrowser → HireFlowApp | HTTP | `:3000 GET /api/users/:id/settings` | None (public) | **PII** (email, phone) |
| UserBrowser → HireFlowApp | HTTP | `:3000 POST /api/webhooks/payment` | None (optional signature) | **Payments** |
| UserBrowser → HireFlowApp | HTTP | `:3000 /api/contracts/*` | auth:user | PII, Payments — multiple IDORs |
| UserBrowser → HireFlowApp | HTTP | `:3000 /api/messages/*` | auth:user | PII — IDOR on conversations |
| UserBrowser → HireFlowApp | HTTP | `:3000 POST /api/webhooks/test` | auth:user | — **SSRF** (POST, no blocklist) |
| UserBrowser → HireFlowApp | HTTP | `:3000 GET /api/integrations/import` | auth:user | — **SSRF** (GET, response returned) |
| UserBrowser → HireFlowApp | HTTP | `:3000 POST /api/messages/conversations/:id/link-preview` | auth:user | — **SSRF** (partial blocklist) |
| UserBrowser → HireFlowApp | HTTP | `:3000 GET /api/contracts/:id/invoice` | auth:user | PII, Payments — **Puppeteer HTML injection** |
| UserBrowser → SocketIO | WS | `:3000 /socket.io?userId=<any>` | None (userId from query param) | PII — user impersonation |
| HireFlowApp → PostgreSQL | TCP | `:5432` | App-internal | PII, Tokens, Payments, Secrets |
| HireFlowApp → MongoDB | TCP | `:27017` | App-internal | Public, Secrets |
| HireFlowApp → Redis | TCP | `:6379` | App-internal | Tokens (session data) |
| HireFlowApp → MinIO | HTTP | `:9000` | App-internal (access key) | PII (avatars, gig images) |
| HireFlowApp → MailHog | SMTP | `:1025` | App-internal | PII (email content, reset tokens) |
| PuppeteerChromium → InternalNetwork | HTTP | `*:*` (attacker-controlled via HTML injection) | None | Secrets, PII |

### 6.4 Guards Directory

| Guard Name | Category | Statement |
|---|---|---|
| auth:user | Auth | Requires a valid user session (`req.session.userId`) or Bearer JWT token. Implemented in `src/middleware/auth.js`. |
| auth:admin | Authorization | Requires `req.user.role` to be `admin` or `superadmin`. Implemented as `requireAdmin` in `src/middleware/rbac.js:35-37`. |
| auth:moderator | Authorization | Requires `req.user.role` to be `moderator`, `admin`, or `superadmin`. Implemented as `requireModerator` in `src/middleware/rbac.js:39-41`. |
| auth:superadmin | Authorization | Requires `req.user.role === 'superadmin'`. Only 2 endpoints use this: `PUT /api/admin/settings` and `GET /api/admin/audit-log`. |
| auth:freelancer | Authorization | Requires `req.user.role === 'freelancer'`. Used for gig CRUD, proposal submission/management. |
| auth:client | Authorization | Requires `req.user.role === 'client'`. Used for project CRUD, proposal status changes. |
| ownership:user | ObjectOwnership | Verifies `req.user.id === req.params.id` (or equivalent). Present on: `PUT /api/users/:id/settings`, `PUT /api/users/:id`, `PUT /api/users/:id/avatar`. |
| ownership:message | ObjectOwnership | Verifies `message.sender_id === req.user.id` in DB query. Present on: `PUT /api/messages/messages/:id`, `DELETE /api/messages/messages/:id`. |
| ownership:review | ObjectOwnership | Verifies `review.reviewer_id === req.user.id`. Present on `PUT /api/reviews/:id`. |
| ownership:proposal | ObjectOwnership | Verifies `proposal.freelancer_id === req.user.id`. Present on `PUT /api/proposals/:id`, `DELETE /api/proposals/:id`. |
| ownership:escrow | ObjectOwnership | Verifies `contract.client_id === req.user.id`. Present on escrow fund/release. |
| ownership:contract | ObjectOwnership | **MISSING** on nearly all contract endpoints. GET, PUT status, milestone CRUD, invoice download — none verify party membership. |
| ownership:conversation | ObjectOwnership | **MISSING** on conversation GET and message POST. Any authenticated user can read/write any conversation. |
| jwt:bypass | Auth | Auth bypass condition in `src/middleware/auth.js:36` — unexpected errors during JWT processing call `next()` without setting `req.user`. |
| signature:optional | Auth | Webhook signature check in `src/integrations/webhook.service.js:14-29` — verification ONLY runs if `x-payment-signature` header is present; omitting the header skips all verification. |

---

## 7. Role & Privilege Architecture

### 7.1 Discovered Roles

| Role Name | Privilege Level | Scope/Domain | Code Implementation |
|---|---|---|---|
| guest | 0 | Global | Unauthenticated users; no auth middleware required |
| client | 1 | Global | Registered buyer; `requireRole('client')` in `src/middleware/rbac.js:17`; assigned at registration |
| freelancer | 1 | Global | Registered seller; `requireRole('freelancer')` in `src/middleware/rbac.js:17`; assigned at registration |
| moderator | 2 | Global | Dispute/content moderator; assigned only by admin via `PUT /api/admin/users/:id`; `requireModerator` in `src/middleware/rbac.js:39` |
| admin | 3 | Global | Platform administrator; `requireAdmin` checks both `admin` and `superadmin`; `src/middleware/rbac.js:35` |
| superadmin | 4 | Global | System superadmin; bypasses ALL `requireRole` checks unconditionally (line 22); exclusive access to settings update and audit log |

### 7.2 Privilege Lattice

```
Privilege Ordering (→ means "can access resources of"):
guest → client/freelancer → moderator → admin → superadmin

Specific Promotion Rules in rbac.js:
- superadmin passes ALL requireRole checks (line 22)
- admin passes requireRole('moderator') (line 27)
- client and freelancer are PEERS (level 1) — neither can access the other's role-gated routes

Parallel Isolation (|| means "not ordered relative to each other"):
client || freelancer (same numeric level, no cross-role inheritance)

Role Assignment:
- client/freelancer: self-assigned at registration (hardcoded to these two values only)
- moderator/admin/superadmin: only assignable via admin API (PUT /api/admin/users/:id)

JWT Weakness:
- Role is embedded in JWT at signing time
- If JWT_SECRET is known (default: 'hireflow2024api'), attacker can forge any role
- Role changes in DB do NOT invalidate existing JWTs
- Effective token lifetime: 7 days from issuance
```

### 7.3 Role Entry Points

| Role | Default Landing Page | Accessible Route Patterns | Authentication Method |
|---|---|---|---|
| guest (anon) | `/` (homepage) | `/`, `/login`, `/register`, `/api/users?search=`, `/api/gigs`, `/api/debug/info`, `/api/users/:id/settings`, `/api/projects`, `/api/reviews`, `/uploads/` | None |
| client | `/dashboard` | `/dashboard`, `/profile`, `/api/projects/*`, `/api/proposals/:id/status`, `/api/contracts/*` (IDOR), `/api/payments/*`, `/api/messages/*` (IDOR), `/api/reviews`, `/api/disputes/*` | Session Cookie or Bearer JWT |
| freelancer | `/dashboard` | `/dashboard`, `/profile`, `/api/gigs/*` (own), `/api/proposals/*` (own), `/api/contracts/*` (IDOR), `/api/payments/*`, `/api/messages/*` (IDOR) | Session Cookie or Bearer JWT |
| moderator | `/admin/dashboard` | All user routes + `/api/admin/dashboard`, `/api/admin/disputes/*`, `/api/disputes/:id/assign`, `/api/disputes/:id/resolve` | Session Cookie or Bearer JWT |
| admin | `/admin` | All moderator routes + `/api/admin/users/*`, `/api/admin/transactions`, `/api/admin/reports/*`, `/api/admin/settings` (read), `/api/admin/categories/*`, `/api/admin/analytics/*` | Session Cookie or Bearer JWT |
| superadmin | `/admin` | All admin routes + `PUT /api/admin/settings`, `GET /api/admin/audit-log` | Session Cookie or Bearer JWT |

### 7.4 Role-to-Code Mapping

| Role | Middleware/Guards | Permission Checks | Storage Location |
|---|---|---|---|
| client | `authenticate` + `requireRole('client')` | `req.user.role === 'client'` (exact string match, `rbac.js:17`) | PostgreSQL `users.role`, JWT `role` claim |
| freelancer | `authenticate` + `requireRole('freelancer')` | `req.user.role === 'freelancer'` (exact string match, `rbac.js:17`) | PostgreSQL `users.role`, JWT `role` claim |
| moderator | `authenticate` + `requireModerator` | `['moderator','admin','superadmin'].includes(req.user.role)` (`rbac.js:39-41`) | PostgreSQL `users.role`, JWT `role` claim |
| admin | `authenticate` + `requireAdmin` | `['admin','superadmin'].includes(req.user.role)` (`rbac.js:35-37`) | PostgreSQL `users.role`, JWT `role` claim |
| superadmin | `authenticate` + `requireRole('superadmin')` | `req.user.role === 'superadmin'` OR implicit bypass in all `requireRole` calls (`rbac.js:22`) | PostgreSQL `users.role`, JWT `role` claim |

---

## 8. Authorization Vulnerability Candidates

### 8.1 Horizontal Privilege Escalation Candidates

| Priority | Endpoint Pattern | Object ID Parameter | Data Type | Sensitivity |
|---|---|---|---|---|
| **High** | `GET /api/contracts/:id` | contract_id | Financial + PII (both parties' emails, amounts) | Any auth user reads any contract |
| **High** | `PUT /api/contracts/:id/status` | contract_id | Contract lifecycle | Any auth user cancels/completes any contract |
| **High** | `GET /api/messages/conversations/:id` | conversation_id | Private messages | Any auth user reads all messages in any conversation |
| **High** | `POST /api/messages/conversations/:id/messages` | conversation_id | Private messages | Any auth user injects messages into any conversation |
| **High** | `GET /api/contracts/:id/invoice` | contract_id | Financial + PII | Any auth user downloads PDF invoice with both parties' emails and financial breakdown |
| **High** | `GET /api/users/:id/settings` | user_id | PII (email, phone, last_login) | **No authentication at all** — fully public |
| **High** | `POST /api/contracts/:id/milestones/:milestoneId/submit` | contract_id, milestoneId | Deliverables | Any auth user submits deliverables on any milestone |
| **High** | `PUT /api/contracts/:id/milestones/:milestoneId/approve` | contract_id, milestoneId | Financial (triggers escrow) | Any auth user approves milestones (may trigger payment) |
| **High** | `POST /api/contracts/:id/milestones` | contract_id | Contract structure | Any auth user adds milestones to any contract |
| **High** | `PUT /api/contracts/:id/milestones/:milestoneId` | contract_id, milestoneId | Financial amounts, due dates | Any auth user modifies any milestone's amount/dates |
| **Medium** | `GET /api/proposals?freelancer_id=` | freelancer_id (query param) | Proposals (cover letters, bid amounts) | Any auth user queries any freelancer's proposals |
| **Medium** | `PUT /api/contracts/:id/milestones/:milestoneId/request-revision` | contract_id, milestoneId | Contract workflow | Any auth user requests revisions |
| **Medium** | `POST /api/reviews` | contract_id, reviewee_id (body) | Reviews | Any auth user posts review for any contract without being party to it |
| **Low** | `GET /api/reviews/:id` | review_id | Review content | Private reviews (`is_public: false`) readable by anyone knowing the ID |

### 8.2 Vertical Privilege Escalation Candidates

| Target Role | Endpoint Pattern | Functionality | Risk Level |
|---|---|---|---|
| any | Forge JWT with secret `hireflow2024api` → any role | Full application compromise via hardcoded JWT secret | **Critical** — forge `superadmin` token |
| moderator/admin | `PUT /api/disputes/:id/assign` | Self-assign as moderator on any dispute | **High** — route has `requireModerator` but controller may lack role recheck |
| moderator/admin | `PUT /api/disputes/:id/resolve` | Trigger financial operations (refunds) on any dispute | **High** — requires moderator but logic is reachable |
| admin | `GET /api/admin/users` | User management list with SQL injection | **High** — admin-only but SQLi provides data exfiltration |
| admin | `GET /api/admin/reports/activity` | NoSQL injection in activity report | **High** — admin-only but NoSQLi provides data manipulation |
| admin | `PUT /api/admin/users/:id` | Promote any user to admin (by a compromised admin account) | **High** — privilege escalation chain via compromised admin |
| superadmin | `PUT /api/admin/settings` | Platform configuration update | **High** — highest privilege endpoint |
| superadmin | `GET /api/admin/audit-log` | Read security audit logs | **Medium** — information gathering |

### 8.3 Context-Based Authorization Candidates

| Workflow | Endpoint | Expected Prior State | Bypass Potential |
|---|---|---|---|
| Contract Milestone Flow | `PUT /api/contracts/:id/milestones/:mid/approve` | Milestone must be in `submitted` state; requester must be client | Direct approval without prior submission; no party check — any user can approve |
| Contract Milestone Flow | `POST /api/contracts/:id/milestones/:mid/submit` | Contract must be active; user must be freelancer on the contract | Any authenticated user can submit; no freelancer role or party check |
| Dispute Resolution | `PUT /api/disputes/:id/resolve` | Dispute must be assigned; moderator must be assigned | May be resolvable before assignment; triggers financial refunds |
| Payment Webhook | `POST /api/webhooks/payment` | Expects HMAC signature from payment provider | Omit `x-payment-signature` header to skip all verification; credit any wallet |
| Password Reset | `POST /api/auth/reset-password` | Valid reset token + within validity window | Token is 64-bit entropy (SHA256 of email+timestamp truncated to 16 hex chars); predictable in narrow time window |
| Email Verification | `GET /api/auth/verify-email/:token` | Account created, verification email sent | Token reuse not prevented after verification |
| Escrow Release | `POST /api/payments/escrow/release/:milestoneId` | Milestone must be approved | Approval IDOR above means an attacker could approve then release escrow on any contract |

---

## 9. Injection Sources

### SQL Injection Sources

**Source 1 — CRITICAL (Public/Unauthenticated):**
- **File:** `src/users/users.service.js`, **line 33**
- **Input:** `req.query.search` via `GET /api/users?search=<payload>`
- **Sink:** Raw SQL string interpolation — `query += \` AND (display_name ILIKE '%${search}%' OR email ILIKE '%${search}%' OR username ILIKE '%${search}%')\``
- **Auth Required:** None — fully public endpoint
- **Impact:** Full read of PostgreSQL database (users, passwords, wallet balances, reset tokens); potential write/delete depending on DB user privileges

**Source 2 — HIGH (Admin-only):**
- **File:** `src/admin/admin.service.js`, **line 66**
- **Input:** `req.query.search` via `GET /api/admin/users?search=<payload>`
- **Sink:** Knex `whereRaw()` with string concatenation — `query.whereRaw("display_name ILIKE '%" + search + "%' OR email ILIKE '%" + search + "%'")`
- **Auth Required:** `admin` role
- **Impact:** Same database-level impact; requires compromised admin credential

### NoSQL Injection Sources

**Source 3 — CRITICAL (Public/Unauthenticated; blocked in deployment):**
- **File:** `src/gigs/gigs.service.js`, **lines 41-45**
- **Input:** `req.query.tag_filter` via `GET /api/gigs?tag_filter=<payload>`
- **Sink:** MongoDB `$where` operator — `query.$where = \`function() { var tags = this.tags || []; return ${tag_filter}; }\``
- **Auth Required:** None — public endpoint
- **Note:** MongoDB 7 disables `$where` by default (`$where is not allowed in this context`). Code is vulnerable but the MongoDB security policy blocks exploitation in this specific deployment.
- **Impact (if exploitable):** Arbitrary server-side JavaScript execution in MongoDB context; blind data exfiltration; CPU exhaustion DoS

**Source 4 — HIGH (Admin-only):**
- **File:** `src/admin/admin.service.js`, **lines 358-364**
- **Input:** `req.query.usernames[]` array via `GET /api/admin/reports/activity?usernames[]=<payload>`
- **Sink:** Manual JSON string construction — `var userFilter = usernames.map(u => '"' + u + '"').join(','); var query = '{ "metadata.username": { "$in": [' + userFilter + '] } }'; filter = JSON.parse(query);`
- **Auth Required:** `admin` role
- **Impact:** MongoDB operator injection; bypass user-scoping filter; exfiltrate all activity log records

### SSRF Sources

**Source 5 — CRITICAL (Authenticated, Full Read SSRF, Response Returned):**
- **File:** `src/integrations/webhook.service.js`, **lines 196-248**
- **Input:** `req.query.url` via `GET /api/integrations/import?url=<payload>`
- **Sink:** `http.request()` / `https.request()` with no URL validation; response body returned to caller
- **Auth Required:** Any authenticated user
- **Impact:** Exfiltrate response from any internal service; cloud metadata credential theft (IMDSv1); internal network scanning

**Source 6 — HIGH (Authenticated, Full POST SSRF):**
- **File:** `src/integrations/webhook.service.js`, **lines 139-188**
- **Input:** `req.body.url` via `POST /api/webhooks/test`
- **Sink:** `http.request()` / `https.request()` — no hostname/IP validation whatsoever; sends JSON POST body
- **Auth Required:** Any authenticated user
- **Impact:** POST to any internal service; trigger state mutations; partial response returned (500 bytes)

**Source 7 — HIGH (Authenticated, Bypassable Blocklist):**
- **File:** `src/messaging/messaging.service.js`, **lines 367-421**
- **Input:** `req.body.url` via `POST /api/messages/conversations/:id/link-preview`
- **Sink:** `http.get()` / `https.get()` — blocklist only blocks exact strings `localhost` and `127.0.0.1`
- **Bypass techniques:** `http://[::1]/`, `http://0.0.0.0/`, `http://127.0.0.2/`, `http://169.254.169.254/`, `http://10.x.x.x/`, decimal IP `http://2130706433/`, docker service names `http://postgres:5432/`
- **Auth Required:** Any authenticated user
- **Impact:** SSRF to cloud metadata, internal services; response includes parsed HTML title/OG tags (up to 500KB read)

**Source 8 — HIGH (Second-Order, via Stored Data → Puppeteer):**
- **File:** `src/utils/pdf.js`, **lines 55-76**
- **Input:** `display_name` (set at registration, `PUT /api/users/:id`), `milestone.title` (set via contract creation), stored in PostgreSQL, rendered into HTML
- **Sink:** `page.setContent(html, { waitUntil: 'networkidle0' })` — user-controlled values interpolated into HTML template string without escaping; executed by Chromium with `--no-sandbox`
- **Trigger:** `GET /api/contracts/:id/invoice` (any authenticated user — IDOR also present)
- **Impact:** Server-side XSS in Puppeteer; SSRF via injected `<img>`/`<script>` tags fetching internal URLs; potential local file read via `file://`; `waitUntil: 'networkidle0'` means full network requests complete

### HTML Injection (Email) Sources

**Source 9 — MEDIUM:**
- **File:** `src/contracts/contracts.service.js`, **lines 296-299, 386-387**
- **Input:** `milestone.title` (contract creation), `reason` (`req.body.reason` in revision request), `contract.title`
- **Sink:** String interpolation into Nodemailer `html` field
- **Trigger:** Milestone submission (`POST /api/contracts/:id/milestones/:mid/submit`), revision request (`PUT /api/contracts/:id/milestones/:mid/request-revision`)
- **Impact:** HTML injection into email body; phishing links in official notifications; most email clients strip `<script>` but `<a href>` and `<img>` tags render

### Stored XSS Sink (Frontend)

**Source 10 — HIGH:**
- **File:** `client/src/pages/GigDetail.jsx`, **line 299**
- **Input:** `review.comment` stored via `POST /api/reviews` (any authenticated user, no contract party check)
- **Sink:** `dangerouslySetInnerHTML={{ __html: review.comment }}`
- **Render Context:** HTML Body in browser; JavaScript executes in victim's browser
- **Impact:** Stored XSS affecting all users who view the gig detail page; JWT tokens in `localStorage` accessible; session cookies (without httpOnly) potentially accessible; initiates API calls on behalf of victim

### Unrestricted File Upload

**Source 11 — MEDIUM-HIGH:**
- **File:** `src/middleware/upload.js`, **lines 50-52** (`deliverableUpload`), messaging upload config
- **Input:** `files[]` multipart upload via `POST /api/contracts/:id/milestones/:mid/submit` and `POST /api/messages/conversations/:id/messages`
- **No `fileFilter`** — all MIME types accepted; original file extension preserved
- **Sink:** File written to `uploads/` directory, served statically with directory listing
- **Impact:** Upload of HTML/SVG files (stored XSS via direct URL access); upload of executable scripts if server-side execution is possible; exfiltration via publicly accessible `/uploads/` with directory listing

### Financial / Logic Injection

**Source 12 — CRITICAL:**
- **File:** `src/integrations/webhook.service.js`, **lines 14-29**
- **Input:** `req.body` via `POST /api/webhooks/payment` — `event`, `data.user_id`, `data.amount`, `data.transaction_id`
- **Auth Required:** None (public endpoint)
- **Bypass:** Omit `x-payment-signature` header to skip HMAC verification entirely
- **Impact:** Credit any amount to any user's wallet without payment; forge complete/failed payment events

---
