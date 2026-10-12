# gatekeeper: status

## Goal
Gatekeeper: a central repository for user and role management for multiple services and applications. External systems call it over REST to query authentication and authorisation for users. (User's description, 2026-10-09.)

## Requirements (from user)
- REST API consumed by other applications.
- Final deployment: containerised with Podman, PostgreSQL database.
- Built stepwise: minimal vertical slice first; in-memory DB to start.
- First functionality: CRUD for users and user roles. More to follow.
- CLI supporting the functionality. Front-end later.
- User will provide git.

## Decisions
- Back-end language: C# (ASP.NET Core). Chosen by user 2026-10-09.
- Integration: token-based (JWT, verified by consumers via JWKS). Chosen by user.
- Database: PostgreSQL behind a repository interface; in-memory first. Slice 2 uses EF Core + Npgsql (user decision 2026-10-11), citext for case-insensitive uniqueness, FK cascades, migrations as an explicit `migrate` command.
- Podman 6.1.1 (rootless) is installed; used for the dev/test Postgres containers.
- Git strategy: trunk-based. Protected `main`, short-lived feat/fix/chore branches squash-merged via PR, Conventional Commits, build once and promote the same image (PR CI -> main publish -> staging -> tag `vX.Y.Z` -> production with manual approval). Approved by user.
- Git host: GitHub (CI via GitHub Actions, registry GHCR proposed).
- Deployment: local for now; eventually a single server with Podman + Quadlet.
- Agent setup approved: planner (opus), developer (sonnet), qa (sonnet), security (opus), defined in `.claude/agents/`.
- Repo prepared locally 2026-10-09: `git init -b main`, origin = https://github.com/sookmoo/gatekeeper.git, .gitignore, .gitattributes, .editorconfig, placeholder CI workflow. Nothing committed or pushed yet.
- .NET SDK 10.0.111 is installed locally.
- Pending: front-end language (after slice 1).
- Usernames stay lowercase slugs (user decision 2026-10-10); uniqueness remains case-insensitive.
- Slugs (app, role, username) must not look like GUIDs, because the CLI accepts name or id.
- Planner note (user): add PATCH (partial update) alongside GET/POST/PUT in the API at some point; the CLI `update` commands currently emulate it with GET + PUT.

## Open questions
- Auth model for external systems (tokens/JWT, API keys, OIDC).
- Git remote/branching conventions; deadline; user/system scale.

## Slice 1: done (PRs #1 and #2 merged 2026-10-10)
In-memory store, REST API under /v1, `gk` CLI, OpenAPI contract, QA + security review fixes. The application entity is `App` in code (avoids clash with the `Gatekeeper.Application` namespace); API path is `/applications`.

## Slice 2: PostgreSQL store (done, PR #3 merged 2026-10-11)
- Done: `Gatekeeper.Infrastructure.Postgres` (EF Core, `InitialCreate` migration, repositories), `Store:Provider` switch, `migrate` command, `/health/ready`, dev/test scripts, CI Postgres service + migration drift check.
- QA + security review fixes applied (2026-10-11): separate owner (migrations) and app (data-only) roles with tests that run the stores as the app role; NUL/control/bidi/invalid-UTF-16 rejected in free text; ASCII-only emails; microsecond timestamps; username-before-email and user-before-role error precedence match in both stores; connection failures become `StoreUnavailableException` -> 503 (CLI exit 4); `migrate` fails cleanly (exit 1, no arguments allowed); `/health/ready` logs failures and checks pending migrations; EF log levels reduced; TLS guidance in README.
- Tests: 153 pass with Postgres (`scripts/test-pg.sh`); without `GATEKEEPER_TEST_PG` the Postgres tests show as skipped. QA parity tests (in-memory vs Postgres) are kept.
- Manually verified with the real roles: migrate as owner, serve as app, DDL refused for the app role, DB-down gives 503 and recovery, migrate failure paths.

## Slice 3: containers (done, PR #4 merged 2026-10-12)
- Done: `Containerfile` (digest-pinned sdk and chiseled aspnet runtime, non-root), `healthcheck` command (no shell in image), explicit `Gatekeeper:AllowNonLoopback` opt-in for the loopback guard, Quadlet units in `deploy/quadlet/` (network, volume, db, one-shot migrate, api), `deploy/install.sh` (podman secrets), CI `image` job (build on PRs, push to GHCR from main).
- Verified locally with Quadlet: migrate runs before the API, API healthy, data persists across restarts, app role cannot DDL, image refuses to start without the opt-in.
- Decision: no podman-compose; Quadlet is used for local and server alike (one mechanism).
- Not done: tag-based promotion to staging/production (needs a server), image vulnerability scan, Dependabot for base-image digests.

## Slice 4a: paging, passwords, login, JWT (branch `feat/slice-4a-auth`)
- Decisions (user: "go for recommended choices", 2026-10-12): split auth into 4a (this) and 4b (service identities, audit table, PATCH, refresh/revocation); admins are users with role `admin` in the reserved app `gatekeeper`; ES256 keys from a podman secret, public key at `/.well-known/jwks.json`.
- Done: lists return `{items,nextCursor}` (limit 1-200, opaque offset cursor) and everything takes a CancellationToken; `user_credentials` table (separate from users) with Argon2id; `PUT /v1/users/{id}/password`; `POST /v1/auth/login` (uniform 401, dummy hash for unknown users, 429 throttle per username/address); ES256 access tokens (aud = application, roles = that app only, typ `at+jwt`, 15 min); JWT bearer on `/v1` with pinned alg/typ/iss/aud and admin policy; `bootstrap-admin` command and `deploy/bootstrap-admin.sh`; `Auth:SeedDevAdmin` for the in-memory store; CLI `login`/`logout`/`set-password`, token file 0600 bound to its server, exit code 5.
- Deviation from the plan: the loopback guard stays (opt-in `Gatekeeper:AllowNonLoopback`), because logins carry passwords over plain HTTP; its message now says so.
- Findings along the way: `InvariantGlobalization` makes `string.Normalize` a silent no-op, so passwords are not normalised (documented); a flaky advisory-lock race in the Postgres test helper was fixed.
- Verified on Quadlet: bootstrap, `gk login`, CRUD with the token, 401 without; a login token verified independently with openssl against the JWKS.
- Reviews (2026-10-12): QA found 4 bugs (roles cut at 200, rehash race, CLI silent list truncation, wrong login message), security found 2 High (unbounded concurrent Argon2, lockout of victims/proxy users), 4 Medium, 7 Low. All fixed: `HashLimiter` (bounded concurrency, 503 when busy) + container memory limit; throttle per (address, username) and per address, per-username counter only slows; trusted proxies setting; 64 KB body limit; throttle keys only for valid usernames; admin tokens re-checked against the store (10 s cache); `AdminGuard` keeps the last active admin; reserved name can't be claimed; bootstrap repairs an existing admin; compare-and-set rehash; login loads all roles; signing key from a mounted secret file; readiness answer cached 2 s; no Server header; CLI: no redirects, https required off-box, output sanitised, list cut-off is an error; fail-closed provider default in container setups.
- Known limits: tokens for other applications stay valid until `exp` (no revocation yet); throttle is per process; no key rotation tooling (JWKS has one key); OpenAPI does not declare the bearer scheme and stays public; offset cursors shift if rows change between pages; 409 messages reveal whether a username/email exists (admin-only); `SSL Mode=Disable` to the DB on the private podman network; connection strings are still environment secrets.

## Slice 4b: service identities, audit trail, PATCH (branch `feat/slice-4b`)
- Decisions (user, 2026-10-12): 4b = audit log + service identities + PATCH/OpenAPI bearer/protected `/health/ready`; refresh tokens + revocation and key rotation deferred to 4c.
- Done: `PATCH` for apps, roles, users, clients (absent field = unchanged; CLI `update` uses it); OpenAPI declares the bearer scheme; `/health/ready` needs an admin token and checks the signed token only (it must work when the store is down); `audit_events` (migration `AddAuditEvents`) is append-only (trigger + no UPDATE/DELETE/TRUNCATE for `gatekeeper_app`, verified with the real `db-roles.sql`), written by an endpoint filter for every state-changing `/v1` call plus logins, client tokens and `bootstrap-admin`; `GET /v1/audit`, `gk audit list`; service identities (`clients`, `client_secrets`, `client_roles`, migration `AddClients`): `/v1/clients` CRUD, one-time secret (`gks_`, SHA-256 at rest), rotate, role assignment limited to the client's application, never in the reserved `gatekeeper` app, `POST /v1/auth/client-token` (uniform 401, own throttle), `gk client ...`.
- Design notes: client tokens carry `client_id` and no `preferred_username`; audit writes are best effort (a failing audit store is logged, the change still succeeds); audit text is sanitised and truncated; secrets/passwords never reach the audit trail (tests).
- Known limits: no audit retention/pruning, and failed logins are attacker-driven rows (throttled per address only); 401/403 rejected before the endpoint are not audited; client lookup timing can reveal whether a client name exists (names are not secret, secrets are 256-bit); client list resolution in the CLI lists all clients; tokens still live until `exp` (no revocation yet).
- Reviews (2026-10-12): security found no High; QA found 3 Medium and 5 Low. All fixed: throttle always keeps the per-address counter, sweeps at most once a second and buckets IPv6 by /64 (a flood of distinct keys no longer turns the limit off or burns CPU); failed attempts record the name only if it exists (a secret typed into the wrong field no longer lands in the immutable trail); PATCH runs under a process-wide gate (lost updates, including a lost disable); audit is middleware so binding failures (400/415/413) are recorded; audit filters with NUL/invalid text return an empty list; audit actions drop route constraints (`{id}` not `{id:guid}`); OpenAPI no longer marks `/v1/auth/client-token` and the JWKS as bearer-secured; undefined table/column maps to 503 (unmigrated database); `POST /v1/clients` without `application` is 400; CLI strips U+2028/2029; in-memory audit rejects duplicate ids; bearer tokens on `/v1/auth/*` are ignored (no store lookup on anonymous routes).
- Not changed: `/health/ready` still trusts the signed token alone (documented); audit has no retention; audit writes stay best effort and synchronous (5 s cap); PATCH gate is per process; no `token_use` claim (consumers use `client_id`/`sub`).
- Tests: 462 with Postgres (Api 227, Contract 103 + 1 skipped, Cli 60, Application 38, Domain 34), including the QA agent's Qa4b* suites; without Postgres the Postgres variants are skipped.

## Slice 4c: sessions, revocation, introspection, key rotation (branch `feat/slice-4c`)
- Decisions (user, 2026-10-12): refresh sessions + introspection for revocation; refresh tokens for users only; key rotation with current + retired key files.
- Done: `sessions` table (migration `AddSessions`; token hash current + previous, absolute expiry, revoked-at; cascades with user/app; expired rows purged after 7 days); refresh tokens `gkr_<session id>.<secret>` with rotation and reuse detection (the just-replaced token coming back ends the session); `POST /v1/auth/refresh|logout|introspect`; login `refresh:true`; `sid` claim; password change, deactivation, role removal and app deletion end sessions; the management API (`AdminAccessCheck`) rejects tokens whose session ended; admin session list/revoke (`/v1/users/{id}/sessions`, `/v1/sessions/{id}`, `gk user sessions|revoke-sessions`); CLI keeps the session alive (auto-refresh under a file lock, logout ends the session server-side); introspection with live roles, client Basic auth, own-application scope; JWKS with retired keys (`Auth__RetiredKeysPemFile`), `deploy/rotate-signing-key.sh` (+ `--compromised`, `--prune`), Quadlet mount for the retired-keys secret.
- Verified on Quadlet (2026-10-12): refresh rotation and reuse detection, ended admin session rejected, key rotate/--compromised/--prune with old-key tokens accepted or rejected as designed, introspection, CLI auto-refresh and logout. Tests: 453 with Postgres (Api 248, Contract 105 + 1 skipped, Cli 66, Application 38, Domain 34).
- Known limits: access tokens without a session (plain login, client tokens) live until `exp` unless the consumer introspects; only the immediately replaced refresh token triggers reuse detection (older ones are just invalid); a client that loses a refresh response (network failure after rotation) must log in again; refresh/PATCH/throttle state is per process; introspection has no caching or rate limit beyond the failure throttle; no per-session device names/IP.

## Deferred hardening (from slice 1 reviews)
Escape control characters in CLI output; request body size limit; pagination and rate limiting; https required for non-loopback CLI URLs; CI hardening (pin action SHAs, `persist-credentials: false`, `global.json`, lock files); central package management; paging + cancellation tokens (before slice 4); unbounded lists today.

## Planner backlog (user ideas, not analysed yet)
1. Local Gatekeeper instances for systems that implement Gatekeeper, with a central master Gatekeeper remaining the source of truth (federated/edge deployment, replication or caching).
2. Proxy/broker mode in front of external identity providers: Entra ID, Active Directory, Keycloak.
3. ~~PATCH~~ done in slice 4b.

## Next action
Slice 4c: implemented and verified on Quadlet (rotation, refresh, introspection, CLI); run independent QA and security reviews, fix, then ask before pushing.
