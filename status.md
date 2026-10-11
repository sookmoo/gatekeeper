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

## Slice 2: PostgreSQL store (branch `feat/slice-2-postgres`, reviews done, PR not yet opened)
- Done: `Gatekeeper.Infrastructure.Postgres` (EF Core, `InitialCreate` migration, repositories), `Store:Provider` switch, `migrate` command, `/health/ready`, dev/test scripts, CI Postgres service + migration drift check.
- QA + security review fixes applied (2026-10-11): separate owner (migrations) and app (data-only) roles with tests that run the stores as the app role; NUL/control/bidi/invalid-UTF-16 rejected in free text; ASCII-only emails; microsecond timestamps; username-before-email and user-before-role error precedence match in both stores; connection failures become `StoreUnavailableException` -> 503 (CLI exit 4); `migrate` fails cleanly (exit 1, no arguments allowed); `/health/ready` logs failures and checks pending migrations; EF log levels reduced; TLS guidance in README.
- Tests: 153 pass with Postgres (`scripts/test-pg.sh`); without `GATEKEEPER_TEST_PG` the Postgres tests show as skipped. QA parity tests (in-memory vs Postgres) are kept.
- Manually verified with the real roles: migrate as owner, serve as app, DDL refused for the app role, DB-down gives 503 and recovery, migrate failure paths.

## Deferred hardening (from slice 1 reviews)
Escape control characters in CLI output; request body size limit; pagination and rate limiting; https required for non-loopback CLI URLs; CI hardening (pin action SHAs, `persist-credentials: false`, `global.json`, lock files); central package management; paging + cancellation tokens (before slice 4); unbounded lists today.

## Planner backlog (user ideas, not analysed yet)
1. Local Gatekeeper instances for systems that implement Gatekeeper, with a central master Gatekeeper remaining the source of truth (federated/edge deployment, replication or caching).
2. Proxy/broker mode in front of external identity providers: Entra ID, Active Directory, Keycloak.
3. PATCH (partial update) alongside GET/POST/PUT in the API; the CLI `update` commands currently emulate it with GET + PUT.

## Next action
Open the slice 2 PR (needs the user's go-ahead to push). Then slice 3 (containers). Security notes for slice 3: keep `LoopbackGuard` but add an explicit in-container opt-in, run `migrate` as a separate one-shot job with the owner credentials, passwords via podman secrets, digest-pinned non-root images, TLS to non-local databases. Slice 4 (auth): paging/cancellation first, audit table with INSERT-only rights, protect `/health/ready`, consider 409 messages as an enumeration channel.
