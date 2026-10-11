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

## Slice 2: PostgreSQL store (branch `feat/slice-2-postgres`, in progress)
- Done: `Gatekeeper.Infrastructure.Postgres` (EF Core mapping, `InitialCreate` migration, repositories with constraint-to-exception translation), `Store:Provider` switch, `migrate` command, `/health/ready`, `scripts/dev-db.sh` and `scripts/test-pg.sh`, CI with a Postgres service and a migration drift check. Contract suite runs against both stores (race tests included). 106 tests pass with Postgres, Postgres tests show as skipped without `GATEKEEPER_TEST_PG`.
- Manually verified: migrate, persistence across API restart, cascade on app delete, fail-fast without a connection string.
- Remaining: PR, independent qa + security review of the Postgres adapter (focus: connection string handling, least-privilege DB role for app vs migrator).

## Deferred hardening (from slice 1 reviews)
Reject control/bidi characters and escape CLI output; request body size limit; pagination and rate limiting; https required for non-loopback CLI URLs; CI hardening (pin action SHAs, `persist-credentials: false`, `global.json`, lock files); central package management; trim/normalise email; username filter on Postgres relies on citext parameter typing (covered by tests).

## Planner backlog (user ideas, not analysed yet)
1. Local Gatekeeper instances for systems that implement Gatekeeper, with a central master Gatekeeper remaining the source of truth (federated/edge deployment, replication or caching).
2. Proxy/broker mode in front of external identity providers: Entra ID, Active Directory, Keycloak.
3. PATCH (partial update) alongside GET/POST/PUT in the API; the CLI `update` commands currently emulate it with GET + PUT.

## Next action
Open the slice 2 PR, then run the independent qa and security reviews of the Postgres adapter. After merge: slice 3 (Containerfile, Quadlet, compose for dev, image build in CI), then slice 4 (passwords, login, JWT + JWKS, caller identities).
