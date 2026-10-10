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
- Database: PostgreSQL behind a repository interface; in-memory first (proposed, not yet confirmed).
- Podman is not installed on the dev machine yet (needs install before container work).
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

## Slice 1 progress (PR #1, branch `feat/slice-1-crud`)
- Done: solution, in-memory store, REST API under /v1, `gk` CLI, `docs/openapi.json`, README; PR #1 open.
- QA and security reviews done (2026-10-10). Fixed on the branch: atomic parent checks in the repositories (role->app, assignment->user/role, contract tests added), loopback-only startup guard, AllowedHosts restricted, `\z` regex anchors, GUID-shaped slugs rejected, global exception handler + 400 for malformed JSON, PUT keeps `isActive` when omitted, CLI maps malformed responses to exit 1 and accepts only http(s) URLs. 86 tests pass.
- Deferred to the auth/Postgres slices: reject control/bidi characters and escape CLI output; request body size limit; pagination and rate limiting; https required for non-loopback CLI URLs; CI hardening (pin action SHAs, `persist-credentials: false`, `global.json`, lock files); central package management; trim/normalise email.
- Naming: the application entity is `App` in code (avoids clash with the `Gatekeeper.Application` namespace); API path is `/applications`.

## Next action
Merge PR #1 once CI is green, then slice 2 (Postgres store; install Podman first).
