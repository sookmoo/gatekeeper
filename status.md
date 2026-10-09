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

## Open questions
- Git `user.name`/`user.email` are not configured; needed before the first commit.
- Auth model for external systems (tokens/JWT, API keys, OIDC).
- Git remote/branching conventions; deadline; user/system scale.

## Slice 1 progress (branch `feat/slice-1-crud`, uncommitted)
- Done: solution (Domain/Application/Infrastructure/Api/Cli + 5 test projects), in-memory store, REST API under /v1, `gk` CLI, `docs/openapi.json`, README. `dotnet build -warnaserror` clean; 45 tests pass.
- Naming: the application entity is `App` in code (avoids clash with the `Gatekeeper.Application` namespace); API path is `/applications`.
- Remaining: QA/security agent pass, commit + push + PR (needs git identity and the GitHub repo).

## Next action
Review slice 1, set git identity, create the GitHub repo, then commit/push and open the PR. After that: slice 2 (Postgres store).
