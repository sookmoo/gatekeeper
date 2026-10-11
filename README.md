# Gatekeeper

Central user and role management for locally developed services. Other systems call it over REST.
Status: slice 2 (applications, roles, users CRUD, role assignment; in-memory or PostgreSQL store; CLI). See `status.md`.

## Run

```bash
dotnet run --project src/Gatekeeper.Api          # http://localhost:5080 (localhost only, no auth yet)
```

By default data is in memory and is lost on restart. The API contract is `docs/openapi.json`
(also served at `/openapi/v1.json`). `/health` is liveness, `/health/ready` checks the store.

### PostgreSQL

Requires Podman for the local database. Two roles are used: `gatekeeper_owner` runs migrations,
`gatekeeper_app` serves requests with data access only (no DDL). The service never holds schema rights.

```bash
scripts/dev-db.sh                      # starts Postgres on 127.0.0.1:5432, creates both roles, prints the settings below
export Store__Provider=Postgres
export ConnectionStrings__GatekeeperMigrations='Host=127.0.0.1;Port=5432;Database=gatekeeper;Username=gatekeeper_owner;Password=...'
export ConnectionStrings__Gatekeeper='Host=127.0.0.1;Port=5432;Database=gatekeeper;Username=gatekeeper_app;Password=...'
dotnet build
cd src/Gatekeeper.Api
dotnet bin/Debug/net10.0/Gatekeeper.Api.dll migrate   # one-off, uses GatekeeperMigrations, then exits
dotnet bin/Debug/net10.0/Gatekeeper.Api.dll           # serve, uses Gatekeeper
```

- The server never migrates on its own and refuses to start with `Store:Provider=Postgres` and no connection string.
- Connection strings belong in the environment (or a secrets store), not in `appsettings.json`.
- Production databases: create the roles with `scripts/db-roles.sql` and real passwords. For any non-local database
  use TLS with certificate validation, for example `SSL Mode=VerifyFull;Root Certificate=/path/ca.crt`.
  Npgsql's default (`Prefer`) silently falls back to plaintext and does not validate the certificate.
- `/health/ready` returns 503 when the database is unreachable or has pending migrations. Data endpoints return 503
  while the store is unavailable (the CLI exits 4).
- Create a migration after changing the model:
  `dotnet tool restore && dotnet tool run dotnet-ef migrations add <Name> --project src/Gatekeeper.Infrastructure.Postgres`.

## CLI

```bash
alias gk='dotnet run --project src/Gatekeeper.Cli --'
gk app create billing
gk role create admin --app billing --description "Full access"
gk user create alice --email alice@example.com --display-name "Alice"
gk user assign alice admin --app billing
gk user roles alice            # add --json for raw JSON
```

Server URL: `--url` or `GATEKEEPER_URL` (default `http://localhost:5080`).
Exit codes: 0 ok, 1 error, 2 not found, 3 conflict, 4 server unreachable or store unavailable.

## Develop

```bash
dotnet build -warnaserror
dotnet test                 # Postgres tests are reported as skipped
scripts/test-pg.sh          # full suite against a disposable Postgres container (needs Podman)
```

Layout: `Domain` (entities, validation) -> `Application` (services, repository interfaces) ->
`Infrastructure` (in-memory store) and `Infrastructure.Postgres` (EF Core) -> `Api` (ASP.NET Core minimal API); `Cli` talks to the API over HTTP.
Every store implementation (in-memory and Postgres) must pass `tests/Gatekeeper.Store.Contract.Tests`.

## Container and Quadlet (rootless Podman)

Build the image: `podman build -t gatekeeper-api -f Containerfile .` (digest-pinned bases, chiseled non-root runtime, no shell).
CI builds it on every PR and publishes `ghcr.io/sookmoo/gatekeeper:<sha>` and `:latest` from `main`.

Run the full stack (Postgres, one-shot migrations as the owner role, API as the data-only role) as systemd user services:

    deploy/install.sh [image]            # copies units to ~/.config/containers/systemd, creates podman secrets
    systemctl --user start gatekeeper-api.service

- The API is published on `127.0.0.1:5080` only. Inside the container it binds `0.0.0.0:8080`, which the loopback guard
  refuses unless `Gatekeeper__AllowNonLoopback=true` is set (the unit sets it). There is still no authentication.
- Passwords and connection strings are podman secrets (random, created by `install.sh`); nothing secret is in the repo or image.
- Roles are created on the first start with an empty data volume. To start over: stop the units, `podman volume rm gatekeeper-db-data`.
- Update: pull or build a new image and `systemctl --user restart gatekeeper-api` (re-runs migrations first).
- For the service to survive logout/reboot: `loginctl enable-linger $USER`.
