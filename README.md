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

Requires Podman for the local database.

```bash
scripts/dev-db.sh                                  # starts Postgres on 127.0.0.1:5432, prints the settings below
export Store__Provider=Postgres
export ConnectionStrings__Gatekeeper='Host=127.0.0.1;Port=5432;Database=gatekeeper;Username=gatekeeper;Password=gatekeeper-dev'
dotnet build
cd src/Gatekeeper.Api
dotnet bin/Debug/net10.0/Gatekeeper.Api.dll migrate   # one-off: apply migrations, then exit
dotnet bin/Debug/net10.0/Gatekeeper.Api.dll           # serve
```

The server never migrates on its own and refuses to start with `Store:Provider=Postgres` and no
connection string. Connection strings belong in the environment, not in `appsettings.json`.
Create a migration after changing the model: `dotnet tool restore && dotnet tool run dotnet-ef migrations add <Name> --project src/Gatekeeper.Infrastructure.Postgres`.

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
Exit codes: 0 ok, 1 error, 2 not found, 3 conflict, 4 server unreachable.

## Develop

```bash
dotnet build -warnaserror
dotnet test                 # Postgres tests are reported as skipped
scripts/test-pg.sh          # full suite against a disposable Postgres container (needs Podman)
```

Layout: `Domain` (entities, validation) -> `Application` (services, repository interfaces) ->
`Infrastructure` (in-memory store) and `Infrastructure.Postgres` (EF Core) -> `Api` (ASP.NET Core minimal API); `Cli` talks to the API over HTTP.
Every store implementation (in-memory and Postgres) must pass `tests/Gatekeeper.Store.Contract.Tests`.
