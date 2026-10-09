# Gatekeeper

Central user and role management for locally developed services. Other systems call it over REST.
Status: slice 1 (applications, roles, users CRUD, role assignment; in-memory store; CLI). See `status.md`.

## Run

```bash
dotnet run --project src/Gatekeeper.Api          # http://localhost:5080 (localhost only, no auth yet)
```

Data is in memory and is lost on restart. The API contract is `docs/openapi.json`
(also served at `/openapi/v1.json`).

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
dotnet test
```

Layout: `Domain` (entities, validation) -> `Application` (services, repository interfaces) ->
`Infrastructure` (in-memory store) -> `Api` (ASP.NET Core minimal API); `Cli` talks to the API over HTTP.
Every store implementation must pass `tests/Gatekeeper.Store.Contract.Tests`.
