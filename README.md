# Gatekeeper

Central user and role management for locally developed services. Other systems call it over REST.
Status: slice 5a (REST API with sessions, introspection and key rotation; CLI; first screens of the administration UI). See `status.md`.

## Run

```bash
Auth__SeedDevAdmin=true dotnet run --project src/Gatekeeper.Api   # http://localhost:5080 (localhost only)
```

`Auth__SeedDevAdmin=true` (in-memory store only) creates an administrator `admin` with a random password that is
printed once in the log. Without it the in-memory store has nobody who can log in.

By default data is in memory and is lost on restart. The API contract is `docs/openapi.json`
(also served at `/openapi/v1.json`). `/health` is liveness (public); `/health/ready` checks the store and needs an admin token.

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
- `/health/ready` (admin token required; it checks only the signed token, not the store, so a just-demoted admin's token still works there until it expires; it only reveals ready/not ready) returns 503 when the database is unreachable or has pending migrations. Data endpoints return 503
  while the store is unavailable (the CLI exits 4).
- Create a migration after changing the model:
  `dotnet tool restore && dotnet tool run dotnet-ef migrations add <Name> --project src/Gatekeeper.Infrastructure.Postgres`.

## Authentication

- `POST /v1/auth/login {"username","password","application"}` returns a short-lived (15 min) ES256 access token.
  It is a JWT with `iss`, `aud` (the application), `sub` (user id), `preferred_username`, `exp`, `jti` and `roles`
  (the user's roles in that application only). Every credential failure is an identical `401` (malformed JSON is a `400`).
  Failed logins are throttled per client address (an IPv6 /64 counts as one address) and username (`429` with `Retry-After`); the owner of an account is never
  locked out from another address. At most a few passwords are hashed at once; beyond that the API answers `503` quickly.
- Consuming systems verify tokens offline with the public keys at `GET /.well-known/jwks.json`: check the signature
  (ES256 only), `iss`, `aud` (your application's name), `exp` and `typ` (`at+jwt`), then read `roles`.
  Use `sub` (not `preferred_username`) to identify the user. The management API re-checks that the token's user is still an
  active administrator (cached for 10 s), so demoting or deactivating an admin takes effect almost immediately; tokens for
  other applications stay valid until `exp`, so keep consumers' acceptance windows short.
- The management API (`/v1/applications`, `/v1/roles`, `/v1/users`, `/v1/clients`, `/v1/audit`) needs a token for the application `gatekeeper`
  with the role `admin`. That application and role are reserved: they cannot be renamed or deleted, no other application can take the name, and the
  last active administrator cannot be deleted, deactivated or stripped of the role.
- Users have a `kind`: `person` (default), `test` or `shared`. A test user always expires (`expiresAt`, default 30 days, at most 365);
  an expired test user cannot sign in, refresh or introspect (an administrator can extend the date). Only a person can hold the
  `admin` role. Tokens and introspection carry `kind`, so a consumer can treat non-personal accounts differently. Service identities
  are separate (`/v1/clients`). `gk user create <name> --email ... --kind test --expires 2026-12-31`, `gk user list --kind test`.
- Create the first administrator (password on stdin or `GATEKEEPER_BOOTSTRAP_PASSWORD`, 12-128 characters):
  `echo ... | dotnet Gatekeeper.Api.dll bootstrap-admin <username> <email>` (Postgres store; see `deploy/bootstrap-admin.sh`).
  Running it for an existing user repairs that user (reactivates, resets the password, restores the admin role): the recovery
  path for a lost admin password.
- Settings: `Auth__SigningKeyPemFile` (path to a PKCS#8 EC P-256 PEM; the Quadlet unit mounts a podman secret there) or
  `Auth__SigningKeyPem` (the PEM itself); one is required with Postgres, a temporary key is generated for the in-memory store;
  `Auth__TrustedProxies` (comma-separated proxy IPs whose `X-Forwarded-For` is trusted for throttling; unset by default), `Auth__Issuer` (default `gatekeeper`), `Auth__AccessTokenMinutes` (1-60, default 15).
  Generate a key: `openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt`.
- Passwords are hashed with Argon2id (64 MiB, 3 passes) and stored apart from users. Plain HTTP only: keep the port on
  loopback or put TLS in front, because logins carry passwords. Behind a proxy also set `Auth__TrustedProxies` and make the
  proxy send `Host: localhost` (or extend `AllowedHosts`).
- The service refuses to start in a container/proxy setup (`Gatekeeper__AllowNonLoopback`) without an explicit `Store__Provider`.

### Sessions, refresh tokens and revocation

- `POST /v1/auth/login` with `"refresh": true` also returns `refreshToken` (`gkr_...`, 256-bit secret, stored only as a SHA-256) and
  `refreshExpiresIn` (default 30 days, absolute: `Auth__RefreshTokenDays`, 1-90). Only users get refresh tokens; service clients simply
  authenticate again with their secret. Access tokens issued from a session carry its id as the `sid` claim.
- `POST /v1/auth/refresh {"refreshToken"}` returns a new access token and a **new** refresh token; the old one stops working.
  Presenting the token that was just replaced means a stale copy exists (theft or a replay), so the whole session is ended, unless it
  comes within `Auth__RefreshReuseGraceSeconds` (default 10) of the rotation: that is a parallel request that lost the race (a retry, two
  tabs), which simply fails and leaves the winner's new token valid. Anything else invalid is a plain `401` (identical for every reason, throttled per address). A refresh re-reads the user: a deactivated
  user, a removed role or a deleted application ends the session (at the next refresh or introspection; a password change ends the
  sessions at once). Refresh failures have their own throttle counters, separate from login. A user has at most 20 active sessions;
  starting another ends the least recently used.
- `POST /v1/auth/logout {"refreshToken"}` ends the session (always `204`). A new password ends all of that user's sessions.
  Admins: `GET /v1/users/{id}/sessions`, `DELETE /v1/users/{id}/sessions` (all), `DELETE /v1/sessions/{id}`; CLI
  `gk user sessions|revoke-sessions <user>`. The management API also checks the token's session, so ending an admin's session ends
  their access within ~10 s without waiting for `exp`. This only covers tokens that carry a `sid`, i.e. logins with `refresh`; a plain
  login token has no session and stays valid until `exp` (an administrator who is deactivated or loses the role is still rejected within ~10 s).
- `gk login` asks for a session and renews the access token by itself; concurrent `gk` commands share one refresh under a file lock,
  because refresh tokens rotate. `gk logout` ends the session on the server too.
- **Introspection** (`POST /v1/auth/introspect {"token"}`, RFC 7662 style) is for systems that cannot wait for `exp`: it returns
  `{"active":false}` or `{"active":true,...}` with the roles **as they are now**, after checking the signature, that the user or client is
  still active and still holds roles in the application, and that the session is not ended. The caller authenticates as a service
  identity of that application (HTTP Basic `clientId:secret`; a client with no roles is fine for this) and can only ask about tokens issued
  for its own application; anything else is `{"active":false}`. Failures of the caller's credentials are one uniform `401`, throttled with the client-token counters (the body is only read after the caller has authenticated).
  Plain offline verification stays valid for the access token's lifetime (15 minutes by default); use introspection where that is too long.

### Key rotation

The JWKS lists the current signing key first, then retired keys (public halves only). Tokens signed by a retired key keep verifying
(here and at consumers) until they expire, so rotating does not log anyone out. Configuration: `Auth__SigningKeyPemFile` (current) and
`Auth__RetiredKeysPemFile` (or `Auth__RetiredKeysPem`): PEM blocks (`PUBLIC KEY`, or a private key) with optional `#` comment lines; at
most 5 retired keys. On the Quadlet installation:

- `deploy/rotate-signing-key.sh` generates a new key, moves the old public key to the retired list (stamped `# retired-at:`) and restarts
  the service. The server stops trusting a stamped key by itself once the tokens it signed have expired (token lifetime + 30 s skew + 1 min),
  and it refuses any token whose validity period is longer than the configured lifetime, so a retired key cannot mint long-lived tokens.
  Keys without a stamp stay until `--prune`. Private-key blocks in the retired file are reduced to public keys on rotation.
- `deploy/rotate-signing-key.sh --compromised` does not keep the old key: everything it signed stops verifying **in Gatekeeper** now.
  Consumers that cache the JWKS keep accepting those tokens until they refetch it (or until `exp`); use introspection where that matters.
- `deploy/rotate-signing-key.sh --prune` empties the retired list at once.
A retired-keys file with text that is not a complete PEM block or a `#` comment (for instance a truncated file) stops startup instead of
silently dropping the keys. Consumers that cache the JWKS must refetch it on an unknown `kid`.

- Not yet: federation, an identity-provider broker (see the planner backlog in `status.md`).

### Service identities (clients)

A client is an external system's own identity (no person, no password). It belongs to exactly one application, holds roles
of that application, and trades its secret for a token: `POST /v1/auth/client-token {"clientId","clientSecret"}` returns the
same kind of ES256 access token as a login, with `aud` = the application, `sub` = the client's id, `client_id` = its name and
`roles`, but no `preferred_username`. Consumers tell people from machines by the presence of `client_id`, and must key
identities on `sub` (the stable id): `client_id` is the client's name, which can be renamed or reused after a delete.

- Manage them with `gk client create|list|get|update|rotate-secret|delete|roles|assign|revoke` (or `/v1/clients`). The secret
  (`gks_...`, 256 random bits, stored only as a SHA-256 hash) is shown once, at creation or rotation; rotating invalidates the old one at once.
- A client can never belong to the reserved `gatekeeper` application, so its token is useless against the management API
  (wrong audience): machines cannot manage Gatekeeper. Failures are one uniform `401`, throttled like logins (separate counters).
- Disabling or deleting a client stops new tokens; tokens already issued live until `exp` (as for users).

### Audit trail

Every state-changing management call (who, the route as listed in `docs/openapi.json`, ids, success or failure and status), every
login and client-token attempt, and `bootstrap-admin` is recorded in `audit_events`:
`GET /v1/audit?actor=&action=&limit=&cursor=` (newest first) or `gk audit list [--actor ..] [--action ..] [--limit n]`.
Calls that fail before reaching the endpoint body (malformed JSON, wrong content type, oversized body) are recorded too.
Bodies, passwords and secrets are never recorded. A failed login or client-token attempt records the name only if it belongs to
a real user or client; any other value (a typo, a probe, a password or secret typed into the wrong field) is recorded as its
length only, because the trail cannot be redacted. Other attacker-chosen text is cut to 200 characters and stripped of control
characters. The table is append-only: the app role has no UPDATE/DELETE/TRUNCATE and a trigger refuses them for everyone
(dropping it needs the owner role and a migration). Writes are best effort: if the audit store fails the change still succeeds
and the error is logged. Not recorded: reads, throttled attempts, and requests rejected by authentication or authorisation
(401/403). There is no retention or pruning yet, and failed logins add rows (bounded only by the throttle).

### PATCH

`PATCH` on `/v1/applications/{id}`, `/v1/roles/{id}`, `/v1/users/{id}` and `/v1/clients/{id}` changes only the fields you send
(an absent or null field is left alone; send `""` to clear a description or display name). The CLI `update` commands use it.
Concurrent PATCHes run one at a time in a process (so one cannot silently undo another's change, for example a disable).

## Administration UI

`src/Gatekeeper.Web` is a small server-rendered web UI (Razor Pages, no JavaScript) in its own container. It signs administrators in
through the API and works as their session: the browser only holds an `HttpOnly`, `SameSite=Strict` cookie, while the access and refresh
tokens stay on the server. Every call to the API carries the signed-in administrator's own token, so the audit trail names the person.
Today it covers sign in/out and applications (list, create, rename, delete); roles, users, clients and audit follow.

```bash
dotnet run --project src/Gatekeeper.Api                                   # terminal 1: http://localhost:5080
dotnet run --project src/Gatekeeper.Web                                   # terminal 2: http://localhost:5090
```

On Quadlet: `systemctl --user start gatekeeper-web.service`, then open http://127.0.0.1:5090 and sign in as an administrator.
Settings: `Gatekeeper__ApiUrl` (default `http://127.0.0.1:5080`, a path prefix is kept; plain http to a non-loopback host needs
`Gatekeeper__AllowPlainApi=true`), `Web__IdleMinutes` (30), `Web__AbsoluteHours` (8). Like the API, the UI refuses to listen on a
non-loopback address unless `Gatekeeper__AllowNonLoopback=true`; it speaks plain HTTP, so publish it on loopback or put TLS in front.
Sessions live in memory: restarting the UI signs everyone out. Bad settings stop startup with a message.

Behind a TLS proxy:
- Set `Web__TrustedProxies` to the address the **container sees** the proxy connection from (with rootless Podman usually the network
  gateway or `127.0.0.1`, not the proxy's own address), so that scheme and client address come from `X-Forwarded-*`.
- Set `Web__SecureCookies=true`: the cookies become `Secure` and `__Host-` prefixed (bound to this exact host). The UI then insists on
  HTTPS requests and answers 500 over plain HTTP rather than issue weak cookies. Add HSTS at the proxy.
- Set `AllowedHosts` to the public host name (the default accepts only localhost).
- Cookies are not isolated by port: on `localhost` another service on the same host name receives them. A dedicated host name over TLS
  with `Web__SecureCookies` fixes that.

Sign-in is throttled per (address, username) and per address, in the UI and again in the API. From the API's point of view every
browser comes from the UI's address, so guessing at one account through the UI makes that account wait (15 minutes) in the UI; the
same account can still sign in with `gk` from another address. Restarting the API clears its counters.

## CLI

```bash
alias gk='dotnet run --project src/Gatekeeper.Cli --'
gk app create billing
gk role create admin --app billing --description "Full access"
gk user create alice --email alice@example.com --display-name "Alice"
gk user assign alice admin --app billing
gk user roles alice            # add --json for raw JSON
```

First `gk login --user <admin>` (password from a hidden prompt, or stdin when piped; never an argument). The token is
saved in `$XDG_STATE_HOME/gatekeeper/token.json` (mode 0600), sent only to the server that issued it, and removed by
`gk logout`. `GATEKEEPER_TOKEN` overrides it (and is sent to whatever URL you point at).
The CLI refuses plain `http://` to non-local hosts (override: `GATEKEEPER_ALLOW_INSECURE=1`), never follows redirects, and
strips control characters from server text before printing. `gk user set-password <user>` sets a password.
`gk client ...` manages service identities and `gk audit list` reads the audit trail.
`gk login` keeps a session (see "Sessions"): the saved login holds a refresh token and renews itself; `gk logout` ends it on the server.

Server URL: `--url` or `GATEKEEPER_URL` (default `http://localhost:5080`).
Exit codes: 0 ok, 1 error, 2 not found, 3 conflict, 4 server unreachable or store unavailable, 5 not logged in or not allowed.
List commands fetch every page; the API itself returns `{items,nextCursor}` (`?limit=` 1-200, default 50).

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
  refuses unless `Gatekeeper__AllowNonLoopback=true` is set (the unit sets it). The API speaks plain HTTP: keep it on loopback or add a TLS proxy.
- After the first start create the administrator: `deploy/bootstrap-admin.sh <username> <email>`. `install.sh` also creates the
  token signing key as the podman secret `gatekeeper-signing-key`.
- Passwords and connection strings are podman secrets (random, created by `install.sh`); nothing secret is in the repo or image.
- Roles are created on the first start with an empty data volume. To start over: stop the units, `podman volume rm gatekeeper-db-data`.
- Update: pull or build a new image and `systemctl --user restart gatekeeper-api` (re-runs migrations first).
- For the service to survive logout/reboot: `loginctl enable-linger $USER`.
