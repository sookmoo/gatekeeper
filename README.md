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
  Use `sub` (not `preferred_username`) to identify the user. The management API re-checks on every request that the token's user is
  still usable and still holds the admin role (cached for 10 s): a deactivated user or an ended session is `401`, a user who is no longer
  an administrator is `403`, so demoting or deactivating an admin takes effect almost immediately; tokens for
  other applications stay valid until `exp`, so keep consumers' acceptance windows short.
- **Self-service.** (Signing in to `gatekeeper` without a role needs `"refresh": true`; without it the login is a `400`, so a role-less token always has a session that can be ended. Assigning the admin role to a signed-in self-service user ends their live `gatekeeper` sessions, so they sign in again. A `403` on a `/v1` route for a valid token is audited with outcome `forbidden`; zero-role logins and refreshes carry `roles=none`.) Any usable `person` or `test` user may sign in to the reserved application `gatekeeper` (login and refresh) without
  holding a role there; the token then has `"roles": []` and only opens `/v1/me`. Every other application still needs at least one role,
  `shared` accounts get no self-service (one member could lock the others out; an administrator manages them), and a disabled, expired or
  unknown user and a wrong password are the same uniform `401` as before. Routes: `GET /v1/me` (id, username, displayName, email, kind, expiresAt),
  `GET /v1/me/sessions` (own active sessions; `current` marks the session of the token, `appName` names the application),
  `DELETE /v1/me/sessions/{id}` (404 both for an unknown session and for another user's; ending the current one ends the token's session),
  `DELETE /v1/me/sessions` (ends all **other** sessions, answers `{"revoked": n}`; the current one ends by signing out or by its id; a token without a session ends all).
  `PUT /v1/me/password` with `{"currentPassword", "newPassword"}` changes the caller's own password (slice 6g): `204` and every **other** session of the user ends
  (the token's session stays; a token without a session ends all of them); `400` when the new password breaks the password rules (12 to 128 characters, no control characters,
  as for the administrator's `PUT /v1/users/{id}/password`; field `newPassword`) or equals the current one (checked only after the current one verified); `403` with problem
  `code` `current-password-incorrect` and the fixed text "The current password is incorrect." for every reason the current password is not accepted (wrong, no stored password,
  out of length, changed meanwhile) - deliberately **not** 401, so a client does not read it as an ended session and sign the user out; `429` with `Retry-After` after 5
  attempts per user (any address) or 20 per client address in 15 minutes: a slot is reserved atomically before any hashing (parallel requests cannot get past the limit), kept for a wrong password and handed back on success, so a 429 is answered without hashing. The current password is verified with the login's hasher and
  `HashLimiter`; the write is a compare-and-set on the verified hash, so a parallel change or an administrator's reset is never overwritten. A wrong password counts against both limits; rule violations and an equal new password (decided without or after a verified current password, so not guesses) count per address only, so the owner's typos never lock them out. Audit rows from this route are therefore bounded; 429 and 503 (busy) answers write none. Once the new hash is stored the write and the session cut-off no longer depend on the request (a client that disconnects cannot leave the old sessions alive). Neither password is ever logged, audited or returned; the audit row is
  `PUT /v1/me/password` with the user as actor and `sessionsRevoked=<n>; kept=<sid|none>` (failures: `reason=current-password` or `same-password`). The user's version/ETag does not change
  (passwords are a separate resource, as in 6d). The limits are per process. A forgotten password is still reset by an administrator; there is no self-service reset.
  Policies: `admin` (the token carries the admin role **and** the store still says so; a self token is `403` on every management route) and `self`
  (any usable person or test user, administrators included). Audit rows of `/v1/me` writes name the user as actor. `/health/ready` still trusts the signed admin role claim
  alone (it must answer while the store is down); a self token has no role and gets `403` there. OpenAPI marks each operation with `x-gatekeeper-access` (`self` or `admin`).
- The management API (`/v1/applications`, `/v1/roles`, `/v1/users`, `/v1/clients`, `/v1/audit`) needs a token for the application `gatekeeper`
  with the role `admin`. That application and role are reserved: they cannot be renamed or deleted, no other application can take the name, the role API refuses (409) every create, change or
  delete of a role in `gatekeeper` (`bootstrap-admin` and the dev seed set up `admin` directly), and the
  last active administrator cannot be deleted, deactivated or stripped of the role.
- Users have a `kind`: `person` (default), `test` or `shared`. A test user always expires (`expiresAt`, default 30 days, at most 365);
  an expired test user cannot sign in, refresh or introspect (an administrator can extend the date). Only a person can hold the
  `admin` role. Tokens and introspection carry `kind`, so a consumer can treat non-personal accounts differently: require
  `kind == "person"` explicitly where only people are allowed, because older tokens and client tokens have no `kind`. A test user's
  tokens and sessions end no later than the account. Give `expiresAt` with an offset or `Z` (the CLI reads a bare date as UTC). Service identities
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
  user, a removed role or a deleted application ends the session (at the next refresh or introspection). Some changes end sessions
  at once: a new password, deactivating the user (re-enabling does not revive them), and removing the user's last role in an application
  (that application's sessions only). Moving a test user's `expiresAt` earlier caps the active sessions to it; extending it later does
  not lengthen them. The audit detail of the user change shows `sessionsRevoked=<n>` / `sessionsCapped=<n>`. Refresh failures have their own throttle counters, separate from login. A user has at most 20 active sessions;
  starting another ends the least recently used.
- `POST /v1/auth/logout {"refreshToken"}` ends the session (always `204`). A new password ends all of that user's sessions.
  Admins: `GET /v1/users/{id}/sessions`, `DELETE /v1/users/{id}/sessions` (all),
  `GET|DELETE /v1/users/{id}/sessions/{sessionId}` (one; 404 both when unknown and when it is another user's; the audit row names user
  and session), `DELETE /v1/sessions/{id}` (deprecated: unscoped, answers with `Deprecation: true` and a `Link` to the scoped route, the audit note names the owner as `user=<id>`; to be removed once no client uses it); CLI
  `gk user sessions|revoke-sessions <user>`, `gk user revoke-session <user> <session>`. The management API also checks the token's session, so ending an admin's session ends
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
Paging is by keyset: `nextCursor` is opaque and encodes the last row's time and id, so events arriving between pages cause no
repeats and no gaps, and deep pages stay cheap. Cursors of the other lists (offsets) are refused here with 400, and so is any
edited cursor. Indexes on `(actor, at DESC, id DESC)` and `(action, at DESC, id DESC)` serve the filters (migration
`AddAuditIndexes`). The migration builds them with `CREATE INDEX CONCURRENTLY`, outside a transaction, so audit writes are not blocked on a
large table; it drops an INVALID leftover of the same name (from an interrupted earlier run) and keeps a valid existing index, so operators may
pre-create both indexes with `CREATE INDEX CONCURRENTLY` under the same names and the migration then skips them.
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

### Versions and `If-Match` (optimistic concurrency)

Applications, roles, users and clients carry a `version` (integer, 1 when created, +1 on every write of the row's own fields;
role assignments, passwords, client secrets and sessions are separate resources and do not change it). Every single-resource
`GET`, `PUT`, `PATCH` and every create (`POST`) answers with the `version` in the body and a strong `ETag: "<version>"`
(for example `"3"`). The ETag of a `POST` create describes the created resource. Lists have no ETag; their items carry `version`.

`PUT`, `PATCH` and `DELETE` of these four resources accept an optional `If-Match` header:

- no header: the write is unconditional, as before;
- `If-Match: "3"` (or a list such as `"2", "3"`): the write happens only if the stored version is one of them, otherwise the answer is
  `412 Precondition Failed` (problem body with a fixed text) and nothing changes. The check is part of the write
  (`UPDATE ... WHERE id = @id AND version = @expected` in Postgres, under the store lock in memory), so of several requests
  carrying the same ETag exactly one wins and the others get 412;
- `If-Match: *` matches any existing resource (a missing one is still 404);
- a weak tag (`W/"3"`) never matches (strong comparison, as RFC 9110 requires for `If-Match`), so a proxy that weakens ETags causes 412, not a silent overwrite;
- anything else (`3`, `"3`, an empty value, `*` mixed with tags, more than 1024 characters) is `400`.

Precedence when several things are wrong: `400` for a malformed `If-Match` first (it is a syntax error), then `404`, then `412`, then
the other checks, which differ a little per resource: applications and clients validate the body (`400`) and then apply their `409`
rules (reserved application and name; name already taken); roles apply the reserved-application `409` first and then validate (`400`);
users validate and then apply the administrator rules (last administrator, admin must be a person) and the taken-name `409`.
Without `If-Match` the order is as it always was (validation first). A refused write does not bump the version, and the 412 is
recorded in the audit trail as a failure. A `PATCH` that changes no value (an application, role, client or user already has the
values) writes nothing: it answers 200 with the current ETag and the version stays (the precondition is still checked first, and so is the
reserved-application rule for roles, so a no-op PATCH of a role of the `gatekeeper` application is still 409; a user
`PATCH` still repairs session effects of an earlier half-done change). A `PATCH` with several tags in `If-Match` writes onto the version it read
and merged its values onto, so a write that slips in between gives 412 rather than being silently overwritten.
Unconditional writes (no `If-Match`) to one row queue on a row lock in Postgres (`FOR NO KEY UPDATE`, so inserts that reference the row, such as sessions, are not blocked), so every one succeeds with its own version; a writer waits at most 2 s for the lock and then gets 503 with `Retry-After`.

**Upgrading to `AddVersions`:** the migration adds a `version` column to four tables. It locks the four tables together up front under a 2 s `lock_timeout`, so it fails cleanly (and
rolls back) instead of queueing behind a long-running query; run `migrate` again at a quiet moment. Do not run old and new API instances
side by side across this migration: an old instance does not know the column and its writes do not bump `version`, which would let a stale
`If-Match` succeed. Stop the old instances, migrate, start the new ones. (A `BEFORE UPDATE` trigger that bumps the version would remove that
requirement; it is a possible follow-up.)

The CLI sends no `If-Match` yet (a `--if-version` option is deferred). The Web UI does (see the Administration UI section).

## Administration UI

`src/Gatekeeper.Web` is a small server-rendered web UI (Razor Pages, no JavaScript) in its own container. Any person or test user may sign in
("Invalid credentials." for every failure); administrators land on the applications, everyone else on `/Account`: a read-only profile and their
own sessions with revoke one / revoke all other sessions (each behind a confirmation page; revoking the current session also ends the web
session), and `/Account/Password` to change their own password (current, new, repeat; the values are never shown again, logged or put in a URL; the texts are fixed;
a wrong current password or a throttled attempt re-renders the form with a fixed message and the web session stays; after a success the user's other sessions end and this one stays). The navigation of a non-administrator shows only Account, and every management page answers 403 to them (the UI decides from the
role claim of the token only to choose pages; the API checks the real role on every call). It signs administrators in
through the API and works as their session: the browser only holds an `HttpOnly`, `SameSite=Strict` cookie, while the access and refresh
tokens stay on the server. Every call to the API carries the signed-in administrator's own token, so the audit trail names the person.
Today it covers sign in/out, applications (list, create, rename, delete), roles (the reserved application's roles are shown read-only),
users (list, create, edit, delete, their roles, password and sessions) and clients (service identities: list with application filter,
create, rename, enable/disable, rotate secret, delete), a client's roles, and the audit trail (read-only, newest first, exact
actor and action filters, paged).

A client's secret is shown once, on the page that answers the create or rotate request (no redirect, `Cache-Control: no-store`,
never in a URL, cookie, log or audit row). Reloading or going back makes the browser offer to resend the form, so the create form and the
rotate confirmation carry a random one-time value that the server remembers per web session (at most 32, not a cookie) and consumes on the
first submit: a resend, a double click or a parallel submit does not call the API again and shows "This was already done" instead (the
secret is not shown a second time). Create and rotate call the API without the browser's cancellation, so a committed change always returns
its secret to the web server; if the API fails or times out on these two actions the page says the change may have taken effect.
Residual risk: the browser's back/forward cache may keep a copy of the secret page for the life of the tab even though the page is
`no-store`. The secret page therefore also sends `Clear-Site-Data: "cache"` (never `"cookies"` or `"storage"`, which would end the
session), but this is best effort and browser dependent: close the tab after copying the secret. Disabling a client stops its tokens
passing introspection only while it stays disabled (enabling it again revives them until they expire), and services that validate tokens
locally accept them until they expire: after a leak, rotate the secret and keep the client disabled until the access-token lifetime has passed.
Known limits of the client screens: the client list reuses its application list for a few seconds per web session; the application list for the create form and the filter reads at most 1000 applications; there is no previous-page link;
the edit forms of users and clients still keep a snapshot of the loaded values, but only to decide which fields to send; the lost-update guard is the version (below).

The edit and delete pages of users, clients, applications and roles carry a hidden `Version` taken from the API (`version`) when the page
is opened and send it back as `If-Match: "<version>"` on the save or delete. If the resource changed meanwhile (another administrator, another
tab) the API answers 412 and the page answers `412` too, shows "Changed by someone else since you opened it. The current values are shown; apply
your change again." and renders the form again with the current values and the current version; nothing is merged and nothing is retried
automatically. A `Version` that is missing, not a canonical positive integer (no sign, spaces or leading zero), or sent more than once is never turned into an unconditional write: the page answers `400`,
shows "The form is out of date or incomplete. The current values are shown; apply your change again." with the current values and version, and sends
nothing to the API. A forged but well-formed version just gets the 412. Deactivating or deleting one's own account ends the web session only when the
API call succeeds, not on a 412. Role assignments, passwords, sessions and secrets have no version and are unchanged.

```bash
dotnet run --project src/Gatekeeper.Api                                   # terminal 1: http://localhost:5080
dotnet run --project src/Gatekeeper.Web                                   # terminal 2: http://localhost:5090
```

On Quadlet: `systemctl --user start gatekeeper-web.service`, then open http://127.0.0.1:5090 and sign in as an administrator.
Settings: `Gatekeeper__ApiUrl` (default `http://127.0.0.1:5080`, a path prefix is kept; plain http to a non-loopback host needs
`Gatekeeper__AllowPlainApi=true`), `Web__IdleMinutes` (30), `Web__AbsoluteHours` (8), `Web__MaxSessionsPerUser` (5: a further sign-in ends that user's oldest web session) and `Web__MaxSessions` (1000: when the table is full of live sessions, new sign-ins get `503` instead of ending other people's sessions; expired ones are reclaimed first). Like the API, the UI refuses to listen on a
non-loopback address unless `Gatekeeper__AllowNonLoopback=true`; it speaks plain HTTP, so publish it on loopback or put TLS in front.
Sessions live in memory: restarting the UI signs everyone out. Bad settings stop startup with a message.

The API throttles logins and refreshes per client address, and it only sees this container. The UI therefore sends the browser's address as
`X-Forwarded-For` on login and refresh, and the API uses it **only** when the connection comes from an address listed in `Auth__TrustedProxies`
(default: nobody is trusted, the header is ignored and all browsers share the UI's address and limit). The Quadlet files pin this: `gatekeeper.network` has `Subnet=10.89.77.0/24`, `gatekeeper-web.container` has `IP=10.89.77.10` and `gatekeeper-api.container` sets `Auth__TrustedProxies=10.89.77.10` (change the three together; the API refuses shorthand such as `10`). Otherwise set `Auth__TrustedProxies` on the API to the
address it sees the UI container connect from (the API takes the last hop of the header, so a browser cannot choose its address). A refresh token that proved its session (hash matched) but whose session is revoked or expired, or whose user is gone, does not count towards the per-address flood limit; it is counted per session instead: after 5 failures within 15 minutes that session's token answers `429` (no store access), and only the first 3 failures write audit rows.

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
`gk me` shows your own account, `gk me sessions` lists your own active sessions and `gk me revoke-session <id>` ends one and `gk me revoke-sessions` ends all your other sessions (like `gk user revoke-sessions`, it asks no confirmation); these work for
any signed-in person or test user, administrator or not (`gk login --user <name>` needs no role).
`gk passwd` changes your own password: it asks for the current and the new password without echo (the new one twice); with piped stdin it reads the current password from the
first line and the new one from the second (like `gk login`, never from arguments). A wrong current password is exit 1 ("The current password is incorrect."), not 5; your other sessions end and the saved login stays.
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
