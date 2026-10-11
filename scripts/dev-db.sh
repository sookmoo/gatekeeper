#!/usr/bin/env bash
# Starts a local Postgres for development on 127.0.0.1:5432 (data kept in a named volume) with
# separate owner (migrations) and app (runtime) roles. Credentials are throwaway and local-only.
set -euo pipefail

NAME=gatekeeper-dev-db
IMAGE=docker.io/library/postgres:17-alpine
OWNER_PW=gatekeeper-dev-owner
APP_PW=gatekeeper-dev-app
cd "$(dirname "$0")"

if podman container exists "$NAME"; then
  if ! podman port "$NAME" 5432/tcp | grep -q '^127.0.0.1:5432$'; then
    echo "Container $NAME exists but is not published on 127.0.0.1:5432. Remove it: podman rm -f $NAME" >&2
    exit 1
  fi
  podman start "$NAME" >/dev/null
else
  podman run -d --name "$NAME" \
    -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=gatekeeper-dev-admin \
    -p 127.0.0.1:5432:5432 \
    -v gatekeeper-dev-data:/var/lib/postgresql/data \
    "$IMAGE" >/dev/null
fi

for _ in $(seq 1 60); do
  podman exec "$NAME" psql -U postgres -tAc 'select 1' >/dev/null 2>&1 && break
  sleep 1
done
podman exec "$NAME" psql -U postgres -tAc 'select 1' >/dev/null 2>&1 || { echo "Postgres did not become ready" >&2; exit 1; }

if [ "$(podman exec "$NAME" psql -U postgres -tAc "select 1 from pg_roles where rolname='gatekeeper_owner'")" != "1" ]; then
  podman exec -i "$NAME" psql -U postgres -v ON_ERROR_STOP=1 -v owner_pw="$OWNER_PW" -v app_pw="$APP_PW" < db-roles.sql >/dev/null
fi

cat <<MSG
Postgres is ready. Migrate with the owner role, then serve with the app role:
  export Store__Provider=Postgres
  export ConnectionStrings__GatekeeperMigrations='Host=127.0.0.1;Port=5432;Database=gatekeeper;Username=gatekeeper_owner;Password=$OWNER_PW'
  export ConnectionStrings__Gatekeeper='Host=127.0.0.1;Port=5432;Database=gatekeeper;Username=gatekeeper_app;Password=$APP_PW'
  dotnet src/Gatekeeper.Api/bin/Debug/net10.0/Gatekeeper.Api.dll migrate
Stop with: podman stop $NAME     Remove data with: podman rm -f $NAME && podman volume rm gatekeeper-dev-data
MSG
