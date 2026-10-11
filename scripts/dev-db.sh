#!/usr/bin/env bash
# Starts a local Postgres for development on 127.0.0.1:5432 (data kept in a named volume).
# The credentials are throwaway and only reachable from this machine.
set -euo pipefail

NAME=gatekeeper-dev-db
IMAGE=docker.io/library/postgres:17-alpine

if podman container exists "$NAME"; then
  podman start "$NAME" >/dev/null
else
  podman run -d --name "$NAME" \
    -e POSTGRES_USER=gatekeeper -e POSTGRES_PASSWORD=gatekeeper-dev -e POSTGRES_DB=gatekeeper \
    -p 127.0.0.1:5432:5432 \
    -v gatekeeper-dev-data:/var/lib/postgresql/data \
    "$IMAGE" >/dev/null
fi

until podman exec "$NAME" pg_isready -U gatekeeper -d gatekeeper >/dev/null 2>&1; do sleep 1; done

cat <<MSG
Postgres is ready. Use:
  export ConnectionStrings__Gatekeeper='Host=127.0.0.1;Port=5432;Database=gatekeeper;Username=gatekeeper;Password=gatekeeper-dev'
  export Store__Provider=Postgres
  dotnet src/Gatekeeper.Api/bin/Debug/net10.0/Gatekeeper.Api.dll migrate
Stop with: podman stop $NAME     Remove data with: podman rm -f $NAME && podman volume rm gatekeeper-dev-data
MSG
