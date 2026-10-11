#!/usr/bin/env bash
# Runs the whole test suite against a disposable Postgres container (port 5433, removed afterwards).
set -euo pipefail

NAME=gatekeeper-test-db
IMAGE=docker.io/library/postgres:17-alpine

cleanup() { podman rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

podman run -d --name "$NAME" \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=test-only \
  -p 127.0.0.1:5433:5432 "$IMAGE" >/dev/null

until podman exec "$NAME" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
# pg_isready can answer before the init restart finishes; confirm a real query works.
until podman exec "$NAME" psql -U postgres -tAc 'select 1' >/dev/null 2>&1; do sleep 1; done

export GATEKEEPER_TEST_PG='Host=127.0.0.1;Port=5433;Username=postgres;Password=test-only;Database=postgres'
cd "$(dirname "$0")/.."
dotnet test "$@"
