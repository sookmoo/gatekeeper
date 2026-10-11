#!/bin/sh
# Runs once on an empty data directory (postgres image init hook). Passwords come from podman secrets via env.
set -eu
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -v owner_pw="$GK_OWNER_PW" -v app_pw="$GK_APP_PW" \
  -f /docker-entrypoint-initdb.d/db-roles.sql.tpl
