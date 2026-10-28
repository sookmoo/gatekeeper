#!/usr/bin/env bash
# Restores a dump made by backup.sh into the EMPTY gatekeeper database: verifies the dump's .sha256, stops the API, the web UI and the
# backup and audit-prune timers, restores as the owner role (one transaction, so a failure leaves the database empty), writes an audit
# row, runs the migrate unit (applies migrations newer than the dump), starts API and web again and restores the timers' previous state.
# It refuses a database that already has tables. To restore over an existing installation, first remove the data volume
# (README "Backup and restore", restore drill). Nothing secret is read or printed: the connection is the unix socket inside the db
# container (the host account is the trust boundary). Never restore a dump you cannot vouch for.
set -uo pipefail
umask 077

usage() {
  cat >&2 <<'USAGE'
usage: restore.sh --yes [--no-services] [--no-verify] <dump-file>
  --yes          required: confirms that the dump is loaded into the (empty) database and the API and web UI are stopped meanwhile
  --no-services  do not stop, migrate or start the systemd units or timers (tests, or when the units are not used); run the migration yourself
  --no-verify    restore without the <dump>.sha256 file (absent or not trusted); only for a dump you can vouch for by other means
Environment: GATEKEEPER_DB_CONTAINER (gatekeeper-db), GATEKEEPER_DB_NAME (gatekeeper), GATEKEEPER_DB_OWNER (gatekeeper_owner),
GATEKEEPER_DB_APP (gatekeeper_app)
USAGE
}

yes=0; services=1; verify=1; file=""
for a in "$@"; do
  case "$a" in
    -h|--help) usage; exit 0 ;;
    --yes) yes=1 ;;
    --no-services) services=0 ;;
    --no-verify) verify=0 ;;
    -*) usage; echo "Unknown option $a" >&2; exit 2 ;;
    *) [ -z "$file" ] || { usage; echo "One dump file only" >&2; exit 2; }; file=$a ;;
  esac
done
[ -n "$file" ] || { usage; exit 2; }
[ "$yes" = 1 ] || { usage; echo "Refusing without --yes." >&2; exit 2; }

container=${GATEKEEPER_DB_CONTAINER:-gatekeeper-db}
db=${GATEKEEPER_DB_NAME:-gatekeeper}
owner=${GATEKEEPER_DB_OWNER:-gatekeeper_owner}
app=${GATEKEEPER_DB_APP:-gatekeeper_app}
ident='^[A-Za-z_][A-Za-z0-9_]*$'
[[ "$db" =~ $ident && "$owner" =~ $ident && "$app" =~ $ident ]] || { echo "GATEKEEPER_DB_NAME, _OWNER and _APP must match $ident" >&2; exit 2; }
[[ "$container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || { echo "GATEKEEPER_DB_CONTAINER is not a valid container name" >&2; exit 2; }

[ -f "$file" ] && [ -r "$file" ] || { echo "$file is not a readable file" >&2; exit 1; }
if [ "$verify" = 1 ]; then
  [ -f "$file.sha256" ] || { echo "No checksum file $file.sha256. Restore only a dump you can vouch for; --no-verify skips this check." >&2; exit 1; }
  want=$(cut -d' ' -f1 "$file.sha256")
  have=$(sha256sum < "$file" | cut -d' ' -f1)
  [[ "$want" =~ ^[0-9a-f]{64}$ && "$want" = "$have" ]] || { echo "Checksum mismatch for $file: the dump is not what backup.sh wrote. Not restoring." >&2; exit 1; }
fi
[ "$(podman inspect --format '{{.State.Running}}' "$container" 2>/dev/null)" = true ] \
  || { echo "Container $container is not running (systemctl --user start gatekeeper-db.service)" >&2; exit 1; }
sql() { podman exec "$container" psql -U "$owner" -d "$db" --no-password -v ON_ERROR_STOP=1 -tA -c "$1"; }

err=$(mktemp); trap 'rm -f -- "$err"' EXIT
podman exec -i "$container" pg_restore --list < "$file" >/dev/null 2>"$err" \
  || { echo "$file is not a valid pg_dump custom-format file, or pg_restore failed:" >&2; cat "$err" >&2; exit 1; }
# Empty means: no table, view, sequence or foreign table in any non-system schema.
existing=$(sql "select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace
                where c.relkind in ('r','p','v','m','S','f') and n.nspname not in ('pg_catalog','information_schema') and n.nspname !~ '^pg_toast'") \
  || { echo "Cannot query database $db as $owner" >&2; exit 1; }
[ "$existing" = 0 ] || { echo "Refusing: database $db is not empty ($existing relations). Restore only into a fresh database (README \"Backup and restore\")." >&2; exit 1; }

# From here on, undo what we changed however the script ends (failure, SIGINT, SIGTERM).
step="start"; revoked=0; done_ok=0; stopped=0; timers_were_active=()
default_privileges() { # revoke | grant: the default privileges of db-roles.sql for tables the owner creates
  if [ "$1" = revoke ]; then
    sql "alter default privileges for role \"$owner\" in schema public revoke all on tables from \"$app\"" >/dev/null
  else
    sql "alter default privileges for role \"$owner\" in schema public grant select, insert, update, delete on tables to \"$app\"" >/dev/null
  fi
}
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [ "$revoked" = 1 ]; then
    if default_privileges grant; then echo "Default privileges of $app put back." >&2
    else echo "WARNING: could not put the default privileges of $app back; run the ALTER DEFAULT PRIVILEGES ... GRANT from scripts/db-roles.sql as $owner." >&2; fi
  fi
  if [ "${#timers_were_active[@]}" -gt 0 ]; then
    systemctl --user start "${timers_were_active[@]}" || echo "WARNING: could not start ${timers_were_active[*]} again; start them by hand." >&2
  fi
  rm -f -- "$err"
  if [ "$done_ok" != 1 ]; then
    echo "Restore did NOT complete (step: $step)." >&2
    if [ "$stopped" = 1 ]; then echo "gatekeeper-api and gatekeeper-web are stopped; they were not started again." >&2; fi
    echo "After fixing the cause, run restore.sh again. The database is empty unless the step was after 'restoring' (check with \\dt); a restore needs an empty database." >&2
    [ "$rc" -ne 0 ] || rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'echo "Interrupted." >&2; exit 130' INT
trap 'echo "Terminated." >&2; exit 143' TERM

run() { # description, command...: report which step failed
  step=$1; shift
  "$@" || { echo "Step failed: $step" >&2; exit 1; }
}

if [ "$services" = 1 ]; then
  for t in gatekeeper-backup.timer gatekeeper-audit-prune.timer; do
    if systemctl --user is-active --quiet "$t"; then timers_were_active+=("$t"); fi
  done
  if [ "${#timers_were_active[@]}" -gt 0 ]; then run "stopping timers" systemctl --user stop "${timers_were_active[@]}"; fi
  stopped=1
  echo "Stopping gatekeeper-web and gatekeeper-api"
  run "stopping web and API" systemctl --user stop gatekeeper-web.service gatekeeper-api.service
fi

# The empty database carries the default privileges of scripts/db-roles.sql (new tables give the app role full DML). The dump only
# GRANTs what the app role should have, it never revokes, so a table created under those defaults would keep DELETE/UPDATE that a migration
# had revoked (audit_events!). So: drop the defaults, restore (the dump grants exactly what the source had), put the defaults back.
echo "Restoring $file into $db"
step="revoking default privileges"; revoked=1
default_privileges revoke || { echo "Step failed: $step" >&2; exit 1; }
step="restoring"
podman exec -i "$container" pg_restore -U "$owner" -d "$db" --no-password --exit-on-error --single-transaction < "$file" \
  || { echo "Restore FAILED; the transaction was rolled back and the database is still empty." >&2; exit 1; }
step="putting default privileges back"
default_privileges grant || { echo "Step failed: $step" >&2; exit 1; }
revoked=0

step="sanity check"
ok=$(sql "select to_regclass('public.\"__EFMigrationsHistory\"') is not null and to_regclass('public.users') is not null") || ok=f
[ "$ok" = t ] || { echo "The restored database has no __EFMigrationsHistory or users table: not a Gatekeeper dump? Not starting the services." >&2; exit 1; }
# A trace in the audit trail (no schema change: the owner may insert, only prune rows are special). The name is passed as a psql variable.
step="writing the audit row"
printf '%s\n' "insert into audit_events (id, at, actor, action, outcome, detail) values (gen_random_uuid(), now(), 'system:restore', 'system.restore', 'success', 'dump=' || left(:'d', 120) || ' verified=$verify')" \
  | podman exec -i "$container" psql -U "$owner" -d "$db" --no-password -v ON_ERROR_STOP=1 -q -v "d=$(basename -- "$file")" >/dev/null \
  || { echo "Step failed: $step (the data is restored)" >&2; exit 1; }

if [ "$services" = 1 ]; then
  echo "Running migrations"
  run "running migrations (gatekeeper-migrate.service)" systemctl --user restart gatekeeper-migrate.service
  echo "Starting gatekeeper-api and gatekeeper-web"
  run "starting API and web" systemctl --user start gatekeeper-api.service gatekeeper-web.service
  stopped=0
else
  echo "Skipped the systemd units (--no-services): run the migrate command, then start the API."
fi
done_ok=1
echo "Restored."
echo "NEXT: the restore brings back the database as of the dump. Sessions and refresh tokens revoked since then are active again, rotated"
echo "refresh tokens are valid again, and passwords changed since then are the old ones. If any of that matters: end all sessions of the"
echo "affected users (DELETE /v1/users/{id}/sessions, or gk), have users with changed passwords reset them, and run"
echo "deploy/rotate-signing-key.sh --compromised to stop every access token issued before the restore. An audit row 'system.restore' was written."
