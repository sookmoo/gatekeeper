#!/usr/bin/env bash
# Backup/restore drill against two disposable Postgres containers (source and target; removed afterwards). Needs podman and the .NET SDK.
# Populates the source (migrations, an administrator, extra audit rows), runs deploy/backup.sh, restores into the fresh target with
# deploy/restore.sh, and compares: row counts per table, the audit trigger, the app role's grants, file modes, retention, refusals.
# Run: scripts/test-backup-restore.sh   (not part of CI: it needs podman and a published build; run it before a release)
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=docker.io/library/postgres:17-alpine
SRC=gk-bkt-src; DST=gk-bkt-dst
SRC_PORT=5441; DST_PORT=5442
work=$(mktemp -d)
cleanup() { podman rm -f "$SRC" "$DST" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
cleanup; work=$(mktemp -d)

# GATEKEEPER_TEST_RESTORE_SCRIPT lets a mutation check run the same tests against a modified copy of restore.sh.
RESTORE=${GATEKEEPER_TEST_RESTORE_SCRIPT:-deploy/restore.sh}
REAL_PODMAN=$(command -v podman)
pass=0
ok()   { pass=$((pass + 1)); echo "ok   - $1"; }
fail() { echo "FAIL - $1" >&2; exit 1; }
check() { local msg=$1; shift; if "$@"; then ok "$msg"; else fail "$msg"; fi; }
# Runs a command that must fail; its output must contain the pattern.
refuses() { local msg=$1 pat=$2; shift 2; local out; if out=$("$@" 2>&1); then fail "$msg (it succeeded)"; fi; [[ "$out" == *"$pat"* ]] || fail "$msg (wrong message: $out)"; ok "$msg"; }

OWNER_PW=owner-test-pw; APP_PW=app-test-pw

start_db() { # name port
  podman run -d --name "$1" -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=test-only -p "127.0.0.1:$2:5432" "$IMAGE" >/dev/null
  until podman exec "$1" psql -U postgres -tAc 'select 1' >/dev/null 2>&1; do sleep 1; done
  # The same role/database setup as production (the init hook feeds this file with the passwords).
  podman exec -i "$1" psql -v ON_ERROR_STOP=1 -q -U postgres -v owner_pw="$OWNER_PW" -v app_pw="$APP_PW" -f - < scripts/db-roles.sql >/dev/null
}
start_db "$SRC" "$SRC_PORT"; start_db "$DST" "$DST_PORT"

dotnet build src/Gatekeeper.Api -v q --nologo >/dev/null
API=$(ls src/Gatekeeper.Api/bin/*/net*/Gatekeeper.Api.dll | head -n1)
gk() { # port, args...: the API binary against one of the databases
  local port=$1; shift
  Store__Provider=Postgres \
  ConnectionStrings__GatekeeperMigrations="Host=127.0.0.1;Port=$port;Database=gatekeeper;Username=gatekeeper_owner;Password=$OWNER_PW" \
  ConnectionStrings__Gatekeeper="Host=127.0.0.1;Port=$port;Database=gatekeeper;Username=gatekeeper_app;Password=$APP_PW" \
  dotnet "$API" "$@"
}
q() { podman exec "$1" psql -U "${3:-gatekeeper_owner}" -d gatekeeper --no-password -tA -c "$2"; } # container, sql, role
counts_sql="select string_agg(format('select %L, count(*) from %I', tablename, tablename), ' union all ' order by tablename) from pg_tables where schemaname = 'public'"
counts() { local s; s=$(q "$1" "$counts_sql"); q "$1" "select * from ($s) t order by 1"; }

gk "$SRC_PORT" migrate >/dev/null
echo 'correct horse battery staple' | gk "$SRC_PORT" bootstrap-admin alice alice@example.test >/dev/null
echo 'another long password here' | gk "$SRC_PORT" bootstrap-admin bob bob@example.test >/dev/null
q "$SRC" "insert into audit_events (id, at, actor, action, outcome) select gen_random_uuid(), now(), 'test', 'test.populate', 'success' from generate_series(1, 25)" gatekeeper_app >/dev/null
src_counts=$(counts "$SRC")
[ "$(echo "$src_counts" | awk -F'|' '$1=="users"{print $2}')" -ge 2 ] || fail "source has users"
ok "source populated"

# --- backup ---
bk="$work/backups"
export GATEKEEPER_DB_CONTAINER=$SRC
refuses "backup refuses a non-numeric keep value" "KEEP_DAYS" env GATEKEEPER_BACKUP_DIR="$bk" GATEKEEPER_BACKUP_KEEP_DAYS=abc deploy/backup.sh
refuses "backup refuses keep 0" "KEEP_DAYS" env GATEKEEPER_BACKUP_DIR="$bk" GATEKEEPER_BACKUP_KEEP_DAYS=0 deploy/backup.sh
refuses "backup refuses a bad container name" "container name" env GATEKEEPER_BACKUP_DIR="$bk" GATEKEEPER_DB_CONTAINER='x;y' deploy/backup.sh
refuses "backup refuses a bad owner name" "must match" env GATEKEEPER_BACKUP_DIR="$bk" GATEKEEPER_DB_OWNER='a b' deploy/backup.sh
mkdir -p "$work/real"; ln -s "$work/real" "$work/link"
refuses "backup refuses a symlinked directory" "symlink" env GATEKEEPER_BACKUP_DIR="$work/link" deploy/backup.sh
refuses "backup refuses a symlinked directory with a trailing slash" "symlink" env GATEKEEPER_BACKUP_DIR="$work/link/" deploy/backup.sh
check "nothing was written through the symlink" test -z "$(ls -A "$work/real")"
mkdir -p "$work/open"; chmod 775 "$work/open"
refuses "backup refuses a group-writable directory" "group- or world-writable" env GATEKEEPER_BACKUP_DIR="$work/open" deploy/backup.sh
chmod 777 "$work/open"
refuses "backup refuses a world-writable directory" "group- or world-writable" env GATEKEEPER_BACKUP_DIR="$work/open" deploy/backup.sh
check "nothing was written to the refused directories" test -z "$(ls -A "$work/open")"
refuses "backup refuses a relative directory" "absolute" env GATEKEEPER_BACKUP_DIR=rel deploy/backup.sh

# Old dumps (and an unrelated file) to check retention; make the directory first so we also test the creation mode.
GATEKEEPER_BACKUP_DIR="$bk" GATEKEEPER_BACKUP_KEEP_DAYS=7 deploy/backup.sh >"$work/out.txt"
check "backup directory created 0700" test "$(stat -c %a "$bk")" = 700
dump=$(ls "$bk"/gatekeeper-*.dump)
check "exactly one dump" test "$(echo "$dump" | wc -l)" = 1
check "dump mode is 0600" test "$(stat -c %a "$dump")" = 600
check "dump checksum file exists, mode 0600" test "$(stat -c %a "$dump.sha256")" = 600
check "checksum matches" bash -c 'cd "$1" && sha256sum -c --quiet "$2"' _ "$bk" "$(basename "$dump").sha256"
check "no temp file left behind" test -z "$(ls -A "$bk" | grep -Ev '^(gatekeeper-.*\.dump(\.sha256)?|\.gatekeeper-backup\.lock)$' || true)"
check "the output does not contain a password" bash -c '! grep -qE "owner-test-pw|app-test-pw|test-only" "$1"' _ "$work/out.txt"

touch -d '10 days ago' "$bk/gatekeeper-20000101T000000Z.dump"
touch -d '6 days ago'  "$bk/gatekeeper-20000102T000000Z.dump"
touch -d '10 days ago' "$bk/gatekeeper-20000101T000000Z.dump.sha256"
echo keep > "$bk/notes.txt"; touch -d '30 days ago' "$bk/notes.txt"
touch -d '3 hours ago' "$bk/.gatekeeper-19990101T000000Z.dump.tmp.1" "$bk/.gatekeeper-19990101T000000Z.dump.sha256.tmp.1"
touch "$bk/.gatekeeper-19990102T000000Z.dump.tmp.2"
sleep 1 # a second dump needs a different timestamp name
GATEKEEPER_BACKUP_DIR="$bk" GATEKEEPER_BACKUP_KEEP_DAYS=7 deploy/backup.sh >/dev/null
check "dump older than 7 days was deleted" test ! -e "$bk/gatekeeper-20000101T000000Z.dump"
check "the old dump's checksum was deleted with it" test ! -e "$bk/gatekeeper-20000101T000000Z.dump.sha256"
check "orphan temp files older than 60 minutes were pruned" test ! -e "$bk/.gatekeeper-19990101T000000Z.dump.tmp.1" -a ! -e "$bk/.gatekeeper-19990101T000000Z.dump.sha256.tmp.1"
check "a fresh temp file was kept" test -e "$bk/.gatekeeper-19990102T000000Z.dump.tmp.2"
rm -f "$bk/.gatekeeper-19990102T000000Z.dump.tmp.2"
check "dump 6 days old was kept" test -e "$bk/gatekeeper-20000102T000000Z.dump"
check "files outside the dump pattern were kept" test -e "$bk/notes.txt"
check "new dumps were kept" test "$(ls "$bk"/gatekeeper-2[0-9][0-9][0-9][0-9][0-9][0-9][0-9]T*.dump | wc -l)" -ge 3
dump=$(ls "$bk"/gatekeeper-20[2-9]*.dump | tail -n1)

# Concurrent backups: hold the lock like a running backup would.
flock "$bk/.gatekeeper-backup.lock" sleep 30 & holder=$!
sleep 0.5 # let flock take the lock
refuses "a second backup is refused while one runs" "Another backup is running" env GATEKEEPER_BACKUP_DIR="$bk" deploy/backup.sh
kill "$holder"; wait "$holder" 2>/dev/null || true
# "08" must be read as decimal 8 (bash arithmetic would call it an invalid octal number).
GATEKEEPER_BACKUP_DIR="$work/bk08" GATEKEEPER_BACKUP_KEEP_DAYS=08 deploy/backup.sh >/dev/null; ok "KEEP_DAYS=08 is accepted"

# --- restore ---
export GATEKEEPER_DB_CONTAINER=$DST
app_defaults() { podman exec "$1" psql -U postgres -d gatekeeper -tA -c "select defaclacl::text from pg_default_acl order by 1"; }
tables_in() { q "$1" "select count(*) from pg_tables where schemaname='public'"; }
refuses "restore refuses without --yes" "--yes" "$RESTORE" --no-services "$dump"
refuses "restore refuses a file that is not a dump" "not a valid" "$RESTORE" --yes --no-verify --no-services "$work/out.txt"
refuses "restore refuses a missing file" "not a readable file" "$RESTORE" --yes --no-services "$work/nope.dump"
refuses "restore refuses a bad database name" "must match" env GATEKEEPER_DB_NAME='a;b' "$RESTORE" --yes --no-services "$dump"

# Checksum: mismatch and absence are refused (--no-verify is the explicit bypass).
mkdir -p "$work/t"; cp "$dump" "$dump.sha256" "$work/t/"
tdump="$work/t/$(basename "$dump")"
printf 'x' >> "$tdump"
refuses "restore refuses a dump that does not match its checksum" "Checksum mismatch" "$RESTORE" --yes --no-services "$tdump"
rm "$tdump.sha256"
refuses "restore refuses a dump without a checksum file" "No checksum file" "$RESTORE" --yes --no-services "$tdump"
check "nothing was restored by the refused attempts" test "$(tables_in "$DST")" = 0

# A dump that cannot be restored (it grants to a role the target does not have): the database stays empty, defaults stay in place.
podman exec "$SRC" psql -U postgres -d gatekeeper -q -c "create role gk_extra" -c "grant select on users to gk_extra" >/dev/null
GATEKEEPER_DB_CONTAINER=$SRC GATEKEEPER_BACKUP_DIR="$work/bad" deploy/backup.sh >/dev/null
podman exec "$SRC" psql -U postgres -d gatekeeper -q -c "revoke select on users from gk_extra" -c "drop role gk_extra" >/dev/null
bad=$(ls "$work/bad"/gatekeeper-*.dump)
defaults_before=$(app_defaults "$DST")
refuses "a failing restore reports it" "Restore FAILED" "$RESTORE" --yes --no-services "$bad"
check "a failing restore leaves the database empty" test "$(tables_in "$DST")" = 0
check "a failing restore puts the default privileges back" test "$(app_defaults "$DST")" = "$defaults_before"
check "the default privileges include the app role" test "$(app_defaults "$DST" | grep -c gatekeeper_app)" -ge 1
cp "$bad" "$work/t/bad.dump"
refuses "--no-verify restores a dump without a checksum (here: fails on the role)" "Restore FAILED" "$RESTORE" --yes --no-verify --no-services "$work/t/bad.dump"

# An interrupted restore: a stand-in "podman" hangs at pg_restore (never touching the real one); restore.sh gets SIGTERM, and so does
# the stand-in's sleep (as a systemd stop or Ctrl-C would signal the whole group).
mkdir -p "$work/fakebin"
cat > "$work/fakebin/podman" <<FAKE
#!/bin/bash
if [[ " \$* " == *" pg_restore -U "* ]]; then touch "$work/hang"; exec sleep 60; fi
exec "$REAL_PODMAN" "\$@"
FAKE
chmod +x "$work/fakebin/podman"
PATH="$work/fakebin:$PATH" "$RESTORE" --yes --no-services "$dump" >"$work/int.txt" 2>&1 & rpid=$!
for _ in $(seq 100); do [ -e "$work/hang" ] && break; sleep 0.1; done
[ -e "$work/hang" ] || fail "the interrupted restore never reached pg_restore"
kill -TERM "$rpid"; pkill -TERM -P "$rpid" sleep || true
if wait "$rpid"; then fail "an interrupted restore must not succeed"; else ok "an interrupted restore exits non-zero"; fi
check "the interrupted restore says so and how to proceed" grep -q "run restore.sh again" "$work/int.txt"
check "the interrupted restore left the database empty" test "$(tables_in "$DST")" = 0
check "the interrupted restore put the default privileges back" test "$(app_defaults "$DST")" = "$defaults_before"

# A restore that was killed hard cannot clean up: simulate the state it leaves (default privileges revoked), then run a restore that
# fails; it must put the defaults back. (The next, real restore then starts from the normal state, so it depends on the revoke/re-grant.)
podman exec "$DST" psql -U gatekeeper_owner -d gatekeeper -q -c 'alter default privileges for role gatekeeper_owner in schema public revoke all on tables from gatekeeper_app' >/dev/null
check "the default privileges are gone (simulated hard kill)" test "$(app_defaults "$DST" | grep -c gatekeeper_app || true)" = 0
"$RESTORE" --yes --no-services "$bad" >/dev/null 2>&1 && fail "the failing dump restored"
check "a restore after a hard kill puts the default privileges back" test "$(app_defaults "$DST")" = "$defaults_before"
"$RESTORE" --yes --no-services "$dump" >"$work/restore.txt"
ok "restore into the fresh database (after the interruptions)"
check "the restore prints the follow-up for revived sessions" grep -q "rotate-signing-key.sh --compromised" "$work/restore.txt"
check "the default privileges are the source's" test "$(app_defaults "$DST")" = "$(app_defaults "$SRC")"
check "a system.restore audit row was written" test "$(q "$DST" "select count(*) from audit_events where actor='system:restore' and action='system.restore'")" = 1
filter() { grep -v '^audit_events|'; }
dst_counts=$(counts "$DST")
check "row counts per table are identical (audit_events: one more, the restore row)" test "$(echo "$src_counts" | filter)" = "$(echo "$dst_counts" | filter)"
check "audit_events has the source rows plus the restore row" test "$(echo "$dst_counts" | awk -F'|' '$1=="audit_events"{print $2}')" = "$(( $(echo "$src_counts" | awk -F'|' '$1=="audit_events"{print $2}') + 1 ))"
check "the migration history came back" test "$(q "$DST" 'select count(*) from "__EFMigrationsHistory"')" -gt 0
refuses "restore refuses a non-empty database" "not empty" "$RESTORE" --yes --no-services "$dump"
check "the refused restore changed nothing" test "$(counts "$DST")" = "$dst_counts"

# The migrate step is a no-op on a current schema, and the restored data is usable with the app role.
gk "$DST_PORT" migrate >/dev/null; ok "migrate runs on the restored database"
check "triggers are the same" test "$(q "$SRC" "select string_agg(tgname, ',' order by tgname) from pg_trigger where not tgisinternal")" = "$(q "$DST" "select string_agg(tgname, ',' order by tgname) from pg_trigger where not tgisinternal")"
grants_sql="select string_agg(table_name||':'||privilege_type||':'||grantee, ',' order by table_name, privilege_type, grantee) from information_schema.role_table_grants where table_schema='public'"
[ "$(q "$SRC" "$grants_sql")" = "$(q "$DST" "$grants_sql")" ] || { diff <(q "$SRC" "$grants_sql" | tr , '\n') <(q "$DST" "$grants_sql" | tr , '\n') >&2 || true; }
check "table grants are the same" test "$(q "$SRC" "$grants_sql")" = "$(q "$DST" "$grants_sql")"
check "tables are owned by the owner role" test "$(q "$DST" "select count(*) from pg_tables where schemaname='public' and tableowner<>'gatekeeper_owner'")" = 0

fails() { local msg=$1 role=$2 sql=$3; if q "$DST" "$sql" "$role" >/dev/null 2>&1; then fail "$msg"; else ok "$msg"; fi; }
fails "app role cannot delete audit rows"  gatekeeper_app "delete from audit_events"
fails "app role cannot update audit rows"  gatekeeper_app "update audit_events set actor = 'x'"
fails "app role cannot truncate audit"     gatekeeper_app "truncate audit_events"
fails "app role cannot create tables"      gatekeeper_app "create table evil (id int)"
fails "app role cannot drop the trigger"   gatekeeper_app "drop trigger audit_events_no_change on audit_events"
fails "app role cannot alter tables"       gatekeeper_app "alter table users add column evil int"
fails "owner is refused by the audit trigger" gatekeeper_owner "delete from audit_events"
check "app role can still insert audit rows" q "$DST" "insert into audit_events (id, at, actor, action, outcome) values (gen_random_uuid(), now(), 'test', 'test.after', 'success')" gatekeeper_app
check "app role can still read users" test "$(q "$DST" "select count(*) from users" gatekeeper_app)" -ge 2
# The prune command still works on the restored database (the owner may delete only through it).
gk "$DST_PORT" prune-audit --older-than 30 --dry-run >/dev/null; ok "prune-audit --dry-run runs on the restored database"

echo "All $pass checks passed."
