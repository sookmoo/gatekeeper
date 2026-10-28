#!/usr/bin/env bash
# Backs up the Gatekeeper database: `pg_dump -Fc` as the owner role, run inside the db container (unix socket, so no password is
# handled here; the host account is the trust boundary). The dump holds Argon2 password hashes, client-secret hashes and the whole audit
# trail: treat it like the database. It does NOT hold the token signing key or the podman secrets (back those up separately, see README
# "Backup and restore"). Next to each dump a <dump>.sha256 file is written; restore.sh verifies it.
#
# Environment (all optional):
#   GATEKEEPER_BACKUP_DIR   target directory (default ~/.local/share/gatekeeper/backups); created 0700 if missing
#   GATEKEEPER_BACKUP_KEEP_DAYS  dumps older than this many days are deleted after a successful run (default 7)
#   GATEKEEPER_DB_CONTAINER container name (default gatekeeper-db), GATEKEEPER_DB_NAME (gatekeeper), GATEKEEPER_DB_OWNER (gatekeeper_owner)
set -euo pipefail
umask 077

usage() { echo "usage: $0   (settings come from GATEKEEPER_BACKUP_DIR, GATEKEEPER_BACKUP_KEEP_DAYS; see the header of this script)" >&2; }
[ $# -eq 0 ] || { usage; exit 2; }

dir=${GATEKEEPER_BACKUP_DIR:-$HOME/.local/share/gatekeeper/backups}
keep=${GATEKEEPER_BACKUP_KEEP_DAYS:-7}
container=${GATEKEEPER_DB_CONTAINER:-gatekeeper-db}
db=${GATEKEEPER_DB_NAME:-gatekeeper}
owner=${GATEKEEPER_DB_OWNER:-gatekeeper_owner}

[[ "$keep" =~ ^[0-9]+$ ]] || { echo "GATEKEEPER_BACKUP_KEEP_DAYS must be a whole number of days, at least 1" >&2; exit 2; }
keep=$((10#$keep)) # "08" is decimal, not an invalid octal number
[ "$keep" -ge 1 ] || { echo "GATEKEEPER_BACKUP_KEEP_DAYS must be a whole number of days, at least 1" >&2; exit 2; }
ident='^[A-Za-z_][A-Za-z0-9_]*$'
[[ "$db" =~ $ident && "$owner" =~ $ident ]] || { echo "GATEKEEPER_DB_NAME and GATEKEEPER_DB_OWNER must match $ident" >&2; exit 2; }
[[ "$container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || { echo "GATEKEEPER_DB_CONTAINER is not a valid container name" >&2; exit 2; }
[[ "$dir" = /* ]] || { echo "GATEKEEPER_BACKUP_DIR must be an absolute path" >&2; exit 2; }
# A trailing slash would make `[ -L ]` follow the link, so strip it before the symlink check.
while [ "${#dir}" -gt 1 ] && [ "${dir%/}" != "$dir" ]; do dir=${dir%/}; done
[ ! -L "$dir" ] || { echo "$dir is a symlink; give the real directory" >&2; exit 1; }

[ -d "$dir" ] || mkdir -p -m 0700 "$dir"
[ -d "$dir" ] || { echo "$dir is not a directory" >&2; exit 1; }
dir=$(cd -P -- "$dir" && pwd)
[ -O "$dir" ] || { echo "$dir is not owned by the current user" >&2; exit 1; }
mode=$(stat -c %a "$dir")
# Refuse when group or others can write (they could replace or delete dumps): the 022 bits of the mode.
if [ $(( 8#$mode & 8#022 )) -ne 0 ]; then
  echo "Refusing: $dir is group- or world-writable (mode $mode). chmod 700 '$dir'" >&2; exit 1
fi
[ $(( 8#$mode & 8#007 )) -eq 0 ] || echo "WARNING: $dir is readable by others (mode $mode); dumps contain password hashes. chmod 700 '$dir' is advised." >&2

# One backup at a time (a timer run and a manual run, or a slow dump and the next timer).
exec 9>"$dir/.gatekeeper-backup.lock"
flock -n 9 || { echo "Another backup is running (lock $dir/.gatekeeper-backup.lock)" >&2; exit 1; }

[ "$(podman inspect --format '{{.State.Running}}' "$container" 2>/dev/null)" = true ] \
  || { echo "Container $container is not running (systemctl --user start gatekeeper-db.service)" >&2; exit 1; }

stamp=$(date -u +%Y%m%dT%H%M%SZ)
name="gatekeeper-$stamp.dump"
final="$dir/$name"
tmp="$dir/.gatekeeper-$stamp.dump.tmp.$$"
tmpsum="$dir/.gatekeeper-$stamp.dump.sha256.tmp.$$"
[ ! -e "$final" ] || { echo "$final already exists (two runs in the same second)" >&2; exit 1; }
trap 'rm -f -- "$tmp" "$tmpsum"' EXIT
# Leftovers of runs that were killed (the lock above means none of them is live): temp files older than 60 minutes.
find "$dir" -maxdepth 1 -type f -name '.gatekeeper-*.tmp.*' -mmin +60 -delete

podman exec "$container" pg_dump -U "$owner" -d "$db" -Fc --no-password > "$tmp"
[ -s "$tmp" ] || { echo "The dump is empty" >&2; exit 1; }
# Fail loudly on a dump that cannot be read back (truncated, wrong format) or that is not a Gatekeeper database.
listing=$(podman exec -i "$container" pg_restore --list < "$tmp") || { echo "The dump does not pass pg_restore --list" >&2; exit 1; }
for t in __EFMigrationsHistory users; do
  grep -Eq "TABLE public $t( |$)" <<<"$listing" || { echo "The dump has no table $t: not a Gatekeeper database? Nothing was kept or deleted." >&2; exit 1; }
done
chmod 0600 "$tmp"
printf '%s  %s\n' "$(sha256sum < "$tmp" | cut -d' ' -f1)" "$name" > "$tmpsum"
# The checksum lands first, so a dump is never visible without it.
mv -n -- "$tmpsum" "$final.sha256"
mv -n -- "$tmp" "$final"
[ -f "$final" ] && [ -f "$final.sha256" ] || { echo "Could not move the dump into place" >&2; exit 1; }
echo "Wrote $final ($(stat -c %s "$final") bytes, mode $(stat -c %a "$final")) and $name.sha256"

# Retention: only our own file patterns, only regular files directly in the directory, only after this run succeeded.
find "$dir" -maxdepth 1 -type f \( -name 'gatekeeper-*.dump' -o -name 'gatekeeper-*.dump.sha256' \) -mmin "+$((keep * 1440))" -print -delete \
  | sed 's/^/Deleted old file: /' || { echo "Pruning old dumps failed" >&2; exit 1; }
