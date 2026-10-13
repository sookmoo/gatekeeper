#!/usr/bin/env bash
# Rotates the token signing key of the Quadlet installation.
#
#   deploy/rotate-signing-key.sh              new key signs from now on; the old PUBLIC key is kept in the JWKS so tokens
#                                             it already signed stay valid until they expire (15 minutes by default); it is stamped, and the server drops it by itself after that
#   deploy/rotate-signing-key.sh --compromised  new key, and the old key is NOT kept: every token it signed stops working now
#   deploy/rotate-signing-key.sh --prune        drop all retired keys (run once the longest token lifetime has passed)
#
# Consumers that cache the JWKS refetch it when they see an unknown kid (or within their cache lifetime); keep your
# acceptance windows in mind. At most 5 retired keys are kept (the oldest are dropped).
set -euo pipefail
umask 077
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
[ $# -le 1 ] || { echo "usage: $0 [--compromised|--prune]" >&2; exit 2; }
mode="${1:-rotate}"
case "$mode" in rotate|--compromised|--prune) ;; *) echo "usage: $0 [--compromised|--prune]" >&2; exit 2;; esac
[ "${1:-}" != "rotate" ] || { echo "usage: $0 [--compromised|--prune]" >&2; exit 2; }

# One rotation at a time.
if command -v flock >/dev/null; then
  exec 9>"${XDG_RUNTIME_DIR:-$HOME}/.gatekeeper-rotate.lock"
  flock -n 9 || { echo "another rotation is running" >&2; exit 1; }
fi

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT; chmod 700 "$tmp"
get() { podman secret inspect --showsecret --format '{{.SecretData}}' "$1"; }
# Replaces a secret without ever leaving none behind: the new content is stored under "<name>.new" first and only removed
# once the real name exists again. If the final step fails, the content is still recoverable from "<name>.new".
put() {
  podman secret rm "$1.new" >/dev/null 2>&1 || true
  podman secret create "$1.new" "$2" >/dev/null
  podman secret rm "$1" >/dev/null 2>&1 || true
  if ! podman secret create "$1" "$2" >/dev/null; then
    echo "Could not create secret $1; the new content is kept as $1.new (podman secret inspect --showsecret $1.new)." >&2
    exit 1
  fi
  podman secret rm "$1.new" >/dev/null 2>&1 || true
}

# Any private-key block in the retired file is reduced to its public key (nothing secret needs to stay there).
publicize() {
  awk '
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/ { blk = $0 "\n"; priv = 1; next }
    priv { blk = blk $0 "\n"; if (/-----END/) { fflush(); cmd = "openssl pkey -pubout"; printf "%s", blk | cmd; close(cmd); priv = 0 } ; next }
    { print }'
}
# One "<retired-at or -> <base64 of the public key>" line per key, and back, so blocks can be counted and trimmed with plain tools.
to_lines() {
  awk '/^# retired-at:/{st=$3;next} /-----BEGIN PUBLIC KEY-----/{b="";p=1;next} /-----END PUBLIC KEY-----/{print (st==""?"-":st), b;p=0;st="";next} p{b=b $0}'
}
from_lines() {
  while read -r st l; do
    [ "$st" = "-" ] || echo "# retired-at: $st"
    echo "-----BEGIN PUBLIC KEY-----"; echo "$l" | fold -w 64; echo "-----END PUBLIC KEY-----"
  done
}

get gatekeeper-signing-key >"$tmp/current.pem"
retired=$(get gatekeeper-retired-keys 2>/dev/null || true)

if [ "$mode" = "--prune" ]; then
  printf '%s' "# no retired keys" >"$tmp/retired.pem"
  put gatekeeper-retired-keys "$tmp/retired.pem"
  echo "Retired keys removed."
else
  if [ "$mode" = "rotate" ]; then
    openssl pkey -in "$tmp/current.pem" -pubout >"$tmp/old-public.pem"
    now=$(date -u +%FT%TZ)
    # existing retired keys + the key being retired (stamped now), newest last; keep at most 5.
    # The server stops trusting a stamped key by itself once the tokens it signed have expired.
    { printf '%s\n' "$retired" | publicize | to_lines; { echo "# retired-at: $now"; cat "$tmp/old-public.pem"; } | to_lines; } \
      | tail -n 5 | from_lines >"$tmp/blocks.pem"
    { printf '# retired keys, last rotation %s\n' "$now"; cat "$tmp/blocks.pem"; } >"$tmp/retired.pem"
  else
    printf '%s' "$retired" >"$tmp/retired.pem"
  fi
  openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt >"$tmp/new.pem"
  put gatekeeper-retired-keys "$tmp/retired.pem"
  put gatekeeper-signing-key "$tmp/new.pem"
  echo "New signing key installed ($mode)."
fi
systemctl --user restart gatekeeper-api.service
sleep 3
systemctl --user is-active --quiet gatekeeper-api.service \
  || { echo "WARNING: gatekeeper-api is not running after the restart; see: journalctl --user -u gatekeeper-api" >&2; exit 1; }
echo "Restarted gatekeeper-api. Check: curl -s http://127.0.0.1:5080/.well-known/jwks.json"
