#!/usr/bin/env bash
# Rotates the token signing key of the Quadlet installation.
#
#   deploy/rotate-signing-key.sh              new key signs from now on; the old PUBLIC key is kept in the JWKS so tokens
#                                             it already signed stay valid until they expire (15 minutes by default)
#   deploy/rotate-signing-key.sh --compromised  new key, and the old key is NOT kept: every token it signed stops working now
#   deploy/rotate-signing-key.sh --prune        drop all retired keys (run once the longest token lifetime has passed)
#
# Consumers that cache the JWKS refetch it when they see an unknown kid (or within their cache lifetime); keep your
# acceptance windows in mind. At most 5 retired keys are kept (the oldest are dropped).
set -euo pipefail
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
mode="${1:-rotate}"
case "$mode" in rotate|--compromised|--prune) ;; *) echo "usage: $0 [--compromised|--prune]" >&2; exit 2;; esac

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT; chmod 700 "$tmp"
get() { podman secret inspect --showsecret --format '{{.SecretData}}' "$1"; }
put() { podman secret rm "$1" >/dev/null 2>&1 || true; podman secret create "$1" "$2" >/dev/null; }

# One PEM public key per line (base64 only) and back, so blocks can be counted and trimmed with plain tools.
to_lines() { awk '/-----BEGIN PUBLIC KEY-----/{b="";p=1;next} /-----END PUBLIC KEY-----/{print b;p=0;next} p{b=b $0}'; }
from_lines() { while read -r l; do echo "-----BEGIN PUBLIC KEY-----"; echo "$l" | fold -w 64; echo "-----END PUBLIC KEY-----"; done; }

get gatekeeper-signing-key >"$tmp/current.pem"
retired=$(get gatekeeper-retired-keys 2>/dev/null || true)

if [ "$mode" = "--prune" ]; then
  printf '%s' "# no retired keys" >"$tmp/retired.pem"
  put gatekeeper-retired-keys "$tmp/retired.pem"
  echo "Retired keys removed."
else
  if [ "$mode" = "rotate" ]; then
    openssl pkey -in "$tmp/current.pem" -pubout >"$tmp/old-public.pem"
    # existing retired blocks + the key being retired, newest last; keep at most 5
    { printf '%s\n' "$retired" | to_lines; to_lines <"$tmp/old-public.pem"; } | tail -n 5 | from_lines >"$tmp/blocks.pem"
    { printf '# retired keys, last rotation %s\n' "$(date -u +%FT%TZ)"; cat "$tmp/blocks.pem"; } >"$tmp/retired.pem"
  else
    printf '%s' "$retired" >"$tmp/retired.pem"
  fi
  openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt >"$tmp/new.pem"
  put gatekeeper-retired-keys "$tmp/retired.pem"
  put gatekeeper-signing-key "$tmp/new.pem"
  echo "New signing key installed ($mode)."
fi
systemctl --user restart gatekeeper-api.service
echo "Restarted gatekeeper-api. Check: curl -s http://127.0.0.1:5080/.well-known/jwks.json"
