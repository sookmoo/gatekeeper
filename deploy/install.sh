#!/usr/bin/env bash
# Installs the Gatekeeper Quadlet units for the current user (rootless Podman) and creates the podman secrets with
# random passwords. Re-running keeps existing secrets.
usage() {
  cat <<'USAGE'
Usage: deploy/install.sh vX.Y.Z[-pre] [sha256:<api-digest> sha256:<web-digest>] [--allow-mismatch]
       deploy/install.sh <api-image> [<web-image>]
       deploy/install.sh --latest
  vX.Y.Z   a release (the way to run a server). Writes Image=<repo>@sha256:<digest> into the units, the tag in a comment.
           With the two digests from the release notes it pulls by digest and fails on a mismatch. Without them it pulls the
           tag and trusts what the registry returns now (trust on first use): compare the printed digests with the release notes.
           The deploy files come from this checkout: it should be the tagged commit (else an error, unless --allow-mismatch).
  images   explicit image references, used as given.
  --latest keep ghcr.io/sookmoo/gatekeeper{,-web}:latest in the units. Local development only: it moves on every merge to main,
           and it replaces pinned units. Without any argument the script refuses, so a re-run never silently unpins a server.
USAGE
}
set -euo pipefail
cd "$(dirname "$0")"

# 1. Parse and validate everything before touching anything.
LATEST=0; ALLOW_MISMATCH=0; args=()
for a in "$@"; do
  case "$a" in
    -h|--help) usage; exit 0 ;;
    --latest) LATEST=1 ;;
    --allow-mismatch) ALLOW_MISMATCH=1 ;;
    *) args+=("$a") ;;
  esac
done
set -- ${args[@]+"${args[@]}"}
VERSION_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
DIGEST_RE='^sha256:[0-9a-f]{64}$'
IMAGE_RE='^[a-z0-9][a-z0-9._:-]*/[a-z0-9._/-]+(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$'
IMAGE=""; WEB_IMAGE=""; VERSION=""; API_DIGEST=""; WEB_DIGEST=""
if [ $# -eq 0 ]; then
  [ "$LATEST" = 1 ] || { usage >&2; echo "Refusing to run without an argument: pass a version, or --latest for local development." >&2; exit 1; }
elif [ "$LATEST" = 1 ]; then
  echo "--latest takes no other arguments" >&2; exit 1
elif [[ "$1" =~ $VERSION_RE ]]; then
  VERSION="$1"
  case $# in
    1) ;;
    3) API_DIGEST="$2"; WEB_DIGEST="$3"
       [[ "$API_DIGEST" =~ $DIGEST_RE && "$WEB_DIGEST" =~ $DIGEST_RE ]] || { echo "Digests must look like sha256:<64 hex>" >&2; exit 1; } ;;
    *) echo "A version takes no arguments, or the API and web digests" >&2; exit 1 ;;
  esac
elif [[ "$1" =~ ^v[0-9] || "$1" == -* || "$1" =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
  echo "'$1' is not a valid version vX.Y.Z[-pre]" >&2; exit 1
else
  [ $# -le 2 ] || { echo "At most two images" >&2; exit 1; }
  for img in "$@"; do [[ "$img" =~ $IMAGE_RE ]] || { echo "'$img' is not a valid image reference" >&2; exit 1; }; done
  IMAGE="$1"; WEB_IMAGE="${2:-}"
fi

# Digest (sha256:...) podman resolved for a pulled reference, plus every digest it knows the image by.
known_digests() { podman image inspect --format '{{.Digest}} {{join .RepoDigests " "}}' "$1"; }
# Prints repo@sha256:<digest>; repo, tag, expected digest (may be empty).
resolve() {
  local repo=$1 tag=$2 want=$3 ref known digest
  if [ -n "$want" ]; then ref="$repo@$want"; else ref="$repo:$tag"; fi
  podman pull --quiet "$ref" >/dev/null || { echo "Cannot pull $ref" >&2; return 1; }
  known=$(known_digests "$ref")
  if [ -n "$want" ]; then
    [[ " $known " == *"$want"* ]] || { echo "Digest mismatch for $ref: podman knows '$known'" >&2; return 1; }
    digest=$want
  else
    digest=${known%% *}
    [[ "$digest" =~ $DIGEST_RE ]] || { echo "Unexpected digest '$digest' for $ref" >&2; return 1; }
  fi
  echo "$repo@$digest"
}

if [ -n "$VERSION" ]; then
  # The deploy files (units, scripts) come from this checkout.
  if command -v git >/dev/null && git rev-parse --git-dir >/dev/null 2>&1; then
    head=$(git rev-parse HEAD)
    if tagc=$(git rev-parse -q --verify "refs/tags/$VERSION^{commit}") && [ "$tagc" != "$head" ] && [ "$ALLOW_MISMATCH" = 0 ]; then
      echo "This checkout is not $VERSION (tag is $tagc, HEAD is $head): git checkout $VERSION, or pass --allow-mismatch" >&2; exit 1
    fi
    [ -n "${tagc:-}" ] || echo "WARNING: tag $VERSION is not in this checkout (git fetch --tags); the deploy files may not match the release." >&2
    [ -z "$(git status --porcelain -- .. 2>/dev/null)" ] || echo "WARNING: the working tree has uncommitted changes; they will be installed." >&2
  else
    echo "WARNING: not a git checkout; cannot check that the deploy files belong to $VERSION." >&2
  fi
  IMAGE=$(resolve ghcr.io/sookmoo/gatekeeper "$VERSION" "$API_DIGEST")
  WEB_IMAGE=$(resolve ghcr.io/sookmoo/gatekeeper-web "$VERSION" "$WEB_DIGEST")
  echo "API: $IMAGE"
  echo "Web: $WEB_IMAGE"
  [ -n "$API_DIGEST" ] || echo "WARNING: no expected digests given (trust on first use): compare the two lines above with the GitHub release notes for $VERSION." >&2
fi

# 2. Edit a private copy of the units and install them only when everything worked.
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp quadlet/* "$stage/"
note="${VERSION:+# $VERSION\n}"
if [ -n "$IMAGE" ]; then sed -i "s|^Image=ghcr.io/sookmoo/gatekeeper:.*|${note}Image=$IMAGE|" "$stage"/gatekeeper-{api,migrate,audit-prune}.container; fi
if [ -n "$WEB_IMAGE" ]; then sed -i "s|^Image=ghcr.io/sookmoo/gatekeeper-web:.*|${note}Image=$WEB_IMAGE|" "$stage"/gatekeeper-web.container; fi

conf="$HOME/.config/gatekeeper/postgres-init"
units="$HOME/.config/containers/systemd"
mkdir -p "$conf" "$units"
install -m 0755 postgres-init/10-roles.sh "$conf/10-roles.sh"
install -m 0644 ../scripts/db-roles.sql "$conf/db-roles.sql"
install -m 0644 "$stage"/* "$units/"
# The retention timer is a plain systemd unit (Quadlet only turns .container files into services). Installed, never enabled here.
timers="$HOME/.config/systemd/user"
mkdir -p "$timers"
install -m 0644 systemd/gatekeeper-audit-prune.timer "$timers/"

secret() { # name value
  podman secret exists "$1" || printf '%s' "$2" | podman secret create "$1" - >/dev/null
}
if ! podman secret exists gatekeeper-conn-app; then
  rand() { head -c 24 /dev/urandom | base64 | tr -d '/+=\n'; }
  admin=$(rand); owner=$(rand); app=$(rand)
  secret gatekeeper-pg-admin "$admin"
  secret gatekeeper-owner-pw "$owner"
  secret gatekeeper-app-pw "$app"
  # Traffic stays on the private podman network; use SslMode=VerifyFull for any database off this host.
  secret gatekeeper-conn-migrations "Host=gatekeeper-db;Database=gatekeeper;Username=gatekeeper_owner;Password=$owner;SSL Mode=Disable"
  secret gatekeeper-conn-app "Host=gatekeeper-db;Database=gatekeeper;Username=gatekeeper_app;Password=$app;SSL Mode=Disable"
fi

if ! podman secret exists gatekeeper-signing-key; then
  command -v openssl >/dev/null || { echo "openssl is required to generate the token signing key" >&2; exit 1; }
  openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt | podman secret create gatekeeper-signing-key - >/dev/null
fi

secret gatekeeper-retired-keys "# no retired keys"

systemctl --user daemon-reload
echo "Installed. Start with: systemctl --user start gatekeeper-api.service"
echo "Then create the first administrator once: deploy/bootstrap-admin.sh <username> <email>"
echo "Audit retention is off. Before enabling the daily prune (older than 365 days): run the command once by hand with --dry-run, then for real (with --allow-large if the dry run says so), as in README \"Audit trail\"; then systemctl --user enable --now gatekeeper-audit-prune.timer"
echo "The administration UI: systemctl --user start gatekeeper-web.service, then open http://127.0.0.1:5090"
