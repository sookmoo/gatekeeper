#!/usr/bin/env bash
# Installs the Gatekeeper Quadlet units for the current user (rootless Podman) and creates the podman secrets with
# random passwords. Re-running keeps existing secrets. Usage: deploy/install.sh [api-image [web-image]]   (default: the units' images)
set -euo pipefail
cd "$(dirname "$0")"
IMAGE="${1:-}"
WEB_IMAGE="${2:-}"

conf="$HOME/.config/gatekeeper/postgres-init"
units="$HOME/.config/containers/systemd"
mkdir -p "$conf" "$units"
install -m 0755 postgres-init/10-roles.sh "$conf/10-roles.sh"
install -m 0644 ../scripts/db-roles.sql "$conf/db-roles.sql"
install -m 0644 quadlet/* "$units/"
if [ -n "$IMAGE" ]; then sed -i "s#^Image=ghcr.io/sookmoo/gatekeeper:.*#Image=$IMAGE#" "$units"/gatekeeper-{api,migrate}.container; fi
if [ -n "$WEB_IMAGE" ]; then sed -i "s#^Image=ghcr.io/sookmoo/gatekeeper-web:.*#Image=$WEB_IMAGE#" "$units"/gatekeeper-web.container; fi

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
echo "The administration UI: systemctl --user start gatekeeper-web.service, then open http://127.0.0.1:5090"
