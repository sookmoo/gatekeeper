#!/usr/bin/env bash
# Installs the Gatekeeper Quadlet units for the current user (rootless Podman) and creates the podman secrets with
# random passwords. Re-running keeps existing secrets. Usage: deploy/install.sh [image]   (default: units' image)
set -euo pipefail
cd "$(dirname "$0")"
IMAGE="${1:-}"

conf="$HOME/.config/gatekeeper/postgres-init"
units="$HOME/.config/containers/systemd"
mkdir -p "$conf" "$units"
install -m 0755 postgres-init/10-roles.sh "$conf/10-roles.sh"
install -m 0644 ../scripts/db-roles.sql "$conf/db-roles.sql"
install -m 0644 quadlet/* "$units/"
if [ -n "$IMAGE" ]; then sed -i "s#^Image=ghcr.io/sookmoo/gatekeeper:.*#Image=$IMAGE#" "$units"/gatekeeper-{api,migrate}.container; fi

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

systemctl --user daemon-reload
echo "Installed. Start with: systemctl --user start gatekeeper-api.service"
