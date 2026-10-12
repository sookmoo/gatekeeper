#!/usr/bin/env bash
# Creates the first Gatekeeper administrator (run once, after install.sh and after the database is up).
# The password is read with a hidden prompt (or from stdin when piped) and never appears in arguments.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 <username> <email>" >&2; exit 2; }

image=$(sed -n 's/^Image=//p' "$HOME/.config/containers/systemd/gatekeeper-api.container")
systemctl --user start gatekeeper-db.service gatekeeper-migrate.service

if [ -t 0 ]; then
  read -r -s -p "Password (min 12 characters): " password; echo
  read -r -s -p "Repeat password: " again; echo
  [ "$password" = "$again" ] || { echo "Passwords do not match." >&2; exit 1; }
else
  read -r password
fi

printf '%s\n' "$password" | podman run --rm -i --network gatekeeper \
  --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -e Store__Provider=Postgres \
  --secret gatekeeper-conn-app,type=env,target=ConnectionStrings__Gatekeeper \
  "$image" bootstrap-admin "$1" "$2"
