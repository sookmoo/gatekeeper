#!/usr/bin/env bash
# Fails if the Postgres image pin differs between the CI service container, the Quadlet unit that is deployed and
# deploy/postgres/Dockerfile (the file Dependabot and the weekly scan read). Dependabot cannot read the first two,
# so all three are bumped together by hand (see the README).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
pattern='postgres:[0-9A-Za-z.-]+@sha256:[0-9a-f]{64}'

pick() { # file, extended regex with the pin as its last group-free part, sed expression to strip the prefix
  { tr -d '\r' < "$ROOT/$1" | grep -E "$2" | sed -E "$3" | sort -u; } || true
}
ci=$(pick .github/workflows/ci.yml "^ +image: $pattern\$" 's/^ +image: //')
quadlet=$(pick deploy/quadlet/gatekeeper-db.container "^Image=.*/$pattern\$" 's/^Image=.*\///')
dockerfile=$(pick deploy/postgres/Dockerfile "^FROM .*/$pattern\$" 's/^FROM .*\///')

[ -n "$ci" ] || { echo "No digest-pinned postgres image in .github/workflows/ci.yml." >&2; exit 1; }
[ -n "$quadlet" ] || { echo "No digest-pinned postgres image in deploy/quadlet/gatekeeper-db.container." >&2; exit 1; }
[ -n "$dockerfile" ] || { echo "No digest-pinned postgres image in deploy/postgres/Dockerfile." >&2; exit 1; }
if [ "$ci" != "$quadlet" ] || [ "$ci" != "$dockerfile" ]; then
  echo "Postgres pins differ: ci.yml '$ci', gatekeeper-db.container '$quadlet', deploy/postgres/Dockerfile '$dockerfile'. Bump all three together." >&2
  exit 1
fi
echo "OK: $ci"
