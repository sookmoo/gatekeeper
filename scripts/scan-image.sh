#!/usr/bin/env bash
# Scans local container images with Trivy (pinned in scripts/trivy/Dockerfile, run as a container).
# Usage: scripts/scan-image.sh <image> [<image>...]   (the images must exist in the local docker/podman store)
# Fails (exit 1) on Critical/High findings that have a fix available and are not in .trivyignore.yaml, and on a
# scanner error. Everything else is only reported (log, and the job summary when GITHUB_STEP_SUMMARY is set).
# Severity is the vendor's; UNKNOWN is not a gate. Unfixed Critical findings are listed as warnings, not gated.
set -euo pipefail

[ "$#" -gt 0 ] || { echo "Usage: $0 <image> [<image>...]" >&2; exit 2; }

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUNTIME=${CONTAINER_RUNTIME:-docker}
TRIVY=$(sed -n 's/^FROM \(ghcr.io\/aquasecurity\/trivy:[^ ]*@sha256:[0-9a-f]\{64\}\)$/\1/p' "$ROOT/scripts/trivy/Dockerfile")
[ -n "$TRIVY" ] || { echo "No pinned Trivy image in scripts/trivy/Dockerfile." >&2; exit 1; }

WORK=$(mktemp -d)
chmod 755 "$WORK"   # Trivy runs as root without capabilities (cap-drop ALL): it cannot read a 0700 directory of another uid
CACHE=gatekeeper-trivy-cache-$$-$RANDOM
cleanup() { rm -rf "$WORK"; "$RUNTIME" volume rm -f "$CACHE" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# trivy <network> <trivy args...>; network is "default" or "none". No capabilities, no privilege gain.
trivy() {
  local net=$1; shift
  local netargs=()
  [ "$net" = none ] && netargs=(--network none)
  "$RUNTIME" run --rm --cap-drop ALL --security-opt no-new-privileges "${netargs[@]}" \
    -v "$CACHE":/root/.cache -v "$WORK":/in:ro -v "$ROOT/.trivyignore.yaml":/ignore.yaml:ro \
    "$TRIVY" image --input /in/image.tar --scanners vuln --ignorefile /ignore.yaml \
    --skip-java-db-update --skip-version-check "$@"
}

status=0
for image in "$@"; do
  echo "== $image"
  rm -f "$WORK/image.tar"
  "$RUNTIME" save -o "$WORK/image.tar" "$image"
  chmod 644 "$WORK/image.tar"

  # Report pass (never gates): all severities, including findings without a fix and suppressed ones. Downloads the database.
  report=$(trivy default --format table --exit-code 0 --show-suppressed)
  echo "$report"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    { echo "### Trivy: $image"; echo '```'; echo "$report"; echo '```'; } >> "$GITHUB_STEP_SUMMARY"
  fi

  # Critical findings that are not gated (no fix available yet): visible as warnings, not hidden by --ignore-unfixed.
  unfixed=$(trivy none --skip-db-update --severity CRITICAL --format template \
    --template '{{ range . }}{{ range .Vulnerabilities }}{{ if not .FixedVersion }}{{ .VulnerabilityID }} {{ .PkgName }}{{ "\n" }}{{ end }}{{ end }}{{ end }}' || true)
  if [ -n "$unfixed" ]; then
    while IFS= read -r finding; do
      [ -n "$finding" ] && echo "::warning::$image: Critical without a fix (not gated): $finding"
    done <<< "$unfixed"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      { echo "Critical without a fix (not gated), $image:"; echo '```'; echo "$unfixed"; echo '```'; } >> "$GITHUB_STEP_SUMMARY"
    fi
  fi

  # Gate pass: only what blocks the build. Exit code 10 means findings; anything else non-zero is a scanner error.
  # No network: the database is already in the cache volume.
  rc=0
  trivy none --skip-db-update --format table --severity CRITICAL,HIGH --ignore-unfixed --exit-code 10 >/dev/null || rc=$?
  case $rc in
    0) ;;
    10) echo "FAIL: $image has Critical/High findings with a fix available (see the report above)." >&2; status=1 ;;
    *) echo "FAIL: scan error (not a finding) for $image, exit code $rc." >&2; status=1 ;;
  esac
done
exit $status
