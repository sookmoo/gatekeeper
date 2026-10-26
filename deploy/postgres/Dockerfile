# Never built. Holds the Postgres image pin so Dependabot (docker ecosystem) proposes bumps and scan-latest scans it.
# The same digest must be in .github/workflows/ci.yml and deploy/quadlet/gatekeeper-db.container
# (scripts/check-pg-digest.sh fails CI if the three differ).
FROM docker.io/library/postgres:17-alpine@sha256:aa90e97ee862e558111d34cfb8b2c4bec768c2b039fb791341686928560263b3
