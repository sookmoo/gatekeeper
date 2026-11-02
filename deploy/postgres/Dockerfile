# Never built. Holds the Postgres image pin so Dependabot (docker ecosystem) proposes bumps and scan-latest scans it.
# The same digest must be in .github/workflows/ci.yml and deploy/quadlet/gatekeeper-db.container
# (scripts/check-pg-digest.sh fails CI if the three differ).
FROM docker.io/library/postgres:18-alpine@sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5
