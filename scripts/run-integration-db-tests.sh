#!/usr/bin/env bash
# Run the database-integration tests against an ephemeral Postgres (needs Docker).
#
# Spins up postgres:17, applies scripts/database/schema.sql, points TEST_DATABASE_URL
# at it, runs the integration tests, then tears the container down. This is the local
# mirror of what the nightly `test-backend` CI job does with its Postgres service.
#
#   make test-integration-db            # all DB-integration tests
#   GO_TEST_FLAGS="-run Resurface" make test-integration-db
set -euo pipefail
cd "$(dirname "$0")/.."

CONTAINER="vista-it-postgres"
PORT="${IT_PG_PORT:-55432}"
PW="postgres"

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "▶ starting postgres:17 on :$PORT ..."
docker run -d --rm --name "$CONTAINER" \
  -e POSTGRES_PASSWORD="$PW" -e POSTGRES_DB=test_db \
  -p "$PORT:5432" postgres:17 >/dev/null

echo "▶ waiting for postgres to accept connections ..."
for _ in $(seq 1 30); do
  if docker exec "$CONTAINER" pg_isready -U postgres -d test_db >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "▶ applying scripts/database/schema.sql ..."
# schema.sql's RLS role-split section references crypto_user (the role real
# deployments connect as); this ephemeral Postgres runs as `postgres`, so
# create the role first or the GRANT/ALTER DEFAULT PRIVILEGES statements fail.
docker exec "$CONTAINER" psql -U postgres -d test_db -c 'CREATE ROLE crypto_user' >/dev/null 2>&1 || true
docker exec -i "$CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d test_db < scripts/database/schema.sql >/dev/null

export TEST_DATABASE_URL="postgres://postgres:${PW}@localhost:${PORT}/test_db?sslmode=disable"
echo "▶ running DB-integration tests (TEST_DATABASE_URL set) ..."

# Keep this list in step with the nightly `test-backend` matrix. Nightly runs
# `go test ./...` per module with TEST_DATABASE_URL set, so it picks up every
# testdb-gated test automatically; this script names its targets explicitly and
# therefore silently misses new ones. shared/services was the first casualty —
# its edition-gate tests guard the paid-feature boundary and ran nightly only,
# so a developer following the documented local command never exercised them.
#
# The second casualty was: shared/entitlements and admin-service's
# entitlement tests are DB-backed but are NOT named Test*Integration*, so the
# `-run Integration` filter skipped them here while they failed in the nightly
# every night for a month. They are listed WITHOUT the filter below — the
# packages are entirely DB-backed, and the whole point of this script is to
# reproduce the nightly locally.
( cd services/compliance-engine && go test "${GO_TEST_FLAGS:--v}" -count=1 -run Integration ./internal/services/ )
( cd shared && go test "${GO_TEST_FLAGS:--v}" -count=1 -run Integration ./services/ )
# shared/database: real RLS enforcement under the non-owner app role, plus the
# grant-order guard. The latter creates its OWN throwaway database and applies
# schema.sql into it exactly ONCE — reusing this database would hide the very
# bug it guards, since the harness (and auth-service's bare blanket GRANT) have
# already patched the grants here. Ran nightly only until.
( cd shared && go test "${GO_TEST_FLAGS:--v}" -count=1 -run Integration ./database/ )
# cbom-service: the compliance-attestation builder reads RLS-policied
# compliance_findings, so its correctness is only observable against a real
# Postgres connected as the non-owner app role. Spelled `./...` rather than
# naming the package: the builder lives under ee/, which the public-tree export
# removes, so a named path would break `make test-integration-db` in Core — and
# `./...` also picks up future integration tests instead of silently missing them
# (the failure mode the comment above describes).
( cd services/cbom-service && go test "${GO_TEST_FLAGS:--v}" -count=1 -run Integration ./... )
# Credential encryption at rest. Each of these asserts on the RAW column
# bytes, which is the only way to catch an "encrypt" that returns its input —
# a round-trip test passes such a bug perfectly. Spelled ./... per the comment
# above so a new store's test is picked up without editing this list.
( cd services/notification-service && go test "${GO_TEST_FLAGS:--v}" -count=1 -run Integration ./... )
( cd services/monitoring-service && go test "${GO_TEST_FLAGS:--v}" -count=1 -run Integration ./... )
( cd services/cluster-sensor-service && go test "${GO_TEST_FLAGS:--v}" -count=1 -run Integration ./... )
( cd services/inventory-service && go test "${GO_TEST_FLAGS:--v}" -count=1 -run Integration ./... )
( cd services/admin-service && go test "${GO_TEST_FLAGS:--v}" -count=1 -run Integration ./... )
# auth-service: signup writes the tenants row every capacity gate then resolves
# against. The default-signup-tier tests are the regression for a tier-less
# tenant resolving max_sensors to the catalog default of 0 — a fresh install
# that could not register a sensor. Only reachable against a real Postgres with
# the seeded tier/entitlement catalog. `./...` per the comment above.
#
# -p 1: internal/api's connectAsBypassRole runs bare `GRANT ... ON ALL TABLES IN
# SCHEMA public`, which deadlocks against internal/auth's concurrent schema+seed
# apply. Unlike testdb's appliers it takes no advisory lock, so the two package
# binaries must not run at the same time.
( cd services/auth-service && go test "${GO_TEST_FLAGS:--v}" -count=1 -p 1 -run Integration ./... )

# sensor-manager: its repository resolves a sensor's owning tenant before every
# by-sensor-id read, which only behaves correctly when that one lookup runs on
# the BYPASSRLS handle and the rest run tenant-scoped. That distinction is
# invisible to the owner connection, so it is only observable here. The service
# was missing from this list entirely when the v0.5.0 RLS regression shipped —
# exactly the silent-omission failure the comment above describes.
( cd services/sensor-manager && go test "${GO_TEST_FLAGS:--v}" -count=1 -run Integration ./... )

( cd services/device-interrogation-service && go test "${GO_TEST_FLAGS:--v}" -count=1 -run Integration ./internal/services/ )
( cd services/monitoring-service && go test "${GO_TEST_FLAGS:--v}" -count=1 -run Integration ./internal/services/ )

( cd shared && go test "${GO_TEST_FLAGS:--v}" -count=1 ./entitlements/ )
( cd services/admin-service && go test "${GO_TEST_FLAGS:--v}" -count=1 ./internal/services/ )


echo "✓ integration tests passed"
