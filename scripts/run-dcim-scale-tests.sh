#!/usr/bin/env bash
# Run the DCIM scale-fixture tests at Scale1 (DATA_MODEL §12: 50,000 assets,
# ...) against an ephemeral Postgres (needs Docker).
#
# A trimmed clone of run-integration-db-tests.sh: same postgres:17, same schema +
# seed + applied-SQL marker, but only shared/testdb/dcimfixture, with DCIM_SCALE=1.
# The budget report lands in $TEST_ARTIFACTS_DIR/dcim-budgets.json (default
# ./build/dcim-scale). Budgets are informative unless DCIM_BUDGETS=enforce, which
# the nightly job sets.
#
#   make test-dcim-scale
#   DCIM_BUDGETS=enforce make test-dcim-scale
set -euo pipefail
cd "$(dirname "$0")/.."

CONTAINER="${IT_PG_CONTAINER:-vista-dcim-scale-pg-$$}"
PW="postgres"
cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "▶ starting postgres:17 (container $CONTAINER) ..."
docker run -d --rm --name "$CONTAINER" -e POSTGRES_PASSWORD="$PW" -e POSTGRES_DB=test_db \
  -p 5432 postgres:17 >/dev/null
PORT="$(docker port "$CONTAINER" 5432/tcp | head -1 | sed 's/.*://')"
[ -n "$PORT" ] || { echo "could not determine the published host port for $CONTAINER" >&2; exit 1; }
for _ in $(seq 1 30); do
  docker exec "$CONTAINER" pg_isready -U postgres -d test_db >/dev/null 2>&1 && break
  sleep 1
done

echo "▶ applying schema.sql and seed.sql ..."
docker exec "$CONTAINER" psql -U postgres -d test_db -c 'CREATE ROLE crypto_user' >/dev/null 2>&1 || true
docker exec -i "$CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d test_db < scripts/database/schema.sql >/dev/null
docker exec -i "$CONTAINER" psql -U postgres -d test_db < scripts/database/seed.sql >/dev/null \
  || echo "Seed warnings — continuing (matches run-integration-db-tests.sh)"

# Record what was applied so the harness does not re-apply it (see
# run-integration-db-tests.sh and shared/testdb/applied_marker.go).
mark_applied() {
  local path="$1" sha
  sha="$(sha256sum "$path" | cut -d' ' -f1)"
  docker exec -i "$CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d test_db >/dev/null <<SQL
CREATE SCHEMA IF NOT EXISTS testdb_meta;
CREATE TABLE IF NOT EXISTS testdb_meta.applied_sql (
        path        text PRIMARY KEY,
        content_sha text NOT NULL,
        applied_at  timestamptz NOT NULL DEFAULT now());
INSERT INTO testdb_meta.applied_sql (path, content_sha) VALUES ('$path', '$sha')
  ON CONFLICT (path) DO UPDATE SET content_sha = EXCLUDED.content_sha, applied_at = now();
SQL
}
mark_applied scripts/database/schema.sql
mark_applied scripts/database/seed.sql

export TEST_DATABASE_URL="postgres://postgres:${PW}@localhost:${PORT}/test_db?sslmode=disable"
export DCIM_SCALE=1
export TEST_ARTIFACTS_DIR="${TEST_ARTIFACTS_DIR:-$PWD/build/dcim-scale}"
rm -f "$TEST_ARTIFACTS_DIR/dcim-budgets.json"

echo "▶ running DCIM scale tests (DCIM_SCALE=1, DCIM_BUDGETS=${DCIM_BUDGETS:-informative}) ..."
( cd shared && go test -v -count=1 -timeout 10m -run 'TestIntegration_DCIMFixture' ./testdb/dcimfixture/ )
# IPAM budgets (row 1.3): prefix tree, available IPs, find, write refresh.
( cd services/inventory-service && go test -v -count=1 -timeout 15m -run 'TestIntegration_IPAM_Budgets' ./internal/services/ )
echo "✓ report: $TEST_ARTIFACTS_DIR/dcim-budgets.json"
