#!/usr/bin/env bash
# Run one hop of the vendor pipeline chain ( W0.2) and require that it
# actually RAN.
#
#   scripts/run-vendor-pipeline-hop.sh <module dir> <package> <test name>
#
# The hops are DB-integration tests: without TEST_DATABASE_URL they skip, and a
# skipped test still makes `go test` print `ok`. A PR gate built on that exit
# code alone would be a check that cannot fail — green on every PR the moment
# the database wiring broke. So this fails unless the named top-level test
# reported `--- PASS`.
#
# Used by the vendor-pipeline job in .github/workflows/ci.yml; the same command
# works locally against any Postgres with the schema and seed applied.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <module dir> <package> <test name>" >&2
  exit 2
fi
MODULE="$1"
PKG="$2"
TEST="$3"

if [ -z "${TEST_DATABASE_URL:-}" ]; then
  echo "❌ TEST_DATABASE_URL is not set: $TEST would skip, and a skipped hop proves nothing" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

set +e
( cd "$ROOT/$MODULE" && go test -count=1 -v -timeout 10m -run "^${TEST}\$" "$PKG" ) 2>&1 | tee "$LOG"
RC="${PIPESTATUS[0]}"
set -e

if [ "$RC" -ne 0 ]; then
  echo "❌ $TEST failed (go test exit $RC)" >&2
  exit "$RC"
fi
if ! grep -qE "^--- PASS: ${TEST} " "$LOG"; then
  echo "❌ $TEST did not report --- PASS (skipped, or matched nothing) — the hop did not run" >&2
  exit 1
fi
echo "✅ $TEST passed"
