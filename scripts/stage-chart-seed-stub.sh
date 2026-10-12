#!/usr/bin/env bash
# Stage a STUB charts/vistaplatform/files/schema/seed.sql so chart render tests
# and `helm lint` run from a bare checkout.
#
# The chart refuses to render the seed-data Job when seed.sql is empty (an empty
# seed exits 0 and silently creates no platform admin). Release workflows put the
# real file there with scripts/stage-chart-sql.sh; a checkout does not have one.
# This writes a placeholder ONLY when no non-empty seed.sql exists, so it never
# overwrites a real staged file. The path is gitignored; never commit it and
# never `helm package` or install from a tree that carries only this stub.
set -euo pipefail
cd "$(dirname "$0")/.."
seed=charts/vistaplatform/files/schema/seed.sql
if [ ! -s "$seed" ]; then
  mkdir -p "$(dirname "$seed")"
  printf '%s\n' '-- STUB seed for chart render tests only (scripts/stage-chart-seed-stub.sh).' 'SELECT 1;' > "$seed"
fi
