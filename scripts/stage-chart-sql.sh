#!/usr/bin/env bash
# Stamp the schema hash into the chart.
#
#   scripts/stage-chart-sql.sh
#
# The chart does not carry schema.sql or seed.sql: Helm stores every
# chart file AND the rendered manifest in one release Secret, which Kubernetes
# caps at 1 MiB, and the two files (~1 MB each, in both halves) put the 5.1.0
# commercial chart over it. The SQL ships in the schema release image
# (scripts/database/Dockerfile) and the chart's Jobs copy it from there.
#
# What the chart needs at template time is the content hash of schema.sql:
# the schema-migration Job records it as the completion marker, every
# backend's wait-for-schema init container and the seed-data Job wait for
# that marker, and the Job refuses an image whose schema.sql hashes
# differently. This writes the full sha256 of scripts/database/schema.sql to
# charts/vistaplatform/files/schema/schema.sha256 (tracked, so a checkout
# renders; scripts/audit-schema-mirror.mjs fails `make audit` when it is
# stale) and removes any SQL a pre-5.1.1 checkout left under files/schema/.
# Both release workflows run it before `helm package`, so the shipped stamp
# is always derived from the tagged source. It is idempotent and leaves an
# up-to-date tree unchanged.
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-}" in
  "") ;;
  --strip-comments)
    echo "stage-chart-sql.sh: --strip-comments no longer exists — the SQL ships in the schema image, not the chart (#2731)" >&2
    exit 2 ;;
  *) echo "usage: $0" >&2; exit 2 ;;
esac

source_sql=scripts/database/schema.sql
test -s "$source_sql"
chart_sql_dir=${CHART_SQL_DIR:-charts/vistaplatform/files/schema}
mkdir -p "$chart_sql_dir"

hash=$(sha256sum "$source_sql" | cut -d' ' -f1)
[[ "$hash" =~ ^[0-9a-f]{64}$ ]] || { echo "stage-chart-sql.sh: could not hash $source_sql" >&2; exit 1; }
printf '%s\n' "$hash" > "$chart_sql_dir/schema.sha256"

# Pre-5.1.1 checkouts and `cp`-by-hand leave the SQL here; it would be
# packaged into the release record (charts/vistaplatform/.helmignore also
# refuses it, belt and braces).
rm -f "$chart_sql_dir/schema.sql" "$chart_sql_dir/seed.sql"

echo "stamped $chart_sql_dir/schema.sha256 = $hash (sha256 of $source_sql)"
