#!/usr/bin/env bash
# Stage SQL into the chart.
#
#   scripts/stage-chart-sql.sh                  byte-identical copies (local use)
#   scripts/stage-chart-sql.sh --strip-comments release packaging
#
# The tracked mirror charts/vistaplatform/files/schema/schema.sql is audited
# byte-identical to scripts/database/schema.sql (scripts/audit-schema-mirror.mjs),
# so the default copy leaves `git status` clean on an up-to-date tree and the
# chart's schema hash is the one a checkout renders. Only the release workflows
# pass --strip-comments, which drops whole-line SQL comments from the packaged
# copy: Helm stores both chart files and rendered ConfigMaps in each release
# Secret, and those comments were enough to push the release over Kubernetes'
# 1 MiB Secret limit at core-v1.0.0-rc.17. SQL statements and blank lines stay
# unchanged, and the migration Job hashes the exact SQL it applies. The stripped
# schema.sql dirties the tracked mirror, which is fine in a throwaway CI
# checkout; do not run --strip-comments in a worktree you intend to commit from.
set -euo pipefail
cd "$(dirname "$0")/.."

strip=0
case "${1:-}" in
  "") ;;
  --strip-comments) strip=1 ;;
  *) echo "usage: $0 [--strip-comments]" >&2; exit 2 ;;
esac

chart_sql_dir=${CHART_SQL_DIR:-charts/vistaplatform/files/schema}
mkdir -p "$chart_sql_dir"
for sql_kind in schema seed; do
  if [ "$strip" = 1 ]; then
    LC_ALL=C awk '$0 !~ /^[[:space:]]*--/' "scripts/database/$sql_kind.sql" > "$chart_sql_dir/$sql_kind.sql"
  else
    cp "scripts/database/$sql_kind.sql" "$chart_sql_dir/$sql_kind.sql"
  fi
  test -s "$chart_sql_dir/$sql_kind.sql"
done
