#!/usr/bin/env bash
# Stage SQL for release charts. The tracked schema mirror stays byte-identical
# to scripts/database/schema.sql; only the packaged copy drops whole-line SQL
# comments. Helm stores both chart files and rendered ConfigMaps in each release
# Secret, so those comments were enough to push the release over Kubernetes'
# 1 MiB Secret limit at core-v1.0.0-rc.17. SQL statements and blank lines stay
# unchanged, and the migration Job hashes the exact SQL it applies.
set -euo pipefail
cd "$(dirname "$0")/.."

chart_sql_dir=charts/vistaplatform/files/schema
mkdir -p "$chart_sql_dir"
for sql_kind in schema seed; do
  LC_ALL=C awk '$0 !~ /^[[:space:]]*--/' "scripts/database/$sql_kind.sql" > "$chart_sql_dir/$sql_kind.sql"
  test -s "$chart_sql_dir/$sql_kind.sql"
done
