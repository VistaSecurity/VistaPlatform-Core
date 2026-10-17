#!/usr/bin/env bash
# Print a NORMALISED schema dump of a schema.sql (+ seed.sql), for diffing two
# versions of the file against each other.
#
# Why this exists: the 5.0.0 re-baseline (asset-inventory ADR-0010 D11) folds
# twenty-odd thousand lines of migration residue — ADD COLUMNs, enum ADD
# VALUEs, DROP/CREATE policy pairs, repeated CREATE OR REPLACEs — into the
# objects they modify. Reading the SQL cannot prove such a refactor; what the
# database ends up containing can. So: apply each file to a fresh Postgres 17,
# dump the result, strip what legitimately differs between two equivalent files
# (comments, SET lines, pg_dump's restrict keys, the order objects were
# created in), and diff.
#
#   scripts/database/tools/schema-normalised-dump.sh [opts] SCHEMA.sql [SEED.sql] > out.dump
#   diff before.dump after.dump
#
# Options:
#   --privileges   keep GRANT / ALTER DEFAULT PRIVILEGES (pg_dump without
#                  --no-privileges). The RLS role split lives in grants, so a
#                  re-baseline must diff clean with this on too.
#   --data         append a normalised data section: every table's rows from
#                  pg_dump --data-only, with UUIDs and timestamps masked and the
#                  lines sorted, plus per-table row counts. Proves that seed rows
#                  a schema change moved between files still arrive.
#   --twice        apply SCHEMA a second time (ON_ERROR_STOP=1) after the seed,
#                  before dumping; fails if the re-apply errors.
#   --keep         leave the container running and print its name on stderr.
#
# The dump is per-object: pg_dump's "-- Name: X; Type: T; Schema: S" headers
# delimit entries, each entry becomes one block keyed "Type|Schema|Name", and
# the blocks are sorted by key. Inside a block the text is pg_dump's own
# (column order, defaults, enum label order, function bodies, policy
# expressions are all significant and all kept); only trailing whitespace and
# blank-line runs are normalised. Global roles are not in pg_dump, so their
# attributes are appended from pg_roles.
#
# Needs Docker. The container is per-invocation (PID-suffixed) and removed on
# exit, so concurrent runs cannot collide.
set -euo pipefail

PRIVS=0 DATA=0 TWICE=0 KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --privileges) PRIVS=1 ;;
    --data) DATA=1 ;;
    --twice) TWICE=1 ;;
    --keep) KEEP=1 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    --*) echo "unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
  shift
done
SCHEMA="${1:?usage: $0 [--privileges] [--data] [--twice] SCHEMA.sql [SEED.sql]}"
SEED="${2:-}"
[ -f "$SCHEMA" ] || { echo "no such file: $SCHEMA" >&2; exit 2; }
[ -z "$SEED" ] || [ -f "$SEED" ] || { echo "no such file: $SEED" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${SCHEMA_DUMP_PG_IMAGE:-postgres:17}"
C="vista-schema-dump-$$"
cleanup() { [ "$KEEP" = 1 ] || docker rm -f "$C" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --rm --name "$C" -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=dump_db "$IMAGE" >/dev/null
for _ in $(seq 1 60); do
  # pg_isready on the socket succeeds during the image's init phase too; wait
  # for the post-init server (it is the one that accepts TCP).
  if docker exec "$C" pg_isready -h 127.0.0.1 -U postgres -d dump_db >/dev/null 2>&1; then break; fi
  sleep 1
done
[ "$KEEP" = 1 ] && echo "container: $C" >&2

psql_file() { # $1 file, $2 on_error_stop(0/1)
  local stop=()
  [ "$2" = 1 ] && stop=(-v ON_ERROR_STOP=1)
  docker exec -i "$C" psql -X -q "${stop[@]}" -U postgres -d dump_db < "$1"
}

# schema.sql's RLS section grants to crypto_user, the role real deployments
# run as; create it exactly as scripts/run-integration-db-tests.sh does.
docker exec "$C" psql -X -q -U postgres -d dump_db -c 'CREATE ROLE crypto_user' >/dev/null

LOG="$(mktemp)"; trap 'rm -f "$LOG"; cleanup' EXIT
if ! psql_file "$SCHEMA" 1 >"$LOG" 2>&1; then
  echo "schema apply FAILED:" >&2; grep -m20 ERROR "$LOG" >&2 || tail -20 "$LOG" >&2; exit 1
fi
if grep -q 'ERROR' "$LOG"; then echo "schema apply printed ERROR lines:" >&2; grep ERROR "$LOG" >&2; exit 1; fi
if [ -n "$SEED" ]; then
  # Seed runs WITHOUT ON_ERROR_STOP, as the chart's seed-data Job and the
  # nightly do; but any ERROR line is still reported, because on a fresh
  # database the seed has no business raising one.
  psql_file "$SEED" 0 >"$LOG" 2>&1 || true
  if grep -q 'ERROR' "$LOG"; then echo "seed apply printed ERROR lines:" >&2; grep -A2 ERROR "$LOG" >&2; exit 1; fi
fi
if [ "$TWICE" = 1 ]; then
  if ! psql_file "$SCHEMA" 1 >"$LOG" 2>&1; then
    echo "schema RE-apply FAILED:" >&2; grep -m20 -A3 ERROR "$LOG" >&2 || tail -20 "$LOG" >&2; exit 1
  fi
fi

DUMP_FLAGS=(--schema-only --no-owner)
[ "$PRIVS" = 1 ] || DUMP_FLAGS+=(--no-privileges)
docker exec "$C" pg_dump "${DUMP_FLAGS[@]}" -U postgres -d dump_db | node "$HERE/normalise-pg-dump.mjs" schema

echo "-- ===== ROLES"
docker exec "$C" psql -X -At -U postgres -d dump_db -c "
  SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolbypassrls
    FROM pg_roles WHERE rolname !~ '^pg_' AND rolname <> 'postgres' ORDER BY rolname"

if [ "$DATA" = 1 ]; then
  echo "-- ===== DATA"
  docker exec "$C" pg_dump --data-only --no-owner -U postgres -d dump_db 2>/dev/null | node "$HERE/normalise-pg-dump.mjs" data
fi
