#!/bin/sh
# Grant LOGIN + a password to the RLS roles, so services connect as a role that
# row-level security actually applies to.
#
# The compose counterpart of the Helm chart's rls-roles Job
# (charts/vistaplatform/templates/jobs/rls-roles.yaml). schema.sql CREATEs the
# two roles NOLOGIN with no password, and grants them their privileges:
#
#   crypto_app    — NOBYPASSRLS, owns nothing. DATABASE_URL. Every
#                   tenant_isolation policy applies to it.
#   crypto_bypass — BYPASSRLS. BYPASS_DATABASE_URL. The annotated cross-tenant
#                   paths (ConnectBypass in shared/database).
#
# Without this step the services had to connect as the schema OWNER, and a
# table owner bypasses RLS: every policy in schema.sql was inert under compose.
#
# Runs as the owner (POSTGRES_USER — only it can ALTER another role), from the
# one-shot `db-roles` compose service on every `docker compose up`, which is
# what makes it work on BOTH a fresh volume and an existing one: Postgres runs
# docker-entrypoint-initdb.d scripts only when the volume is first created, so
# an init script alone would never reach a database that already exists.
# Idempotent — ALTER ROLE ... LOGIN PASSWORD can be re-run any number of times,
# and re-running it picks up a changed POSTGRES_PASSWORD.
#
# The password is the owner's POSTGRES_PASSWORD, exactly as the chart reuses
# its postgres-password. It is read inside psql with \getenv, so it never
# appears in a command line or in the SQL text.
#
# Environment (libpq): PGHOST PGPORT PGUSER PGDATABASE PGPASSWORD.
# Optional: DB_ROLES_WAIT_SECONDS (default 600) — how long to wait for Postgres
# to accept TCP connections. On a fresh volume that is only after schema.sql and
# seed.sql have been applied: the image's init server listens on a local socket
# only, so a TCP connection succeeding means initialisation is over.
set -eu

ROLE_APP=crypto_app
ROLE_BYPASS=crypto_bypass
WAIT_SECONDS="${DB_ROLES_WAIT_SECONDS:-600}"

: "${PGHOST:?PGHOST is required}"
: "${PGUSER:?PGUSER is required}"
: "${PGDATABASE:?PGDATABASE is required}"
: "${PGPASSWORD:?PGPASSWORD is required (POSTGRES_PASSWORD in .env)}"

schema_hint() {
  cat >&2 <<EOF
This database was created from a schema.sql that predates the RLS roles, or its
grants are incomplete. Re-apply the current schema (idempotent; keeps your data):

  docker compose exec -T postgres psql -U ${PGUSER} -d ${PGDATABASE} \\
    -v ON_ERROR_STOP=1 -f /docker-entrypoint-initdb.d/01-schema.sql

then run 'docker compose up -d' again. Or start over with 'make db-reset'
(destroys data).
EOF
}

echo "db-roles: waiting for Postgres at ${PGHOST}:${PGPORT:-5432} (up to ${WAIT_SECONDS}s)..."
waited=0
until pg_isready -q; do
  if [ "$waited" -ge "$WAIT_SECONDS" ]; then
    echo "db-roles: Postgres did not accept connections within ${WAIT_SECONDS}s" >&2
    exit 1
  fi
  sleep 2
  waited=$((waited + 2))
done
# pg_isready can report ready a moment before the database itself accepts a
# session, so wait for a real query too — but give up at once on an error that
# waiting cannot fix (a wrong password is the usual one: Postgres keeps the
# POSTGRES_PASSWORD it was created with, whatever .env says now).
until err=$(psql -tAc 'SELECT 1' 2>&1 >/dev/null); do
  case "$err" in
    *"authentication failed"*|*"does not exist"*|*"no pg_hba.conf entry"*)
      echo "db-roles: cannot connect as ${PGUSER} to ${PGDATABASE}: ${err}" >&2
      exit 1 ;;
  esac
  if [ "$waited" -ge "$WAIT_SECONDS" ]; then
    echo "db-roles: could not open a session as ${PGUSER} on ${PGDATABASE}: ${err}" >&2
    exit 1
  fi
  sleep 2
  waited=$((waited + 2))
done

present=$(psql -tAc "SELECT count(*) FROM pg_roles WHERE rolname IN ('${ROLE_APP}','${ROLE_BYPASS}')")
if [ "$present" != "2" ]; then
  echo "db-roles: roles ${ROLE_APP} / ${ROLE_BYPASS} do not exist." >&2
  schema_hint
  exit 1
fi

echo "db-roles: granting LOGIN + password to ${ROLE_APP} and ${ROLE_BYPASS}..."
# Script mode (stdin), not -c: psql only expands :'pw' in scripts.
psql -q -v ON_ERROR_STOP=1 <<EOF
\getenv pw PGPASSWORD
ALTER ROLE ${ROLE_APP}    LOGIN PASSWORD :'pw';
ALTER ROLE ${ROLE_BYPASS} LOGIN PASSWORD :'pw';
EOF

# Posture: the whole point is that crypto_app is subject to RLS. Refuse to
# report success if anything about the database would quietly undo that —
# the same properties shared/database's RLS integration tests assert.
posture=$(psql -tAF'|' <<EOF
SELECT
  (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = '${ROLE_APP}'),
  (SELECT rolbypassrls            FROM pg_roles WHERE rolname = '${ROLE_BYPASS}'),
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('public','audit') AND pg_get_userbyid(c.relowner) = '${ROLE_APP}'),
  has_table_privilege('${ROLE_APP}', 'public.tenants', 'SELECT'),
  has_table_privilege('${ROLE_BYPASS}', 'public.tenants', 'SELECT');
EOF
)
IFS='|' read -r app_bypasses bypass_bypasses app_owns app_reads bypass_reads <<EOF
$posture
EOF

if [ "$app_bypasses" != "f" ]; then
  echo "db-roles: ${ROLE_APP} is a superuser or has BYPASSRLS — RLS would not apply to it." >&2
  exit 1
fi
if [ "$app_owns" != "0" ]; then
  echo "db-roles: ${ROLE_APP} owns ${app_owns} table(s) in public/audit — an owner bypasses RLS." >&2
  exit 1
fi
if [ "$bypass_bypasses" != "t" ]; then
  echo "db-roles: ${ROLE_BYPASS} lacks BYPASSRLS — the cross-tenant paths would read nothing." >&2
  schema_hint
  exit 1
fi
if [ "$app_reads" != "t" ] || [ "$bypass_reads" != "t" ]; then
  echo "db-roles: the RLS roles have no privileges on public.tenants." >&2
  schema_hint
  exit 1
fi

echo "db-roles: ok — services connect as ${ROLE_APP} (RLS enforced) and ${ROLE_BYPASS} (cross-tenant paths)."
