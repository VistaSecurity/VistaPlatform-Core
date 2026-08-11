#!/bin/bash
# Retrieves the bootstrap CA certificate from the database.
# POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_HOST_PORT / POSTGRES_DB are
# exported by the deploy script; fall back to dev defaults if run standalone.
_PG_USER="${POSTGRES_USER:-crypto_user}"
_PG_PASS="${POSTGRES_PASSWORD:-crypto_pass_dev}"
_PG_PORT="${POSTGRES_HOST_PORT:-5432}"
_PG_DB="${POSTGRES_DB:-crypto_inventory}"
DB_URL="${DATABASE_URL:-postgres://${_PG_USER}:${_PG_PASS}@localhost:${_PG_PORT}/${_PG_DB}?sslmode=disable}"
psql "$DB_URL" -t -c "SELECT ca_cert_pem FROM platform_bootstrap_ca WHERE is_active = TRUE LIMIT 1" > bootstrap-ca-cert.pem
