#!/bin/bash

# Validate Compliance Logging Configuration
# Checks that all required environment variables and database schema are configured
# for compliance-centric logging with S3 storage and incident response hooks.
#
# Documentation:
#   - See docsv4/platform-admin-docs/monitoring/log-management.md for complete logging setup guide
#   - See docsv4/platform-admin-docs/monitoring/setup.md for monitoring and alerting configuration

set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Validating compliance logging configuration...${NC}"

# Check if we're in development mode
ENV="${ENV:-development}"
if [ "$ENV" = "development" ]; then
  echo -e "${YELLOW}⚠️  Development mode detected - using dummy values for S3 configuration${NC}"
  # Set dummy values if not already set
  export S3_LOG_BUCKET="${S3_LOG_BUCKET:-dev-logs-bucket}"
  export S3_REGION="${S3_REGION:-us-east-1}"
  export S3_KMS_KEY_ID="${S3_KMS_KEY_ID:-dev-kms-key-id}"
fi

missing=0

require_env() {
  local name="$1"
  local value="${!name:-}"
  if [ -z "$value" ]; then
    echo -e "${RED}❌ Missing ${name}${NC}"
    missing=$((missing + 1))
  else
    echo -e "${GREEN}✅ ${name}=${value}${NC}"
  fi
}

require_env "S3_LOG_BUCKET"
require_env "S3_REGION"
require_env "S3_KMS_KEY_ID"

if [ -n "${ENABLE_INCIDENT_HOOKS:-}" ]; then
  echo -e "${GREEN}✅ ENABLE_INCIDENT_HOOKS=${ENABLE_INCIDENT_HOOKS}${NC}"
else
  echo -e "${GREEN}✅ ENABLE_INCIDENT_HOOKS defaulting to true (set to false to disable hooks)${NC}"
fi

if [ -n "${LOG_RETENTION_INTERVAL_HOURS:-}" ]; then
  echo -e "${GREEN}✅ LOG_RETENTION_INTERVAL_HOURS=${LOG_RETENTION_INTERVAL_HOURS}${NC}"
else
  echo -e "${YELLOW}⚠️  LOG_RETENTION_INTERVAL_HOURS not set (defaults to 24)${NC}"
fi

if [ "$missing" -gt 0 ]; then
  echo -e "${RED}Compliance logging env configuration incomplete${NC}"
  exit 1
fi

if command -v psql >/dev/null 2>&1 && [ -n "${DATABASE_URL:-}" ]; then
  echo -e "${BLUE}Checking database schema for logging tables...${NC}"
  psql "$DATABASE_URL" <<'SQL'
SELECT 'platform_log_metadata' AS table, to_regclass('public.platform_log_metadata') IS NOT NULL AS exists
UNION ALL
SELECT 'platform_log_access_audit', to_regclass('public.platform_log_access_audit') IS NOT NULL
UNION ALL
SELECT 'platform_log_retention_jobs', to_regclass('public.platform_log_retention_jobs') IS NOT NULL;
SQL
else
  echo -e "${YELLOW}⚠️  DATABASE_URL or psql not available; skipping schema validation${NC}"
fi

echo -e "${GREEN}Compliance logging validation complete${NC}"
