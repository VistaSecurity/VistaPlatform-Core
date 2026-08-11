#!/bin/bash

# Helper script to apply core seed data (seed.sql - now includes templates and frameworks) idempotently.
# This is intended to be called from session-init.sh and deployment scripts.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

source scripts/database-validation.sh

DCMD="${DCMD:-docker compose}"

echo -e "${BLUE}Applying core platform seed data (seed.sql - includes templates and frameworks)...${NC}"

if [ ! -f "scripts/database/seed.sql" ]; then
  echo -e "${YELLOW}⚠️  seed.sql not found - skipping core seed apply${NC}"
  exit 0
fi

# Get container name early (needed for validation)
actual_container=$(get_container_name "postgres")

if [ -z "$actual_container" ]; then
  echo -e "${RED}❌ Could not determine postgres container name${NC}"
  exit 1
fi

# Best-effort dependency validation for seed.sql; log issues but do not block.
if ! validate_seed_dependencies "seed.sql" "postgres" "crypto_user" "crypto_inventory"; then
  echo -e "${YELLOW}⚠️  seed.sql dependency validation reported issues (continuing; relying on schema.sql)${NC}"
fi

# CRITICAL: Validate measurement_types data exists before seeding frameworks
# Frameworks depend on specific measurement_type codes, and seed.sql will silently fail
# if these codes don't exist (DO blocks check for NULL and skip framework creation)
echo -e "${BLUE}   Validating measurement_types data exists...${NC}"
if ! validate_measurement_types_data "postgres" "crypto_user" "crypto_inventory"; then
  echo -e "${RED}❌ CRITICAL: Required measurement_types codes are missing!${NC}"
  echo -e "${YELLOW}   Framework seeding will fail. Checking if schema needs to be applied...${NC}"

  # Check if measurement_types table is empty
  local type_count=$(execute_sql "SELECT COUNT(*) FROM measurement_types;" "postgres" "crypto_user" "crypto_inventory" | tr -d ' ' || echo "0")
  if [ "$type_count" = "0" ] || [ -z "$type_count" ]; then
    echo -e "${YELLOW}   measurement_types table is empty - schema may not have been fully applied${NC}"
    echo -e "${YELLOW}   This is a critical issue. Framework seeding will fail silently.${NC}"
    echo -e "${YELLOW}   Consider re-applying scripts/database/schema.sql and restarting services${NC}"
  else
    echo -e "${YELLOW}   measurement_types table has $type_count entries but missing required codes${NC}"
  fi

  echo -e "${YELLOW}   Continuing with seed.sql, but frameworks may not be created.${NC}"
  echo -e "${YELLOW}   After seed completes, check framework count and re-run if needed.${NC}"
fi

# Apply core seed via stdin (more reliable than -f with copied files)
echo -e "${BLUE}   Applying seed.sql inside postgres container...${NC}"
# NOTE: Do not use ON_ERROR_STOP here; some measurement template inserts may fail
# due to optional foreign keys, but later DO blocks (platform frameworks) should
# still run successfully.
# Use stdin instead of -f to ensure proper handling of DO blocks
seed_result=$(docker exec -i "$actual_container" psql -U crypto_user -d crypto_inventory < scripts/database/seed.sql 2>&1 || true)

# Check for critical errors (EXCEPTION) vs warnings
if echo "$seed_result" | grep -qiE "exception|critical.*framework"; then
  echo -e "${RED}❌ CRITICAL ERROR: Framework seeding failed!${NC}"
  echo -e "${RED}   Framework creation cannot proceed without required dependencies${NC}"
  echo "$seed_result" | grep -iE "exception|critical" | head -10 | sed 's/^/     /'
  echo -e "${YELLOW}   Action required: Ensure schema.sql has been applied and measurement_types are populated${NC}"
  exit 1
elif echo "$seed_result" | grep -qiE "warning.*measurement_types|warning.*framework"; then
  echo -e "${YELLOW}⚠️  Warnings detected during framework seeding${NC}"
  echo "$seed_result" | grep -i "warning" | head -10 | sed 's/^/     /'
elif [ -z "$seed_result" ]; then
  echo -e "${GREEN}✅ Core seed applied (no output)${NC}"
elif echo "$seed_result" | grep -qiE "error.*(duplicate key|already exists)"; then
  echo -e "${GREEN}✅ Core seed applied (some data already existed - this is expected)${NC}"
elif echo "$seed_result" | grep -qi "error"; then
  echo -e "${YELLOW}⚠️  Core seed application completed with some errors (likely non-critical)${NC}"
  error_count=$(echo "$seed_result" | grep -ci "error" || echo "0")
  echo -e "${BLUE}   Found $error_count error(s) - showing up to 5:${NC}"
  echo "$seed_result" | grep -i "error" | head -5 | sed 's/^/     /'
else
  echo -e "${GREEN}✅ Core seed applied successfully${NC}"
fi

# Extract NOTICE messages (framework creation confirmations)
if echo "$seed_result" | grep -qi "notice.*framework created"; then
  echo -e "${BLUE}   Framework creation notices:${NC}"
  echo "$seed_result" | grep -i "notice.*framework" | sed 's/^/     /'
fi

# CRITICAL: Verify frameworks were actually created
echo -e "${BLUE}   Verifying frameworks were created...${NC}"
# Wait longer for transaction to commit and ensure consistency
sleep 3
# Force a connection refresh to see committed data
execute_sql "SELECT 1;" "postgres" "crypto_user" "crypto_inventory" >/dev/null 2>&1 || true
sleep 1
framework_count=$(execute_sql "SELECT COUNT(*) FROM platform_frameworks WHERE status = 'published';" "postgres" "crypto_user" "crypto_inventory" | tr -d ' ' || echo "0")

if [ "$framework_count" = "0" ] || [ -z "$framework_count" ]; then
  echo -e "${RED}❌ CRITICAL: No published frameworks found after seeding!${NC}"
  echo -e "${YELLOW}   This indicates framework creation failed silently${NC}"
  echo -e "${YELLOW}   Common causes:${NC}"
  echo -e "${YELLOW}     1. measurement_types table is empty or missing required codes${NC}"
  echo -e "${YELLOW}     2. Schema.sql was not fully applied${NC}"
  echo -e "${YELLOW}     3. DO blocks failed due to missing dependencies${NC}"
  echo -e "${BLUE}   Checking measurement_types...${NC}"
  mt_count=$(execute_sql "SELECT COUNT(*) FROM measurement_types;" "postgres" "crypto_user" "crypto_inventory" | tr -d ' ' || echo "0")
  if [ "$mt_count" = "0" ] || [ -z "$mt_count" ]; then
    echo -e "${RED}   ❌ measurement_types table is empty!${NC}"
    echo -e "${YELLOW}   Action: Ensure schema.sql has been applied${NC}"
  else
    echo -e "${BLUE}   measurement_types has $mt_count entries${NC}"
    # Check for specific required codes
    required_codes=("tls_version" "cert_expiration_days" "key_size" "symmetric_encryption")
    for code in "${required_codes[@]}"; do
      code_exists=$(execute_sql "SELECT COUNT(*) FROM measurement_types WHERE code = '$code';" "postgres" "crypto_user" "crypto_inventory" | tr -d ' ' || echo "0")
      if [ "$code_exists" = "0" ]; then
        echo -e "${RED}   ❌ Missing required code: $code${NC}"
      fi
    done
  fi
  exit 1
elif [ "$framework_count" -lt 5 ]; then
  echo -e "${YELLOW}⚠️  Only $framework_count of 5 expected frameworks created${NC}"
  echo -e "${YELLOW}   Some frameworks may have failed to create${NC}"
  echo -e "${BLUE}   Created frameworks:${NC}"
  execute_sql "SELECT code, name, version FROM platform_frameworks WHERE status = 'published' ORDER BY code;" "postgres" "crypto_user" "crypto_inventory" | sed 's/^/     /' || true
  exit 1
else
  echo -e "${GREEN}✅ Verified: $framework_count published framework(s) created${NC}"
  echo -e "${BLUE}   Frameworks:${NC}"
  execute_sql "SELECT code, name, version FROM platform_frameworks WHERE status = 'published' ORDER BY code;" "postgres" "crypto_user" "crypto_inventory" | sed 's/^/     /' || true
fi

# RBAC initialization (admin user + tenant roles for all tenants) is now consolidated into seed.sql
# and runs as part of Tier 1 seed. No separate ensure-rbac-initialization.sql step needed.

# Permission reconciliation (super_admin catch-all, platform.analytics) is now in schema.sql
# and runs at init. No separate critical-tables step needed.

exit 0
