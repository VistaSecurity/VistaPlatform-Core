#!/bin/bash
# Test Database Initialization
# This script tests the database initialization improvements

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

# Load database validation functions
source scripts/database-validation.sh

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "🧪 Testing Database Initialization"
echo "=================================="
echo ""

# Detect docker compose command
if command -v docker-compose >/dev/null 2>&1; then
    DCMD="docker-compose"
else
    DCMD="docker compose"
fi

# Test 1: Check if Postgres is running
echo -e "${BLUE}Test 1: PostgreSQL Availability${NC}"
if check_postgres_ready "postgres" "crypto_user" "crypto_inventory"; then
    echo -e "${GREEN}  ✅ PostgreSQL is ready${NC}"
else
    echo -e "${RED}  ❌ PostgreSQL is not ready${NC}"
    echo -e "${YELLOW}     Start PostgreSQL: docker compose up -d postgres${NC}"
    exit 1
fi

# Test 2: Detect fresh vs existing database
echo -e "${BLUE}Test 2: Database State Detection${NC}"
if is_database_fresh "postgres" "crypto_user" "crypto_inventory"; then
    echo -e "${GREEN}  ✅ Fresh database detected${NC}"
else
    echo -e "${YELLOW}  ⚠️  Existing database detected${NC}"
fi

# Test 3: Check critical tables and columns
echo -e "${BLUE}Test 3: Critical Tables and Columns${NC}"
if check_critical_tables_and_columns "postgres" "crypto_user" "crypto_inventory"; then
    echo -e "${GREEN}  ✅ All critical tables and columns exist${NC}"
else
    echo -e "${RED}  ❌ Missing critical tables or columns${NC}"
    if [ ${#CRITICAL_MISSING_TABLES[@]} -gt 0 ]; then
        echo -e "${YELLOW}     Missing tables:${NC}"
        for table_info in "${CRITICAL_MISSING_TABLES[@]}"; do
            IFS=':' read -r table_name service_name description <<< "$table_info"
            echo -e "${YELLOW}       - $table_name ($service_name): $description${NC}"
        done
    fi
    if [ ${#CRITICAL_MISSING_COLUMNS[@]} -gt 0 ]; then
        echo -e "${YELLOW}     Missing columns:${NC}"
        for col_info in "${CRITICAL_MISSING_COLUMNS[@]}"; do
            IFS=':' read -r column_ref description <<< "$col_info"
            echo -e "${YELLOW}       - $column_ref: $description${NC}"
        done
    fi
fi

# Test 4: Verify seed data
echo -e "${BLUE}Test 4: Seed Data Verification${NC}"
if verify_seed_data "postgres" "crypto_user" "crypto_inventory"; then
    echo -e "${GREEN}  ✅ Seed data verified${NC}"
else
    echo -e "${RED}  ❌ Missing seed data${NC}"
    if [ ${#SEED_DATA_MISSING[@]} -gt 0 ]; then
        echo -e "${YELLOW}     Missing data:${NC}"
        for data_info in "${SEED_DATA_MISSING[@]}"; do
            IFS=':' read -r table_name issue <<< "$data_info"
            echo -e "${YELLOW}       - $table_name: $issue${NC}"
        done
    fi
fi

# Test 5: Comprehensive initialization validation
echo -e "${BLUE}Test 5: Comprehensive Initialization Validation${NC}"
if validate_database_initialization "postgres" "crypto_user" "crypto_inventory" 10; then
    echo -e "${GREEN}  ✅ Database initialization validation passed${NC}"
else
    echo -e "${RED}  ❌ Database initialization validation failed${NC}"
fi

echo ""
echo -e "${GREEN}✅ Database initialization tests complete${NC}"
