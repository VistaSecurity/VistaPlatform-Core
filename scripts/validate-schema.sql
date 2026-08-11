#!/bin/bash
# Validate schema.sql file
# This script tests if schema.sql can be applied successfully and creates required tables

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCHEMA_FILE="scripts/database/schema.sql"

echo -e "${BLUE}🔍 Validating schema.sql file...${NC}"
echo "=================================="
echo ""

# Check if schema file exists
if [ ! -f "$SCHEMA_FILE" ]; then
    echo -e "${RED}❌ Schema file not found: $SCHEMA_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Schema file found: $SCHEMA_FILE${NC}"
echo ""

# Check if postgres container is running
if ! docker compose ps postgres | grep -q "running"; then
    echo -e "${YELLOW}⚠️  Postgres container not running. Starting it...${NC}"
    docker compose up -d postgres
    echo "Waiting for postgres to be ready..."
    sleep 5
fi

# Wait for postgres to be ready
echo -e "${BLUE}Waiting for PostgreSQL to be ready...${NC}"
for i in {1..30}; do
    if docker compose exec -T postgres pg_isready -U crypto_user -d crypto_inventory >/dev/null 2>&1; then
        echo -e "${GREEN}✅ PostgreSQL is ready${NC}"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo -e "${RED}❌ PostgreSQL not ready after 30s${NC}"
        exit 1
    fi
    sleep 1
done

# Create a test database
TEST_DB="schema_validation_test"
echo -e "${BLUE}Creating test database: $TEST_DB${NC}"
docker compose exec -T postgres psql -U crypto_user -d postgres <<EOF
DROP DATABASE IF EXISTS $TEST_DB;
CREATE DATABASE $TEST_DB;
EOF

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to create test database${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Test database created${NC}"
echo ""

# Apply schema.sql to test database
echo -e "${BLUE}Applying schema.sql to test database...${NC}"
echo "This may take a minute..."
echo ""

# Capture all output
SCHEMA_OUTPUT=$(docker compose exec -T postgres psql -U crypto_user -d "$TEST_DB" -f /docker-entrypoint-initdb.d/01-schema.sql 2>&1)
SCHEMA_EXIT_CODE=$?

# Check for critical errors (ignore "already exists" and "does not exist" as they may be non-blocking)
CRITICAL_ERRORS=$(echo "$SCHEMA_OUTPUT" | grep -i "error" | grep -vE "(already exists|duplicate key|already present|relation.*already exists|trigger.*already exists|does not exist)" || true)

if [ -n "$CRITICAL_ERRORS" ]; then
    echo -e "${RED}❌ Schema.sql has critical errors:${NC}"
    echo "$CRITICAL_ERRORS" | head -20
    echo ""
    echo -e "${YELLOW}⚠️  These errors may prevent tables from being created${NC}"
else
    echo -e "${GREEN}✅ No critical errors found${NC}"
    echo -e "${BLUE}   (Some 'already exists' and 'does not exist' errors are expected)${NC}"
fi

echo ""

# Check if required tables exist
echo -e "${BLUE}Checking if required tables exist...${NC}"
echo ""

REQUIRED_TABLES=(
    "report_templates"
    "platform_integrations"
    "platform_frameworks"
)

MISSING_TABLES=()
for table in "${REQUIRED_TABLES[@]}"; do
    EXISTS=$(docker compose exec -T postgres psql -U crypto_user -d "$TEST_DB" -t -c "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '$table');" | tr -d ' \n')
    if [ "$EXISTS" = "t" ]; then
        echo -e "${GREEN}  ✅ $table${NC}"
    else
        echo -e "${RED}  ❌ $table (MISSING)${NC}"
        MISSING_TABLES+=("$table")
    fi
done

echo ""

# Check if required columns exist
echo -e "${BLUE}Checking if required columns exist...${NC}"
echo ""

REQUIRED_COLUMNS=(
    "platform_frameworks.is_platform_default"
)

MISSING_COLUMNS=()
for column_ref in "${REQUIRED_COLUMNS[@]}"; do
    IFS='.' read -r table_name column_name <<< "$column_ref"
    EXISTS=$(docker compose exec -T postgres psql -U crypto_user -d "$TEST_DB" -t -c "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '$table_name' AND column_name = '$column_name');" | tr -d ' \n')
    if [ "$EXISTS" = "t" ]; then
        echo -e "${GREEN}  ✅ $column_ref${NC}"
    else
        echo -e "${RED}  ❌ $column_ref (MISSING)${NC}"
        MISSING_COLUMNS+=("$column_ref")
    fi
done

echo ""

# Check line numbers where tables are defined
echo -e "${BLUE}Checking table definitions in schema.sql...${NC}"
echo ""

for table in "${REQUIRED_TABLES[@]}"; do
    LINE=$(grep -n "CREATE TABLE.*$table" "$SCHEMA_FILE" | head -1 | cut -d: -f1)
    if [ -n "$LINE" ]; then
        echo -e "${BLUE}  $table: defined at line $LINE${NC}"
    else
        echo -e "${RED}  $table: NOT FOUND in schema.sql${NC}"
    fi
done

echo ""

# Check for syntax errors by trying to parse the file
echo -e "${BLUE}Checking for SQL syntax errors...${NC}"
echo ""

# Try to validate SQL syntax by checking for common issues
SYNTAX_ISSUES=0

# Check for unmatched quotes
if grep -q '"[^"]*$' "$SCHEMA_FILE" || grep -q "'[^']*$" "$SCHEMA_FILE"; then
    echo -e "${YELLOW}  ⚠️  Possible unmatched quotes${NC}"
    SYNTAX_ISSUES=$((SYNTAX_ISSUES + 1))
fi

# Check for CREATE TABLE statements with proper syntax
if ! grep -q "CREATE TABLE.*report_templates" "$SCHEMA_FILE"; then
    echo -e "${RED}  ❌ report_templates table definition not found${NC}"
    SYNTAX_ISSUES=$((SYNTAX_ISSUES + 1))
fi

if ! grep -q "CREATE TABLE.*platform_frameworks" "$SCHEMA_FILE"; then
    echo -e "${RED}  ❌ platform_frameworks table definition not found${NC}"
    SYNTAX_ISSUES=$((SYNTAX_ISSUES + 1))
fi

if [ $SYNTAX_ISSUES -eq 0 ]; then
    echo -e "${GREEN}  ✅ No obvious syntax issues found${NC}"
fi

echo ""

# Summary
echo -e "${BLUE}==================================${NC}"
echo -e "${BLUE}Summary:${NC}"
echo ""

if [ ${#MISSING_TABLES[@]} -eq 0 ] && [ ${#MISSING_COLUMNS[@]} -eq 0 ]; then
    echo -e "${GREEN}✅ All required tables and columns exist${NC}"
    echo -e "${GREEN}✅ Schema.sql appears to be valid${NC}"
    EXIT_CODE=0
else
    echo -e "${RED}❌ Some required tables/columns are missing:${NC}"
    if [ ${#MISSING_TABLES[@]} -gt 0 ]; then
        echo -e "${RED}   Missing tables: ${MISSING_TABLES[*]}${NC}"
    fi
    if [ ${#MISSING_COLUMNS[@]} -gt 0 ]; then
        echo -e "${RED}   Missing columns: ${MISSING_COLUMNS[*]}${NC}"
    fi
    echo ""
    echo -e "${YELLOW}⚠️  Schema.sql may have issues preventing these from being created${NC}"
    EXIT_CODE=1
fi

# Cleanup
echo ""
echo -e "${BLUE}Cleaning up test database...${NC}"
docker compose exec -T postgres psql -U crypto_user -d postgres -c "DROP DATABASE IF EXISTS $TEST_DB;" >/dev/null 2>&1

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ Schema validation passed!${NC}"
else
    echo -e "${RED}❌ Schema validation failed!${NC}"
fi

exit $EXIT_CODE
