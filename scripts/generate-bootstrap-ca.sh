#!/bin/bash

# Generate Platform Bootstrap CA
# This script generates the platform-level bootstrap CA used for issuing
# bootstrap certificates to platform services

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Generating Platform Bootstrap CA...${NC}"
echo "======================================"
echo ""

# Source env file only if key variables are not already exported by the caller
# (e.g. deploy-ec2-smoke.sh exports them via "set -a; source .env.ec2-smoke; set +a").
# Sourcing .env here when running under deploy-ec2-smoke.sh would clobber the
# ec2-smoke secrets with dev credentials.
if [ -z "${POSTGRES_PASSWORD:-}" ]; then
    if [ -f ".env" ]; then
        set -a
        source .env
        set +a
    fi
fi

# Check for database URL — prefer DATABASE_URL, then build from individual vars,
# then fall back to dev defaults. POSTGRES_PASSWORD etc. are exported by the
# deploy script via "set -a; source .env.ec2-smoke; set +a".
if [ -n "$DATABASE_URL" ]; then
    DB_URL="$DATABASE_URL"
elif [ -n "$POSTGRES_USER" ] && [ -n "$POSTGRES_PASSWORD" ] && [ -n "$POSTGRES_DB" ]; then
    DB_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:${POSTGRES_HOST_PORT:-5432}/${POSTGRES_DB}?sslmode=disable"
else
    DB_URL="postgres://crypto_user:crypto_pass_dev@localhost:5432/crypto_inventory?sslmode=disable"
fi

# Check for encryption key
ENCRYPTION_KEY="${ENCRYPTION_MASTER_KEY:-}"
if [ -z "$ENCRYPTION_KEY" ]; then
    echo -e "${YELLOW}Error: ENCRYPTION_MASTER_KEY is required${NC}"
    echo -e "${RED}Error: ENCRYPTION_MASTER_KEY must be set. Generate one with: openssl rand -hex 32${NC}"
    exit 1
fi

# Check if Go is available
if ! command -v go >/dev/null 2>&1; then
    echo -e "${RED}Error: Go is required but not found${NC}"
    exit 1
fi

# Check if database is accessible
echo -e "${BLUE}Checking database connection...${NC}"
DB_CONTAINER=$(docker ps -q --filter "name=crypto-postgres" 2>/dev/null | head -1)
if [ -z "$DB_CONTAINER" ]; then
    echo -e "${YELLOW}Warning: Postgres container not found, using direct connection${NC}"
    # Try direct connection
    if ! psql "$DB_URL" -c "SELECT 1" >/dev/null 2>&1; then
        echo -e "${RED}Error: Cannot connect to database${NC}"
        exit 1
    fi
else
    # Use docker exec for connection check
    if ! docker exec "$DB_CONTAINER" psql -U ${POSTGRES_USER:-crypto_user} -d ${POSTGRES_DB:-crypto_inventory} -c "SELECT 1" >/dev/null 2>&1; then
        echo -e "${RED}Error: Cannot connect to database container${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✅ Database connection successful${NC}"

# Run Go program to create/bootstrap CA
echo -e "${BLUE}Creating/bootstrap CA...${NC}"
DB_URL_HOST="postgres://${POSTGRES_USER:-crypto_user}:${POSTGRES_PASSWORD:-crypto_pass_dev}@localhost:${POSTGRES_HOST_PORT:-5432}/${POSTGRES_DB:-crypto_inventory}?sslmode=disable"
go run "$SCRIPT_DIR/initialize-bootstrap-ca.go" \
    -db-url "$DB_URL_HOST" \
    -encryption-key "$ENCRYPTION_KEY" \
    -action create-ca

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Bootstrap CA created/retrieved successfully${NC}"
else
    echo -e "${RED}❌ Failed to create/bootstrap CA${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}======================================"
echo -e "✅ Platform Bootstrap CA Ready"
echo -e "======================================${NC}"
echo ""
