#!/bin/bash

# Generate Platform Service CA
# This script generates the platform-level service CA used for issuing
# mTLS certificates to all platform services

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

echo -e "${BLUE}Generating Platform Service CA...${NC}"
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
    elif [ -f ".env.ec2-smoke" ]; then
        set -a
        source .env.ec2-smoke
        set +a
    fi
fi

# Check for database URL - use DATABASE_URL from environment if available
if [ -n "$DATABASE_URL" ]; then
    DB_URL="$DATABASE_URL"
elif [ -n "$POSTGRES_USER" ] && [ -n "$POSTGRES_PASSWORD" ] && [ -n "$POSTGRES_DB" ]; then
    # Construct from individual components
    POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
    POSTGRES_PORT="${POSTGRES_HOST_PORT:-5432}"
    DB_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}?sslmode=disable"
else
    # Fallback to default (development only)
    DB_URL="postgres://crypto_user:crypto_pass_dev@localhost:5432/crypto_inventory?sslmode=disable"
    echo -e "${YELLOW}Warning: Using default database URL (development only)${NC}"
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
    # Use docker exec for connection
    if ! docker exec "$DB_CONTAINER" psql -U ${POSTGRES_USER:-crypto_user} -d ${POSTGRES_DB:-crypto_inventory} -c "SELECT 1" >/dev/null 2>&1; then
        echo -e "${RED}Error: Cannot connect to database container${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✅ Database connection successful${NC}"

# Run Go program to create/bootstrap CA
echo -e "${BLUE}Creating/bootstrap service CA...${NC}"
set +e
if [ -n "$DB_CONTAINER" ]; then
    # If using docker, construct URL for host access
    POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
    POSTGRES_PORT="${POSTGRES_HOST_PORT:-5432}"
    if [ -n "$POSTGRES_USER" ] && [ -n "$POSTGRES_PASSWORD" ] && [ -n "$POSTGRES_DB" ]; then
        DB_URL_HOST="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}?sslmode=disable"
    else
        # Extract from DB_URL if it's a full URL
        DB_URL_HOST="$DB_URL"
    fi
    go run "$SCRIPT_DIR/initialize-service-ca.go" \
        -db-url "$DB_URL_HOST" \
        -encryption-key "$ENCRYPTION_KEY" \
        -action create-ca > /tmp/service-ca-output.txt 2>&1
    GO_RUN_STATUS=$?
else
    go run "$SCRIPT_DIR/initialize-service-ca.go" \
        -db-url "$DB_URL" \
        -encryption-key "$ENCRYPTION_KEY" \
        -action create-ca > /tmp/service-ca-output.txt 2>&1
    GO_RUN_STATUS=$?
fi
set -e

if [ $GO_RUN_STATUS -eq 0 ]; then
    echo -e "${GREEN}✅ Service CA created/retrieved successfully${NC}"
    # Extract CA cert from output
    mkdir -p ./service-certs
    CA_CERT=$(awk 'found {print} /CA Certificate:/ {found=1}' /tmp/service-ca-output.txt)
    if [ -z "$CA_CERT" ]; then
        echo -e "${RED}❌ Failed to extract CA certificate from output${NC}"
        cat /tmp/service-ca-output.txt
        rm -f /tmp/service-ca-output.txt
        exit 1
    fi
    echo "$CA_CERT" > ./service-certs/platform-ca-cert.pem
    chmod 644 ./service-certs/platform-ca-cert.pem
    echo -e "${GREEN}✅ CA certificate saved to ./service-certs/platform-ca-cert.pem${NC}"
    rm -f /tmp/service-ca-output.txt
else
    echo -e "${RED}❌ Failed to create/bootstrap service CA${NC}"
    cat /tmp/service-ca-output.txt
    rm -f /tmp/service-ca-output.txt
    exit 1
fi

echo ""
echo -e "${GREEN}======================================"
echo -e "✅ Platform Service CA Ready"
echo -e "======================================${NC}"
echo ""
