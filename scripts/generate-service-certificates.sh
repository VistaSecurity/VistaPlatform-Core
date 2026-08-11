#!/bin/bash

# Generate Service Certificates for All Platform Services
# This script generates server and client certificates for all platform services
# using the platform service CA

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

echo -e "${BLUE}Generating Service Certificates for All Platform Services...${NC}"
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
    if ! psql "$DB_URL" -c "SELECT 1" >/dev/null 2>&1; then
        echo -e "${RED}Error: Cannot connect to database${NC}"
        exit 1
    fi
    DB_URL_HOST="$DB_URL"
else
    if ! docker exec "$DB_CONTAINER" psql -U ${POSTGRES_USER:-crypto_user} -d ${POSTGRES_DB:-crypto_inventory} -c "SELECT 1" >/dev/null 2>&1; then
        echo -e "${RED}Error: Cannot connect to database container${NC}"
        exit 1
    fi
    # Construct URL for host access
    POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
    POSTGRES_PORT="${POSTGRES_HOST_PORT:-5432}"
    if [ -n "$POSTGRES_USER" ] && [ -n "$POSTGRES_PASSWORD" ] && [ -n "$POSTGRES_DB" ]; then
        DB_URL_HOST="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}?sslmode=disable"
    else
        # Extract from DB_URL if it's a full URL
        DB_URL_HOST="$DB_URL"
    fi
fi

echo -e "${GREEN}✅ Database connection successful${NC}"

# List of all platform services (from service-registry.yaml)
SERVICES=(
    "auth-service"
    "inventory-service"
    "compliance-engine"
    "cbom-service"
    "sensor-manager"
    "admin-service"
    "monitoring-service"
    "resource-tracker-service"
    "tenant-health-service"
    "device-interrogation-service"
    "audit-service"
    "notification-service"
    "discovery-processor-service"
    "cluster-sensor-service"
    "pcap-processor"
    "mcp-service"
    "api-gateway"
)

# Create service-certs directory structure
mkdir -p ./service-certs

# Copy CA cert to each service directory (will be done at the end)
CA_CERT_PATH="./service-certs/platform-ca-cert.pem"
if [ ! -f "$CA_CERT_PATH" ]; then
    echo -e "${YELLOW}Warning: CA certificate not found at $CA_CERT_PATH${NC}"
    echo -e "${BLUE}Running generate-service-ca.sh first...${NC}"
    "$SCRIPT_DIR/generate-service-ca.sh"
fi

# Generate certificates for each service
TOTAL=${#SERVICES[@]}
CURRENT=0
FAILED=0

for SERVICE in "${SERVICES[@]}"; do
    CURRENT=$((CURRENT + 1))
    echo ""
    echo -e "${BLUE}[$CURRENT/$TOTAL] Generating certificates for ${SERVICE}...${NC}"

    # Create service directory
    SERVICE_DIR="./service-certs/${SERVICE}"
    mkdir -p "$SERVICE_DIR"

    # Generate certificates
    OUTPUT_FILE="/tmp/${SERVICE}-certs.txt"
    set +e
    if [ -n "$DB_CONTAINER" ]; then
        go run "$SCRIPT_DIR/initialize-service-ca.go" \
            -db-url "$DB_URL_HOST" \
            -encryption-key "$ENCRYPTION_KEY" \
            -action create-cert \
            -service-name "$SERVICE" > "$OUTPUT_FILE" 2>&1
        GO_RUN_STATUS=$?
    else
        go run "$SCRIPT_DIR/initialize-service-ca.go" \
            -db-url "$DB_URL" \
            -encryption-key "$ENCRYPTION_KEY" \
            -action create-cert \
            -service-name "$SERVICE" > "$OUTPUT_FILE" 2>&1
        GO_RUN_STATUS=$?
    fi
    set -e

    if [ $GO_RUN_STATUS -eq 0 ]; then
        # Extract certificates from output
        # Server certificate
        sed -n '/Server Certificate:/,/Server Key:/p' "$OUTPUT_FILE" | head -n -1 | tail -n +2 > "$SERVICE_DIR/server-cert.pem"
        # Server key
        sed -n '/Server Key:/,/Client Certificate:/p' "$OUTPUT_FILE" | head -n -1 | tail -n +2 > "$SERVICE_DIR/server-key.pem"
        # Client certificate
        sed -n '/Client Certificate:/,/Client Key:/p' "$OUTPUT_FILE" | head -n -1 | tail -n +2 > "$SERVICE_DIR/client-cert.pem"
        # Client key
        sed -n '/Client Key:/,$p' "$OUTPUT_FILE" | tail -n +2 > "$SERVICE_DIR/client-key.pem"

        # Copy CA cert to service directory
        cp "$CA_CERT_PATH" "$SERVICE_DIR/platform-ca-cert.pem"

        # Create symlinks for API gateway client certificates (gateway expects specific names)
        if [ "$SERVICE" = "api-gateway" ]; then
            if [ -f "$SERVICE_DIR/client-cert.pem" ] && [ ! -f "$SERVICE_DIR/api-gateway-client-cert.pem" ]; then
                ln -sf client-cert.pem "$SERVICE_DIR/api-gateway-client-cert.pem"
            fi
            if [ -f "$SERVICE_DIR/client-key.pem" ] && [ ! -f "$SERVICE_DIR/api-gateway-client-key.pem" ]; then
                ln -sf client-key.pem "$SERVICE_DIR/api-gateway-client-key.pem"
            fi
        fi

        # Set proper permissions - certs readable, private keys owner-only
        chmod 644 "$SERVICE_DIR"/*.pem
        chmod 600 "$SERVICE_DIR"/*-key.pem

        echo -e "${GREEN}✅ Certificates generated for ${SERVICE}${NC}"
        echo -e "   Server cert: $SERVICE_DIR/server-cert.pem"
        echo -e "   Server key:  $SERVICE_DIR/server-key.pem"
        echo -e "   Client cert: $SERVICE_DIR/client-cert.pem"
        echo -e "   Client key:  $SERVICE_DIR/client-key.pem"
    else
        echo -e "${RED}❌ Failed to generate certificates for ${SERVICE}${NC}"
        cat "$OUTPUT_FILE"
        FAILED=$((FAILED + 1))
    fi

    rm -f "$OUTPUT_FILE"
done

echo ""
echo -e "${BLUE}======================================"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All Service Certificates Generated Successfully${NC}"
    echo -e "${GREEN}   Total services: $TOTAL${NC}"
    echo -e "${GREEN}   Certificates location: ./service-certs/${NC}"
else
    echo -e "${RED}❌ Certificate Generation Completed with Errors${NC}"
    echo -e "${RED}   Successful: $((TOTAL - FAILED))${NC}"
    echo -e "${RED}   Failed: $FAILED${NC}"
    exit 1
fi
echo -e "${BLUE}======================================${NC}"
echo ""
