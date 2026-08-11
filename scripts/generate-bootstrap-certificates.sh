#!/bin/bash

# Generate Bootstrap Certificates for Platform Services
# This script generates bootstrap certificates for cluster-sensor-service
# and device-interrogation-service using the platform bootstrap CA

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

echo -e "${BLUE}Generating Bootstrap Certificates for Platform Services...${NC}"
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
fi
DB_URL_HOST="postgres://${POSTGRES_USER:-crypto_user}:${POSTGRES_PASSWORD:-crypto_pass_dev}@localhost:${POSTGRES_HOST_PORT:-5432}/${POSTGRES_DB:-crypto_inventory}?sslmode=disable"

# Create certificates directory
CERT_DIR="${BOOTSTRAP_CERT_DIR:-./bootstrap-certs}"
mkdir -p "$CERT_DIR"

# Services to generate certificates for
SERVICES=("cluster-sensor-service" "device-interrogation-service")

for SERVICE in "${SERVICES[@]}"; do
    echo -e "${BLUE}Generating certificate for $SERVICE...${NC}"

    # Generate certificate using Go program
    OUTPUT=$(go run "$SCRIPT_DIR/initialize-bootstrap-ca.go" \
        -db-url "$DB_URL_HOST" \
        -encryption-key "$ENCRYPTION_KEY" \
        -action create-cert \
        -service-name "$SERVICE" 2>&1)

    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Failed to generate certificate for $SERVICE${NC}"
        echo "$OUTPUT"
        exit 1
    fi

    # Extract certificate and key from output
    # The Go program outputs the cert and key in PEM format
    CERT_PEM=$(echo "$OUTPUT" | sed -n '/Certificate PEM:/,/Private Key PEM:/p' | sed '/Private Key PEM:/d' | sed '1d')
    KEY_PEM=$(echo "$OUTPUT" | sed -n '/Private Key PEM:/,$p' | sed '1d')

    # Save certificate and key to files
    CERT_FILE="$CERT_DIR/${SERVICE}-cert.pem"
    KEY_FILE="$CERT_DIR/${SERVICE}-key.pem"
    CA_FILE="$CERT_DIR/${SERVICE}-ca-cert.pem"

    echo "$CERT_PEM" > "$CERT_FILE"
    echo "$KEY_PEM" > "$KEY_FILE"

    # Get CA certificate
    CA_OUTPUT=$(go run "$SCRIPT_DIR/initialize-bootstrap-ca.go" \
        -db-url "$DB_URL_HOST" \
        -encryption-key "$ENCRYPTION_KEY" \
        -action get-ca 2>&1 || echo "")

    # For now, we'll get the CA cert from the database in a separate step
    # Save a placeholder - the CA cert will be retrieved separately
    echo "# Bootstrap CA certificate will be retrieved from database" > "$CA_FILE"

    chmod 600 "$CERT_FILE" "$KEY_FILE"
    chmod 644 "$CA_FILE"

    echo -e "${GREEN}✅ Certificate generated for $SERVICE${NC}"
    echo -e "${BLUE}  Certificate: $CERT_FILE${NC}"
    echo -e "${BLUE}  Private Key: $KEY_FILE${NC}"
    echo -e "${BLUE}  CA Certificate: $CA_FILE${NC}"
done

# Get and save bootstrap CA certificate
echo -e "${BLUE}Retrieving bootstrap CA certificate...${NC}"
# We'll need to query the database for the CA cert
# For now, create a script to retrieve it
cat > "$CERT_DIR/get-ca-cert.sh" << 'EOF'
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
EOF
chmod +x "$CERT_DIR/get-ca-cert.sh"

echo ""
echo -e "${GREEN}======================================"
echo -e "✅ Bootstrap Certificates Generated"
echo -e "======================================${NC}"
echo ""
echo "Certificates saved to: $CERT_DIR"
echo ""
echo "Next steps:"
echo "  1. Review certificates in $CERT_DIR"
echo "  2. Update docker-compose.yml to mount certificate directory"
echo "  3. Configure services to use bootstrap certificates"
echo ""
