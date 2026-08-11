#!/bin/bash
# =================================================================
# Trigger Compliance Evaluation Events
# =================================================================
# This script compiles and runs the Go CLI tool to publish
# AssetChangedEvent events for demo tenant assets, triggering
# compliance evaluation to generate findings naturally.
#
# Usage: ./scripts/database/trigger-compliance-evaluation.sh
# =================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}Triggering Compliance Evaluation${NC}"
echo -e "${BLUE}==========================================${NC}"

# Check if Go is available
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed or not in PATH${NC}"
    exit 1
fi

# Check if NATS container is running
if ! docker ps --format '{{.Names}}' | grep -q "^crypto-nats$"; then
    echo -e "${YELLOW}⚠️  NATS container not running. Starting it...${NC}"
    docker compose up -d nats
    echo -e "${BLUE}Waiting for NATS to be ready...${NC}"
    sleep 5
fi

# Compile the Go tool
echo -e "${BLUE}Compiling trigger-compliance-evaluation tool...${NC}"
GO_TOOL="$SCRIPT_DIR/trigger-compliance-evaluation"
# Compile from script directory (has its own go.mod)
cd "$SCRIPT_DIR"
if ! go build -o "$GO_TOOL" trigger-compliance-evaluation.go; then
    echo -e "${RED}Failed to compile trigger-compliance-evaluation tool${NC}"
    exit 1
fi
cd "$ROOT_DIR"

# Load .env if it exists to get NATS port
if [ -f "$ROOT_DIR/.env" ]; then
    set -a
    source "$ROOT_DIR/.env"
    set +a
fi

# Set environment variables for database and NATS
export DATABASE_URL="${DATABASE_URL:-postgres://crypto_user:crypto_pass_dev@localhost:5432/crypto_inventory?sslmode=disable}"
# Use NATS_CLIENT_HOST_PORT from .env if available, otherwise default to 4222
NATS_PORT="${NATS_CLIENT_HOST_PORT:-4222}"
export NATS_URL="${NATS_URL:-nats://nats_user:nats_pass_dev@localhost:${NATS_PORT}}"

# Run the tool
echo -e "${BLUE}Publishing AssetChangedEvent events...${NC}"
if "$GO_TOOL" -wait -timeout 60s; then
    echo -e "${GREEN}✅ Compliance evaluation triggered successfully${NC}"
    rm -f "$GO_TOOL"  # Clean up compiled binary
else
    echo -e "${RED}❌ Failed to trigger compliance evaluation${NC}"
    rm -f "$GO_TOOL"  # Clean up compiled binary
    exit 1
fi

echo -e "${GREEN}==========================================${NC}"
