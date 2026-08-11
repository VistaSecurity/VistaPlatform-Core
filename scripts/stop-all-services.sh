#!/bin/bash

# Stop All Services Script
# This script stops all services including those with profiles

set -e

# Ensure we run from the repository root regardless of current working directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

echo "🛑 Stopping All Services"
echo "========================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to run command and report
run_command() {
    local description="$1"
    local command="$2"
    
    echo -e "${BLUE}Running:${NC} $description"
    if eval "$command"; then
        echo -e "${GREEN}✅ Success:${NC} $description"
        return 0
    else
        echo -e "${RED}❌ Failed:${NC} $description"
        return 1
    fi
}

# Detect Docker Compose command
if command -v docker-compose >/dev/null 2>&1; then
    DCMD="docker-compose"
else
    DCMD="docker compose"
fi

echo -e "${BLUE}Using Docker Compose command:${NC} $DCMD"

# Stop all services including those with profiles
echo -e "${BLUE}Stopping all services...${NC}"
run_command "Stop all services" "$DCMD --profile ai down"

echo ""
echo -e "${GREEN}🎉 All services stopped successfully!${NC}"
echo ""
echo -e "${YELLOW}Note:${NC} To start all services again, run:"
echo -e "  ./scripts/start-all-services.sh"
echo ""
echo -e "${YELLOW}Or to start only core services:${NC}"
echo -e "  ./scripts/session-init.sh"
