#!/bin/bash
# Simple wrapper for building the crypto-sensor binary
# This script ensures the sensor directory exists and builds the binary

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SENSOR_DIR="$PROJECT_ROOT/sensor"
BIN_DIR="$PROJECT_ROOT/bin"
ARTIFACTS_DIR="$PROJECT_ROOT/artifacts/sensor"

echo -e "${BLUE}Building crypto-sensor...${NC}"

# Check if sensor directory exists
if [[ ! -d "$SENSOR_DIR" ]]; then
    echo -e "${RED}Error: Sensor directory not found at $SENSOR_DIR${NC}"
    echo "Please ensure the sensor directory exists with cmd/main.go"
    exit 1
fi

# Check if main.go exists
if [[ ! -f "$SENSOR_DIR/cmd/main.go" ]]; then
    echo -e "${RED}Error: Sensor main.go not found at $SENSOR_DIR/cmd/main.go${NC}"
    exit 1
fi

# Create bin directory if it doesn't exist
mkdir -p "$BIN_DIR"

# Build the sensor binary
echo -e "${BLUE}Building sensor binary...${NC}"
cd "$SENSOR_DIR"
CGO_ENABLED=1 go build -o "$BIN_DIR/crypto-sensor" cmd/main.go

if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}✅ Success: crypto-sensor built successfully${NC}"
    echo -e "${BLUE}Binary location: $BIN_DIR/crypto-sensor${NC}"
    
    # Show binary info
    if command -v file >/dev/null 2>&1; then
        echo -e "${BLUE}Binary info:${NC}"
        file "$BIN_DIR/crypto-sensor"
    fi
    
    if command -v ls >/dev/null 2>&1; then
        echo -e "${BLUE}Binary size:${NC}"
        ls -lh "$BIN_DIR/crypto-sensor"
    fi

    # Copy into artifacts tree for downloads
    echo -e "${BLUE}Placing binary into artifacts tree...${NC}"
    mkdir -p "$ARTIFACTS_DIR/linux/amd64"
    cp -f "$BIN_DIR/crypto-sensor" "$ARTIFACTS_DIR/linux/amd64/crypto-sensor"
    echo -e "${GREEN}✅ Artifacts updated at ${ARTIFACTS_DIR}${NC}"
else
    echo -e "${RED}❌ Error: Failed to build crypto-sensor${NC}"
    exit 1
fi
