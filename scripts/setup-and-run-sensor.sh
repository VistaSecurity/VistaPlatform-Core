#!/bin/bash
# Complete setup and run script for sensor with full monitoring

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SENSOR_DIR="$PROJECT_ROOT/sensor"
LOG_DIR="/tmp/sensor-monitoring"

mkdir -p "$LOG_DIR"

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Crypto Inventory Sensor - Complete E2E Setup & Monitor  ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Step 1: Check prerequisites
echo -e "${BLUE}📋 Step 1: Checking prerequisites...${NC}"
if [ ! -f "$SENSOR_DIR/crypto-sensor" ]; then
    echo -e "${RED}❌ Sensor binary not found${NC}"
    echo "   Building sensor..."
    cd "$SENSOR_DIR"
    if ! go build -o crypto-sensor ./cmd; then
        echo -e "${RED}❌ Failed to build sensor${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Sensor built successfully${NC}"
fi

# Check if platform is running
if ! curl -s -f "http://localhost:8080/api/v1/health" > /dev/null 2>&1; then
    echo -e "${RED}❌ Platform is not running${NC}"
    echo "   Please start the platform first:"
    echo "   ./start-session.sh"
    exit 1
fi
echo -e "${GREEN}✅ Platform is running${NC}"
echo ""

# Step 2: Generate registration key
echo -e "${BLUE}📋 Step 2: Registration Key Setup${NC}"
echo ""

if [ -n "$REGISTRATION_KEY" ]; then
    echo -e "${GREEN}✅ Using registration key from environment${NC}"
    REGISTER_MODE="true"
else
    echo "You have two options:"
    echo "  1) Generate a registration key via the UI (recommended)"
    echo "  2) Use test mode (no registration required)"
    echo ""
    read -p "Generate registration key via UI? (y/n, default: y): " USE_UI

    if [ "${USE_UI:-y}" = "y" ] || [ "${USE_UI:-y}" = "Y" ]; then
        echo ""
        echo -e "${YELLOW}📝 To generate a registration key:${NC}"
        echo "  1. Open http://localhost:3000 in your browser"
        echo "  2. Navigate to the Sensors page"
        echo "  3. Click 'Register new sensor'"
        echo "  4. Fill in:"
        echo "     - Name: Local Dev Sensor"
        echo "     - Description: Sensor for E2E testing"
        echo "     - IP Address: 127.0.0.1"
        echo "     - Profile: standard"
        echo "     - Network Interfaces: eth0"
        echo "  5. Click 'Generate Registration Key'"
        echo "  6. Copy the registration key"
        echo ""
        read -p "Enter your registration key (or press Enter for test mode): " REG_KEY
        
        if [ -n "$REG_KEY" ]; then
            export REGISTRATION_KEY="$REG_KEY"
            REGISTER_MODE="true"
            echo -e "${GREEN}✅ Registration key set${NC}"
        else
            REGISTER_MODE="false"
            echo -e "${YELLOW}⚠️  Using test mode (no registration)${NC}"
        fi
    else
        REGISTER_MODE="false"
        echo -e "${YELLOW}⚠️  Using test mode${NC}"
    fi
fi
echo ""

# Step 3: Configure sensor
echo -e "${BLUE}📋 Step 3: Configuring sensor...${NC}"
export CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-http://localhost:8080}"
export INTERFACES="${INTERFACES:-eth0}"
export DATA_PATH="${DATA_PATH:-$HOME/.crypto-sensor}"
export REPORTING_INTERVAL="${REPORTING_INTERVAL:-30s}"
export ACTIVE_PROBING="${ACTIVE_PROBING:-true}"
export NETWORK_DISCOVERY="${NETWORK_DISCOVERY:-true}"

mkdir -p "$DATA_PATH"

echo "   Control Plane: $CONTROL_PLANE_URL"
echo "   Interfaces: $INTERFACES"
echo "   Data Path: $DATA_PATH"
echo "   Registration: $([ "$REGISTER_MODE" = "true" ] && echo "Yes" || echo "No (test mode)")"
echo -e "${GREEN}✅ Configuration complete${NC}"
echo ""

# Step 4: Start monitoring
echo -e "${BLUE}📋 Step 4: Starting monitoring...${NC}"
"$SCRIPT_DIR/monitor-sensor-e2e.sh" > "$LOG_DIR/monitoring.log" 2>&1 &
MONITOR_PID=$!
echo "   Monitor PID: $MONITOR_PID"
echo "   Monitor log: $LOG_DIR/monitoring.log"
echo -e "${GREEN}✅ Monitoring started${NC}"
echo ""

# Step 5: Start sensor
echo -e "${BLUE}📋 Step 5: Starting sensor...${NC}"
cd "$SENSOR_DIR"

if [ "$REGISTER_MODE" = "true" ]; then
    echo "   Starting with registration..."
    ./crypto-sensor -verbose -register > "$LOG_DIR/sensor.log" 2>&1 &
else
    echo "   Starting in test mode..."
    ./crypto-sensor -test -verbose > "$LOG_DIR/sensor.log" 2>&1 &
fi

SENSOR_PID=$!
echo "   Sensor PID: $SENSOR_PID"
echo "   Sensor log: $LOG_DIR/sensor.log"

# Wait for sensor to start
sleep 3

if ! kill -0 "$SENSOR_PID" 2>/dev/null; then
    echo -e "${RED}❌ Sensor failed to start${NC}"
    echo "   Last 20 lines of sensor log:"
    tail -20 "$LOG_DIR/sensor.log"
    kill "$MONITOR_PID" 2>/dev/null || true
    exit 1
fi

echo -e "${GREEN}✅ Sensor started successfully${NC}"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}🛑 Shutting down...${NC}"
    
    if [ -n "$SENSOR_PID" ] && kill -0 "$SENSOR_PID" 2>/dev/null; then
        echo "   Stopping sensor (PID: $SENSOR_PID)..."
        kill "$SENSOR_PID" 2>/dev/null || true
        wait "$SENSOR_PID" 2>/dev/null || true
    fi
    
    if [ -n "$MONITOR_PID" ] && kill -0 "$MONITOR_PID" 2>/dev/null; then
        echo "   Stopping monitor (PID: $MONITOR_PID)..."
        kill "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✅ Cleanup complete${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Display status
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    🚀 System Running                       ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}✅ Sensor is running${NC} (PID: $SENSOR_PID)"
echo -e "${GREEN}✅ Monitor is running${NC} (PID: $MONITOR_PID)"
echo ""
echo -e "${BLUE}📊 View logs:${NC}"
echo "   • Sensor:    tail -f $LOG_DIR/sensor.log"
echo "   • Monitor:   tail -f $LOG_DIR/monitoring.log"
echo ""
echo -e "${BLUE}📈 Monitor output:${NC}"
echo "   The monitor will show:"
echo "   • Sensor registration status"
echo "   • Discovery counts"
echo "   • Data ingestion status"
echo "   • Classification status"
echo ""
echo -e "${YELLOW}💡 Press Ctrl+C to stop sensor and monitoring${NC}"
echo ""

# Show sensor logs
tail -f "$LOG_DIR/sensor.log"
