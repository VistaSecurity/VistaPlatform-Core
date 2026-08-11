#!/bin/bash
# Start sensor and monitoring in one script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SENSOR_DIR="$PROJECT_ROOT/sensor"
LOG_DIR="/tmp/sensor-monitoring"

mkdir -p "$LOG_DIR"

echo -e "${BLUE}🚀 Starting Sensor with E2E Monitoring${NC}"
echo "=========================================="
echo ""

# Check if registration key is provided
if [ -z "$REGISTRATION_KEY" ]; then
    echo -e "${YELLOW}⚠️  No registration key provided${NC}"
    echo ""
    echo "To get a registration key:"
    echo "  1. Go to http://localhost:3000"
    echo "  2. Navigate to Sensors page"
    echo "  3. Click 'Register new sensor'"
    echo "  4. Fill in the form and click 'Generate Registration Key'"
    echo "  5. Copy the registration key"
    echo ""
    read -p "Enter your registration key (or press Enter to skip registration): " REG_KEY
    if [ -n "$REG_KEY" ]; then
        export REGISTRATION_KEY="$REG_KEY"
    else
        echo -e "${YELLOW}⚠️  Starting sensor without registration (test mode)${NC}"
        export REGISTRATION_KEY=""
    fi
fi

# Set default environment variables
export CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-http://localhost:8080}"
export INTERFACES="${INTERFACES:-eth0}"
export DATA_PATH="${DATA_PATH:-$HOME/.crypto-sensor}"
export REPORTING_INTERVAL="${REPORTING_INTERVAL:-30s}"
export ACTIVE_PROBING="${ACTIVE_PROBING:-true}"
export NETWORK_DISCOVERY="${NETWORK_DISCOVERY:-true}"

# Create data directory
mkdir -p "$DATA_PATH"

echo -e "${BLUE}📋 Configuration:${NC}"
echo "   Control Plane: $CONTROL_PLANE_URL"
if [ -n "$REGISTRATION_KEY" ]; then
    echo "   Registration Key: ${REGISTRATION_KEY:0:20}..."
else
    echo "   Registration Key: (none - test mode)"
fi
echo "   Interfaces: $INTERFACES"
echo "   Data Path: $DATA_PATH"
echo ""

# Check if sensor binary exists
if [ ! -f "$SENSOR_DIR/crypto-sensor" ]; then
    echo -e "${RED}❌ Sensor binary not found at $SENSOR_DIR/crypto-sensor${NC}"
    echo "   Please build the sensor first:"
    echo "   cd $SENSOR_DIR && go build -o crypto-sensor ./cmd"
    exit 1
fi

# Start monitoring script in background
echo -e "${BLUE}📊 Starting monitoring...${NC}"
"$SCRIPT_DIR/monitor-sensor-e2e.sh" > "$LOG_DIR/monitoring.log" 2>&1 &
MONITOR_PID=$!
echo "   Monitoring PID: $MONITOR_PID"
echo "   Monitoring log: $LOG_DIR/monitoring.log"
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}🛑 Shutting down...${NC}"
    
    # Kill sensor if running
    if [ -n "$SENSOR_PID" ]; then
        echo "   Stopping sensor (PID: $SENSOR_PID)..."
        kill "$SENSOR_PID" 2>/dev/null || true
        wait "$SENSOR_PID" 2>/dev/null || true
    fi
    
    # Kill monitor if running
    if [ -n "$MONITOR_PID" ]; then
        echo "   Stopping monitor (PID: $MONITOR_PID)..."
        kill "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✅ Cleanup complete${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start sensor
echo -e "${BLUE}🚀 Starting sensor...${NC}"
cd "$SENSOR_DIR"

if [ -n "$REGISTRATION_KEY" ]; then
    ./crypto-sensor -verbose -register > "$LOG_DIR/sensor.log" 2>&1 &
else
    ./crypto-sensor -test -verbose > "$LOG_DIR/sensor.log" 2>&1 &
fi

SENSOR_PID=$!
echo "   Sensor PID: $SENSOR_PID"
echo "   Sensor log: $LOG_DIR/sensor.log"
echo ""

# Wait a moment for sensor to start
sleep 2

# Check if sensor started successfully
if ! kill -0 "$SENSOR_PID" 2>/dev/null; then
    echo -e "${RED}❌ Sensor failed to start${NC}"
    echo "   Check logs: $LOG_DIR/sensor.log"
    tail -20 "$LOG_DIR/sensor.log"
    cleanup
    exit 1
fi

echo -e "${GREEN}✅ Sensor started successfully${NC}"
echo ""
echo -e "${BLUE}📊 Monitoring Status:${NC}"
echo "   • Sensor is running (PID: $SENSOR_PID)"
echo "   • Monitor is running (PID: $MONITOR_PID)"
echo "   • View sensor logs: tail -f $LOG_DIR/sensor.log"
echo "   • View monitoring: tail -f $LOG_DIR/monitoring.log"
echo ""
echo -e "${YELLOW}💡 Press Ctrl+C to stop sensor and monitoring${NC}"
echo ""

# Follow sensor logs
tail -f "$LOG_DIR/sensor.log"
