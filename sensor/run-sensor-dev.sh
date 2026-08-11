#!/bin/bash
# Quick script to run sensor with dev configuration

# Default values
CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-http://localhost:8080}"
REGISTRATION_KEY="${REGISTRATION_KEY:-}"
INTERFACES="${INTERFACES:-eth0}"
DATA_PATH="${DATA_PATH:-$HOME/.crypto-sensor}"

# Create data directory if it doesn't exist
mkdir -p "$DATA_PATH"

echo "🚀 Starting Crypto Inventory Sensor (Dev Mode)"
echo "=============================================="
echo "Control Plane: $CONTROL_PLANE_URL"
echo "Registration Key: ${REGISTRATION_KEY:0:20}..." 
echo "Interfaces: $INTERFACES"
echo "Data Path: $DATA_PATH"
echo ""

# Export environment variables
export CONTROL_PLANE_URL
export REGISTRATION_KEY
export INTERFACES
export DATA_PATH
export REPORTING_INTERVAL="30s"
export ACTIVE_PROBING="true"
export NETWORK_DISCOVERY="true"

# Run sensor with registration
cd "$(dirname "$0")"
./crypto-sensor -verbose -register
