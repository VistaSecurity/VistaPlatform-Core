#!/bin/bash

# Quick Health Check Script
# Checks health of all services

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok() { echo -e "${GREEN}✅${NC} $1"; }
warn() { echo -e "${YELLOW}⚠️${NC} $1"; }
err() { echo -e "${RED}❌${NC} $1"; }

# Service port mappings
declare -A SERVICES=(
    ["auth-service"]="8081"
    ["inventory-service"]="8082"
    ["compliance-engine"]="8083"
    ["cbom-service"]="8084"
    ["sensor-manager"]="8085"
    ["admin-service"]="8089"
    ["monitoring-service"]="8091"
    ["cluster-sensor-service"]="8088"
    ["resource-tracker-service"]="8092"
    ["tenant-health-service"]="8093"
    ["device-interrogation-service"]="8095"
    ["audit-service"]="8096"
    ["notification-service"]="8097"
    ["discovery-processor-service"]="8090"
)

# API Gateway
echo "Checking API Gateway..."
if curl -sf "http://localhost:${API_GATEWAY_HOST_PORT:-8080}/health" > /dev/null 2>&1; then
    ok "API Gateway is healthy"
else
    err "API Gateway is down"
fi
echo ""

# Individual services
echo "Checking backend services..."
for service in "${!SERVICES[@]}"; do
    port="${SERVICES[$service]}"
    if curl -sf "http://localhost:$port/health" > /dev/null 2>&1; then
        ok "$service is healthy (port $port)"
    else
        err "$service is down (port $port)"
    fi
done
echo ""

# Frontend services
echo "Checking frontend services..."
if curl -sf "http://localhost:${WEB_UI_HOST_PORT:-3000}" > /dev/null 2>&1; then
    ok "web-ui is responding (port ${WEB_UI_HOST_PORT:-3000})"
else
    err "web-ui is down (port ${WEB_UI_HOST_PORT:-3000})"
fi

if curl -sf "http://localhost:${ADMIN_UI_HOST_PORT:-3006}" > /dev/null 2>&1; then
    ok "admin-ui is responding (port ${ADMIN_UI_HOST_PORT:-3006})"
else
    err "admin-ui is down (port ${ADMIN_UI_HOST_PORT:-3006})"
fi
