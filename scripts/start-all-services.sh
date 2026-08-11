#!/bin/bash

# Start All Services Script
# This script starts all services including frontend applications, development tools, and AI services

set -e

# Ensure we run from the repository root regardless of current working directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

echo "🚀 Starting All Services"
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

# Start infrastructure services first
echo -e "${BLUE}Starting infrastructure services...${NC}"
run_command "Start infrastructure" "$DCMD up -d postgres redis nats influxdb"

# Wait for infrastructure to be healthy
echo -e "${BLUE}Waiting for infrastructure to be healthy...${NC}"
sleep 10

# Start core backend services
echo -e "${BLUE}Starting core backend services...${NC}"
run_command "Start core services" "$DCMD up -d auth-service inventory-service compliance-engine cbom-service sensor-manager admin-service cluster-sensor-service monitoring-service resource-tracker-service tenant-health-service device-interrogation-service audit-service notification-service discovery-processor-service"

# Start API gateway (before frontend so UIs have gateway available)
echo -e "${BLUE}Starting API gateway...${NC}"
run_command "Start API gateway" "$DCMD up -d api-gateway"

# Start frontend applications
echo -e "${BLUE}Starting frontend applications...${NC}"
run_command "Start frontend applications" "$DCMD up -d web-ui admin-ui"

# Start development tools
echo -e "${BLUE}Starting development tools...${NC}"
run_command "Start development tools" "$DCMD up -d adminer"

# Start observability stack
echo -e "${BLUE}Starting observability stack...${NC}"
run_command "Start observability" "$DCMD up -d otel-collector jaeger grafana"


echo ""
echo -e "${GREEN}🎉 All services started successfully!${NC}"
echo ""
echo -e "${BLUE}Service URLs:${NC}"
echo -e "  • API Gateway:     http://localhost:8080"
echo -e "  • Web UI:          http://localhost:3000"
echo -e "  • Admin UI:        http://localhost:${ADMIN_UI_HOST_PORT:-3006}"
echo -e "  • Adminer (DB):    http://localhost:${ADMINER_HOST_PORT:-18003}"
echo ""
echo -e "${BLUE}Observability:${NC}"
echo -e "  • Grafana:         http://localhost:${GRAFANA_HOST_PORT:-18002}"
echo -e "  • Jaeger:          http://localhost:16686"
echo -e "  • OTel Collector:  localhost:4317 (gRPC), localhost:4318 (HTTP)"
echo ""
echo -e "${BLUE}Backend Services:${NC}"
echo -e "  • Auth Service:    http://localhost:8081"
echo -e "  • Inventory:       http://localhost:8082"
echo -e "  • Compliance:      http://localhost:8083"
echo -e "  • Reports:         http://localhost:8084"
echo -e "  • Sensors:         http://localhost:8085"
echo -e "  • Admin Service:   http://localhost:8089"
echo -e "  • Monitoring:      http://localhost:8091"
echo -e "  • Resource Tracker: http://localhost:8092"
echo -e "  • Tenant Health:   http://localhost:8093"
echo -e "  • Device Interrogation: http://localhost:8095"
echo -e "  • Audit Service:   http://localhost:8096"
echo -e "  • Notification Service: http://localhost:8097"
echo -e "  • Discovery Processor: http://localhost:8090"
echo ""
echo -e "${YELLOW}Note:${NC} Some services may take a few moments to become fully ready."
echo -e "Run 'docker compose ps' to check the status of all services."
