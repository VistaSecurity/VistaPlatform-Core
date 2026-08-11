#!/bin/bash
set -eo pipefail

# Service Validation Script
# Run this after session-init to validate all services are running properly
# This addresses timing issues by waiting longer and checking thoroughly
#
# Documentation:
#   - See docsv4/development/standards/TROUBLESHOOTING.md for service troubleshooting
#   - See docsv4/operations/monitoring/monitoring.md for monitoring setup

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

# Source local .env if present (for infrastructure port overrides)
if [ -f ".env" ]; then
    set -a
    source .env
    set +a
fi

echo "🔍 Validating All Services"
echo "========================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Detect Docker Compose command
if command -v docker-compose >/dev/null 2>&1; then
    DCMD="docker-compose"
else
    DCMD="docker compose"
fi

# Configuration
VALIDATION_TIMEOUT="${VALIDATION_TIMEOUT_SECS:-5}"
STABILIZATION_WAIT="${STABILIZATION_WAIT_SECS:-5}"

echo -e "${BLUE}Waiting ${STABILIZATION_WAIT}s for services to stabilize...${NC}"
echo ""
sleep "${STABILIZATION_WAIT}"

# Helper functions
check_service_running() {
  local name="$1"
  if $DCMD ps --format json >/dev/null 2>&1; then
    $DCMD ps --format json 2>/dev/null | grep -q "\"Service\":\"$name\"" && return 0
    $DCMD ps --format json 2>/dev/null | grep -q "\"Name\":\"$name\"" && return 0
    $DCMD ps --format json 2>/dev/null | grep -q "\"Name\":\"crypto-$name\"" && return 0
    return 1
  else
    $DCMD ps 2>/dev/null | grep -q "^$name" && return 0
    return 1
  fi
}

check_health_endpoint() {
  local url="$1"
  local timeout="${2:-${VALIDATION_TIMEOUT}}"
  local code=$(curl -s -o /dev/null -w "%{http_code}" "$url" --max-time "$timeout" 2>/dev/null || echo "000")
  echo "$code"
}

FAILED_SERVICES=()
PASSED_COUNT=0
TOTAL_COUNT=0

# 1. Infrastructure
echo -e "${BLUE}🧱 Infrastructure Services:${NC}"
for s in postgres redis nats influxdb; do
  TOTAL_COUNT=$((TOTAL_COUNT + 1))
  if check_service_running "$s"; then
    case "$s" in
      postgres)
        if $DCMD exec -T postgres pg_isready -U "${POSTGRES_USER:-crypto_user}" -d "${POSTGRES_DB:-crypto_inventory}" >/dev/null 2>&1; then
          echo -e "  ${GREEN}✅${NC} $s"
          PASSED_COUNT=$((PASSED_COUNT + 1))
        else
          echo -e "  ${RED}❌${NC} $s (running but not responding)"
          FAILED_SERVICES+=("$s")
        fi
        ;;
      redis)
        # Check if redis is responding to ping
        redis_result=$($DCMD exec -T redis redis-cli -a "${REDIS_PASSWORD:-redis_pass_dev}" ping 2>&1)
        if echo "$redis_result" | grep -q "PONG"; then
          echo -e "  ${GREEN}✅${NC} $s"
          PASSED_COUNT=$((PASSED_COUNT + 1))
        else
          echo -e "  ${RED}❌${NC} $s (running but not responding)"
          FAILED_SERVICES+=("$s")
        fi
        ;;
      nats)
        NATS_HTTP_PORT="${NATS_HTTP_HOST_PORT:-8222}"
        code=$(check_health_endpoint "http://localhost:${NATS_HTTP_PORT}/healthz")
        if [ "$code" = "200" ]; then
          echo -e "  ${GREEN}✅${NC} $s"
          PASSED_COUNT=$((PASSED_COUNT + 1))
        else
          echo -e "  ${RED}❌${NC} $s (HTTP $code)"
          FAILED_SERVICES+=("$s")
        fi
        ;;
      influxdb)
        code=$(check_health_endpoint "http://localhost:8086/health")
        if [ "$code" = "200" ] || [ "$code" = "204" ]; then
          echo -e "  ${GREEN}✅${NC} $s"
          PASSED_COUNT=$((PASSED_COUNT + 1))
        else
          echo -e "  ${RED}❌${NC} $s (HTTP $code)"
          FAILED_SERVICES+=("$s")
        fi
        ;;
    esac
  else
    echo -e "  ${RED}❌${NC} $s (not running)"
    FAILED_SERVICES+=("$s")
  fi
done

echo ""

# 2. API Gateway
echo -e "${BLUE}🌐 API Gateway:${NC}"
TOTAL_COUNT=$((TOTAL_COUNT + 1))
if check_service_running "api-gateway"; then
  code=$(check_health_endpoint "http://localhost:${API_GATEWAY_HOST_PORT:-8080}/")
  if [ "$code" = "200" ] || [ "$code" = "404" ] || [ "$code" = "502" ]; then
    echo -e "  ${GREEN}✅${NC} api-gateway (HTTP $code)"
    PASSED_COUNT=$((PASSED_COUNT + 1))
  else
    echo -e "  ${RED}❌${NC} api-gateway (HTTP $code)"
    FAILED_SERVICES+=("api-gateway")
  fi
else
  echo -e "  ${RED}❌${NC} api-gateway (not running)"
  FAILED_SERVICES+=("api-gateway")
fi

echo ""

# 3. Backend Services (from registry)
echo -e "${BLUE}🧩 Backend Services:${NC}"
if command -v node >/dev/null 2>&1 && [ -f "standards/service-registry.yaml" ]; then
  # Read services from registry
  node -e '
    const fs=require("fs");
    const YAML=require("./scripts/node_modules/yaml");
    const doc=YAML.parse(fs.readFileSync("standards/service-registry.yaml","utf8"));
    const services=(doc&&doc.services)||[];
    const portEnv = {
      "auth-service":"AUTH_SERVICE_HOST_PORT",
      "inventory-service":"INVENTORY_SERVICE_HOST_PORT",
      "compliance-engine":"COMPLIANCE_ENGINE_HOST_PORT",
      "cbom-service":"CBOM_SERVICE_HOST_PORT",
      "sensor-manager":"SENSOR_MANAGER_HOST_PORT",
      "cluster-sensor-service":"CLUSTER_SENSOR_HOST_PORT",
      "admin-service":"ADMIN_SERVICE_HOST_PORT",
      "monitoring-service":"MONITORING_SERVICE_HOST_PORT",
      "resource-tracker-service":"RESOURCE_TRACKER_HOST_PORT",
      "tenant-health-service":"TENANT_HEALTH_HOST_PORT",
      "device-interrogation-service":"DEVICE_INTERROGATION_SERVICE_HOST_PORT",
      "audit-service":"AUDIT_SERVICE_HOST_PORT",
      "notification-service":"NOTIFICATION_SERVICE_HOST_PORT",
      "discovery-processor-service":"DISCOVERY_PROCESSOR_SERVICE_HOST_PORT"
    };
    for (const s of services) {
      const key=s.key||s.name;
      const ext=s.external_port||"";
      const env=portEnv[key]||"";
      const status=(s.status||"").toLowerCase();
      console.log(`${key}|${ext}|${env}|${status}`);
    }
  ' | while IFS='|' read -r key ext envvar svcstatus; do
    # Safely get environment variable value if set
    if [ -n "$envvar" ]; then
      # Temporarily disable unbound variable check for this eval
      set +u
      eval "ovr=\"\${${envvar}}\""
      set -u
    else
      ovr=""
    fi
    port="${ovr:-$ext}"

    # Skip optional services that aren't running
    if [ "$svcstatus" = "optional" ] && ! check_service_running "$key"; then
      echo -e "  ${YELLOW}⏭️${NC} $key (optional, not running)"
      continue
    fi

    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    if check_service_running "$key"; then
      code=$(check_health_endpoint "http://localhost:${port}/health")
      if [ "$code" = "200" ]; then
        echo -e "  ${GREEN}✅${NC} $key (http://localhost:${port}/health)"
        PASSED_COUNT=$((PASSED_COUNT + 1))
      else
        echo -e "  ${RED}❌${NC} $key (HTTP $code)"
        FAILED_SERVICES+=("$key")
      fi
    else
      echo -e "  ${RED}❌${NC} $key (not running)"
      FAILED_SERVICES+=("$key")
    fi
  done
else
  echo -e "  ${YELLOW}⚠️${NC} Skipping registry-driven checks (Node or registry missing)"
fi

echo ""

# 4. Frontend
echo -e "${BLUE}🖥️ Frontend Services:${NC}"
TOTAL_COUNT=$((TOTAL_COUNT + 1))
web_code=$(check_health_endpoint "http://localhost:${WEB_UI_HOST_PORT:-3000}")
if [ "$web_code" = "200" ] || [ "$web_code" = "302" ]; then
  echo -e "  ${GREEN}✅${NC} web-ui (http://localhost:${WEB_UI_HOST_PORT:-3000})"
  PASSED_COUNT=$((PASSED_COUNT + 1))
else
  echo -e "  ${RED}❌${NC} web-ui (HTTP $web_code)"
  FAILED_SERVICES+=("web-ui")
fi

TOTAL_COUNT=$((TOTAL_COUNT + 1))
admin_code=$(check_health_endpoint "http://localhost:${ADMIN_UI_HOST_PORT:-3006}")
if [ "$admin_code" = "200" ] || [ "$admin_code" = "302" ]; then
  echo -e "  ${GREEN}✅${NC} admin-ui (http://localhost:${ADMIN_UI_HOST_PORT:-3006})"
  PASSED_COUNT=$((PASSED_COUNT + 1))
else
  echo -e "  ${RED}❌${NC} admin-ui (HTTP $admin_code)"
  FAILED_SERVICES+=("admin-ui")
fi

echo ""

# 5. Dev Tools (Optional - don't count toward pass/fail)
echo -e "${BLUE}🛠️ Development Tools:${NC}"
for tool in adminer grafana; do
  if check_service_running "$tool"; then
    echo -e "  ${GREEN}✅${NC} $tool"
  else
    echo -e "  ${YELLOW}⚠️${NC} $tool (not running - optional)"
    # Don't count these as they're optional development tools
  fi
done

echo ""
echo "========================="
echo -e "${BLUE}📊 Validation Summary${NC}"
echo "========================="
echo ""
echo "Passed: ${GREEN}$PASSED_COUNT${NC} / $TOTAL_COUNT"
echo ""

if [ ${#FAILED_SERVICES[@]} -gt 0 ]; then
  echo -e "${RED}❌ Failed Services:${NC}"
  for svc in "${FAILED_SERVICES[@]}"; do
    echo "  • $svc"
  done
  echo ""
  echo "Run 'make monitor' for more details or check logs:"
  echo "  docker compose logs <service-name>"
  exit 1
else
  echo -e "${GREEN}🎉 All services are healthy!${NC}"
  echo ""
  echo "Quick links:"
  echo "  Web UI: http://localhost:${WEB_UI_HOST_PORT:-3000}"
  echo "  Admin UI: http://localhost:${ADMIN_UI_HOST_PORT:-3006}"
  echo "  API Gateway: http://localhost:${API_GATEWAY_HOST_PORT:-8080}"
  exit 0
fi
