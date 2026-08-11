#!/bin/bash
# End-to-end sensor monitoring script
# Monitors sensor, platform services, and data flow

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-http://localhost:8080}"
SENSOR_DIR="${SENSOR_DIR:-$(pwd)/sensor}"
DATA_DIR="${DATA_DIR:-$HOME/.crypto-sensor}"
LOG_DIR="${LOG_DIR:-/tmp/sensor-monitoring}"
MONITOR_INTERVAL="${MONITOR_INTERVAL:-5}"

# Create log directory
mkdir -p "$LOG_DIR"

echo -e "${BLUE}🔍 Crypto Inventory Sensor E2E Monitoring${NC}"
echo "=========================================="
echo ""

# Function to check service health
check_service() {
    local service=$1
    local url=$2
    local name=$3

    if curl -s -f "$url" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ $name is healthy${NC}"
        return 0
    else
        echo -e "${RED}❌ $name is not responding${NC}"
        return 1
    fi
}

# Function to get sensor count from database
get_sensor_count() {
    docker exec crypto-postgres psql -U crypto_user -d crypto_inventory -t -c \
        "SELECT COUNT(*) FROM sensors WHERE status = 'active';" 2>/dev/null | tr -d ' ' || echo "0"
}

# Function to get discovery count from database
get_discovery_count() {
    docker exec crypto-postgres psql -U crypto_user -d crypto_inventory -t -c \
        "SELECT COUNT(*) FROM sensor_discoveries;" 2>/dev/null | tr -d ' ' || echo "0"
}

# Function to get recent discoveries
get_recent_discoveries() {
    docker exec crypto-postgres psql -U crypto_user -d crypto_inventory -t -c \
        "SELECT protocol, dest_ip, port, confidence, created_at
         FROM sensor_discoveries
         ORDER BY created_at DESC
         LIMIT 5;" 2>/dev/null
}

# Function to get infrastructure assets created from discoveries
get_network_assets_count() {
    docker exec crypto-postgres psql -U crypto_user -d crypto_inventory -t -c \
        "SELECT COUNT(*) FROM network_assets WHERE source = 'sensor';" 2>/dev/null | tr -d ' ' || echo "0"
}

# Function to get crypto implementations count
get_crypto_implementations_count() {
    docker exec crypto-postgres psql -U crypto_user -d crypto_inventory -t -c \
        "SELECT COUNT(*) FROM crypto_implementations;" 2>/dev/null | tr -d ' ' || echo "0"
}

# Function to check sensor logs
check_sensor_logs() {
    if [ -f "$LOG_DIR/sensor.log" ]; then
        echo -e "${BLUE}📋 Recent sensor activity:${NC}"
        tail -5 "$LOG_DIR/sensor.log" | sed 's/^/   /'
    fi
}

# Function to check platform logs
check_platform_logs() {
    echo -e "${BLUE}📋 Recent platform activity:${NC}"

    # Sensor manager logs
    echo -e "   ${YELLOW}Sensor Manager:${NC}"
    docker logs crypto-sensor-manager --tail 3 2>&1 | grep -E "(discovery|sensor|register)" | tail -3 | sed 's/^/      /' || echo "      (no recent activity)"

    # Inventory service logs
    echo -e "   ${YELLOW}Inventory Service:${NC}"
    docker logs crypto-inventory-service --tail 3 2>&1 | grep -E "(asset|discovery)" | tail -3 | sed 's/^/      /' || echo "      (no recent activity)"
}

# Initial health checks
echo -e "${BLUE}1. Checking platform services...${NC}"
check_service "api-gateway" "$CONTROL_PLANE_URL/api/v1/health" "API Gateway"
check_service "sensor-manager" "$CONTROL_PLANE_URL/api/v1/sensor-manager/health" "Sensor Manager"
check_service "inventory-service" "$CONTROL_PLANE_URL/api/v1/inventory-service/health" "Inventory Service"

echo ""
echo -e "${BLUE}2. Checking database connectivity...${NC}"
if docker exec crypto-postgres pg_isready -U crypto_user -d crypto_inventory > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Database is ready${NC}"
else
    echo -e "${RED}❌ Database is not ready${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}3. Current platform state:${NC}"
SENSOR_COUNT=$(get_sensor_count)
DISCOVERY_COUNT=$(get_discovery_count)
echo "   Active sensors: $SENSOR_COUNT"
echo "   Total discoveries: $DISCOVERY_COUNT"

echo ""
echo -e "${BLUE}4. Starting monitoring loop...${NC}"
echo "   Monitoring interval: ${MONITOR_INTERVAL}s"
echo "   Press Ctrl+C to stop"
echo ""

# Monitoring loop
PREV_SENSOR_COUNT=$SENSOR_COUNT
PREV_DISCOVERY_COUNT=$DISCOVERY_COUNT
ITERATION=0

while true; do
    ITERATION=$((ITERATION + 1))
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}[$TIMESTAMP] Monitoring Check #$ITERATION${NC}"
    echo ""

    # Check sensor process
    if pgrep -f "crypto-sensor" > /dev/null; then
        echo -e "${GREEN}✅ Sensor process is running${NC}"
    else
        echo -e "${RED}❌ Sensor process is not running${NC}"
    fi

    # Check current counts
    CURRENT_SENSOR_COUNT=$(get_sensor_count)
    CURRENT_DISCOVERY_COUNT=$(get_discovery_count)
    CURRENT_ASSETS_COUNT=$(get_network_assets_count)
    CURRENT_CRYPTO_COUNT=$(get_crypto_implementations_count)

    echo ""
    echo -e "${BLUE}📊 Data Statistics:${NC}"
    echo "   Active sensors: $CURRENT_SENSOR_COUNT"
    echo "   Total discoveries: $CURRENT_DISCOVERY_COUNT"
    echo "   Infrastructure assets (from sensors): $CURRENT_ASSETS_COUNT"
    echo "   Crypto implementations: $CURRENT_CRYPTO_COUNT"

    # Check for changes
    if [ "$CURRENT_SENSOR_COUNT" != "$PREV_SENSOR_COUNT" ]; then
        echo -e "${GREEN}   🎉 Sensor count changed: $PREV_SENSOR_COUNT → $CURRENT_SENSOR_COUNT${NC}"
        PREV_SENSOR_COUNT=$CURRENT_SENSOR_COUNT
    fi

    if [ "$CURRENT_DISCOVERY_COUNT" != "$PREV_DISCOVERY_COUNT" ]; then
        NEW_DISCOVERIES=$((CURRENT_DISCOVERY_COUNT - PREV_DISCOVERY_COUNT))
        echo -e "${GREEN}   🎉 New discoveries detected: +$NEW_DISCOVERIES (total: $CURRENT_DISCOVERY_COUNT)${NC}"
        PREV_DISCOVERY_COUNT=$CURRENT_DISCOVERY_COUNT

        # Show recent discoveries
        echo ""
        echo -e "${BLUE}📋 Recent discoveries:${NC}"
        RECENT_DISCOVERIES=$(get_recent_discoveries)
        if [ -n "$RECENT_DISCOVERIES" ]; then
            echo "$RECENT_DISCOVERIES" | while IFS='|' read -r protocol ip port confidence created_at; do
                # Trim whitespace
                protocol=$(echo "$protocol" | xargs)
                ip=$(echo "$ip" | xargs)
                port=$(echo "$port" | xargs)
                confidence=$(echo "$confidence" | xargs)
                created_at=$(echo "$created_at" | xargs)

                if [ -n "$protocol" ] && [ "$protocol" != "protocol" ]; then
                    echo "   • $protocol on $ip:$port (confidence: ${confidence:-N/A}) at ${created_at:-N/A}"
                fi
            done
        else
            echo "   (no discoveries yet)"
        fi
    fi

    # Check logs
    echo ""
    check_sensor_logs
    echo ""
    check_platform_logs

    # Check for errors
    echo ""
    echo -e "${BLUE}🔍 Error Check:${NC}"
    ERROR_COUNT=$(docker logs crypto-sensor-manager --tail 100 2>&1 | grep -i "error\|failed" | wc -l)
    if [ "$ERROR_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}   ⚠️  Found $ERROR_COUNT potential errors in recent logs${NC}"
        docker logs crypto-sensor-manager --tail 20 2>&1 | grep -i "error\|failed" | tail -3 | sed 's/^/      /'
    else
        echo -e "${GREEN}   ✅ No recent errors detected${NC}"
    fi

    echo ""
    sleep "$MONITOR_INTERVAL"
done
