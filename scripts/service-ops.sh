#!/bin/bash

# Service Operations Script
# Unified script for service operations (build/test/lint/run)
# Usage: ./scripts/service-ops.sh <operation> <service1> [service2] ...

set -euo pipefail

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}$*${NC}"; }
ok() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}$*${NC}"; }
err() { echo -e "${RED}$*${NC}"; }

OPERATION="${1:-}"
shift || true

if [ -z "$OPERATION" ]; then
    err "Usage: $0 <operation> <service1> [service2] ..."
    err "Operations: build, test, lint, run"
    err "Services: auth-service, inventory-service, compliance-engine, etc."
    err "Special: 'all' for all services"
    exit 1
fi

# List of all services
ALL_SERVICES=(
    "auth-service"
    "inventory-service"
    "compliance-engine"
    "cbom-service"
    "sensor-manager"
    "admin-service"
    "monitoring-service"
    "cluster-sensor-service"
    "resource-tracker-service"
    "tenant-health-service"
)

# Determine which services to operate on
if [ $# -eq 0 ] || [ "$1" = "all" ]; then
    SERVICES=("${ALL_SERVICES[@]}")
else
    SERVICES=("$@")
fi

# Validate services
VALID_SERVICES=()
for service in "${SERVICES[@]}"; do
    if [[ " ${ALL_SERVICES[*]} " =~ " ${service} " ]]; then
        VALID_SERVICES+=("$service")
    else
        warn "Unknown service: $service (skipping)"
    fi
done

if [ ${#VALID_SERVICES[@]} -eq 0 ]; then
    err "No valid services specified"
    exit 1
fi

# Execute operation
case "$OPERATION" in
    build)
        log "Building services: ${VALID_SERVICES[*]}"
        for service in "${VALID_SERVICES[@]}"; do
            service_var=$(echo "$service" | tr '-' '_')
            if make "build-${service_var}" 2>/dev/null; then
                ok "✅ $service built"
            else
                err "❌ $service build failed"
            fi
        done
        ;;
    test)
        log "Testing services: ${VALID_SERVICES[*]}"
        for service in "${VALID_SERVICES[@]}"; do
            service_var=$(echo "$service" | tr '-' '_')
            if make "test-${service_var}" 2>/dev/null; then
                ok "✅ $service tests passed"
            else
                err "❌ $service tests failed"
            fi
        done
        ;;
    lint)
        log "Linting services: ${VALID_SERVICES[*]}"
        for service in "${VALID_SERVICES[@]}"; do
            service_var=$(echo "$service" | tr '-' '_')
            if make "lint-${service_var}" 2>/dev/null; then
                ok "✅ $service linted"
            else
                err "❌ $service lint failed"
            fi
        done
        ;;
    run)
        log "Running services: ${VALID_SERVICES[*]}"
        warn "Note: Use 'docker compose up <service>' to run services"
        for service in "${VALID_SERVICES[@]}"; do
            log "To run $service: docker compose up -d $service"
        done
        ;;
    *)
        err "Unknown operation: $OPERATION"
        err "Valid operations: build, test, lint, run"
        exit 1
        ;;
esac
