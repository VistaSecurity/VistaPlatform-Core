#!/bin/bash

# Update Dependencies Script
# Updates dependencies across the Go workspace

set -euo pipefail

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${BLUE}$*${NC}"; }
ok() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}$*${NC}"; }

log "Updating Go dependencies across workspace..."
echo ""

# Update shared first
if [ -f "shared/go.mod" ]; then
    log "Updating shared dependencies..."
    cd shared
    go get -u ./...
    go mod tidy
    cd ..
    ok "✅ Shared dependencies updated"
fi

# Update shared/rbac
if [ -f "shared/rbac/go.mod" ]; then
    log "Updating shared/rbac dependencies..."
    cd shared/rbac
    go get -u ./...
    go mod tidy
    cd ../..
    ok "✅ Shared RBAC dependencies updated"
fi

# Update all services
log "Updating service dependencies..."
for service in services/*/; do
    if [ -f "$service/go.mod" ]; then
        service_name=$(basename "$service")
        log "Updating $service_name..."
        cd "$service"
        go get -u ./...
        go mod tidy
        cd ../..
        ok "✅ $service_name dependencies updated"
    fi
done

# Sync workspace
log "Syncing workspace..."
go work sync
ok "✅ Workspace synced"

echo ""
ok "All dependencies updated successfully!"
