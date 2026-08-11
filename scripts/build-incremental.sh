#!/bin/bash

# Incremental Build Script
# Builds only services that have changed since the last commit
# Usage: ./scripts/build-incremental.sh [base-ref]

set -euo pipefail

# Colors for output
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${BLUE}$*${NC}"; }
ok() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}$*${NC}"; }

# Base reference (default to HEAD~1 for comparison)
BASE_REF="${1:-HEAD~1}"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    warn "Not in a git repository. Building all services..."
    make build-services
    exit 0
fi

# Detect changed services
log "Detecting changed services since $BASE_REF..."

CHANGED_SERVICES=$(git diff --name-only "$BASE_REF" HEAD | \
  grep -E '^services/[^/]+/' | \
  cut -d'/' -f2 | \
  sort -u)

# Also check if shared code changed (affects all services)
SHARED_CHANGED=$(git diff --name-only "$BASE_REF" HEAD | \
  grep -E '^shared/' | wc -l)

if [ "$SHARED_CHANGED" -gt 0 ]; then
    warn "Shared code changed - building all services"
    make build-services
    exit 0
fi

if [ -z "$CHANGED_SERVICES" ]; then
    warn "No service changes detected since $BASE_REF"
    log "Run 'make build-services' to build all services"
    exit 0
fi

log "Building changed services: $CHANGED_SERVICES"
echo ""

# Build each changed service
for service in $CHANGED_SERVICES; do
    if [ ! -d "services/$service" ]; then
        warn "Service directory not found: services/$service"
        continue
    fi
    
    if [ ! -f "services/$service/go.mod" ]; then
        warn "No go.mod found for $service - skipping"
        continue
    fi
    
    log "Building $service..."
    if make build-${service//-/_} 2>/dev/null || \
       (cd "services/$service" && go build -o "../../bin/$service" ./cmd/main.go); then
        ok "✅ $service built successfully"
    else
        warn "⚠️  $service build failed"
    fi
done

ok "Incremental build complete!"
