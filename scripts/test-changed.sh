#!/bin/bash

# Test Changed Services Script
# Tests only services that have changed since the last commit
# Usage: ./scripts/test-changed.sh [base-ref]

set -euo pipefail

# Colors for output
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}$*${NC}"; }
ok() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}$*${NC}"; }
err() { echo -e "${RED}$*${NC}"; }

# Base reference (default to HEAD for uncommitted changes, or HEAD~1 for last commit)
BASE_REF="${1:-HEAD}"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    warn "Not in a git repository. Testing all services..."
    make test-unit
    exit 0
fi

# Detect changed services
log "Detecting changed services since $BASE_REF..."

CHANGED_SERVICES=$(git diff --name-only "$BASE_REF" | \
  grep -E '^services/[^/]+/' | \
  cut -d'/' -f2 | \
  sort -u)

# Also check if shared code changed (affects all services)
SHARED_CHANGED=$(git diff --name-only "$BASE_REF" | \
  grep -E '^shared/' | wc -l)

if [ "$SHARED_CHANGED" -gt 0 ]; then
    warn "Shared code changed - testing all services"
    make test-unit
    exit 0
fi

if [ -z "$CHANGED_SERVICES" ]; then
    warn "No service changes detected"
    log "Run 'make test-unit' to test all services"
    exit 0
fi

log "Testing changed services: $CHANGED_SERVICES"
echo ""

FAILED=0

# Test each changed service
for service in $CHANGED_SERVICES; do
    if [ ! -d "services/$service" ]; then
        warn "Service directory not found: services/$service"
        continue
    fi
    
    if [ ! -f "services/$service/go.mod" ]; then
        warn "No go.mod found for $service - skipping"
        continue
    fi
    
    log "Testing $service..."
    if make test-${service//-/_} 2>/dev/null || \
       (cd "services/$service" && go test -v ./...); then
        ok "✅ $service tests passed"
    else
        err "❌ $service tests failed"
        FAILED=$((FAILED + 1))
    fi
    echo ""
done

if [ $FAILED -eq 0 ]; then
    ok "All changed service tests passed!"
    exit 0
else
    err "$FAILED service(s) failed tests"
    exit 1
fi
