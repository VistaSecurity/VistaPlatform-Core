#!/bin/bash

# Validate Optimizations Script
# Validates that all optimizations are working correctly

set -euo pipefail

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}$*${NC}"; }
ok() { echo -e "${GREEN}✅${NC} $1"; }
warn() { echo -e "${YELLOW}⚠️${NC} $1"; }
err() { echo -e "${RED}❌${NC} $1"; }

PASSED=0
FAILED=0

check() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        ok "$name"
        PASSED=$((PASSED + 1))
        return 0
    else
        err "$name"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

log "Validating Optimizations"
log "========================"
echo ""

# Docker optimizations
log "Docker Optimizations:"
check "Docker BuildKit enabled" [ "$DOCKER_BUILDKIT" = "1" ] || docker build --help | grep -q buildkit
check ".dockerignore exists" [ -f ".dockerignore" ]
check "Dockerfile.prod optimized (auth-service)" grep -q "Layer 1:" services/auth-service/Dockerfile.prod
check "Dockerfile.prod optimized (inventory-service)" grep -q "Layer 1:" services/inventory-service/Dockerfile.prod

# Makefile optimizations
log ""
log "Makefile Optimizations:"
check "build-incremental target exists" make -n build-incremental >/dev/null 2>&1
check "build-services-parallel target exists" make -n build-services-parallel >/dev/null 2>&1
check "test-incremental target exists" make -n test-incremental >/dev/null 2>&1
check "test-parallel target exists" make -n test-parallel >/dev/null 2>&1
check "dev-dashboard target exists" make -n dev-dashboard >/dev/null 2>&1
check "clean-cache target exists" make -n clean-cache >/dev/null 2>&1
check "validate-cache target exists" make -n validate-cache >/dev/null 2>&1

# Script optimizations
log ""
log "Script Optimizations:"
check "build-incremental.sh exists" [ -f "scripts/build-incremental.sh" ]
check "test-changed.sh exists" [ -f "scripts/test-changed.sh" ]
check "dev-dashboard.sh exists" [ -f "scripts/dev-dashboard.sh" ]
check "health-check.sh exists" [ -f "scripts/health-check.sh" ]
check "service-ops.sh exists" [ -f "scripts/service-ops.sh" ]
check "clean-cache.sh exists" [ -f "scripts/clean-cache.sh" ]

# CI/CD optimizations
log ""
log "CI/CD Optimizations:"
check "CI workflow has detect-changes job" grep -q "detect-changes:" .github/workflows/ci.yml
check "CI workflow has matrix strategy" grep -q "strategy:" .github/workflows/ci.yml
check "CI workflow has Docker BuildKit" grep -q "DOCKER_BUILDKIT" .github/workflows/ci.yml
check "CI workflow has cache configuration" grep -q "cache-from" .github/workflows/ci.yml

# Session init optimizations
log ""
log "Session Init Optimizations:"
check "session-init.sh has cache pre-warming" grep -q "Pre-warming Go module cache" scripts/session-init.sh
check "session-init.sh has incremental detection" grep -q "Incremental Build Detection" scripts/session-init.sh

# Deployment optimizations
log ""
log "Deployment Optimizations:"
check "deploy-ec2-smoke.sh has parallel pulls" grep -q "parallel" scripts/deploy-ec2-smoke.sh
check "pre-deploy-check.sh has cache validation" grep -q "cache" scripts/pre-deploy-check.sh

# Documentation
log ""
log "Documentation:"
check "BUILD_OPTIMIZATION.md exists" [ -f "docsv4/operations/BUILD_OPTIMIZATION.md" ] || check "BUILD_OPTIMIZATION.md exists (archived)" [ -f "docsv4/archive/BUILD_OPTIMIZATION.md" ]
check "DAILY_DEVELOPMENT_WORKFLOW.md exists" [ -f "docsv4/operations/DAILY_DEVELOPMENT_WORKFLOW.md" ] || check "DAILY_DEVELOPMENT_WORKFLOW.md exists (archived)" [ -f "docsv4/archive/DAILY_DEVELOPMENT_WORKFLOW.md" ]
check "DEPLOYMENT_PROCEDURES.md exists" [ -f "docsv4/operations/deployment/DEPLOYMENT_PROCEDURES.md" ] || check "DEPLOYMENT_PROCEDURES.md exists (archived)" [ -f "docsv4/archive/DEPLOYMENT_PROCEDURES.md" ]
check "CACHE_MANAGEMENT.md exists" [ -f "docsv4/operations/CACHE_MANAGEMENT.md" ] || check "CACHE_MANAGEMENT.md exists (archived)" [ -f "docsv4/archive/CACHE_MANAGEMENT.md" ]

# Summary
echo ""
log "Validation Summary"
log "=================="
ok "Passed: $PASSED"
if [ $FAILED -gt 0 ]; then
    err "Failed: $FAILED"
    exit 1
else
    ok "All optimizations validated successfully!"
    exit 0
fi
