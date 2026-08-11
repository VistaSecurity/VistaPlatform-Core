#!/bin/bash

# Clean Cache Script
# Cleans various build caches (Docker, Go, npm)

set -euo pipefail

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${BLUE}$*${NC}"; }
ok() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}$*${NC}"; }

log "Cleaning build caches..."
echo ""

# Go build cache
if [ -d "$HOME/.cache/go-build" ]; then
    log "Cleaning Go build cache..."
    go clean -cache
    ok "✅ Go build cache cleaned"
fi

# Go module cache (optional - be careful)
if [ "${CLEAN_MOD_CACHE:-}" = "1" ]; then
    if [ -d "$HOME/go/pkg/mod" ]; then
        warn "Cleaning Go module cache (this will require re-downloading modules)..."
        go clean -modcache
        ok "✅ Go module cache cleaned"
    fi
else
    log "Skipping Go module cache (set CLEAN_MOD_CACHE=1 to clean)"
fi

# Docker build cache.
#
# This one cannot be scoped to a project: BuildKit's cache is shared across
# every build on the daemon, so pruning it slows down the next build of
# everything else on the machine too. Harmless on a laptop, rude on a shared
# host — so it asks, and skips itself when nobody is there to answer.
if command -v docker >/dev/null 2>&1; then
    if [ "${CLEAN_DOCKER_CACHE:-}" = "1" ]; then
        log "Cleaning Docker build cache (CLEAN_DOCKER_CACHE=1)..."
        docker builder prune -f
        ok "✅ Docker build cache cleaned"
    elif [ -t 0 ]; then
        warn "The Docker build cache is shared by every project on this machine."
        read -r -p "Prune it? (y/N): " reply
        if [[ "$reply" =~ ^[Yy]$ ]]; then
            docker builder prune -f
            ok "✅ Docker build cache cleaned"
        else
            log "Skipping Docker build cache"
        fi
    else
        log "Skipping Docker build cache (host-wide; set CLEAN_DOCKER_CACHE=1 to prune)"
    fi
fi

# npm cache (if node_modules exist)
if [ -d "frontend-v2/node_modules" ] || [ -d "admin-ui-v2/node_modules" ]; then
    log "Cleaning npm cache..."
    if command -v npm >/dev/null 2>&1; then
        npm cache clean --force 2>/dev/null || true
        ok "✅ npm cache cleaned"
    fi
fi

# Local build artifacts
if [ -d "bin" ]; then
    log "Cleaning local build artifacts..."
    rm -rf bin/*
    ok "✅ Build artifacts cleaned"
fi

echo ""
ok "Cache cleanup complete!"
warn "Note: Go module cache was not cleaned (set CLEAN_MOD_CACHE=1 to clean)"
