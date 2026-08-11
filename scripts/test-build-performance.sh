#!/bin/bash

# Build Performance Testing Script
# Benchmarks build times before/after optimizations

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

RESULTS_FILE="build-performance-results.txt"

log "Build Performance Benchmark"
log "==========================="
echo ""

# Function to time a command
time_command() {
    local label="$1"
    shift
    local start=$(date +%s.%N)
    "$@" >/dev/null 2>&1
    local end=$(date +%s.%N)
    local duration=$(echo "$end - $start" | bc)
    echo "$duration"
}

# Test 1: Full build (sequential)
log "Test 1: Full build (sequential)..."
FULL_SEQUENTIAL=$(time_command "Full sequential build" make build-services)
ok "Full sequential build: ${FULL_SEQUENTIAL}s"

# Test 2: Full build (parallel)
log "Test 2: Full build (parallel)..."
FULL_PARALLEL=$(time_command "Full parallel build" make build-services-parallel)
ok "Full parallel build: ${FULL_PARALLEL}s"

# Test 3: Incremental build (one service changed)
log "Test 3: Incremental build (simulated change)..."
# Simulate a change by touching a file
touch services/auth-service/cmd/main.go
INCREMENTAL=$(time_command "Incremental build" make build-incremental)
ok "Incremental build: ${INCREMENTAL}s"

# Test 4: Docker build (with cache)
log "Test 4: Docker build (with cache)..."
DOCKER_CACHED=$(time_command "Docker build cached" docker build -f services/auth-service/Dockerfile.prod -t test-auth-service . 2>&1 | tail -1)
ok "Docker build (cached): ${DOCKER_CACHED}s"

# Test 5: Docker build (no cache)
log "Test 5: Docker build (no cache)..."
DOCKER_NO_CACHE=$(time_command "Docker build no cache" docker build --no-cache -f services/auth-service/Dockerfile.prod -t test-auth-service . 2>&1 | tail -1)
ok "Docker build (no cache): ${DOCKER_NO_CACHE}s"

# Test 6: Test execution (sequential)
log "Test 6: Test execution (sequential)..."
TEST_SEQUENTIAL=$(time_command "Test sequential" make test-unit)
ok "Test sequential: ${TEST_SEQUENTIAL}s"

# Test 7: Test execution (parallel)
log "Test 7: Test execution (parallel)..."
TEST_PARALLEL=$(time_command "Test parallel" make test-parallel)
ok "Test parallel: ${TEST_PARALLEL}s"

# Calculate improvements
echo ""
log "Performance Summary"
log "==================="

PARALLEL_IMPROVEMENT=$(echo "scale=1; (($FULL_SEQUENTIAL - $FULL_PARALLEL) / $FULL_SEQUENTIAL) * 100" | bc)
INCREMENTAL_IMPROVEMENT=$(echo "scale=1; (($FULL_SEQUENTIAL - $INCREMENTAL) / $FULL_SEQUENTIAL) * 100" | bc)
DOCKER_CACHE_IMPROVEMENT=$(echo "scale=1; (($DOCKER_NO_CACHE - $DOCKER_CACHED) / $DOCKER_NO_CACHE) * 100" | bc)
TEST_IMPROVEMENT=$(echo "scale=1; (($TEST_SEQUENTIAL - $TEST_PARALLEL) / $TEST_SEQUENTIAL) * 100" | bc)

echo "Parallel build improvement: ${PARALLEL_IMPROVEMENT}%"
echo "Incremental build improvement: ${INCREMENTAL_IMPROVEMENT}%"
echo "Docker cache improvement: ${DOCKER_CACHE_IMPROVEMENT}%"
echo "Parallel test improvement: ${TEST_IMPROVEMENT}%"

# Save results
cat > "$RESULTS_FILE" <<EOF
Build Performance Results
==========================

Full Sequential Build: ${FULL_SEQUENTIAL}s
Full Parallel Build: ${FULL_PARALLEL}s
Incremental Build: ${INCREMENTAL}s
Docker Build (Cached): ${DOCKER_CACHED}s
Docker Build (No Cache): ${DOCKER_NO_CACHE}s
Test Sequential: ${TEST_SEQUENTIAL}s
Test Parallel: ${TEST_PARALLEL}s

Improvements:
- Parallel build: ${PARALLEL_IMPROVEMENT}%
- Incremental build: ${INCREMENTAL_IMPROVEMENT}%
- Docker cache: ${DOCKER_CACHE_IMPROVEMENT}%
- Parallel test: ${TEST_IMPROVEMENT}%
EOF

ok "Results saved to $RESULTS_FILE"
