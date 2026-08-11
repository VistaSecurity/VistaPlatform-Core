#!/bin/bash

# Dockerfile Validation Script
# Validates that all Dockerfiles follow project standards
#
# Documentation:
#   - See docsv4/development/standards/GO_STANDARDS.md for Dockerfile standards
#   - See docsv4/development/standards/QUICK_REFERENCE.md for quick reference

# Note: Not using 'set -e' here because we want to collect all errors/warnings
# before exiting, not exit on the first one

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "🐳 Validating Dockerfiles..."
echo "============================"
echo ""

ERRORS=0
WARNINGS=0

# Expected Go version
EXPECTED_GO_VERSION="1.26"

# Function to check a Dockerfile
check_dockerfile() {
    local dockerfile="$1"
    local type="${2:-unknown}" # prod or dev
    local service_name=$(basename $(dirname "$dockerfile"))
    
    echo -e "${BLUE}Checking $dockerfile...${NC}"
    
    # Check if file exists
    if [ ! -f "$dockerfile" ]; then
        echo -e "${YELLOW}  ⚠️  File not found, skipping${NC}"
        return
    fi
    
    # Check if this is a Python service (skip Go-specific checks)
    # Matches both upstream python: and Docker Hardened Images dhi.io/python: base images
    if grep -qE "FROM (dhi\.io/)?python:" "$dockerfile"; then
        echo -e "${BLUE}  ℹ️  Python service - skipping Go-specific checks${NC}"
        
        # Just check for health check and non-root user
        if grep -q "HEALTHCHECK" "$dockerfile"; then
            echo -e "${GREEN}  ✅ Has health check${NC}"
        else
            echo -e "${YELLOW}  ⚠️  Missing health check${NC}"
            ((WARNINGS++))
        fi
        
        if grep -q "USER appuser" "$dockerfile" || grep -q "USER [0-9]" "$dockerfile"; then
            echo -e "${GREEN}  ✅ Runs as non-root user${NC}"
        else
            echo -e "${YELLOW}  ⚠️  May be running as root${NC}"
            ((WARNINGS++))
        fi
        
        echo ""
        return
    fi
    
    # 1. Check Go version
    local go_version=$(grep -E "^FROM golang:" "$dockerfile" | head -1 | sed -E 's/.*golang:([0-9.]+).*/\1/')
    if [ -n "$go_version" ]; then
        if [[ "$go_version" =~ ^$EXPECTED_GO_VERSION ]]; then
            echo -e "${GREEN}  ✅ Go version: $go_version${NC}"
        else
            echo -e "${RED}  ❌ Go version: $go_version (expected $EXPECTED_GO_VERSION)${NC}"
            ((ERRORS++))
        fi
    fi
    
    # 2. Check for workspace pattern in production Dockerfiles
    if [[ "$type" == "prod" ]]; then
        if grep -q "COPY go.work" "$dockerfile" && \
           grep -q "COPY shared" "$dockerfile" && \
           grep -q "COPY services" "$dockerfile"; then
            echo -e "${GREEN}  ✅ Uses workspace pattern${NC}"
        else
            echo -e "${RED}  ❌ Missing workspace pattern (should copy go.work, shared, services)${NC}"
            ((ERRORS++))
        fi
        
        # Check for go mod tidy in production (should NOT have it in workspace mode)
        if grep -q "go mod tidy" "$dockerfile"; then
            echo -e "${RED}  ❌ Uses 'go mod tidy' (workspace mode handles deps, remove this)${NC}"
            ((ERRORS++))
        else
            echo -e "${GREEN}  ✅ No 'go mod tidy' (workspace handles dependencies)${NC}"
        fi
        
        # Check for -mod=mod flag in production (should not have it)
        if grep -q "go build.*-mod=mod" "$dockerfile"; then
            echo -e "${RED}  ❌ Uses -mod=mod flag (production should use 'go mod tidy')${NC}"
            ((ERRORS++))
        else
            echo -e "${GREEN}  ✅ No -mod=mod flag in production${NC}"
        fi
    fi
    
    # 3. Check for workspace pattern in development Dockerfiles
    if [[ "$type" == "dev" ]]; then
        if grep -q "COPY services/$service_name/" "$dockerfile" && \
           grep -q "COPY shared/" "$dockerfile"; then
            echo -e "${GREEN}  ✅ Uses workspace pattern${NC}"
        else
            echo -e "${YELLOW}  ⚠️  May not be using workspace pattern correctly${NC}"
            ((WARNINGS++))
        fi
        
        # Development can use -mod=mod to bypass vendor
        if grep -q "go build.*-mod=mod" "$dockerfile"; then
            echo -e "${GREEN}  ✅ Uses -mod=mod to bypass stale vendor (dev only)${NC}"
        fi
    fi
    
    # 4. Check for multi-stage build
    if grep -qE "FROM.*AS (builder|base)" "$dockerfile"; then
        echo -e "${GREEN}  ✅ Multi-stage build${NC}"
    else
        echo -e "${YELLOW}  ⚠️  Not using multi-stage build${NC}"
        ((WARNINGS++))
    fi
    
    # 5. Check for non-root user
    if grep -q "USER appuser" "$dockerfile" || grep -q "USER [0-9]" "$dockerfile"; then
        echo -e "${GREEN}  ✅ Runs as non-root user${NC}"
    else
        echo -e "${YELLOW}  ⚠️  May be running as root${NC}"
        ((WARNINGS++))
    fi
    
    # 6. Check for health check
    if grep -q "HEALTHCHECK" "$dockerfile"; then
        echo -e "${GREEN}  ✅ Has health check${NC}"
    else
        echo -e "${YELLOW}  ⚠️  Missing health check${NC}"
        ((WARNINGS++))
    fi
    
    # 7. Check for proper EXPOSE
    if grep -q "EXPOSE 8080" "$dockerfile"; then
        echo -e "${GREEN}  ✅ Exposes port 8080${NC}"
    else
        echo -e "${YELLOW}  ⚠️  Missing or incorrect EXPOSE directive${NC}"
        ((WARNINGS++))
    fi
    
    echo ""
}

echo "Production Dockerfiles:"
echo "----------------------"
for dockerfile in services/*/Dockerfile.prod; do
    if [ -f "$dockerfile" ]; then
        check_dockerfile "$dockerfile" "prod"
    fi
done

echo ""
echo "Development Dockerfiles:"
echo "-----------------------"
for dockerfile in services/*/Dockerfile.dev; do
    if [ -f "$dockerfile" ]; then
        check_dockerfile "$dockerfile" "dev"
    fi
done

# -----------------------------------------------------------------------------
# Structural parity: Dockerfile.dev vs Dockerfile.{prod,licensed,dist}
# -----------------------------------------------------------------------------
# Each Go service can have up to four Dockerfile variants — .dev (local
# docker-compose), .prod (internal/staging release), .licensed (dev-key
# license build, no obfuscation), and .dist (garble-obfuscated customer
# release). They share build logic: COPY graph, ENV, EXPOSE, HEALTHCHECK,
# CMD, non-root setup. They diverge in a small, known set of ways:
# base images (alpine vs DHI), optimizer flags, build tags, garble prefix,
# and an optional prod-only mkdir for /app/uploads.
#
# This check normalizes each file (strips comments/blanks, joins backslash
# continuations, collapses the allowed diffs) and then diffs .prod, .licensed,
# .dist (whichever exist) against the canonicalized .dev. Any leftover diff
# is a structural drift that will silently bite us when code that works in
# dev breaks in the release path (or vice versa).
#
# Allow-list of expected differences (anything else fails):
#   - Leading comment line                       (stripped)
#   - ARG GO_BUILDER_IMAGE / ARG RUNTIME_IMAGE   (dev/licensed-only; stripped)
#   - FROM ${GO_BUILDER_IMAGE} ↔ FROM <host>/dhi-proxy/golang:...
#       (normalized to <builder>)
#   - FROM ${RUNTIME_IMAGE}    ↔ FROM <host>/dhi-proxy/alpine-base:...
#       (normalized to <runtime>)
#   - go build -ldflags="-w -s"                  (prod/licensed/dist;
#       stripped)
#   - go build -tags ee                          (Enterprise edition selector on
#     carved services — see OPEN_SOURCE_CARVE_TRACKER.md §5.5; stripped)
#   - garble -literals [-tiny] build             (dist; normalized to
#       "go build" — the line entry point matches .dev/.prod after this.
#       -tiny is optional: compliance-engine drops it to avoid a garble/runtime
# "bad g in signal handler" crash under heavy concurrency —.)
#   - RUN go install mvdan.cc/garble@<version>   (dist-only; stripped — any
#       @latest or @vX.Y.Z pin accepted, dist images must pin to a release tag)
#   - "&& mkdir -p /app/uploads/..." + matching chown -R appuser:appgroup
#     /app/uploads tail                          (prod/licensed/dist;
#       stripped)
#
# Skipped:
#   - Python services (.dev and .prod intentionally differ — single-stage
#     vs multi-stage with --user installs).
#   - Missing variants (e.g. pcap-processor has no .licensed/.dist because
#     CGO can't be garbled).

PARITY_ERRORS=0

# Returns 0 if files are structurally equivalent after normalization.
# Echoes the normalized unified diff to stdout on mismatch (caller prints).
dockerfile_canonicalize() {
    # POSIX-ish pipeline:
    #   1. drop comment lines and blank lines
    #   2. join '\' continuations into a single line (collapsing the
    #      continuation whitespace to one space)
    #   3. strip the allowed diffs
    sed -E -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$1" \
    | awk '
        BEGIN { buf = "" }
        {
            line = $0
            if (match(line, /\\[[:space:]]*$/)) {
                sub(/[[:space:]]*\\[[:space:]]*$/, " ", line)
                buf = buf line
                next
            }
            if (buf != "") {
                sub(/^[[:space:]]+/, "", line)
                print buf line
                buf = ""
            } else {
                print line
            }
        }
        END { if (buf != "") print buf }
    ' \
    | sed -E \
        -e '/^ARG (GO_BUILDER_IMAGE|RUNTIME_IMAGE)=/d' \
        -e '/^RUN go install mvdan\.cc\/garble@(latest|v[0-9]+\.[0-9]+\.[0-9]+)$/d' \
        -e 's|^FROM \$\{GO_BUILDER_IMAGE\}|FROM <builder>|' \
        -e 's|^FROM \$\{RUNTIME_IMAGE\}$|FROM <runtime>|' \
        -e 's|^FROM [^ /]+(:[0-9]+)?/dhi-proxy/golang:[^ ]+|FROM <builder>|' \
        -e 's|^FROM [^ /]+(:[0-9]+)?/dhi-proxy/alpine-base:[^ ]+$|FROM <runtime>|' \
        -e 's|garble -literals( -tiny)? build|go build|g' \
        -e 's| -tags ee||g' \
        -e 's| -ldflags="-w -s"||g' \
        -e 's|[[:space:]]+&&[[:space:]]+chown -R appuser:appgroup /app/uploads[[:space:]]*$||' \
        -e 's|[[:space:]]+&&[[:space:]]+mkdir -p /app/uploads[^&]*$||'
}

echo ""
echo "Dev/Prod/Licensed/Dist Structural Parity (each variant compared to .dev):"
echo "------------------------------------------------------------------------"
for dev in services/*/Dockerfile.dev; do
    service_dir=$(dirname "$dev")
    service_name=$(basename "$service_dir")

    # Skip python services (intentionally different shapes). The .dev
    # may use FROM ${PYTHON_IMAGE} with `ARG PYTHON_IMAGE=python:...`,
    # so match the ARG line OR a literal FROM python:/dhi-proxy/python:.
    if grep -qE "^ARG PYTHON_IMAGE=|^FROM (dhi\.io/|[^/]+/dhi-proxy/)?python:" "$dev"; then
        echo -e "${BLUE}  ℹ️  $service_name: python service — skipping parity check${NC}"
        continue
    fi

    tmp_dev=$(mktemp)
    dockerfile_canonicalize "$dev" > "$tmp_dev"

    for variant in prod licensed dist; do
        target="$service_dir/Dockerfile.$variant"
        if [ ! -f "$target" ]; then
            # Missing variant is fine — e.g. pcap-processor has no .licensed
            # or .dist because its CGO+libpcap build can't be garbled.
            continue
        fi

        tmp_target=$(mktemp)
        dockerfile_canonicalize "$target" > "$tmp_target"

        if diff -q "$tmp_dev" "$tmp_target" >/dev/null 2>&1; then
            echo -e "${GREEN}  ✅ $service_name.$variant aligned with .dev${NC}"
        else
            # Default: STRICT — every drift is an error. The check is
            # stable now that pre-existing drifts have been reconciled.
            # Set STRICT_DOCKERFILE_PARITY=0 to demote drift to a warning;
            # use only when intentionally introducing a temporary
            # divergence.
            if [ "${STRICT_DOCKERFILE_PARITY:-1}" = "0" ]; then
                echo -e "${YELLOW}  ⚠️  $service_name: .dev ↔ .$variant drifted${NC}"
                ((WARNINGS++))
            else
                echo -e "${RED}  ❌ $service_name: .dev ↔ .$variant drifted${NC}"
                ((ERRORS++))
            fi
            echo "       Normalized diff (.dev → .$variant):"
            diff -u "$tmp_dev" "$tmp_target" | sed 's/^/         /'
            ((PARITY_ERRORS++))
        fi
        rm -f "$tmp_target"
    done

    rm -f "$tmp_dev"
done

if [ $PARITY_ERRORS -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}Note: dev/prod parity drift means a change to one Dockerfile was not${NC}"
    echo -e "${YELLOW}mirrored in the other. Replicate the change in both, or extend the${NC}"
    echo -e "${YELLOW}allow-list in dockerfile_canonicalize() if the diff is intentional.${NC}"
fi

# Summary
echo "============================"
echo "Summary:"
echo "--------"

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✅ All Dockerfiles are valid!${NC}"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Found $WARNINGS warning(s)${NC}"
    echo -e "${YELLOW}Warnings are informational and don't block commits${NC}"
    exit 0
else
    echo -e "${RED}❌ Found $ERRORS error(s) and $WARNINGS warning(s)${NC}"
    echo -e "${RED}Please fix errors before committing${NC}"
    echo ""
    echo "Common fixes:"
    echo "  - Update Go version to $EXPECTED_GO_VERSION"
    echo "  - Ensure workspace pattern (COPY go.work, shared, services)"
    echo "  - Remove 'go mod tidy' from production Dockerfiles (workspace handles deps)"
    echo "  - Remove -mod=mod from production Dockerfiles"
    echo "  - Add 'git' to apk add in builder stage"
    exit 1
fi
