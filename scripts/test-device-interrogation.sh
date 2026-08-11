#!/bin/bash
set -euo pipefail

# Device Interrogation Lab Test Script
# Tests device interrogation capability end-to-end in lab environment
#
# Usage:
#   ./scripts/test-device-interrogation.sh [device_type]
#
# Examples:
#   ./scripts/test-device-interrogation.sh              # Test all device types
#   ./scripts/test-device-interrogation.sh fortinet     # Test only Fortinet
#   ./scripts/test-device-interrogation.sh f5           # Test only F5
#   ./scripts/test-device-interrogation.sh cisco        # Test only Cisco
#   ./scripts/test-device-interrogation.sh palo_alto    # Test only Palo Alto
#   ./scripts/test-device-interrogation.sh aws          # Test AWS cloud discovery
#
# Prerequisites:
#   - All services running (./start-session.sh)
#   - ENCRYPTION_MASTER_KEY configured in device-interrogation-service
#   - Test devices configured (see docsv4/development/testing/device-interrogation-lab-setup.md)
#   - Platform integration created for cloud testing (AWS, etc.)

API_GATEWAY="${API_GATEWAY:-http://localhost:8080}"
DEVICE_API="$API_GATEWAY/api/v1/device-interrogation-service"
AUTH_API="$API_GATEWAY/api/v1/auth-service/auth"
EMAIL="${TEST_EMAIL:-admin@democorp.com}"
PASSWORD="${TEST_PASSWORD:-Password123!}"

# Test device configurations (override via environment variables)
# These should point to your lab test devices
FORTINET_HOST="${FORTINET_HOST:-fortinet-lab.example.com}"
FORTINET_USER="${FORTINET_USER:-admin}"
FORTINET_PASS="${FORTINET_PASS:-test-password}"

F5_HOST="${F5_HOST:-f5-lab.example.com}"
F5_USER="${F5_USER:-admin}"
F5_PASS="${F5_PASS:-test-password}"

CISCO_HOST="${CISCO_HOST:-cisco-lab.example.com}"
CISCO_USER="${CISCO_USER:-admin}"
CISCO_PASS="${CISCO_PASS:-test-password}"
CISCO_PORT="${CISCO_PORT:-22}"

PALO_ALTO_HOST="${PALO_ALTO_HOST:-palo-alto-lab.example.com}"
PALO_ALTO_USER="${PALO_ALTO_USER:-admin}"
PALO_ALTO_PASS="${PALO_ALTO_PASS:-test-password}"

UNIFI_HOST="${UNIFI_HOST:-unifi-lab.example.com}"
UNIFI_USER="${UNIFI_USER:-admin}"
UNIFI_PASS="${UNIFI_PASS:-test-password}"
UNIFI_PORT="${UNIFI_PORT:-8443}"
UNIFI_SITE_ID="${UNIFI_SITE_ID:-default}"  # Optional: specific site ID

AWS_INTEGRATION_ID="${AWS_INTEGRATION_ID:-}"  # UUID of AWS platform integration

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

log() {
    echo -e "${GREEN}[TEST]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if jq is available
if ! command -v jq >/dev/null 2>&1; then
    warn "jq not found - JSON parsing will be limited. Install jq for better output."
    JQ_AVAILABLE=false
else
    JQ_AVAILABLE=true
fi

# Extract JSON field (works with or without jq)
extract_field() {
    local field="$1"
    local json="$2"
    if [ "$JQ_AVAILABLE" = true ]; then
        echo "$json" | jq -r "$field // empty" 2>/dev/null || echo ""
    else
        echo "$json" | sed -n "s/.*\"$field\":\"\([^\"]*\)\".*/\1/p" | head -1
    fi
}

# Authenticate and get token
authenticate() {
    log "Authenticating as $EMAIL..."
    LOGIN_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
        "$AUTH_API/login" 2>/dev/null)

    if echo "$LOGIN_RESPONSE" | grep -q "access_token"; then
        TOKEN=$(extract_field "access_token" "$LOGIN_RESPONSE")
        if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
            error "Failed to extract token from login response"
            return 1
        fi
        log "✓ Authentication successful"
        return 0
    else
        error "Login failed: $LOGIN_RESPONSE"
        return 1
    fi
}

# Create platform integration for device credentials
create_platform_integration() {
    local integration_type="$1"
    local name="$2"
    local credentials_json="$3"

    info "Creating platform integration: $name"
    INTEGRATION_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{
            \"integration_type\": \"$integration_type\",
            \"name\": \"$name\",
            \"credentials\": $credentials_json,
            \"status\": \"active\"
        }" \
        "$API_GATEWAY/api/v1/admin-service/integrations" 2>/dev/null)

    if echo "$INTEGRATION_RESPONSE" | grep -q "id"; then
        INTEGRATION_ID=$(extract_field "id" "$INTEGRATION_RESPONSE")
        log "✓ Platform integration created: $INTEGRATION_ID"
        echo "$INTEGRATION_ID"
        return 0
    else
        error "Failed to create platform integration: $INTEGRATION_RESPONSE"
        return 1
    fi
}

# Create device
create_device() {
    local device_type="$1"
    local hostname="$2"
    local ip_address="$3"
    local management_url="$4"
    local credential_id="$5"
    local metadata="${6:-{}}"

    info "Creating device: $device_type ($hostname)"
    DEVICE_PAYLOAD=$(cat <<EOF
{
    "device_type": "$device_type",
    "vendor": "$(echo $device_type | tr '[:lower:]' '[:upper:]')",
    "hostname": "$hostname",
    "ip_address": "$ip_address",
    "management_url": "$management_url",
    "discovery_method": "device_interrogation",
    "credential_id": "$credential_id",
    "metadata": $metadata
}
EOF
)

    DEVICE_RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$DEVICE_PAYLOAD" \
        "$DEVICE_API/devices" 2>/dev/null)

    if echo "$DEVICE_RESPONSE" | grep -q "id"; then
        DEVICE_ID=$(extract_field "id" "$DEVICE_RESPONSE")
        log "✓ Device created: $DEVICE_ID"
        echo "$DEVICE_ID"
        return 0
    else
        error "Failed to create device: $DEVICE_RESPONSE"
        return 1
    fi
}

# Interrogate device
interrogate_device() {
    local device_id="$1"
    local device_type="$2"

    info "Interrogating device: $device_id ($device_type)"
    INTERROGATE_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
        -H "Authorization: Bearer $TOKEN" \
        "$DEVICE_API/devices/$device_id/interrogate" 2>/dev/null)

    HTTP_STATUS=$(echo "$INTERROGATE_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
    BODY=$(echo "$INTERROGATE_RESPONSE" | sed '/HTTP_STATUS:/d')

    if [ "$HTTP_STATUS" = "202" ]; then
        JOB_ID=$(extract_field "job_id" "$BODY")
        log "✓ Interrogation job queued: $JOB_ID"
        echo "$JOB_ID"
        return 0
    else
        error "Interrogation failed (HTTP $HTTP_STATUS): $BODY"
        return 1
    fi
}

# Wait for discovery job to complete
wait_for_job() {
    local job_id="$1"
    local max_wait="${2:-120}"  # Default 2 minutes
    local wait_interval="${3:-5}"  # Check every 5 seconds

    info "Waiting for job $job_id to complete (max ${max_wait}s)..."
    ELAPSED=0
    JOB_STATUS=""

    while [ $ELAPSED -lt $max_wait ]; do
        JOB_RESPONSE=$(curl -s -X GET \
            -H "Authorization: Bearer $TOKEN" \
            "$API_GATEWAY/api/v1/discovery/jobs/$job_id" 2>/dev/null)

        JOB_STATUS=$(extract_field "status" "$JOB_RESPONSE")

        if [ "$JOB_STATUS" = "completed" ]; then
            log "✓ Job completed successfully"
            return 0
        elif [ "$JOB_STATUS" = "failed" ]; then
            ERROR_MSG=$(extract_field "error_message" "$JOB_RESPONSE")
            error "Job failed: $ERROR_MSG"
            return 1
        fi

        sleep "$wait_interval"
        ELAPSED=$((ELAPSED + wait_interval))
        echo -n "."
    done

    echo ""
    warn "Job did not complete within ${max_wait}s (status: $JOB_STATUS)"
    return 1
}

# Get discovery job results
get_job_results() {
    local job_id="$1"

    info "Getting job results: $job_id"
    RESULTS_RESPONSE=$(curl -s -X GET \
        -H "Authorization: Bearer $TOKEN" \
        "$API_GATEWAY/api/v1/discovery/jobs/$job_id/results" 2>/dev/null)

    if [ "$JQ_AVAILABLE" = true ]; then
        echo "$RESULTS_RESPONSE" | jq '.'
    else
        echo "$RESULTS_RESPONSE"
    fi

    # Count discovered assets
    if [ "$JQ_AVAILABLE" = true ]; then
        ASSET_COUNT=$(echo "$RESULTS_RESPONSE" | jq '.findings | length' 2>/dev/null || echo "0")
    else
        ASSET_COUNT=$(echo "$RESULTS_RESPONSE" | grep -o '"findings"' | wc -l || echo "0")
    fi

    if [ "$ASSET_COUNT" -gt 0 ]; then
        log "✓ Found $ASSET_COUNT discovered assets"
        return 0
    else
        warn "No assets discovered"
        return 1
    fi
}

# Test Fortinet device
test_fortinet() {
    log "=== Testing Fortinet Device Interrogation ==="

    # Create platform integration
    CREDENTIALS_JSON="{\"username\":\"$FORTINET_USER\",\"password\":\"$FORTINET_PASS\"}"
    CREDENTIAL_ID=$(create_platform_integration "fortinet" "Fortinet Lab Device" "$CREDENTIALS_JSON")
    if [ -z "$CREDENTIAL_ID" ]; then
        error "Failed to create Fortinet integration"
        return 1
    fi

    # Create device
    DEVICE_ID=$(create_device \
        "fortinet" \
        "$FORTINET_HOST" \
        "$FORTINET_HOST" \
        "https://$FORTINET_HOST" \
        "$CREDENTIAL_ID" \
        "{\"environment\":\"lab\"}")

    if [ -z "$DEVICE_ID" ]; then
        error "Failed to create Fortinet device"
        return 1
    fi

    # Interrogate
    JOB_ID=$(interrogate_device "$DEVICE_ID" "fortinet")
    if [ -z "$JOB_ID" ]; then
        error "Failed to start Fortinet interrogation"
        return 1
    fi

    # Wait for completion
    if wait_for_job "$JOB_ID" 120; then
        # Get results
        if get_job_results "$JOB_ID"; then
            TESTS_PASSED=$((TESTS_PASSED + 1))
            log "✓ Fortinet test passed"
            return 0
        fi
    fi

    error "Fortinet test failed"
    return 1
}

# Test F5 device
test_f5() {
    log "=== Testing F5 BigIP Device Interrogation ==="

    # Create platform integration
    CREDENTIALS_JSON="{\"username\":\"$F5_USER\",\"password\":\"$F5_PASS\"}"
    CREDENTIAL_ID=$(create_platform_integration "f5" "F5 Lab Device" "$CREDENTIALS_JSON")
    if [ -z "$CREDENTIAL_ID" ]; then
        error "Failed to create F5 integration"
        return 1
    fi

    # Create device
    DEVICE_ID=$(create_device \
        "f5" \
        "$F5_HOST" \
        "$F5_HOST" \
        "https://$F5_HOST" \
        "$CREDENTIAL_ID" \
        "{\"environment\":\"lab\"}")

    if [ -z "$DEVICE_ID" ]; then
        error "Failed to create F5 device"
        return 1
    fi

    # Interrogate
    JOB_ID=$(interrogate_device "$DEVICE_ID" "f5")
    if [ -z "$JOB_ID" ]; then
        error "Failed to start F5 interrogation"
        return 1
    fi

    # Wait for completion
    if wait_for_job "$JOB_ID" 120; then
        # Get results
        if get_job_results "$JOB_ID"; then
            TESTS_PASSED=$((TESTS_PASSED + 1))
            log "✓ F5 test passed"
            return 0
        fi
    fi

    error "F5 test failed"
    return 1
}

# Test Cisco device
test_cisco() {
    log "=== Testing Cisco Device Interrogation ==="

    # Create platform integration
    CREDENTIALS_JSON="{\"username\":\"$CISCO_USER\",\"password\":\"$CISCO_PASS\"}"
    CREDENTIAL_ID=$(create_platform_integration "cisco" "Cisco Lab Device" "$CREDENTIALS_JSON")
    if [ -z "$CREDENTIAL_ID" ]; then
        error "Failed to create Cisco integration"
        return 1
    fi

    # Create device
    DEVICE_ID=$(create_device \
        "cisco_router" \
        "$CISCO_HOST" \
        "$CISCO_HOST" \
        "ssh://$CISCO_HOST:$CISCO_PORT" \
        "$CREDENTIAL_ID" \
        "{\"environment\":\"lab\",\"ssh_port\":$CISCO_PORT}")

    if [ -z "$DEVICE_ID" ]; then
        error "Failed to create Cisco device"
        return 1
    fi

    # Interrogate
    JOB_ID=$(interrogate_device "$DEVICE_ID" "cisco_router")
    if [ -z "$JOB_ID" ]; then
        error "Failed to start Cisco interrogation"
        return 1
    fi

    # Wait for completion
    if wait_for_job "$JOB_ID" 120; then
        # Get results
        if get_job_results "$JOB_ID"; then
            TESTS_PASSED=$((TESTS_PASSED + 1))
            log "✓ Cisco test passed"
            return 0
        fi
    fi

    error "Cisco test failed"
    return 1
}

# Test Palo Alto device
test_palo_alto() {
    log "=== Testing Palo Alto Device Interrogation ==="

    # Create platform integration
    CREDENTIALS_JSON="{\"username\":\"$PALO_ALTO_USER\",\"password\":\"$PALO_ALTO_PASS\"}"
    CREDENTIAL_ID=$(create_platform_integration "palo_alto" "Palo Alto Lab Device" "$CREDENTIALS_JSON")
    if [ -z "$CREDENTIAL_ID" ]; then
        error "Failed to create Palo Alto integration"
        return 1
    fi

    # Create device
    DEVICE_ID=$(create_device \
        "palo_alto" \
        "$PALO_ALTO_HOST" \
        "$PALO_ALTO_HOST" \
        "https://$PALO_ALTO_HOST" \
        "$CREDENTIAL_ID" \
        "{\"environment\":\"lab\"}")

    if [ -z "$DEVICE_ID" ]; then
        error "Failed to create Palo Alto device"
        return 1
    fi

    # Interrogate
    JOB_ID=$(interrogate_device "$DEVICE_ID" "palo_alto")
    if [ -z "$JOB_ID" ]; then
        error "Failed to start Palo Alto interrogation"
        return 1
    fi

    # Wait for completion
    if wait_for_job "$JOB_ID" 120; then
        # Get results
        if get_job_results "$JOB_ID"; then
            TESTS_PASSED=$((TESTS_PASSED + 1))
            log "✓ Palo Alto test passed"
            return 0
        fi
    fi

    error "Palo Alto test failed"
    return 1
}

# Test UniFi device
test_unifi() {
    log "=== Testing UniFi Device Interrogation ==="

    # Create platform integration
    CREDENTIALS_JSON="{\"username\":\"$UNIFI_USER\",\"password\":\"$UNIFI_PASS\"}"
    CREDENTIAL_ID=$(create_platform_integration "unifi" "UniFi Lab Device" "$CREDENTIALS_JSON")
    if [ -z "$CREDENTIAL_ID" ]; then
        error "Failed to create UniFi integration"
        return 1
    fi

    # Create device metadata with optional site ID
    METADATA_JSON="{\"environment\":\"lab\""
    if [ "$UNIFI_SITE_ID" != "default" ] && [ -n "$UNIFI_SITE_ID" ]; then
        METADATA_JSON="$METADATA_JSON,\"site_id\":\"$UNIFI_SITE_ID\""
    fi
    METADATA_JSON="$METADATA_JSON}"

    # Create device
    DEVICE_ID=$(create_device \
        "unifi" \
        "$UNIFI_HOST" \
        "$UNIFI_HOST" \
        "https://$UNIFI_HOST:$UNIFI_PORT" \
        "$CREDENTIAL_ID" \
        "$METADATA_JSON")

    if [ -z "$DEVICE_ID" ]; then
        error "Failed to create UniFi device"
        return 1
    fi

    # Interrogate
    JOB_ID=$(interrogate_device "$DEVICE_ID" "unifi")
    if [ -z "$JOB_ID" ]; then
        error "Failed to start UniFi interrogation"
        return 1
    fi

    # Wait for completion
    if wait_for_job "$JOB_ID" 120; then
        # Get results
        if get_job_results "$JOB_ID"; then
            TESTS_PASSED=$((TESTS_PASSED + 1))
            log "✓ UniFi test passed"
            return 0
        fi
    fi

    error "UniFi test failed"
    return 1
}

# Test AWS cloud discovery
test_aws_cloud() {
    log "=== Testing AWS Cloud Discovery ==="

    if [ -z "$AWS_INTEGRATION_ID" ]; then
        warn "AWS_INTEGRATION_ID not set - skipping AWS cloud test"
        warn "Set AWS_INTEGRATION_ID environment variable to test AWS cloud discovery"
        return 1
    fi

    info "Discovering AWS cloud resources..."
    DISCOVER_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{
            \"integration_id\": \"$AWS_INTEGRATION_ID\",
            \"resource_types\": [\"alb\", \"elb\", \"nlb\"],
            \"regions\": [\"us-east-1\"]
        }" \
        "$DEVICE_API/cloud/discover" 2>/dev/null)

    HTTP_STATUS=$(echo "$DISCOVER_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
    BODY=$(echo "$DISCOVER_RESPONSE" | sed '/HTTP_STATUS:/d')

    if [ "$HTTP_STATUS" = "202" ]; then
        JOB_ID=$(extract_field "job_id" "$BODY")
        log "✓ AWS discovery job queued: $JOB_ID"

        # Wait for completion
        if wait_for_job "$JOB_ID" 180; then
            # Get results
            if get_job_results "$JOB_ID"; then
                TESTS_PASSED=$((TESTS_PASSED + 1))
                log "✓ AWS cloud test passed"
                return 0
            fi
        fi
    else
        error "AWS discovery failed (HTTP $HTTP_STATUS): $BODY"
        return 1
    fi

    error "AWS cloud test failed"
    return 1
}

# Main test execution
main() {
    local test_type="${1:-all}"

    echo "=========================================="
    echo "Device Interrogation Lab Test"
    echo "=========================================="
    echo ""

    # Authenticate
    if ! authenticate; then
        error "Authentication failed - cannot proceed"
        exit 1
    fi

    echo ""

    # Run tests based on argument
    case "$test_type" in
        fortinet|fortigate)
            test_fortinet
            ;;
        f5|bigip)
            test_f5
            ;;
        cisco)
            test_cisco
            ;;
        palo_alto|paloalto)
            test_palo_alto
            ;;
        unifi|ubiquiti|unifi_controller|udm_pro)
            test_unifi
            ;;
        aws|cloud)
            test_aws_cloud
            ;;
        all)
            log "Running all device interrogation tests..."
            echo ""
            test_fortinet
            echo ""
            test_f5
            echo ""
            test_cisco
            echo ""
            test_palo_alto
            echo ""
            test_unifi
            echo ""
            test_aws_cloud
            ;;
        *)
            error "Unknown test type: $test_type"
            echo "Usage: $0 [fortinet|f5|cisco|palo_alto|unifi|aws|all]"
            exit 1
            ;;
    esac

    echo ""
    echo "=========================================="
    echo "Test Summary"
    echo "=========================================="
    echo "Passed:  $TESTS_PASSED"
    echo "Failed:  $TESTS_FAILED"
    echo "Skipped: $TESTS_SKIPPED"
    echo "=========================================="

    if [ $TESTS_FAILED -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# Run main function
main "$@"
