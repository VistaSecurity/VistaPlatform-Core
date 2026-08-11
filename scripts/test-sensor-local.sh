#!/bin/bash
# Local end-to-end test for sensor deployment flow
# This script tests the complete sensor registration and data flow locally

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
API_BASE="http://localhost:8080"
SENSOR_BIN="./bin/crypto-sensor"
TEST_LOG_FILE="./test-sensor-output.log"
TEST_DURATION=30

echo -e "${BLUE}🧪 Starting local sensor end-to-end test...${NC}"

# Function to check if services are running
check_services() {
    echo -e "${BLUE}Checking if services are running...${NC}"
    
    # Check if API gateway is responding
    if ! curl -s -f "$API_BASE/health" >/dev/null 2>&1; then
        echo -e "${RED}❌ API gateway not responding at $API_BASE${NC}"
        echo -e "${YELLOW}💡 Run './scripts/session-init.sh' to start services${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Services are running${NC}"
}

# Function to get a dev JWT token (simplified for testing)
get_dev_token() {
    echo -e "${BLUE}Getting dev JWT token...${NC}"
    
    # For testing, we'll use a simple approach
    # In a real scenario, you'd authenticate properly
    echo -e "${YELLOW}⚠️  Using mock token for testing - replace with real auth in production${NC}"
    echo "mock-jwt-token-for-testing"
}

# Function to create a pending sensor
create_pending_sensor() {
    echo -e "${BLUE}Creating pending sensor...${NC}"
    
    local token="$1"
    local response
    
    response=$(curl -s -X POST "$API_BASE/api/v1/sensor-manager/sensors/pending" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $token" \
        -H "X-Tenant-ID: test-tenant" \
        -d '{
            "name": "test-sensor-local",
            "ip_address": "192.168.1.100",
            "profile": "standard",
            "network_interfaces": ["eth0"],
            "tags": ["test", "local"],
            "description": "Local test sensor"
        }')
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✅ Pending sensor created${NC}"
        echo "$response"
    else
        echo -e "${RED}❌ Failed to create pending sensor${NC}"
        exit 1
    fi
}

# Function to extract registration key from response
extract_registration_key() {
    local response="$1"
    echo "$response" | grep -o '"registration_key":"[^"]*"' | cut -d'"' -f4
}

# Function to build sensor if not present
build_sensor_if_needed() {
    echo -e "${BLUE}Checking if sensor binary exists...${NC}"
    
    if [[ ! -f "$SENSOR_BIN" ]]; then
        echo -e "${YELLOW}⚠️  Sensor binary not found, building...${NC}"
        ./scripts/build-sensor.sh
    else
        echo -e "${GREEN}✅ Sensor binary found${NC}"
    fi
}

# Function to run sensor in test mode
run_sensor_test() {
    echo -e "${BLUE}Running sensor in test mode for ${TEST_DURATION}s...${NC}"
    
    local registration_key="$1"
    
    # Remove old test log
    rm -f "$TEST_LOG_FILE"
    
    # Run sensor with test flags
    timeout "$TEST_DURATION" "$SENSOR_BIN" \
        --register \
        --test \
        --registration-key "$registration_key" \
        --control-plane "$API_BASE" \
        --log-file "$TEST_LOG_FILE" \
        --test-duration "$TEST_DURATION" || true
    
    echo -e "${GREEN}✅ Sensor test completed${NC}"
}

# Function to validate test output
validate_test_output() {
    echo -e "${BLUE}Validating test output...${NC}"
    
    if [[ ! -f "$TEST_LOG_FILE" ]]; then
        echo -e "${RED}❌ Test log file not found: $TEST_LOG_FILE${NC}"
        return 1
    fi
    
    # Check for heartbeat entries
    local heartbeat_count=$(grep -c "heartbeat" "$TEST_LOG_FILE" || echo "0")
    echo -e "${BLUE}Heartbeat entries: $heartbeat_count${NC}"
    
    # Check for discovery entries
    local discovery_count=$(grep -c "discovery" "$TEST_LOG_FILE" || echo "0")
    echo -e "${BLUE}Discovery entries: $discovery_count${NC}"
    
    # Check for JSON structure
    local json_lines=$(grep -c "^{" "$TEST_LOG_FILE" || echo "0")
    echo -e "${BLUE}JSON entries: $json_lines${NC}"
    
    # Show sample output
    echo -e "${BLUE}Sample test output:${NC}"
    head -5 "$TEST_LOG_FILE" | cat
    
    if [[ $heartbeat_count -gt 0 && $discovery_count -gt 0 ]]; then
        echo -e "${GREEN}✅ Test output validation passed${NC}"
        return 0
    else
        echo -e "${RED}❌ Test output validation failed${NC}"
        return 1
    fi
}

# Function to test registration endpoint
test_registration_endpoint() {
    echo -e "${BLUE}Testing registration endpoint accessibility...${NC}"
    
    # Test without auth (should work)
    local response
    response=$(curl -s -X POST "$API_BASE/api/v1/sensor-manager/sensors/register" \
        -H "Content-Type: application/json" \
        -d '{
            "registration_key": "test-key",
            "name": "test-sensor",
            "platform": "linux",
            "version": "1.0.0",
            "profile": "standard"
        }' || echo "failed")
    
    if [[ "$response" != "failed" ]]; then
        echo -e "${GREEN}✅ Registration endpoint accessible without auth${NC}"
    else
        echo -e "${RED}❌ Registration endpoint not accessible${NC}"
        return 1
    fi
}

# Main test flow
main() {
    echo -e "${BLUE}🚀 Starting sensor deployment test...${NC}"
    
    # Step 1: Check services
    check_services
    
    # Step 2: Test registration endpoint
    test_registration_endpoint
    
    # Step 3: Get token and create pending sensor
    local token
    token=$(get_dev_token)
    
    local pending_response
    pending_response=$(create_pending_sensor "$token")
    
    # Step 4: Extract registration key
    local registration_key
    registration_key=$(extract_registration_key "$pending_response")
    
    if [[ -z "$registration_key" ]]; then
        echo -e "${RED}❌ Failed to extract registration key${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Registration key: $registration_key${NC}"
    
    # Step 5: Build sensor if needed
    build_sensor_if_needed
    
    # Step 6: Run sensor test
    run_sensor_test "$registration_key"
    
    # Step 7: Validate output
    if validate_test_output; then
        echo -e "${GREEN}🎉 End-to-end test completed successfully!${NC}"
        echo -e "${BLUE}Test log saved to: $TEST_LOG_FILE${NC}"
    else
        echo -e "${RED}❌ End-to-end test failed${NC}"
        exit 1
    fi
}

# Run main function
main "$@"
