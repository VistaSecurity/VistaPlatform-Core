#!/bin/bash

# Test mTLS Configuration
# This script verifies that mTLS is properly configured and working across all services

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Testing mTLS Configuration...${NC}"
echo "======================================"
echo ""

# Source .env if present
if [ -f ".env" ]; then
    set -a
    source .env
    set +a
fi

# Check if OpenSSL is available
if ! command -v openssl >/dev/null 2>&1; then
    echo -e "${RED}Error: OpenSSL is required but not found${NC}"
    exit 1
fi

# Check if curl is available
if ! command -v curl >/dev/null 2>&1; then
    echo -e "${RED}Error: curl is required but not found${NC}"
    exit 1
fi

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

# Function to test service health endpoint (HTTP, port 8080)
test_health_endpoint() {
    local service_name=$1
    local port=$2
    local url="http://localhost:${port}/health"

    echo -e "${BLUE}Testing health endpoint: ${service_name} (HTTP port ${port})...${NC}"
    if curl -s -f -m 5 "$url" >/dev/null 2>&1; then
        echo -e "${GREEN}  ✅ Health endpoint accessible: ${url}${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}  ❌ Health endpoint not accessible: ${url}${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Function to test mTLS endpoint (HTTPS, port 8443)
test_mtls_endpoint() {
    local service_name=$1
    local port=$2
    local cert_dir="service-certs/${service_name}"
    local url="https://localhost:${port}/api/v1/${service_name}/health"

    echo -e "${BLUE}Testing mTLS endpoint: ${service_name} (HTTPS port ${port})...${NC}"

    # Check if certificates exist
    if [ ! -f "${cert_dir}/client-cert.pem" ] || [ ! -f "${cert_dir}/client-key.pem" ] || [ ! -f "${cert_dir}/platform-ca-cert.pem" ]; then
        echo -e "${YELLOW}  ⚠️  Certificates not found for ${service_name}, skipping mTLS test${NC}"
        return 0
    fi

    # Test with mTLS client certificate
    if curl -s -f -m 5 \
        --cert "${cert_dir}/client-cert.pem" \
        --key "${cert_dir}/client-key.pem" \
        --cacert "${cert_dir}/platform-ca-cert.pem" \
        --insecure \
        "$url" >/dev/null 2>&1; then
        echo -e "${GREEN}  ✅ mTLS endpoint accessible with valid certificate: ${url}${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}  ❌ mTLS endpoint not accessible: ${url}${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Function to test that mTLS endpoint rejects connections without certificate
test_mtls_rejects_no_cert() {
    local service_name=$1
    local port=$2
    local url="https://localhost:${port}/api/v1/${service_name}/health"

    echo -e "${BLUE}Testing mTLS rejects connections without certificate: ${service_name}...${NC}"

    # Try to connect without client certificate (should fail)
    if curl -s -f -m 5 --insecure "$url" >/dev/null 2>&1; then
        echo -e "${RED}  ❌ mTLS endpoint accepted connection without certificate (security issue!)${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    else
        echo -e "${GREEN}  ✅ mTLS endpoint correctly rejects connections without certificate${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi
}

# Function to verify certificate files exist
test_certificates_exist() {
    local service_name=$1
    local cert_dir="service-certs/${service_name}"

    echo -e "${BLUE}Checking certificates for ${service_name}...${NC}"

    local missing_certs=()
    [ ! -f "${cert_dir}/server-cert.pem" ] && missing_certs+=("server-cert.pem")
    [ ! -f "${cert_dir}/server-key.pem" ] && missing_certs+=("server-key.pem")
    [ ! -f "${cert_dir}/client-cert.pem" ] && missing_certs+=("client-cert.pem")
    [ ! -f "${cert_dir}/client-key.pem" ] && missing_certs+=("client-key.pem")
    [ ! -f "${cert_dir}/platform-ca-cert.pem" ] && missing_certs+=("platform-ca-cert.pem")

    if [ ${#missing_certs[@]} -eq 0 ]; then
        echo -e "${GREEN}  ✅ All certificates present${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}  ❌ Missing certificates: ${missing_certs[*]}${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Function to verify certificate validity
test_certificate_validity() {
    local service_name=$1
    local cert_dir="service-certs/${service_name}"

    echo -e "${BLUE}Verifying certificate validity for ${service_name}...${NC}"

    if [ ! -f "${cert_dir}/server-cert.pem" ] || [ ! -f "${cert_dir}/platform-ca-cert.pem" ]; then
        echo -e "${YELLOW}  ⚠️  Certificates not found, skipping validity check${NC}"
        return 0
    fi

    # Check if certificate is valid and not expired
    if openssl x509 -in "${cert_dir}/server-cert.pem" -noout -checkend 0 >/dev/null 2>&1; then
        echo -e "${GREEN}  ✅ Server certificate is valid and not expired${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}  ❌ Server certificate is expired or invalid${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi

    # Verify certificate is signed by platform CA
    if openssl verify -CAfile "${cert_dir}/platform-ca-cert.pem" "${cert_dir}/server-cert.pem" >/dev/null 2>&1; then
        echo -e "${GREEN}  ✅ Server certificate is signed by platform CA${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}  ❌ Server certificate is not signed by platform CA${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi

    return 0
}

# Get list of services from docker-compose
echo -e "${BLUE}Discovering services...${NC}"
SERVICES=(
    "auth-service:8081:8443"
    "inventory-service:8082:8443"
    "compliance-engine:8083:8443"
    "cbom-service:8084:8443"
    "sensor-manager:8085:8443"
    "cluster-sensor-service:8088:8443"
    "admin-service:8089:8443"
    "monitoring-service:8091:8443"
    "resource-tracker-service:8092:8443"
    "tenant-health-service:8093:8443"
    "device-interrogation-service:8095:8443"
    "audit-service:8096:8443"
    "notification-service:8097:8443"
    "discovery-processor-service:8090:8443"
)

echo ""
echo "1. Testing Certificate Files"
echo "----------------------------"
for service_info in "${SERVICES[@]}"; do
    IFS=':' read -r service_name http_port https_port <<< "$service_info"
    test_certificates_exist "$service_name"
done

echo ""
echo "2. Testing Certificate Validity"
echo "-------------------------------"
for service_info in "${SERVICES[@]}"; do
    IFS=':' read -r service_name http_port https_port <<< "$service_info"
    test_certificate_validity "$service_name"
done

echo ""
echo "3. Testing Health Endpoints (HTTP)"
echo "-----------------------------------"
for service_info in "${SERVICES[@]}"; do
    IFS=':' read -r service_name http_port https_port <<< "$service_info"
    test_health_endpoint "$service_name" "$http_port"
done

echo ""
echo "4. Testing mTLS Endpoints (HTTPS)"
echo "----------------------------------"
for service_info in "${SERVICES[@]}"; do
    IFS=':' read -r service_name http_port https_port <<< "$service_info"
    test_mtls_endpoint "$service_name" "$https_port"
done

echo ""
echo "5. Testing mTLS Security (Reject No Certificate)"
echo "-------------------------------------------------"
for service_info in "${SERVICES[@]}"; do
    IFS=':' read -r service_name http_port https_port <<< "$service_info"
    test_mtls_rejects_no_cert "$service_name" "$https_port"
done

echo ""
echo "======================================"
echo "Test Summary"
echo "======================================"
echo -e "${GREEN}Tests Passed: ${TESTS_PASSED}${NC}"
echo -e "${RED}Tests Failed: ${TESTS_FAILED}${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ All mTLS tests passed!${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}❌ Some mTLS tests failed${NC}"
    exit 1
fi
