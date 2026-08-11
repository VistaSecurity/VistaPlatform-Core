#!/bin/bash

# CORS Testing Script for Crypto Inventory Platform
# Tests all API endpoints for proper CORS configuration
#
# Documentation:
#   - See docsv4/development/standards/QUICK_REFERENCE.md for CORS configuration details
#   - See docsv4/architecture/api-gateway-patterns.md for gateway patterns
#   - See archive/docs_outdated/docs/development/CORS_TROUBLESHOOTING.md for troubleshooting

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
API_GATEWAY="http://localhost:8080"
FRONTEND_ORIGIN="http://localhost:3000"
ADMIN_ORIGIN="http://localhost:3006"
GATEWAY_HEALTH_ENDPOINT="$API_GATEWAY/api/v1/health"
GATEWAY_WAIT_SECS=30

# Obtain JWT for authenticated routes
AUTHORIZATION=""
if command -v jq >/dev/null 2>&1; then
  TOKEN=$("$(dirname "$0")"/dev-login.sh 2>/dev/null)
  if [ -n "$TOKEN" ]; then
    AUTHORIZATION="-H Authorization: Bearer $TOKEN"
  fi
fi

# Test results
PASSED=0
FAILED=0
WARNINGS=0

# Function to test CORS for an endpoint
test_cors() {
    local endpoint="$1"
    local method="${2:-GET}"
    local origin="${3:-$FRONTEND_ORIGIN}"
    local description="$4"
    
    echo -n "Testing $description ($method $endpoint)... "
    
    # Test preflight request
    local preflight_response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Origin: $origin" \
        -H "Access-Control-Request-Method: $method" \
        -H "Access-Control-Request-Headers: Content-Type, Authorization" \
        -X OPTIONS \
        "$API_GATEWAY$endpoint" 2>/dev/null || echo "000")
    
    if [ "$preflight_response" = "204" ] || [ "$preflight_response" = "200" ]; then
        
        local actual_response
        if [ -n "$AUTHORIZATION" ]; then
            # Split AUTHORIZATION into header and value
            local auth_header=$(echo "$AUTHORIZATION" | cut -d' ' -f2 | sed 's/:$//')
            local auth_value=$(echo "$AUTHORIZATION" | cut -d' ' -f3-)
            actual_response=$(curl -s -o /dev/null -w "%{http_code}" \
                -H "Origin: $origin" \
                -H "$auth_header: $auth_value" \
                -X "$method" \
                "$API_GATEWAY$endpoint" 2>/dev/null || echo "000")
        else
            actual_response=$(curl -s -o /dev/null -w "%{http_code}" \
                -H "Origin: $origin" \
                -X "$method" \
                "$API_GATEWAY$endpoint" 2>/dev/null || echo "000")
        fi
        
        # Add small delay to prevent rate limiting
        sleep 0.1
        
        # Check for CORS headers regardless of HTTP status code
        # CORS headers should be present even on error responses (500, 503, etc.)
        # We're testing CORS configuration, not service functionality
        local cors_headers
        if [ -n "$AUTHORIZATION" ]; then
            local auth_header=$(echo "$AUTHORIZATION" | cut -d' ' -f2 | sed 's/:$//')
            local auth_value=$(echo "$AUTHORIZATION" | cut -d' ' -f3-)
            cors_headers=$(curl -s -I -H "Origin: $origin" -H "$auth_header: $auth_value" "$API_GATEWAY$endpoint" 2>/dev/null | grep -i "access-control" || echo "")
        else
            cors_headers=$(curl -s -I -H "Origin: $origin" "$API_GATEWAY$endpoint" 2>/dev/null | grep -i "access-control" || echo "")
        fi
        
        # Accept any HTTP response that includes CORS headers
        # 200, 404, 401, 403, 405 are always acceptable
        # 400 for POST without body is acceptable
        # 500, 503 are acceptable if CORS headers are present (service errors, not CORS issues)
        if echo "$cors_headers" | grep -q "Access-Control-Allow-Origin"; then
            # CORS headers present - this is a pass for CORS testing
            if [ "$actual_response" = "200" ] || [ "$actual_response" = "404" ] || [ "$actual_response" = "401" ] || [ "$actual_response" = "403" ] || [ "$actual_response" = "405" ] || [ "$actual_response" = "500" ] || [ "$actual_response" = "503" ] || { [ "$method" = "POST" ] && [ "$actual_response" = "400" ]; }; then
                echo -e "${GREEN}✓ PASS${NC}"
                ((PASSED++))
            else
                # CORS headers present but unexpected status - still pass for CORS
                echo -e "${GREEN}✓ PASS (HTTP $actual_response, but CORS headers present)${NC}"
                ((PASSED++))
            fi
        else
            # No CORS headers - this is a CORS configuration failure
            echo -e "${RED}✗ FAIL - No CORS headers (HTTP $actual_response)${NC}"
            ((FAILED++))
        fi
    else
        echo -e "${RED}✗ FAIL - Preflight failed (HTTP $preflight_response)${NC}"
        ((FAILED++))
    fi
}

# Function to test CORS headers in detail
test_cors_headers() {
    local endpoint="$1"
    local origin="${2:-$FRONTEND_ORIGIN}"
    
    echo -e "\n${BLUE}Detailed CORS headers for $endpoint:${NC}"
    if [ -n "$AUTHORIZATION" ]; then
        local auth_header=$(echo "$AUTHORIZATION" | cut -d' ' -f2 | sed 's/:$//')
        local auth_value=$(echo "$AUTHORIZATION" | cut -d' ' -f3-)
        curl -s -I -H "Origin: $origin" -H "$auth_header: $auth_value" "$API_GATEWAY$endpoint" | grep -i "access-control" || echo "No CORS headers found"
    else
        curl -s -I -H "Origin: $origin" "$API_GATEWAY$endpoint" | grep -i "access-control" || echo "No CORS headers found"
    fi
}

# Wait for gateway to be reachable to avoid false negatives during boot
wait_for_gateway() {
  local attempt=0
  while [ $attempt -lt $GATEWAY_WAIT_SECS ]; do
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY_HEALTH_ENDPOINT" 2>/dev/null || echo "000")
    if [ "$status" = "200" ] || [ "$status" = "204" ]; then
      return 0
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  return 1
}

echo -e "${BLUE}🔍 CORS Testing for Crypto Inventory Platform${NC}"
echo "=================================================="
echo "API Gateway: $API_GATEWAY"
echo "Frontend Origin: $FRONTEND_ORIGIN"
echo "Admin Origin: $ADMIN_ORIGIN"
echo ""

if ! wait_for_gateway; then
  echo -e "${RED}Gateway ($GATEWAY_HEALTH_ENDPOINT) is not responding after ${GATEWAY_WAIT_SECS}s. Start api-gateway (docker compose up api-gateway) before running this test.${NC}"
  exit 1
fi

# Test core endpoints
echo -e "${YELLOW}Testing Core API Endpoints:${NC}"
test_cors "/api/v1/health" "GET" "$FRONTEND_ORIGIN" "Health Check"
test_cors "/api/v1/auth-service/" "GET" "$FRONTEND_ORIGIN" "Auth Service"
test_cors "/api/v1/inventory-service/" "GET" "$FRONTEND_ORIGIN" "Inventory Service"
test_cors "/api/v1/compliance-engine/" "GET" "$FRONTEND_ORIGIN" "Compliance Engine"
test_cors "/api/v1/sensor-manager/" "GET" "$FRONTEND_ORIGIN" "Sensor Manager"
test_cors "/api/v1/cbom-service/" "GET" "$FRONTEND_ORIGIN" "Report Generator"
test_cors "/api/v1/admin-service/" "GET" "$FRONTEND_ORIGIN" "Admin Service"

echo ""
echo -e "${YELLOW}Testing Frontend-Specific Endpoints:${NC}"
test_cors "/api/v1/sensor-manager/sensors" "GET" "$FRONTEND_ORIGIN" "Sensor List"
test_cors "/api/v1/sensor-manager/sensors/stats" "GET" "$FRONTEND_ORIGIN" "Sensor Stats"
test_cors "/api/v1/cbom-service/reports" "GET" "$FRONTEND_ORIGIN" "Reports List"
test_cors "/api/v1/cbom-service/reports/templates" "GET" "$FRONTEND_ORIGIN" "Report Templates"
test_cors "/api/v1/inventory-service/assets" "GET" "$FRONTEND_ORIGIN" "Assets List"
test_cors "/api/v1/admin-service/admin/stats/platform" "GET" "$ADMIN_ORIGIN" "Admin Platform Stats"

echo ""
echo -e "${YELLOW}Testing Admin-Specific Endpoints:${NC}"
test_cors "/api/v1/admin-service/admin/tenants" "GET" "$ADMIN_ORIGIN" "Admin Tenants"
test_cors "/api/v1/admin-service/admin/stats/platform" "GET" "$ADMIN_ORIGIN" "Admin Stats"

echo ""
echo -e "${YELLOW}Testing Admin Impersonation Endpoints:${NC}"
test_cors "/api/v1/auth-service/admin/impersonations" "POST" "$ADMIN_ORIGIN" "Start Impersonation"
test_cors "/api/v1/auth-service/admin/impersonations/stop" "POST" "$ADMIN_ORIGIN" "Stop Impersonation"
test_cors "/api/v1/auth-service/admin/impersonations/audit" "GET" "$ADMIN_ORIGIN" "Impersonation Audit"
test_cors "/api/v1/admin-service/admin/tenants/00000000-0000-0000-0000-000000000000/users" "GET" "$ADMIN_ORIGIN" "Tenant Users"

echo ""
echo -e "${YELLOW}Testing POST Endpoints:${NC}"
test_cors "/api/v1/sensor-manager/sensors/pending" "POST" "$FRONTEND_ORIGIN" "Create Pending Sensor"
test_cors "/api/v1/cbom-service/reports/generate" "POST" "$FRONTEND_ORIGIN" "Generate Report"

echo ""
echo -e "${YELLOW}Testing Auth Endpoints (new):${NC}"
test_cors "/api/v1/auth-service/auth/login" "POST" "$FRONTEND_ORIGIN" "Auth Login"
test_cors "/api/v1/auth-service/auth/me" "GET" "$FRONTEND_ORIGIN" "Auth Me"
test_cors "/api/v1/auth-service/auth/sso/providers" "GET" "$FRONTEND_ORIGIN" "Auth SSO Providers"

echo ""
echo -e "${YELLOW}Testing v2 API endpoints:${NC}"
test_cors "/api/v2/health" "GET" "$FRONTEND_ORIGIN" "v2 Health"
test_cors "/api/v2/auth-service/auth/sso/providers" "GET" "$FRONTEND_ORIGIN" "v2 Auth SSO Providers"
test_cors "/api/v2/auth-service/auth/login" "POST" "$FRONTEND_ORIGIN" "v2 Auth Login"
test_cors "/api/v2/inventory-service/" "GET" "$FRONTEND_ORIGIN" "v2 Inventory Service"

# Show detailed headers for failed tests
if [ $FAILED -gt 0 ]; then
    echo ""
    echo -e "${RED}❌ Some tests failed. Showing detailed CORS headers:${NC}"
    test_cors_headers "/api/v1/health" "$FRONTEND_ORIGIN"
fi

# Summary
echo ""
echo "=================================================="
echo -e "${BLUE}📊 CORS Test Summary:${NC}"
echo -e "  ${GREEN}✓ Passed: $PASSED${NC}"
echo -e "  ${RED}✗ Failed: $FAILED${NC}"
echo -e "  ${YELLOW}⚠ Warnings: $WARNINGS${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All CORS tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}❌ $FAILED CORS tests failed. Check configuration.${NC}"
    exit 1
fi
