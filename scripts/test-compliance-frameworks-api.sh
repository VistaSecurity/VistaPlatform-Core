#!/bin/bash

# Comprehensive test script for compliance framework APIs
# Tests platform admin and tenant workflows end-to-end

# Don't exit on error - we want to continue testing
set +e

API_GATEWAY="http://localhost:8080"
ADMIN_API="$API_GATEWAY/api/v1/admin-service"
COMPLIANCE_API="$API_GATEWAY/api/v1/compliance-engine"
COMPLIANCE_ADMIN_API="$COMPLIANCE_API/admin"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to print test results
print_test() {
    local name=$1
    local status=$2
    local details=$3
    
    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✓${NC} $name"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗${NC} $name"
        echo -e "  ${RED}Error:${NC} $details"
        ((TESTS_FAILED++))
    fi
}

# Helper function to make authenticated API calls
api_call() {
    local method=$1
    local url=$2
    local token=$3
    local data=$4
    
    if [ -n "$data" ]; then
        curl -s -w "\nHTTP_STATUS:%{http_code}" -X "$method" "$url" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$data"
    else
        curl -s -w "\nHTTP_STATUS:%{http_code}" -X "$method" "$url" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json"
    fi
}

# Extract HTTP status and body from response
extract_response() {
    local response=$1
    local http_status=$(echo "$response" | grep "HTTP_STATUS:" | cut -d':' -f2 | tr -d ' ' || echo "000")
    local body=$(echo "$response" | sed '/HTTP_STATUS:/d' || echo "")
    echo "$http_status|$body"
}

echo -e "${BLUE}=== Compliance Framework API Testing ===${NC}"
echo ""

# =================================================================
# Step 1: Platform Admin Authentication
# =================================================================
echo -e "${BLUE}Step 1: Platform Admin Authentication${NC}"

# Use admin-service login endpoint for platform admin
LOGIN_RESPONSE=$(curl -s -X POST "$ADMIN_API/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
        "email": "su_admin@example.com",
        "password": "Password123!"
    }')

ADMIN_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token' 2>/dev/null)

if [ "$ADMIN_TOKEN" == "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo -e "${RED}ERROR: Failed to authenticate as platform admin${NC}"
    echo "Response: $LOGIN_RESPONSE"
    exit 1
fi

print_test "Platform admin login" "PASS"
echo ""

# =================================================================
# Step 2: Get Available Measurement Types
# =================================================================
echo -e "${BLUE}Step 2: Get Available Measurement Types${NC}"

RESPONSE=$(api_call "GET" "$COMPLIANCE_API/measurement-types" "$ADMIN_TOKEN")
RESULT=$(extract_response "$RESPONSE")
HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
BODY=$(echo "$RESULT" | cut -d'|' -f2-)

if [ "$HTTP_STATUS" = "200" ]; then
    MEASUREMENT_TYPES=$(echo "$BODY" | jq -r '.measurement_types // .' 2>/dev/null)
    echo "Available measurement types:"
    echo "$MEASUREMENT_TYPES" | jq -r '.[] | "  - \(.code): \(.name)"' 2>/dev/null || echo "$MEASUREMENT_TYPES"
    print_test "List measurement types" "PASS"
else
    print_test "List measurement types" "FAIL" "HTTP $HTTP_STATUS: $BODY"
fi
echo ""

# =================================================================
# Step 3: Create Test Framework 1 - TLS Compliance
# =================================================================
echo -e "${BLUE}Step 3: Create Test Framework 1 - TLS Compliance${NC}"

TIMESTAMP=$(date +%s)
FRAMEWORK1_CODE="TEST-TLS-${TIMESTAMP}"

FRAMEWORK1_DATA=$(cat <<EOF
{
    "code": "$FRAMEWORK1_CODE",
    "name": "Test TLS Compliance Framework",
    "version": "1.0",
    "description": "Test framework for TLS compliance with various measurement types",
    "organization": "Test Organization"
}
EOF
)

RESPONSE=$(api_call "POST" "$COMPLIANCE_ADMIN_API/frameworks" "$ADMIN_TOKEN" "$FRAMEWORK1_DATA")
RESULT=$(extract_response "$RESPONSE")
HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
BODY=$(echo "$RESULT" | cut -d'|' -f2-)

if [ "$HTTP_STATUS" = "201" ]; then
    FRAMEWORK1_ID=$(echo "$BODY" | jq -r '.framework.id' 2>/dev/null)
    echo "Created framework: $FRAMEWORK1_ID"
    print_test "Create framework 1" "PASS"
else
    print_test "Create framework 1" "FAIL" "HTTP $HTTP_STATUS: $BODY"
    exit 1
fi
echo ""

# =================================================================
# Step 4: Add Controls to Framework 1
# =================================================================
echo -e "${BLUE}Step 4: Add Controls to Framework 1${NC}"

# Control 1: TLS Version Check
CONTROL1_DATA='{
    "control_id": "TLS-1.1",
    "title": "TLS Version Must Be 1.2 or Higher",
    "description": "All connections must use TLS 1.2 or higher",
    "baseline_severity": "High",
    "crypto_relevant": true
}'

RESPONSE=$(api_call "POST" "$COMPLIANCE_ADMIN_API/frameworks/$FRAMEWORK1_ID/controls" "$ADMIN_TOKEN" "$CONTROL1_DATA")
RESULT=$(extract_response "$RESPONSE")
HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
BODY=$(echo "$RESULT" | cut -d'|' -f2-)

if [ "$HTTP_STATUS" = "201" ]; then
    CONTROL1_ID=$(echo "$BODY" | jq -r '.control.id' 2>/dev/null)
    echo "Created control 1: $CONTROL1_ID"
    print_test "Add control 1 (TLS version)" "PASS"
else
    print_test "Add control 1" "FAIL" "HTTP $HTTP_STATUS: $BODY"
    CONTROL1_ID=""
fi

# Control 2: Cipher Suite Check
CONTROL2_DATA='{
    "control_id": "TLS-2.1",
    "title": "Strong Cipher Suites Required",
    "description": "Only approved cipher suites are allowed",
    "baseline_severity": "Med",
    "crypto_relevant": true
}'

RESPONSE=$(api_call "POST" "$COMPLIANCE_ADMIN_API/frameworks/$FRAMEWORK1_ID/controls" "$ADMIN_TOKEN" "$CONTROL2_DATA")
RESULT=$(extract_response "$RESPONSE")
HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')

if [ "$HTTP_STATUS" = "201" ]; then
    CONTROL2_ID=$(echo "$BODY" | jq -r '.control.id' 2>/dev/null)
    echo "Created control 2: $CONTROL2_ID"
    print_test "Add control 2 (Cipher suite)" "PASS"
else
    print_test "Add control 2" "FAIL" "HTTP $HTTP_STATUS: $BODY"
    CONTROL2_ID=""
fi

# Control 3: Certificate Validity
CONTROL3_DATA='{
    "control_id": "TLS-3.1",
    "title": "Certificate Validity Period",
    "description": "Certificates must not expire within 30 days",
    "baseline_severity": "Med",
    "crypto_relevant": true
}'

RESPONSE=$(api_call "POST" "$COMPLIANCE_ADMIN_API/frameworks/$FRAMEWORK1_ID/controls" "$ADMIN_TOKEN" "$CONTROL3_DATA")
RESULT=$(extract_response "$RESPONSE")
HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')

if [ "$HTTP_STATUS" = "201" ]; then
    CONTROL3_ID=$(echo "$BODY" | jq -r '.control.id' 2>/dev/null)
    echo "Created control 3: $CONTROL3_ID"
    print_test "Add control 3 (Certificate validity)" "PASS"
else
    print_test "Add control 3" "FAIL" "HTTP $HTTP_STATUS: $BODY"
    CONTROL3_ID=""
fi
echo ""

# =================================================================
# Step 5: Add Measurements to Controls (Test Different Rule Types)
# =================================================================
echo -e "${BLUE}Step 5: Add Measurements to Controls${NC}"

# First, get a measurement type ID (assuming TLS version exists)
MEASUREMENT_TYPES_RESPONSE=$(api_call "GET" "$COMPLIANCE_API/measurement-types" "$ADMIN_TOKEN")
MEASUREMENT_TYPES_RESULT=$(extract_response "$MEASUREMENT_TYPES_RESPONSE")
MEASUREMENT_TYPES_BODY=$(echo "$MEASUREMENT_TYPES_RESULT" | cut -d'|' -f2-)

# Try to find TLS version measurement type
TLS_VERSION_MT_ID=$(echo "$MEASUREMENT_TYPES_BODY" | jq -r '.[] | select(.code == "tls_version") | .id' 2>/dev/null || echo "")
CIPHER_SUITE_MT_ID=$(echo "$MEASUREMENT_TYPES_BODY" | jq -r '.[] | select(.code == "cipher_suite") | .id' 2>/dev/null || echo "")
CERT_VALIDITY_MT_ID=$(echo "$MEASUREMENT_TYPES_BODY" | jq -r '.[] | select(.code == "certificate_validity") | .id' 2>/dev/null || echo "")

# If measurement types don't exist, we'll use the first available one or create generic predicates
if [ -z "$TLS_VERSION_MT_ID" ] && [ -n "$CONTROL1_ID" ]; then
    # Use first available measurement type or create a generic one
    TLS_VERSION_MT_ID=$(echo "$MEASUREMENT_TYPES_BODY" | jq -r '.[0].id' 2>/dev/null || echo "")
fi

# Measurement 1: Threshold rule type (TLS version >= 1.2)
if [ -n "$CONTROL1_ID" ] && [ -n "$TLS_VERSION_MT_ID" ]; then
    MEASUREMENT1_DATA=$(cat <<EOF
{
    "measurement_type_id": "$TLS_VERSION_MT_ID",
    "rule_type": "threshold",
    "predicate": {
        "operator": ">=",
        "value": "1.2"
    },
    "severity_override": "High",
    "weight": 1.0
}
EOF
)
    
    RESPONSE=$(api_call "POST" "$COMPLIANCE_ADMIN_API/controls/$CONTROL1_ID/measurements" "$ADMIN_TOKEN" "$MEASUREMENT1_DATA")
    RESULT=$(extract_response "$RESPONSE")
    HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
    BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')
    
    if [ "$HTTP_STATUS" = "201" ]; then
        MEASUREMENT1_ID=$(echo "$BODY" | jq -r '.measurement.id' 2>/dev/null)
        echo "Created measurement 1 (threshold): $MEASUREMENT1_ID"
        print_test "Add measurement 1 (threshold rule)" "PASS"
    else
        print_test "Add measurement 1" "FAIL" "HTTP $HTTP_STATUS: $BODY"
    fi
fi

# Measurement 2: Presence rule type (Cipher suite must exist)
if [ -n "$CONTROL2_ID" ] && [ -n "$CIPHER_SUITE_MT_ID" ]; then
    MEASUREMENT2_DATA=$(cat <<EOF
{
    "measurement_type_id": "$CIPHER_SUITE_MT_ID",
    "rule_type": "presence",
    "predicate": {
        "required": true
    },
    "weight": 1.0
}
EOF
)
    
    RESPONSE=$(api_call "POST" "$COMPLIANCE_ADMIN_API/controls/$CONTROL2_ID/measurements" "$ADMIN_TOKEN" "$MEASUREMENT2_DATA")
    RESULT=$(extract_response "$RESPONSE")
    HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
    BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')
    
    if [ "$HTTP_STATUS" = "201" ]; then
        MEASUREMENT2_ID=$(echo "$BODY" | jq -r '.measurement.id' 2>/dev/null)
        echo "Created measurement 2 (presence): $MEASUREMENT2_ID"
        print_test "Add measurement 2 (presence rule)" "PASS"
    else
        print_test "Add measurement 2" "FAIL" "HTTP $HTTP_STATUS: $BODY"
    fi
fi

# Measurement 3: Pattern rule type (Certificate pattern matching)
if [ -n "$CONTROL3_ID" ] && [ -n "$CERT_VALIDITY_MT_ID" ]; then
    MEASUREMENT3_DATA=$(cat <<EOF
{
    "measurement_type_id": "$CERT_VALIDITY_MT_ID",
    "rule_type": "pattern",
    "predicate": {
        "pattern": "^[A-Z0-9-]+$",
        "flags": "i"
    },
    "weight": 0.8
}
EOF
)
    
    RESPONSE=$(api_call "POST" "$COMPLIANCE_ADMIN_API/controls/$CONTROL3_ID/measurements" "$ADMIN_TOKEN" "$MEASUREMENT3_DATA")
    RESULT=$(extract_response "$RESPONSE")
    HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
    BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')
    
    if [ "$HTTP_STATUS" = "201" ]; then
        MEASUREMENT3_ID=$(echo "$BODY" | jq -r '.measurement.id' 2>/dev/null)
        echo "Created measurement 3 (pattern): $MEASUREMENT3_ID"
        print_test "Add measurement 3 (pattern rule)" "PASS"
    else
        print_test "Add measurement 3" "FAIL" "HTTP $HTTP_STATUS: $BODY"
    fi
fi

# Measurement 4: Range rule type (Certificate expiration days)
if [ -n "$CONTROL3_ID" ] && [ -n "$CERT_VALIDITY_MT_ID" ]; then
    MEASUREMENT4_DATA=$(cat <<EOF
{
    "measurement_type_id": "$CERT_VALIDITY_MT_ID",
    "rule_type": "range",
    "predicate": {
        "min": 30,
        "max": 365
    },
    "weight": 1.0
}
EOF
)
    
    RESPONSE=$(api_call "POST" "$COMPLIANCE_ADMIN_API/controls/$CONTROL3_ID/measurements" "$ADMIN_TOKEN" "$MEASUREMENT4_DATA")
    RESULT=$(extract_response "$RESPONSE")
    HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
    BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')
    
    if [ "$HTTP_STATUS" = "201" ]; then
        MEASUREMENT4_ID=$(echo "$BODY" | jq -r '.measurement.id' 2>/dev/null)
        echo "Created measurement 4 (range): $MEASUREMENT4_ID"
        print_test "Add measurement 4 (range rule)" "PASS"
    else
        print_test "Add measurement 4" "FAIL" "HTTP $HTTP_STATUS: $BODY"
    fi
fi
echo ""

# =================================================================
# Step 6: Publish Framework 1
# =================================================================
echo -e "${BLUE}Step 6: Publish Framework 1${NC}"

PUBLISH_DATA='{
    "status": "published"
}'

RESPONSE=$(api_call "POST" "$COMPLIANCE_ADMIN_API/frameworks/$FRAMEWORK1_ID/publish" "$ADMIN_TOKEN" "$PUBLISH_DATA")
RESULT=$(extract_response "$RESPONSE")
HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')

if [ "$HTTP_STATUS" = "200" ]; then
    echo "Framework published successfully"
    print_test "Publish framework 1" "PASS"
else
    print_test "Publish framework 1" "FAIL" "HTTP $HTTP_STATUS: $BODY"
fi
echo ""

# =================================================================
# Step 7: Create Framework 2 (Simpler, for tenant customization testing)
# =================================================================
echo -e "${BLUE}Step 7: Create Framework 2 - Simple Test Framework${NC}"

FRAMEWORK2_CODE="TEST-SIMPLE-${TIMESTAMP}"

FRAMEWORK2_DATA=$(cat <<EOF
{
    "code": "$FRAMEWORK2_CODE",
    "name": "Simple Test Framework",
    "version": "1.0",
    "description": "Simple framework for tenant customization testing",
    "organization": "Test Organization"
}
EOF
)

RESPONSE=$(api_call "POST" "$COMPLIANCE_ADMIN_API/frameworks" "$ADMIN_TOKEN" "$FRAMEWORK2_DATA")
RESULT=$(extract_response "$RESPONSE")
HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')

if [ "$HTTP_STATUS" = "201" ]; then
    FRAMEWORK2_ID=$(echo "$BODY" | jq -r '.framework.id' 2>/dev/null)
    echo "Created framework 2: $FRAMEWORK2_ID"
    print_test "Create framework 2" "PASS"
    
    # Add one control
    SIMPLE_CONTROL_DATA='{
        "control_id": "SIMPLE-1.1",
        "title": "Simple Control",
        "description": "A simple control for testing",
        "baseline_severity": "Low",
        "crypto_relevant": false
    }'
    
    RESPONSE=$(api_call "POST" "$COMPLIANCE_ADMIN_API/frameworks/$FRAMEWORK2_ID/controls" "$ADMIN_TOKEN" "$SIMPLE_CONTROL_DATA")
    RESULT=$(extract_response "$RESPONSE")
    HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
    
    if [ "$HTTP_STATUS" = "201" ]; then
        echo "Added control to framework 2"
    fi
    
    # Publish framework 2
    RESPONSE=$(api_call "POST" "$COMPLIANCE_ADMIN_API/frameworks/$FRAMEWORK2_ID/publish" "$ADMIN_TOKEN" "$PUBLISH_DATA")
    RESULT=$(extract_response "$RESPONSE")
    HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
    
    if [ "$HTTP_STATUS" = "200" ]; then
        echo "Framework 2 published"
    fi
else
    print_test "Create framework 2" "FAIL" "HTTP $HTTP_STATUS: $BODY"
    FRAMEWORK2_ID=""
fi
echo ""

# =================================================================
# Step 8: Tenant Authentication
# =================================================================
echo -e "${BLUE}Step 8: Tenant Authentication${NC}"

# Login as tenant user (using dev tenant)
TENANT_LOGIN_RESPONSE=$(curl -s -X POST "$API_GATEWAY/api/v1/auth-service/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
        "email": "admin@democorp.com",
        "password": "Password123!"
    }')

TENANT_TOKEN=$(echo "$TENANT_LOGIN_RESPONSE" | jq -r '.access_token' 2>/dev/null)

if [ "$TENANT_TOKEN" == "null" ] || [ -z "$TENANT_TOKEN" ]; then
    echo -e "${YELLOW}WARNING: Failed to authenticate as tenant user${NC}"
    echo "Response: $TENANT_LOGIN_RESPONSE"
    echo "Skipping tenant tests..."
    TENANT_TOKEN=""
else
    print_test "Tenant login" "PASS"
fi
echo ""

# =================================================================
# Step 9: Tenant - List Published Frameworks
# =================================================================
if [ -n "$TENANT_TOKEN" ]; then
    echo -e "${BLUE}Step 9: Tenant - List Published Frameworks${NC}"
    
    RESPONSE=$(api_call "GET" "$COMPLIANCE_API/frameworks/published" "$TENANT_TOKEN")
    RESULT=$(extract_response "$RESPONSE")
    HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
    BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')
    
    if [ "$HTTP_STATUS" = "200" ]; then
        FRAMEWORK_COUNT=$(echo "$BODY" | jq -r '.frameworks | length' 2>/dev/null || echo "0")
        echo "Found $FRAMEWORK_COUNT published frameworks"
        print_test "List published frameworks (tenant)" "PASS"
    else
        print_test "List published frameworks (tenant)" "FAIL" "HTTP $HTTP_STATUS: $BODY"
    fi
    echo ""
    
    # =================================================================
    # Step 10: Tenant - View Published Framework
    # =================================================================
    if [ -n "$FRAMEWORK1_ID" ]; then
        echo -e "${BLUE}Step 10: Tenant - View Published Framework${NC}"
        
        RESPONSE=$(api_call "GET" "$COMPLIANCE_API/frameworks/published/$FRAMEWORK1_ID" "$TENANT_TOKEN")
        RESULT=$(extract_response "$RESPONSE")
        HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
        BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')
        
        if [ "$HTTP_STATUS" = "200" ]; then
            FRAMEWORK_NAME=$(echo "$BODY" | jq -r '.framework.name' 2>/dev/null)
            CONTROL_COUNT=$(echo "$BODY" | jq -r '.framework.controls | length' 2>/dev/null || echo "0")
            echo "Framework: $FRAMEWORK_NAME"
            echo "Controls: $CONTROL_COUNT"
            print_test "View published framework (tenant)" "PASS"
        else
            print_test "View published framework (tenant)" "FAIL" "HTTP $HTTP_STATUS: $BODY"
        fi
        echo ""
        
        # =================================================================
        # Step 11: Tenant - Copy Framework
        # =================================================================
        echo -e "${BLUE}Step 11: Tenant - Copy Framework${NC}"
        
        COPY_DATA=$(cat <<EOF
{
    "source_framework_id": "$FRAMEWORK1_ID",
    "name": "My Custom TLS Framework",
    "version": "1.0",
    "copy_controls": true
}
EOF
)
        
        RESPONSE=$(api_call "POST" "$COMPLIANCE_API/frameworks/copy" "$TENANT_TOKEN" "$COPY_DATA")
        RESULT=$(extract_response "$RESPONSE")
        HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
        BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')
        
        if [ "$HTTP_STATUS" = "201" ]; then
            TENANT_FRAMEWORK_ID=$(echo "$BODY" | jq -r '.framework.id' 2>/dev/null)
            echo "Copied framework: $TENANT_FRAMEWORK_ID"
            print_test "Copy framework to tenant" "PASS"
        else
            print_test "Copy framework to tenant" "FAIL" "HTTP $HTTP_STATUS: $BODY"
            TENANT_FRAMEWORK_ID=""
        fi
        echo ""
        
        # =================================================================
        # Step 12: Tenant - List Tenant Frameworks
        # =================================================================
        if [ -n "$TENANT_FRAMEWORK_ID" ]; then
            echo -e "${BLUE}Step 12: Tenant - List Tenant Frameworks${NC}"
            
            RESPONSE=$(api_call "GET" "$COMPLIANCE_API/frameworks/tenant" "$TENANT_TOKEN")
            RESULT=$(extract_response "$RESPONSE")
            HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
            BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')
            
            if [ "$HTTP_STATUS" = "200" ]; then
                TENANT_FW_COUNT=$(echo "$BODY" | jq -r '.frameworks | length' 2>/dev/null || echo "0")
                echo "Found $TENANT_FW_COUNT tenant frameworks"
                print_test "List tenant frameworks" "PASS"
            else
                print_test "List tenant frameworks" "FAIL" "HTTP $HTTP_STATUS: $BODY"
            fi
            echo ""
            
            # =================================================================
            # Step 13: Tenant - View Tenant Framework
            # =================================================================
            echo -e "${BLUE}Step 13: Tenant - View Tenant Framework${NC}"
            
            RESPONSE=$(api_call "GET" "$COMPLIANCE_API/frameworks/tenant/$TENANT_FRAMEWORK_ID" "$TENANT_TOKEN")
            RESULT=$(extract_response "$RESPONSE")
            HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
            BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')
            
            if [ "$HTTP_STATUS" = "200" ]; then
                TENANT_FW_NAME=$(echo "$BODY" | jq -r '.framework.name' 2>/dev/null)
                TENANT_CONTROL_COUNT=$(echo "$BODY" | jq -r '.framework.controls | length' 2>/dev/null || echo "0")
                echo "Tenant framework: $TENANT_FW_NAME"
                echo "Controls: $TENANT_CONTROL_COUNT"
                print_test "View tenant framework" "PASS"
            else
                print_test "View tenant framework" "FAIL" "HTTP $HTTP_STATUS: $BODY"
            fi
            echo ""
        fi
    fi
fi

# =================================================================
# Step 14: Platform Admin - List All Frameworks
# =================================================================
echo -e "${BLUE}Step 14: Platform Admin - List All Frameworks${NC}"

RESPONSE=$(api_call "GET" "$COMPLIANCE_ADMIN_API/frameworks" "$ADMIN_TOKEN")
RESULT=$(extract_response "$RESPONSE")
HTTP_STATUS=$(echo "$RESULT" | cut -d'|' -f1)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')

if [ "$HTTP_STATUS" = "200" ]; then
    TOTAL_FRAMEWORKS=$(echo "$BODY" | jq -r '.frameworks | length' 2>/dev/null || echo "$BODY" | jq -r 'length' 2>/dev/null || echo "0")
    PUBLISHED_COUNT=$(echo "$BODY" | jq -r '[.[] | select(.status == "published")] | length' 2>/dev/null || echo "0")
    echo "Total frameworks: $TOTAL_FRAMEWORKS"
    echo "Published: $PUBLISHED_COUNT"
    print_test "List all frameworks (admin)" "PASS"
else
    print_test "List all frameworks (admin)" "FAIL" "HTTP $HTTP_STATUS: $BODY"
fi
echo ""

# =================================================================
# Summary
# =================================================================
echo -e "${BLUE}=== Test Summary ===${NC}"
echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
