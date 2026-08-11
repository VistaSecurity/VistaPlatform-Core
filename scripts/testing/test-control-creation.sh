#!/bin/bash

# Test script to debug control creation with measurements

echo "=== Testing Control Creation ==="
echo ""

JWT_SECRET="${JWT_SECRET:-dev-secret-key-change-in-production}"
ADMIN_API="http://localhost:8080/api/v1/admin-service"
COMPLIANCE_API="http://localhost:8080/api/v1/compliance-engine/admin"

# Step 1: Login
echo "Step 1: Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST "$ADMIN_API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "su_admin@example.com",
    "password": "Password123!"
  }')

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token' 2>/dev/null)

if [ "$TOKEN" == "null" ] || [ -z "$TOKEN" ]; then
  echo "ERROR: Failed to get access token"
  exit 1
fi

echo "Got token"
echo ""

# Step 2: Get or create a framework
echo "Step 2: Getting frameworks..."
FRAMEWORKS_RESPONSE=$(curl -s -X GET "$COMPLIANCE_API/frameworks" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json")

FRAMEWORK_ID=$(echo "$FRAMEWORKS_RESPONSE" | jq -r '.frameworks[0].id' 2>/dev/null)

if [ "$FRAMEWORK_ID" == "null" ] || [ -z "$FRAMEWORK_ID" ]; then
  echo "Creating a test framework..."
  CREATE_FRAMEWORK_RESPONSE=$(curl -s -X POST "$COMPLIANCE_API/frameworks" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "code": "test-framework-control",
      "name": "Test Framework for Control",
      "version": "1.0.0",
      "description": "Test"
    }')
  
  FRAMEWORK_ID=$(echo "$CREATE_FRAMEWORK_RESPONSE" | jq -r '.framework.id' 2>/dev/null)
fi

echo "Using framework ID: $FRAMEWORK_ID"
echo ""

# Step 3: Try to create a control
echo "Step 3: Testing POST /frameworks/$FRAMEWORK_ID/controls..."
CREATE_CONTROL_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$COMPLIANCE_API/frameworks/$FRAMEWORK_ID/controls" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "control_id": "TEST-001",
    "title": "Test Control",
    "description": "Test Description",
    "baseline_severity": "Med",
    "crypto_relevant": false,
    "family_id": ""
  }')

HTTP_STATUS=$(echo "$CREATE_CONTROL_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$CREATE_CONTROL_RESPONSE" | sed '/HTTP_STATUS:/d')

echo "HTTP Status: $HTTP_STATUS"
echo "Response body:"
echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"
echo ""

# Step 4: Try with null family_id
echo "Step 4: Testing with null family_id..."
CREATE_CONTROL_RESPONSE2=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$COMPLIANCE_API/frameworks/$FRAMEWORK_ID/controls" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "control_id": "TEST-002",
    "title": "Test Control 2",
    "description": "Test Description",
    "baseline_severity": "Med",
    "crypto_relevant": false
  }')

HTTP_STATUS2=$(echo "$CREATE_CONTROL_RESPONSE2" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY2=$(echo "$CREATE_CONTROL_RESPONSE2" | sed '/HTTP_STATUS:/d')

echo "HTTP Status: $HTTP_STATUS2"
echo "Response body:"
echo "$BODY2" | jq '.' 2>/dev/null || echo "$BODY2"
echo ""

echo "=== Test Complete ==="
