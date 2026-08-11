#!/bin/bash

# Test script to debug compliance framework API issues
# This simulates what the browser is doing

echo "=== Testing Compliance Framework API ==="
echo ""

# Get JWT secret (should match admin-service)
JWT_SECRET="${JWT_SECRET:-dev-secret-key-change-in-production}"
ADMIN_API="http://localhost:8080/api/v1/admin-service"
COMPLIANCE_API="http://localhost:8080/api/v1/compliance-engine/admin"

# Step 1: Login to get a token
echo "Step 1: Logging in as platform admin..."
LOGIN_RESPONSE=$(curl -s -X POST "$ADMIN_API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "su_admin@example.com",
    "password": "Password123!"
  }')

echo "Login response:"
echo "$LOGIN_RESPONSE" | jq '.' 2>/dev/null || echo "$LOGIN_RESPONSE"
echo ""

# Extract token
TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token' 2>/dev/null)

if [ "$TOKEN" == "null" ] || [ -z "$TOKEN" ]; then
  echo "ERROR: Failed to get access token"
  exit 1
fi

echo "Got token: ${TOKEN:0:50}..."
echo ""

# Decode token to see claims (without verification, just for inspection)
echo "Step 2: Decoding token claims..."
PAYLOAD=$(echo "$TOKEN" | cut -d'.' -f2)
# Add padding if needed
PADDING=$((4 - ${#PAYLOAD} % 4))
if [ $PADDING -ne 4 ]; then
  PAYLOAD="${PAYLOAD}$(printf '%*s' $PADDING | tr ' ' '=')"
fi
echo "$PAYLOAD" | base64 -d 2>/dev/null | jq '.' 2>/dev/null || echo "Failed to decode"
echo ""

# Step 3: Try to list frameworks
echo "Step 3: Testing GET /frameworks..."
GET_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X GET "$COMPLIANCE_API/frameworks" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json")

HTTP_STATUS=$(echo "$GET_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$GET_RESPONSE" | sed '/HTTP_STATUS:/d')

echo "HTTP Status: $HTTP_STATUS"
echo "Response body:"
echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"
echo ""

# Step 4: Try to create a framework
echo "Step 4: Testing POST /frameworks..."
POST_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$COMPLIANCE_API/frameworks" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "test-framework",
    "name": "Test Framework",
    "description": "Test Description",
    "version": "1.0.0"
  }')

HTTP_STATUS=$(echo "$POST_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$POST_RESPONSE" | sed '/HTTP_STATUS:/d')

echo "HTTP Status: $HTTP_STATUS"
echo "Response body:"
echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"
echo ""

echo "=== Test Complete ==="
