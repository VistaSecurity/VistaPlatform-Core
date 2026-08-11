#!/bin/bash

# Test script for network segment tagging and ownership functionality
# Uses v2 API: locations + network-segments. Tests classification and tag application.
#
# Prerequisites:
# - Database must be running and accessible
# - Environment variables must be set (see script for details)
# - API must be running

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
API_BASE_URL="${API_BASE_URL:-http://localhost:8080}"
TENANT_SLUG="${TENANT_SLUG:-demo-corp}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin123}"

echo -e "${GREEN}=== Network Segment Tagging Test Suite (v2 API) ===${NC}\n"

# Step 1: Authenticate and get token
echo -e "${YELLOW}Step 1: Authenticating...${NC}"
AUTH_RESPONSE=$(curl -s -X POST "${API_BASE_URL}/api/v1/auth-service/auth/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"${ADMIN_EMAIL}\",
    \"password\": \"${ADMIN_PASSWORD}\"
  }")

TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.token // .access_token // empty')

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
  echo -e "${RED}Failed to authenticate. Response:${NC}"
  echo "$AUTH_RESPONSE" | jq '.'
  exit 1
fi

echo -e "${GREEN}✓ Authenticated successfully${NC}\n"

# Step 2: Get tenant ID
echo -e "${YELLOW}Step 2: Getting tenant information...${NC}"
TENANT_RESPONSE=$(curl -s -X GET "${API_BASE_URL}/api/v1/admin-service/tenants" \
  -H "Authorization: Bearer ${TOKEN}")

TENANT_ID=$(echo "$TENANT_RESPONSE" | jq -r ".tenants[] | select(.slug == \"${TENANT_SLUG}\") | .id")

if [ -z "$TENANT_ID" ] || [ "$TENANT_ID" == "null" ]; then
  echo -e "${RED}Failed to find tenant '${TENANT_SLUG}'. Response:${NC}"
  echo "$TENANT_RESPONSE" | jq '.'
  exit 1
fi

echo -e "${GREEN}✓ Found tenant: ${TENANT_SLUG} (${TENANT_ID})${NC}\n"

# Step 3: Create location and network segment with tags (v2 API)
echo -e "${YELLOW}Step 3: Creating location and network segment with tags (v2)...${NC}"
LOC_RESPONSE=$(curl -s -X POST "${API_BASE_URL}/api/v2/inventory-service/locations" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name": "TestSite", "location_type": "site"}')
if echo "$LOC_RESPONSE" | jq -e '.error' > /dev/null; then
  echo -e "${RED}Failed to create location. Response:${NC}"
  echo "$LOC_RESPONSE" | jq '.'
  exit 1
fi
LOCATION_ID=$(echo "$LOC_RESPONSE" | jq -r '.id')
if [ -z "$LOCATION_ID" ] || [ "$LOCATION_ID" == "null" ]; then
  echo -e "${RED}Location ID missing. Response:${NC}"
  echo "$LOC_RESPONSE" | jq '.'
  exit 1
fi

SEG_RESPONSE=$(curl -s -X POST "${API_BASE_URL}/api/v2/inventory-service/network-segments" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Dev 192.168.100\",
    \"segment_type\": \"cidr\",
    \"value\": \"192.168.100.0/24\",
    \"network_type\": \"private\",
    \"environment\": \"development\",
    \"location_id\": \"${LOCATION_ID}\",
    \"description\": \"Development network for testing\",
    \"is_active\": true,
    \"auto_approve_discoveries\": false,
    \"tags\": {\"environment\": \"dev\", \"team\": \"backend\"}
  }")
if echo "$SEG_RESPONSE" | jq -e '.error' > /dev/null; then
  echo -e "${RED}Failed to create network segment. Response:${NC}"
  echo "$SEG_RESPONSE" | jq '.'
  exit 1
fi
SEGMENT_ID=$(echo "$SEG_RESPONSE" | jq -r '.id')
echo -e "${GREEN}✓ Location and network segment created successfully${NC}\n"

# Step 4: Verify network segment was created
echo -e "${YELLOW}Step 4: Verifying network segment...${NC}"
GET_SEGMENTS_RESPONSE=$(curl -s -X GET "${API_BASE_URL}/api/v2/inventory-service/network-segments" \
  -H "Authorization: Bearer ${TOKEN}")
SEGMENT_COUNT=$(echo "$GET_SEGMENTS_RESPONSE" | jq '.network_segments | length')
if [ "$SEGMENT_COUNT" -eq 0 ]; then
  echo -e "${RED}No network segments found. Response:${NC}"
  echo "$GET_SEGMENTS_RESPONSE" | jq '.'
  exit 1
fi
CREATED_SEG=$(echo "$GET_SEGMENTS_RESPONSE" | jq ".network_segments[] | select(.id == \"${SEGMENT_ID}\")")
ENV_TAG=$(echo "$CREATED_SEG" | jq -r '.tags.environment // empty')
TEAM_TAG=$(echo "$CREATED_SEG" | jq -r '.tags.team // empty')
if [ "$ENV_TAG" != "dev" ] || [ "$TEAM_TAG" != "backend" ]; then
  echo -e "${RED}Tags not correctly saved. Expected environment=dev, team=backend. Got:${NC}"
  echo "$CREATED_SEG" | jq '.tags'
  exit 1
fi
echo -e "${GREEN}✓ Network segment verified with tags: environment=${ENV_TAG}, team=${TEAM_TAG}${NC}\n"

# Step 5: Create an asset in the network range
echo -e "${YELLOW}Step 5: Creating asset in network range...${NC}"
ASSET_RESPONSE=$(curl -s -X POST "${API_BASE_URL}/api/v2/inventory-service/infrastructure-assets" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"hostname\": \"test-server.example.com\",
    \"ip_address\": \"192.168.100.50\",
    \"port\": 443,
    \"asset_type\": \"server\",
    \"description\": \"Test asset for network space tagging\"
  }")

if echo "$ASSET_RESPONSE" | jq -e '.error' > /dev/null; then
  echo -e "${RED}Failed to create asset. Response:${NC}"
  echo "$ASSET_RESPONSE" | jq '.'
  exit 1
fi

ASSET_ID=$(echo "$ASSET_RESPONSE" | jq -r '.id // .asset.id')
ASSET_OWNERSHIP=$(echo "$ASSET_RESPONSE" | jq -r '.asset_ownership // .asset.asset_ownership // empty')
ASSET_ENV_TAG=$(echo "$ASSET_RESPONSE" | jq -r '.tags.environment // .asset.tags.environment // empty')
ASSET_TEAM_TAG=$(echo "$ASSET_RESPONSE" | jq -r '.tags.team // .asset.tags.team // empty')

echo -e "${GREEN}✓ Asset created: ${ASSET_ID}${NC}"

# Step 6: Verify ownership and tags
echo -e "${YELLOW}Step 6: Verifying asset ownership and tags...${NC}"

if [ "$ASSET_OWNERSHIP" != "internal" ]; then
  echo -e "${RED}✗ Asset ownership should be 'internal', got '${ASSET_OWNERSHIP}'${NC}"
  exit 1
fi
echo -e "${GREEN}✓ Asset ownership: ${ASSET_OWNERSHIP}${NC}"

if [ "$ASSET_ENV_TAG" != "dev" ]; then
  echo -e "${RED}✗ Asset should have tag environment=dev, got '${ASSET_ENV_TAG}'${NC}"
  exit 1
fi
echo -e "${GREEN}✓ Asset tag environment: ${ASSET_ENV_TAG}${NC}"

if [ "$ASSET_TEAM_TAG" != "backend" ]; then
  echo -e "${RED}✗ Asset should have tag team=backend, got '${ASSET_TEAM_TAG}'${NC}"
  exit 1
fi
echo -e "${GREEN}✓ Asset tag team: ${ASSET_TEAM_TAG}${NC}\n"

# Step 7: Test reclassification (v2 reclassify-all)
echo -e "${YELLOW}Step 7: Testing reclassification...${NC}"
RECLASSIFY_RESPONSE=$(curl -s -X POST "${API_BASE_URL}/api/v2/inventory-service/network-segments/reclassify-all" \
  -H "Authorization: Bearer ${TOKEN}")

UPDATED_COUNT=$(echo "$RECLASSIFY_RESPONSE" | jq -r '.updated // .updated_count // 0')
if [ "$UPDATED_COUNT" -lt 1 ]; then
  echo -e "${YELLOW}⚠ No assets were updated (this may be expected if asset was already classified)${NC}"
else
  echo -e "${GREEN}✓ Reclassified ${UPDATED_COUNT} assets${NC}"
fi

# Step 8: Verify asset after reclassification
echo -e "${YELLOW}Step 8: Verifying asset after reclassification...${NC}"
GET_ASSET_RESPONSE=$(curl -s -X GET "${API_BASE_URL}/api/v2/inventory-service/infrastructure-assets/${ASSET_ID}" \
  -H "Authorization: Bearer ${TOKEN}")

FINAL_OWNERSHIP=$(echo "$GET_ASSET_RESPONSE" | jq -r '.asset_ownership // .asset.asset_ownership // empty')
FINAL_ENV_TAG=$(echo "$GET_ASSET_RESPONSE" | jq -r '.tags.environment // .asset.tags.environment // empty')
FINAL_TEAM_TAG=$(echo "$GET_ASSET_RESPONSE" | jq -r '.tags.team // .asset.tags.team // empty')

if [ "$FINAL_OWNERSHIP" != "internal" ]; then
  echo -e "${RED}✗ Asset ownership should still be 'internal', got '${FINAL_OWNERSHIP}'${NC}"
  exit 1
fi

if [ "$FINAL_ENV_TAG" != "dev" ] || [ "$FINAL_TEAM_TAG" != "backend" ]; then
  echo -e "${RED}✗ Asset tags should be preserved. Got:${NC}"
  echo "$GET_ASSET_RESPONSE" | jq '.tags // .asset.tags'
  exit 1
fi

echo -e "${GREEN}✓ Asset ownership and tags verified after reclassification${NC}\n"

# Summary
echo -e "${GREEN}=== Test Summary ===${NC}"
echo -e "${GREEN}✓ All tests passed!${NC}"
echo -e "\nTest Results:"
echo -e "  - Location and network segment created with tags (v2 API)"
echo -e "  - Asset ownership correctly set to 'internal'"
echo -e "  - Tags automatically applied: environment=dev, team=backend"
echo -e "  - Reclassification preserves ownership and tags"
echo -e "\nAsset ID: ${ASSET_ID}"
echo -e "Network Segment ID: ${SEGMENT_ID}"
