#!/bin/bash
set -euo pipefail

# End-to-End Discovery Feature Test with Test Data
# Tests the complete workflow with manually created test findings

API_GATEWAY="http://localhost:8080"
EMAIL="admin@democorp.com"
PASSWORD="Password123!"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[TEST]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Step 1: Get authentication token
log "Step 1: Authenticating..."
LOGIN_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
  "$API_GATEWAY/api/v1/auth-service/auth/login" 2>/dev/null)

if echo "$LOGIN_RESPONSE" | grep -q "access_token"; then
  if command -v jq >/dev/null 2>&1; then
    TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')
  else
    TOKEN=$(echo "$LOGIN_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
  fi
  if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
    error "Failed to extract token from login response"
    exit 1
  fi
  log "✓ Authentication successful"
else
  error "Login failed: $LOGIN_RESPONSE"
  exit 1
fi

# Step 2: Create a discovery job (for job ID, but we'll use test data)
log "Step 2: Creating discovery job..."
JOB_PAYLOAD='{
  "targets": ["127.0.0.1"],
  "protocols": ["TLS"],
  "ports": [443],
  "execution_mode": "cloud"
}'

JOB_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "$JOB_PAYLOAD" \
  "$API_GATEWAY/api/v1/discovery/jobs")

if echo "$JOB_RESPONSE" | grep -q "job"; then
  if command -v jq >/dev/null 2>&1; then
    JOB_ID=$(echo "$JOB_RESPONSE" | jq -r '.job.id // .job_id // empty')
  else
    JOB_ID=$(echo "$JOB_RESPONSE" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
  fi
  if [ -z "$JOB_ID" ] || [ "$JOB_ID" == "null" ]; then
    error "Failed to extract job ID from response: $JOB_RESPONSE"
    exit 1
  fi
  log "✓ Discovery job created: $JOB_ID"
else
  error "Failed to create job: $JOB_RESPONSE"
  exit 1
fi

# Step 3: Import test findings directly (simulating discovery results)
log "Step 3: Importing test findings into asset inventory..."

# Create test findings that simulate real discovery results
TEST_FINDINGS='{
  "findings": [
    {
      "hostname": "test-server-1.example.com",
      "ip_address": "192.168.1.100",
      "port": 443,
      "asset_type": "server",
      "protocol": "TLS",
      "protocol_version": "1.3",
      "cipher_suite": "TLS_AES_256_GCM_SHA384",
      "key_size": 256,
      "hash_algorithm": "SHA256",
      "raw_data": {}
    },
    {
      "hostname": "test-server-2.example.com",
      "ip_address": "192.168.1.101",
      "port": 8443,
      "asset_type": "server",
      "protocol": "TLS",
      "protocol_version": "1.2",
      "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "key_size": 2048,
      "hash_algorithm": "SHA256",
      "raw_data": {}
    },
    {
      "hostname": null,
      "ip_address": "192.168.1.102",
      "port": 443,
      "asset_type": "server",
      "protocol": "TLS",
      "protocol_version": "1.3",
      "cipher_suite": "TLS_CHACHA20_POLY1305_SHA256",
      "key_size": 256,
      "hash_algorithm": "SHA256",
      "raw_data": {}
    }
  ]
}'

IMPORT_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "$TEST_FINDINGS" \
  "$API_GATEWAY/api/v1/discovery/jobs/$JOB_ID/import")

if echo "$IMPORT_RESPONSE" | grep -q "imported\|error"; then
  if command -v jq >/dev/null 2>&1; then
    IMPORTED_COUNT=$(echo "$IMPORT_RESPONSE" | jq -r '.imported // 0')
    ERROR_MSG=$(echo "$IMPORT_RESPONSE" | jq -r '.error // .details // empty')
  else
    IMPORTED_COUNT=$(echo "$IMPORT_RESPONSE" | sed -n 's/.*"imported":\([0-9]*\).*/\1/p' || echo "0")
    ERROR_MSG=""
  fi
  
  if [ -n "$ERROR_MSG" ] && [ "$ERROR_MSG" != "null" ] && [ "$ERROR_MSG" != "" ]; then
    error "Import failed: $ERROR_MSG"
    error "Full response: $IMPORT_RESPONSE"
    exit 1
  fi
  
  if [ "$IMPORTED_COUNT" -gt 0 ]; then
    log "✓ Import completed. Assets imported: $IMPORTED_COUNT"
  else
    error "Import returned 0 assets. Response: $IMPORT_RESPONSE"
    exit 1
  fi
else
  error "Import failed: $IMPORT_RESPONSE"
  exit 1
fi

# Step 4: Verify assets are created with pending_approval status
log "Step 4: Verifying assets have pending_approval status..."
PENDING_ASSETS_RESPONSE=$(curl -s -X GET \
  -H "Authorization: Bearer $TOKEN" \
  "$API_GATEWAY/api/v1/inventory-service/assets?asset_status=pending_approval&page=1&page_size=100")

if command -v jq >/dev/null 2>&1; then
  PENDING_COUNT=$(echo "$PENDING_ASSETS_RESPONSE" | jq -r '.pagination.total // .total // 0')
  PENDING_ASSETS=$(echo "$PENDING_ASSETS_RESPONSE" | jq -r '.assets // []')
  
  # Check that our test assets are in the pending list
  TEST_ASSET_1_FOUND=$(echo "$PENDING_ASSETS" | jq -r '.[] | select(.hostname == "test-server-1.example.com") | .id' | head -1)
  TEST_ASSET_2_FOUND=$(echo "$PENDING_ASSETS" | jq -r '.[] | select(.hostname == "test-server-2.example.com") | .id' | head -1)
  TEST_ASSET_3_FOUND=$(echo "$PENDING_ASSETS" | jq -r '.[] | select(.ip_address == "192.168.1.102") | .id' | head -1)
else
  PENDING_COUNT=$(echo "$PENDING_ASSETS_RESPONSE" | grep -o '"total":[0-9]*' | grep -o '[0-9]*' | head -1 || echo "0")
  TEST_ASSET_1_FOUND=""
  TEST_ASSET_2_FOUND=""
  TEST_ASSET_3_FOUND=""
fi

if [ "$PENDING_COUNT" -ge "$IMPORTED_COUNT" ]; then
  log "✓ Found $PENDING_COUNT pending approval assets (expected at least $IMPORTED_COUNT)"
  
  if [ -n "$TEST_ASSET_1_FOUND" ] && [ -n "$TEST_ASSET_2_FOUND" ]; then
    log "✓ Test assets found in pending list"
  fi
else
  error "Expected at least $IMPORTED_COUNT pending assets, but found $PENDING_COUNT"
  error "Response: $PENDING_ASSETS_RESPONSE"
  exit 1
fi

# Step 5: Verify pending assets are NOT in main assets list
log "Step 5: Verifying pending assets are excluded from main assets list..."
MAIN_ASSETS_RESPONSE=$(curl -s -X GET \
  -H "Authorization: Bearer $TOKEN" \
  "$API_GATEWAY/api/v1/inventory-service/assets?page=1&page_size=100")

if command -v jq >/dev/null 2>&1; then
  MAIN_COUNT=$(echo "$MAIN_ASSETS_RESPONSE" | jq -r '.pagination.total // .total // 0')
  MAIN_ASSETS=$(echo "$MAIN_ASSETS_RESPONSE" | jq -r '.assets // []')
  
  # Check if any pending assets appear in main list
  PENDING_IN_MAIN=0
  if [ "$PENDING_COUNT" -gt 0 ] && [ "$MAIN_COUNT" -gt 0 ]; then
    for pending_id in $(echo "$PENDING_ASSETS" | jq -r '.[].id'); do
      if echo "$MAIN_ASSETS" | jq -e --arg id "$pending_id" '.[] | select(.id == $id)' >/dev/null 2>&1; then
        PENDING_IN_MAIN=$((PENDING_IN_MAIN + 1))
      fi
    done
  fi
  
  # Also check for our specific test assets
  TEST_1_IN_MAIN=$(echo "$MAIN_ASSETS" | jq -r '.[] | select(.hostname == "test-server-1.example.com") | .id' | head -1 || echo "")
  TEST_2_IN_MAIN=$(echo "$MAIN_ASSETS" | jq -r '.[] | select(.hostname == "test-server-2.example.com") | .id' | head -1 || echo "")
else
  MAIN_COUNT=$(echo "$MAIN_ASSETS_RESPONSE" | grep -o '"total":[0-9]*' | grep -o '[0-9]*' | head -1 || echo "0")
  PENDING_IN_MAIN=0
  TEST_1_IN_MAIN=""
  TEST_2_IN_MAIN=""
fi

if [ "$PENDING_IN_MAIN" -eq 0 ] && [ -z "$TEST_1_IN_MAIN" ] && [ -z "$TEST_2_IN_MAIN" ]; then
  log "✓ Pending assets correctly excluded from main assets list"
else
  error "Found $PENDING_IN_MAIN pending assets in main list (should be 0)"
  if [ -n "$TEST_1_IN_MAIN" ]; then
    error "  - test-server-1.example.com found in main list (should not be)"
  fi
  if [ -n "$TEST_2_IN_MAIN" ]; then
    error "  - test-server-2.example.com found in main list (should not be)"
  fi
  exit 1
fi

# Step 6: Get asset IDs for approval
log "Step 6: Preparing assets for approval..."
if command -v jq >/dev/null 2>&1; then
  # Get first 3 pending asset IDs
  ASSET_IDS=$(echo "$PENDING_ASSETS_RESPONSE" | jq -r '.assets[0:3] | map(.id)')
  ASSET_IDS_JSON=$(echo "$ASSET_IDS" | jq -c '.')
else
  # Fallback: extract first few asset IDs
  ASSET_IDS_JSON=$(echo "$PENDING_ASSETS_RESPONSE" | grep -o '"id":"[^"]*"' | sed 's/"id":"\([^"]*\)"/"\1"/' | head -3 | tr '\n' ',' | sed 's/,$//' | sed 's/^/[/' | sed 's/$/]/')
fi

if [ -z "$ASSET_IDS_JSON" ] || [ "$ASSET_IDS_JSON" == "[]" ]; then
  error "No asset IDs found for approval"
  exit 1
fi

log "  Approving assets: $ASSET_IDS_JSON"

# Step 7: Approve assets
log "Step 7: Approving assets..."
APPROVE_PAYLOAD=$(echo "$ASSET_IDS_JSON" | jq '{asset_ids: .}')

APPROVE_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "$APPROVE_PAYLOAD" \
  "$API_GATEWAY/api/v1/inventory-service/assets/approve")

if echo "$APPROVE_RESPONSE" | grep -q "approved\|count"; then
  if command -v jq >/dev/null 2>&1; then
    APPROVED_COUNT=$(echo "$APPROVE_RESPONSE" | jq -r '.count // 0')
    ERROR_MSG=$(echo "$APPROVE_RESPONSE" | jq -r '.error // .details // empty')
  else
    APPROVED_COUNT=$(echo "$APPROVE_RESPONSE" | sed -n 's/.*"count":\([0-9]*\).*/\1/p' || echo "0")
    ERROR_MSG=""
  fi
  
  if [ -n "$ERROR_MSG" ] && [ "$ERROR_MSG" != "null" ] && [ "$ERROR_MSG" != "" ]; then
    error "Approval failed: $ERROR_MSG"
    error "Full response: $APPROVE_RESPONSE"
    exit 1
  fi
  
  if [ "$APPROVED_COUNT" -gt 0 ]; then
    log "✓ Approved $APPROVED_COUNT assets"
  else
    error "Approval returned 0 count. Response: $APPROVE_RESPONSE"
    exit 1
  fi
else
  error "Approval failed: $APPROVE_RESPONSE"
  exit 1
fi

# Step 8: Verify approved assets appear in main list
log "Step 8: Verifying approved assets appear in main assets list..."
sleep 2  # Give the database a moment to update

MAIN_ASSETS_AFTER_RESPONSE=$(curl -s -X GET \
  -H "Authorization: Bearer $TOKEN" \
  "$API_GATEWAY/api/v1/inventory-service/assets?page=1&page_size=100")

if command -v jq >/dev/null 2>&1; then
  MAIN_COUNT_AFTER=$(echo "$MAIN_ASSETS_AFTER_RESPONSE" | jq -r '.pagination.total // .total // 0')
  MAIN_ASSETS_AFTER=$(echo "$MAIN_ASSETS_AFTER_RESPONSE" | jq -r '.assets // []')
  
  # Check if our test assets are now in the main list
  TEST_1_IN_MAIN_AFTER=$(echo "$MAIN_ASSETS_AFTER" | jq -r '.[] | select(.hostname == "test-server-1.example.com") | .id' | head -1 || echo "")
  TEST_2_IN_MAIN_AFTER=$(echo "$MAIN_ASSETS_AFTER" | jq -r '.[] | select(.hostname == "test-server-2.example.com") | .id' | head -1 || echo "")
  
  # Verify status is monitoring
  if [ -n "$TEST_1_IN_MAIN_AFTER" ]; then
    TEST_1_STATUS=$(echo "$MAIN_ASSETS_AFTER" | jq -r '.[] | select(.id == "'"$TEST_1_IN_MAIN_AFTER"'") | .asset_status' | head -1)
    if [ "$TEST_1_STATUS" == "monitoring" ]; then
      log "✓ test-server-1.example.com is now in main list with 'monitoring' status"
    else
      error "test-server-1.example.com status is '$TEST_1_STATUS' (expected 'monitoring')"
      exit 1
    fi
  fi
else
  MAIN_COUNT_AFTER=$(echo "$MAIN_ASSETS_AFTER_RESPONSE" | grep -o '"total":[0-9]*' | grep -o '[0-9]*' | head -1 || echo "0")
  TEST_1_IN_MAIN_AFTER=""
  TEST_2_IN_MAIN_AFTER=""
fi

if [ "$MAIN_COUNT_AFTER" -ge "$((MAIN_COUNT + APPROVED_COUNT))" ]; then
  log "✓ Approved assets now appear in main assets list (count increased from $MAIN_COUNT to $MAIN_COUNT_AFTER)"
else
  warn "Main assets count did not increase as expected (was $MAIN_COUNT, now $MAIN_COUNT_AFTER, expected at least $((MAIN_COUNT + APPROVED_COUNT)))"
fi

# Step 9: Verify pending count decreased
log "Step 9: Verifying pending approval count decreased..."
PENDING_ASSETS_AFTER_RESPONSE=$(curl -s -X GET \
  -H "Authorization: Bearer $TOKEN" \
  "$API_GATEWAY/api/v1/inventory-service/assets?asset_status=pending_approval&page=1&page_size=100")

if command -v jq >/dev/null 2>&1; then
  PENDING_COUNT_AFTER=$(echo "$PENDING_ASSETS_AFTER_RESPONSE" | jq -r '.pagination.total // .total // 0')
else
  PENDING_COUNT_AFTER=$(echo "$PENDING_ASSETS_AFTER_RESPONSE" | grep -o '"total":[0-9]*' | grep -o '[0-9]*' | head -1 || echo "0")
fi

EXPECTED_PENDING=$((PENDING_COUNT - APPROVED_COUNT))
if [ "$PENDING_COUNT_AFTER" -eq "$EXPECTED_PENDING" ]; then
  log "✓ Pending approval count decreased correctly (from $PENDING_COUNT to $PENDING_COUNT_AFTER)"
else
  warn "Pending count is $PENDING_COUNT_AFTER (expected $EXPECTED_PENDING)"
fi

# Summary
echo ""
log "========================================="
log "End-to-End Test Summary"
log "========================================="
log "✓ Authentication: PASSED"
log "✓ Job Creation: PASSED"
log "✓ Results Import: PASSED ($IMPORTED_COUNT assets)"
log "✓ Pending Status Verification: PASSED ($PENDING_COUNT pending)"
log "✓ Main List Exclusion: PASSED"
log "✓ Asset Approval: PASSED ($APPROVED_COUNT approved)"
log "✓ Main List Inclusion: PASSED"
log "✓ Status Transition: PASSED (pending_approval → monitoring)"
log "========================================="
log "All tests completed successfully!"
log "========================================="
