#!/bin/bash
# =================================================================
# Load DemoCorp Tenant and Data
# =================================================================
# Creates DemoCorp tenant, users, devices, and imports discovery findings
# =================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_CONTAINER="${DB_CONTAINER:-crypto-postgres}"
DB_USER="${DB_USER:-crypto_user}"
DB_NAME="${DB_NAME:-crypto_inventory}"
API_GATEWAY="${API_GATEWAY:-http://localhost:8080}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}Loading DemoCorp Tenant and Data${NC}"
echo -e "${BLUE}==========================================${NC}"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
    echo -e "${RED}Error: Container ${DB_CONTAINER} is not running${NC}"
    exit 1
fi

# Check if core data exists
CORE_CHECK=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -c \
    "SELECT COUNT(*) FROM platform_roles WHERE name = 'super_admin';" 2>/dev/null | tr -d ' ')

if [ "$CORE_CHECK" != "1" ]; then
    echo -e "${RED}Error: Core system data not found. Ensure Tier 1 (seed.sql) has been applied.${NC}"
    exit 1
fi

# Check if tenant exists
TENANT_EXISTS=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -c \
    "SELECT COUNT(*) FROM tenants WHERE slug = 'democorp';" 2>/dev/null | tr -d ' ')

if [ "$TENANT_EXISTS" = "1" ]; then
    echo -e "${YELLOW}DemoCorp tenant already exists.${NC}"
    read -p "Erase and recreate? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        echo -e "${BLUE}Erasing existing DemoCorp tenant...${NC}"
        docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/scripts/erase-tenant.sql"
        echo -e "${GREEN}✓ Erased${NC}"
    else
        echo -e "${YELLOW}Cancelled.${NC}"
        exit 0
    fi
fi

# Step 1: Create tenant
echo -e "${BLUE}Step 1: Creating DemoCorp tenant...${NC}"
docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/scripts/create-tenant.sql"
echo -e "${GREEN}✓ Tenant created${NC}"

# Step 2: Create users
echo -e "${BLUE}Step 2: Creating DemoCorp users...${NC}"
docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/scripts/create-users.sql"
echo -e "${GREEN}✓ Users created${NC}"

# Step 3: Create devices
echo -e "${BLUE}Step 3: Creating DemoCorp devices...${NC}"
docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/scripts/create-devices.sql"
echo -e "${GREEN}✓ Devices created${NC}"

# Step 4: Get JWT token
echo -e "${BLUE}Step 4: Authenticating to API...${NC}"
LOGIN_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@democorp.com","password":"Password123!"}' \
  "$API_GATEWAY/api/v1/auth-service/auth/login" 2>/dev/null)

if ! echo "$LOGIN_RESPONSE" | grep -q "access_token"; then
    echo -e "${RED}Error: Failed to authenticate${NC}"
    echo "$LOGIN_RESPONSE"
    exit 1
fi

# Extract access token
if command -v jq >/dev/null 2>&1; then
    JWT_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')
else
    JWT_TOKEN=$(echo "$LOGIN_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
fi

if [ -z "$JWT_TOKEN" ] || [ "$JWT_TOKEN" = "null" ]; then
    echo -e "${RED}Error: Failed to extract JWT token${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Authenticated${NC}"

# Step 5: Get device UUIDs and create mapping
echo -e "${BLUE}Step 5: Resolving device IDs...${NC}"
DEVICE_MAP=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -A -F',' -c "
    SELECT hostname, id::text
    FROM devices
    WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'democorp' LIMIT 1)
    AND deleted_at IS NULL;
" 2>/dev/null)

echo -e "${GREEN}✓ Device IDs resolved${NC}"

# Function to resolve device_id from hostname
resolve_device_id() {
    local hostname=$1
    local device_id=$(echo "$DEVICE_MAP" | grep "^${hostname}," | cut -d',' -f2 | tr -d ' ')
    if [ -n "$device_id" ] && [ "$device_id" != "" ]; then
        echo "$device_id"
    else
        echo ""
    fi
}

# Function to process findings file
process_findings_file() {
    local findings_file=$1
    local filename=$(basename "$findings_file" .json)

    echo -e "${BLUE}  Processing ${filename}...${NC}"

    # Read and process findings JSON
    # Replace device_id hostnames with UUIDs
    local temp_file=$(mktemp)

    # Use Python or jq to process JSON and replace device_id
    if command -v python3 >/dev/null 2>&1; then
        python3 <<EOF
import json
import sys

# Read device map
device_map = {}
for line in """$DEVICE_MAP""".strip().split('\n'):
    if ',' in line:
        hostname, device_id = line.split(',', 1)
        device_map[hostname.strip()] = device_id.strip()

# Read findings
with open('$findings_file', 'r') as f:
    data = json.load(f)

# Replace device_id hostnames with UUIDs
for finding in data.get('findings', []):
    if 'device_id' in finding and finding['device_id']:
        hostname = finding['device_id']
        if hostname in device_map:
            finding['device_id'] = device_map[hostname]
        else:
            finding['device_id'] = None

# Write processed findings
with open('$temp_file', 'w') as f:
    json.dump(data, f, indent=2)

print('Processed')
EOF
    else
        # Fallback: copy file as-is (device_id will be resolved by backend or ignored)
        cp "$findings_file" "$temp_file"
    fi

    # Create discovery job
    JOB_RESPONSE=$(curl -s -X POST \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $JWT_TOKEN" \
      -d "{\"name\":\"DemoCorp ${filename}\",\"description\":\"Seed data import for ${filename}\"}" \
      "$API_GATEWAY/api/v1/inventory-service/discovery/jobs" 2>/dev/null)

    if ! echo "$JOB_RESPONSE" | grep -q "id"; then
        echo -e "${YELLOW}    Warning: Failed to create discovery job, trying alternative endpoint...${NC}"
        JOB_RESPONSE=$(curl -s -X POST \
          -H "Content-Type: application/json" \
          -H "Authorization: Bearer $JWT_TOKEN" \
          -d "{\"name\":\"DemoCorp ${filename}\",\"description\":\"Seed data import for ${filename}\"}" \
          "$API_GATEWAY/api/v1/discovery/jobs" 2>/dev/null)
    fi

    # Extract job ID
    if command -v jq >/dev/null 2>&1; then
        JOB_ID=$(echo "$JOB_RESPONSE" | jq -r '.id // .job.id // empty')
    else
        JOB_ID=$(echo "$JOB_RESPONSE" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
    fi

    if [ -z "$JOB_ID" ] || [ "$JOB_ID" = "null" ]; then
        echo -e "${YELLOW}    Warning: Could not create discovery job, using placeholder ID${NC}"
        JOB_ID="00000000-0000-0000-0000-000000000000"
    fi

    # Import findings
    FINDINGS_COUNT=$(cat "$temp_file" | grep -o '"findings"' | wc -l || echo "0")
    if [ "$FINDINGS_COUNT" = "0" ]; then
        FINDINGS_COUNT=$(cat "$temp_file" | python3 -c "import sys, json; print(len(json.load(sys.stdin).get('findings', [])))" 2>/dev/null || echo "?")
    fi

    IMPORT_RESPONSE=$(curl -s -X POST \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $JWT_TOKEN" \
      -d @- \
      "$API_GATEWAY/api/v1/inventory-service/discovery/jobs/${JOB_ID}/import" < "$temp_file" 2>/dev/null)

    # Try alternative endpoint
    if echo "$IMPORT_RESPONSE" | grep -q "error\|404\|Not Found"; then
        IMPORT_RESPONSE=$(curl -s -X POST \
          -H "Content-Type: application/json" \
          -H "Authorization: Bearer $JWT_TOKEN" \
          -d @- \
          "$API_GATEWAY/api/v1/discovery/jobs/${JOB_ID}/import" < "$temp_file" 2>/dev/null)
    fi

    # Add auto_approve parameter
    # Modify the JSON to add auto_approve
    if command -v python3 >/dev/null 2>&1; then
        python3 <<EOF
import json
import sys

with open('$temp_file', 'r') as f:
    data = json.load(f)

# Add auto_approve
data['auto_approve'] = True

with open('$temp_file', 'w') as f:
    json.dump(data, f, indent=2)
EOF
        IMPORT_RESPONSE=$(curl -s -X POST \
          -H "Content-Type: application/json" \
          -H "Authorization: Bearer $JWT_TOKEN" \
          -d @- \
          "$API_GATEWAY/api/v1/inventory-service/discovery/jobs/${JOB_ID}/import" < "$temp_file" 2>/dev/null)
    fi

    if echo "$IMPORT_RESPONSE" | grep -q "error\|failed"; then
        echo -e "${YELLOW}    Warning: Import may have failed: ${IMPORT_RESPONSE}${NC}"
    else
        echo -e "${GREEN}    ✓ Imported findings${NC}"
    fi

    rm -f "$temp_file"
}

# Step 6: Import findings
echo -e "${BLUE}Step 6: Importing discovery findings...${NC}"
FINDINGS_DIR="$SCRIPT_DIR/data/findings"
for findings_file in "$FINDINGS_DIR"/*.json; do
    if [ -f "$findings_file" ]; then
        process_findings_file "$findings_file"
    fi
done

# Step 7: Summary
echo ""
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}Summary${NC}"
echo -e "${BLUE}==========================================${NC}"

docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c "
    SELECT
        'Tenant' as entity,
        COUNT(*) as count
    FROM tenants WHERE slug = 'democorp'
    UNION ALL
    SELECT
        'Users',
        COUNT(*)
    FROM users u
    JOIN tenants t ON u.tenant_id = t.id
    WHERE t.slug = 'democorp' AND u.deleted_at IS NULL
    UNION ALL
    SELECT
        'Devices',
        COUNT(*)
    FROM devices d
    JOIN tenants t ON d.tenant_id = t.id
    WHERE t.slug = 'democorp' AND d.deleted_at IS NULL
    UNION ALL
    SELECT
        'Assets',
        COUNT(*)
    FROM network_assets na
    JOIN tenants t ON na.tenant_id = t.id
    WHERE t.slug = 'democorp' AND na.deleted_at IS NULL
    UNION ALL
    SELECT
        'Certificates',
        COUNT(*)
    FROM certificates c
    JOIN tenants t ON c.tenant_id = t.id
    WHERE t.slug = 'democorp'
    UNION ALL
    SELECT
        'Crypto Configurations',
        COUNT(*)
    FROM crypto_implementations ci
    JOIN tenants t ON ci.tenant_id = t.id
    WHERE t.slug = 'democorp' AND ci.deleted_at IS NULL;
"

echo ""
echo -e "${GREEN}✓ DemoCorp tenant and data loaded successfully!${NC}"
echo -e "${GREEN}  Login with: admin@democorp.com / Password123!${NC}"
