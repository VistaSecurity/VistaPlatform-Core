#!/bin/bash
# =================================================================
# Erase DemoCorp Data
# =================================================================
# Standalone script to erase DemoCorp tenant and/or data
# =================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_CONTAINER="${DB_CONTAINER:-crypto-postgres}"
DB_USER="${DB_USER:-crypto_user}"
DB_NAME="${DB_NAME:-crypto_inventory}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}DemoCorp Data Erasure${NC}"
echo -e "${BLUE}==========================================${NC}"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
    echo -e "${RED}Error: Container ${DB_CONTAINER} is not running${NC}"
    exit 1
fi

# Check if tenant exists
TENANT_EXISTS=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -c \
    "SELECT COUNT(*) FROM tenants WHERE slug = 'democorp';" 2>/dev/null | tr -d ' ')

if [ "$TENANT_EXISTS" = "0" ]; then
    echo -e "${YELLOW}DemoCorp tenant not found. Nothing to erase.${NC}"
    exit 0
fi

# Show current state
echo -e "${BLUE}Current DemoCorp data:${NC}"
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
echo -e "${YELLOW}What would you like to erase?${NC}"
echo "1. Erase tenant (all data including tenant and users)"
echo "2. Erase data only (keep tenant and users)"
echo "3. Cancel"
echo ""
read -p "Enter choice [1-3]: " choice

case $choice in
    1)
        echo -e "${YELLOW}WARNING: This will delete the entire DemoCorp tenant and ALL associated data.${NC}"
        read -p "Are you sure? (yes/no): " confirm
        if [ "$confirm" != "yes" ]; then
            echo -e "${YELLOW}Cancelled.${NC}"
            exit 0
        fi
        echo -e "${BLUE}Erasing DemoCorp tenant and all data...${NC}"
        docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/scripts/erase-tenant.sql"
        echo -e "${GREEN}✓ DemoCorp tenant and all data erased successfully${NC}"
        ;;
    2)
        echo -e "${YELLOW}This will delete all inventory data but keep the tenant and users.${NC}"
        read -p "Are you sure? (yes/no): " confirm
        if [ "$confirm" != "yes" ]; then
            echo -e "${YELLOW}Cancelled.${NC}"
            exit 0
        fi
        echo -e "${BLUE}Erasing DemoCorp inventory data...${NC}"
        docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/scripts/erase-data.sql"
        echo -e "${GREEN}✓ DemoCorp inventory data erased successfully${NC}"
        echo -e "${GREEN}  Tenant and users remain intact${NC}"
        ;;
    3)
        echo -e "${YELLOW}Cancelled.${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac
