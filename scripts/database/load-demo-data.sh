#!/bin/bash
# =================================================================
# Load Demo Data (Tier 2)
# =================================================================
# This script loads optional demo/test data into the database.
# Run after fresh deployment to add Demo Corporation tenant, users,
# and sample data for testing.
#
# Usage: ./scripts/database/load-demo-data.sh
#        ./scripts/database/load-demo-data.sh --force  (skip confirmation)
# =================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_CONTAINER="${DB_CONTAINER:-crypto-postgres}"
DB_USER="${DB_USER:-crypto_user}"
DB_NAME="${DB_NAME:-crypto_inventory}"
FORCE="${1:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}Loading Demo Data (Tier 2)${NC}"
echo -e "${BLUE}==========================================${NC}"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
    echo -e "${RED}Error: Container ${DB_CONTAINER} is not running${NC}"
    exit 1
fi

# Check if core data exists (platform_roles with super_admin)
CORE_CHECK=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -c \
    "SELECT COUNT(*) FROM platform_roles WHERE name = 'super_admin';" 2>/dev/null | tr -d ' ')

if [ "$CORE_CHECK" != "1" ]; then
    echo -e "${RED}Error: Core system data not found. Ensure Tier 1 (seed.sql) has been applied.${NC}"
    exit 1
fi

# Check if demo-corp tenant already exists
DEMO_TENANT=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -c \
    "SELECT COUNT(*) FROM tenants WHERE slug = 'demo-corp';" 2>/dev/null | tr -d ' ')

DEMO_USERS=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -c \
    "SELECT COUNT(*) FROM users u JOIN tenants t ON u.tenant_id = t.id WHERE t.slug = 'demo-corp';" 2>/dev/null | tr -d ' ')

DEMO_ASSETS=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -c \
    "SELECT COUNT(*) FROM network_assets na JOIN tenants t ON na.tenant_id = t.id WHERE t.slug = 'demo-corp' AND na.deleted_at IS NULL;" 2>/dev/null | tr -d ' ')

if [ "$DEMO_TENANT" -ge "1" ] && [ "$DEMO_USERS" -ge "6" ] && [ "$DEMO_ASSETS" -ge "200" ]; then
    echo -e "${GREEN}Demo data already exists:${NC}"
    echo ""

    # Show current state
    docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c "
        SELECT 'Demo tenant' as entity, COUNT(*) as count FROM tenants WHERE slug = 'demo-corp'
        UNION ALL
        SELECT 'Tenant roles', COUNT(*) FROM tenant_roles tr JOIN tenants t ON tr.tenant_id = t.id WHERE t.slug = 'demo-corp'
        UNION ALL
        SELECT 'Demo users', COUNT(*) FROM users u JOIN tenants t ON u.tenant_id = t.id WHERE t.slug = 'demo-corp'
        UNION ALL
        SELECT 'User role assignments', COUNT(*) FROM user_tenant_roles utr JOIN tenants t ON utr.tenant_id = t.id WHERE t.slug = 'demo-corp'
        UNION ALL
        SELECT 'Demo assets', COUNT(*) FROM network_assets na JOIN tenants t ON na.tenant_id = t.id WHERE t.slug = 'demo-corp' AND na.deleted_at IS NULL;
    "
    exit 0
fi

# If partial data exists, warn and offer to continue
if [ "$DEMO_TENANT" -ge "1" ] && [ "$DEMO_USERS" -lt "6" ]; then
    echo -e "${YELLOW}Partial demo data detected (tenant exists but not all users).${NC}"
    echo -e "${YELLOW}Continuing will add missing data...${NC}"
fi

if [ "$DEMO_TENANT" -ge "1" ] && [ "$DEMO_USERS" -ge "6" ] && [ "$DEMO_ASSETS" -lt "200" ]; then
    echo -e "${YELLOW}Demo tenant and users exist, but assets are missing or incomplete.${NC}"
    echo -e "${YELLOW}Continuing will load assets...${NC}"
fi

echo ""
echo -e "${BLUE}Loading demo data...${NC}"
docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/seed_demo.sql"

echo ""
echo -e "${BLUE}Loading demo assets (265+ assets)...${NC}"
if [ -f "$SCRIPT_DIR/seed_democorp_assets.sql" ]; then
    docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/seed_democorp_assets.sql"
    ASSET_COUNT=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -c \
        "SELECT COUNT(*) FROM network_assets WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND deleted_at IS NULL;" 2>/dev/null | tr -d ' ')
    echo -e "${GREEN}✓ Loaded $ASSET_COUNT assets for DemoCorp tenant${NC}"
else
    echo -e "${YELLOW}⚠️  Asset seed file not found (seed_democorp_assets.sql)${NC}"
    echo -e "${YELLOW}   Assets will not be loaded${NC}"
fi

echo ""
echo -e "${BLUE}Configuring compliance frameworks for demo tenant...${NC}"
if [ -f "$SCRIPT_DIR/seed_democorp_compliance.sql" ]; then
    docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/seed_democorp_compliance.sql"
    FRAMEWORK_COUNT=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -c \
        "SELECT COUNT(*) FROM tenant_frameworks WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1);" 2>/dev/null | tr -d ' ')
    echo -e "${GREEN}✓ Configured $FRAMEWORK_COUNT tenant framework(s) for DemoCorp tenant${NC}"
else
    echo -e "${YELLOW}⚠️  Compliance seed file not found (seed_democorp_compliance.sql)${NC}"
    echo -e "${YELLOW}   Compliance frameworks will not be configured${NC}"
fi

echo ""
echo -e "${BLUE}Creating crypto implementations linking assets to certificates...${NC}"
if [ -f "$SCRIPT_DIR/seed_democorp_crypto_implementations.sql" ]; then
    docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/seed_democorp_crypto_implementations.sql"
    IMPL_COUNT=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -c \
        "SELECT COUNT(*) FROM crypto_implementations WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'demo-corp' LIMIT 1) AND deleted_at IS NULL;" 2>/dev/null | tr -d ' ')
    echo -e "${GREEN}✓ Created $IMPL_COUNT crypto implementations${NC}"
else
    echo -e "${YELLOW}⚠️  Crypto implementations seed file not found (seed_democorp_crypto_implementations.sql)${NC}"
    echo -e "${YELLOW}   Crypto implementations will not be created${NC}"
fi

echo ""
echo -e "${BLUE}Seeding compliance violations for event-driven findings...${NC}"
if [ -f "$SCRIPT_DIR/seed_democorp_compliance_violations.sql" ]; then
    docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/seed_democorp_compliance_violations.sql"
    echo -e "${GREEN}✓ Seeded compliance violations${NC}"
else
    echo -e "${YELLOW}⚠️  Violation seed file not found (seed_democorp_compliance_violations.sql)${NC}"
    echo -e "${YELLOW}   Compliance violations will not be seeded${NC}"
fi

echo ""
echo -e "${BLUE}Compliance evaluation:${NC} Triggered after core services start (see session-init). To run manually: $SCRIPT_DIR/trigger-compliance-evaluation.sh"
echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}Demo Data Loaded Successfully!${NC}"
echo -e "${GREEN}==========================================${NC}"
echo ""
echo -e "Demo Credentials (all passwords: ${YELLOW}Password123!${NC}):"
echo ""
echo "  Tenant: Demo Corporation (demo-corp)"
echo ""
echo "  owner@democorp.com    - Tenant Owner (full access)"
echo "  admin@democorp.com    - Tenant Admin"
echo "  security@democorp.com - Security Admin"
echo "  analyst@democorp.com  - Viewer (analyst role retired, #219)"
echo "  viewer@democorp.com   - Viewer (read-only)"
echo "  api@democorp.com      - API User"
echo ""
if [ -n "$ASSET_COUNT" ] && [ "$ASSET_COUNT" -gt 0 ]; then
    echo -e "${GREEN}Demo Assets: $ASSET_COUNT assets loaded${NC}"
    echo ""
fi
echo -e "${GREEN}==========================================${NC}"
