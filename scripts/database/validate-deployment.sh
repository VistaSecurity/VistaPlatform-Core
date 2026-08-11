#!/bin/bash
# =================================================================
# Validate Deployment - Database Data Verification
# =================================================================
# This script validates that the required seed data exists.
# Use this after deployment to verify the database is properly seeded.
#
# Usage:
#   ./scripts/database/validate-deployment.sh           # Validate Tier 1 only
#   ./scripts/database/validate-deployment.sh --demo    # Also validate Tier 2 (demo data)
# =================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_CONTAINER="${DB_CONTAINER:-crypto-postgres}"
DB_USER="${DB_USER:-crypto_user}"
DB_NAME="${DB_NAME:-crypto_inventory}"
VALIDATE_DEMO="${1:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ERRORS=0

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}Deployment Validation${NC}"
echo -e "${BLUE}==========================================${NC}"
echo ""

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
    echo -e "${RED}Error: Container ${DB_CONTAINER} is not running${NC}"
    exit 1
fi

# Helper function to run SQL and get count
get_count() {
    local query="$1"
    docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -c "$query" 2>/dev/null | tr -d ' ' || echo "0"
}

# Helper function to check count
check_count() {
    local name="$1"
    local count="$2"
    local min="$3"
    
    if [ "$count" -ge "$min" ]; then
        echo -e "  ${GREEN}✅${NC} $name: $count (>= $min expected)"
        return 0
    else
        echo -e "  ${RED}❌${NC} $name: $count (>= $min expected)"
        ERRORS=$((ERRORS + 1))
        return 1
    fi
}

# =================================================================
# Tier 1 Validation (Core System Data)
# =================================================================
echo -e "${BLUE}Tier 1: Core System Data${NC}"
echo "----------------------------------------"

# Platform roles
PLATFORM_ROLES=$(get_count "SELECT COUNT(*) FROM platform_roles;")
check_count "Platform Roles" "$PLATFORM_ROLES" 3

# Platform users (at least super_admin)
PLATFORM_USERS=$(get_count "SELECT COUNT(*) FROM platform_users WHERE is_active = true;")
check_count "Platform Users" "$PLATFORM_USERS" 1

# Super admin exists
SUPER_ADMIN=$(get_count "SELECT COUNT(*) FROM platform_users pu JOIN platform_roles pr ON pu.role_id = pr.id WHERE pr.name = 'super_admin' AND pu.is_active = true;")
check_count "Super Admin User" "$SUPER_ADMIN" 1

# Subscription tiers
SUB_TIERS=$(get_count "SELECT COUNT(*) FROM subscription_tiers;")
check_count "Subscription Tiers" "$SUB_TIERS" 3

# Tenant permissions
TENANT_PERMS=$(get_count "SELECT COUNT(*) FROM tenant_permissions;")
check_count "Tenant Permissions" "$TENANT_PERMS" 10

# Platform frameworks
FRAMEWORKS=$(get_count "SELECT COUNT(*) FROM platform_frameworks WHERE status = 'published';")
check_count "Published Frameworks" "$FRAMEWORKS" 5

# Measurement types
MEAS_TYPES=$(get_count "SELECT COUNT(*) FROM measurement_types;")
check_count "Measurement Types" "$MEAS_TYPES" 5

# Measurement templates
MEAS_TEMPLATES=$(get_count "SELECT COUNT(*) FROM measurement_templates;")
check_count "Measurement Templates" "$MEAS_TEMPLATES" 5

echo ""

# =================================================================
# Tier 2 Validation (Demo Data) - Optional
# =================================================================
if [ "$VALIDATE_DEMO" = "--demo" ]; then
    echo -e "${BLUE}Tier 2: Demo Data${NC}"
    echo "----------------------------------------"
    
    # Demo tenant
    DEMO_TENANT=$(get_count "SELECT COUNT(*) FROM tenants WHERE slug = 'demo-corp';")
    check_count "Demo Tenant (demo-corp)" "$DEMO_TENANT" 1
    
    # Demo tenant roles
    DEMO_ROLES=$(get_count "SELECT COUNT(*) FROM tenant_roles tr JOIN tenants t ON tr.tenant_id = t.id WHERE t.slug = 'demo-corp';")
    check_count "Demo Tenant Roles" "$DEMO_ROLES" 6
    
    # Demo users
    DEMO_USERS=$(get_count "SELECT COUNT(*) FROM users u JOIN tenants t ON u.tenant_id = t.id WHERE t.slug = 'demo-corp';")
    check_count "Demo Users" "$DEMO_USERS" 6
    
    # Demo role assignments
    DEMO_ASSIGNMENTS=$(get_count "SELECT COUNT(*) FROM user_tenant_roles utr JOIN tenants t ON utr.tenant_id = t.id WHERE t.slug = 'demo-corp';")
    check_count "Demo Role Assignments" "$DEMO_ASSIGNMENTS" 6
    
    echo ""
else
    echo -e "${BLUE}Tier 2: Demo Data${NC} (skipped, use --demo to validate demo data, or use QA Platform for tenant data)"
    echo ""
fi

# =================================================================
# Summary
# =================================================================
echo "=========================================="
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}✅ Validation PASSED${NC}"
    echo ""
    echo "All required data is present."
    exit 0
else
    echo -e "${RED}❌ Validation FAILED${NC}"
    echo ""
    echo "$ERRORS check(s) failed."
    exit 1
fi
