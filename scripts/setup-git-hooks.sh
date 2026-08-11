#!/bin/bash
# Setup Git Hooks
# Installs pre-commit and pre-push hooks for development workflow

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Setting up Git hooks...${NC}"

# Ensure .git/hooks directory exists
mkdir -p .git/hooks

# Install pre-commit hook
if [ ! -f ".git/hooks/pre-commit" ]; then
    echo -e "${BLUE}Installing pre-commit hook...${NC}"
    cat > .git/hooks/pre-commit <<'EOF'
#!/bin/bash
set -e

# Ensure go.work exists and is synced when Go is present
# Use GOTOOLCHAIN=local to prevent automatic Go version upgrades
if command -v go >/dev/null 2>&1; then
  if [ ! -f go.work ]; then
    echo "🧩 Creating go.work (workspace)"
    GOTOOLCHAIN=local go work init ./shared ./shared/rbac \
      ./services/auth-service ./services/inventory-service ./services/compliance-engine \
      ./services/monitoring-service ./services/report-generator ./services/admin-service \
      ./services/cluster-sensor-service ./services/sensor-manager ./services/resource-tracker-service \
      ./services/tenant-health-service ./sensor || true
  fi
  GOTOOLCHAIN=local go work sync || true
fi

echo "🔎 Running standards-check..."
make standards-check
echo "✅ Pre-commit checks passed"
EOF
    chmod +x .git/hooks/pre-commit
    echo -e "${GREEN}✅ Pre-commit hook installed${NC}"
else
    echo -e "${GREEN}✅ Pre-commit hook already exists${NC}"
fi

# Install pre-push hook
if [ ! -f ".git/hooks/pre-push" ]; then
    echo -e "${BLUE}Installing pre-push hook...${NC}"
    cat > .git/hooks/pre-push <<'EOF'
#!/bin/bash
# Fast pre-push validation - only quick checks
# Full validation should be done before commit (pre-commit hook)
set -e

echo "🔎 Running fast pre-push checks..."

# Quick check: verify generated files exist (don't regenerate)
make verify-generated || {
  echo "❌ Generated files missing. Run 'make generate' before committing."
  exit 1
}

# Quick check: validate registry compliance (fast validation only)
make validate-registry || {
  echo "❌ Registry validation failed. Run 'make registry-first' to fix."
  exit 1
}

# Skip CORS testing - requires running services and can timeout
# Run 'make test-cors' manually if needed

echo "✅ Pre-push checks passed"
EOF
    chmod +x .git/hooks/pre-push
    echo -e "${GREEN}✅ Pre-push hook installed${NC}"
else
    echo -e "${GREEN}✅ Pre-push hook already exists${NC}"
    # Update existing hook if it's the old slow version
    if grep -q "make standards-check" .git/hooks/pre-push 2>/dev/null; then
        echo -e "${BLUE}Updating pre-push hook to fast version...${NC}"
        cat > .git/hooks/pre-push <<'EOF'
#!/bin/bash
# Fast pre-push validation - only quick checks
# Full validation should be done before commit (pre-commit hook)
set -e

echo "🔎 Running fast pre-push checks..."

# Quick check: verify generated files exist (don't regenerate)
make verify-generated || {
  echo "❌ Generated files missing. Run 'make generate' before committing."
  exit 1
}

# Quick check: validate registry compliance (fast validation only)
make validate-registry || {
  echo "❌ Registry validation failed. Run 'make registry-first' to fix."
  exit 1
}

# Skip CORS testing - requires running services and can timeout
# Run 'make test-cors' manually if needed

echo "✅ Pre-push checks passed"
EOF
        chmod +x .git/hooks/pre-push
        echo -e "${GREEN}✅ Pre-push hook updated to fast version${NC}"
    fi
fi

echo ""
echo -e "${GREEN}✅ Git hooks setup complete!${NC}"
