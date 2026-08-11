#!/bin/bash

# Standards Enforcement Script
# This script enforces coding standards across the project
#
# Documentation:
#   - See docsv4/development/standards/CODING_STANDARDS.md for coding standards
#   - See docsv4/development/standards/QUICK_REFERENCE.md for quick reference
#   - See docsv4/development/standards/GO_STANDARDS.md for Go-specific standards

set -e

echo "🔧 Enforcing Coding Standards..."
echo "================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to run command and report status
run_command() {
    local description="$1"
    local command="$2"
    
    echo -e "${BLUE}Running:${NC} $description"
    if eval "$command"; then
        echo -e "${GREEN}✅ Success:${NC} $description"
    else
        echo -e "${RED}❌ Failed:${NC} $description"
        return 1
    fi
}

echo ""
echo "1. Running ESLint on Frontend Code..."
echo "------------------------------------"

# Run `npm run lint` for each frontend app. ESLint is configured to exit 0
# on warnings-only results (no errors), so this is a blocking gate that only
# fails if there are actual errors (not just style warnings).
FRONTENDS=("frontend-v2" "admin-ui-v2")
FOUND_FRONTEND=false
for FE in "${FRONTENDS[@]}"; do
    if [ -f "$FE/package.json" ] && [ -d "$FE/node_modules" ]; then
        FOUND_FRONTEND=true
        run_command "ESLint check ($FE)" "cd $FE && npm run lint && cd -"
    elif [ -f "$FE/package.json" ]; then
        echo -e "${YELLOW}⚠️  $FE/node_modules not found; run 'npm ci' in $FE first${NC}"
    fi
done
if [ "$FOUND_FRONTEND" = false ]; then
    echo -e "${YELLOW}⚠️  No frontend projects found with installed deps, skipping ESLint${NC}"
fi

echo ""
echo "2. Running Go Linting..."
echo "------------------------"

# Check for Go files and run golangci-lint
if command -v golangci-lint &> /dev/null; then
    if find . -name "*.go" | head -1 | grep -q .; then
        run_command "Go linting" "golangci-lint run ./..."
    else
        echo -e "${YELLOW}⚠️  No Go files found${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  golangci-lint not found, skipping Go linting${NC}"
fi

echo ""
echo "3. Checking Docker Configuration..."
echo "----------------------------------"

# Validate docker compose config (prefer v2)
if [ -f "docker-compose.yml" ]; then
    if docker compose version >/dev/null 2>&1; then
        run_command "Docker Compose (v2) validation" "docker compose config"
    elif command -v docker-compose &> /dev/null; then
        run_command "Docker Compose (legacy) validation" "docker-compose config"
    else
        echo -e "${YELLOW}⚠️  docker compose not found, skipping validation${NC}"
    fi
else
    echo -e "${RED}❌ docker-compose.yml not found${NC}"
fi

echo ""
echo "4. Checking File Naming Conventions..."
echo "-------------------------------------"

# Check for kebab-case in directories
find . -type d -name "*" | grep -E "[A-Z]" | while read -r dir; do
    # Skip any path under any node_modules plus common tooling dirs
    if [[ "$dir" == *"/node_modules/"* ]] || [[ "$dir" == *"/node_modules" ]]; then
        continue
    fi
    if [[ "$dir" =~ ^\./(\.git|\.vscode|\.idea|vendor) ]]; then
        continue
    fi
    echo -e "${YELLOW}⚠️  Directory should use kebab-case: $dir${NC}"
done

# Check for consistent file naming
find . -name "*.go" -o -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" | while read -r file; do
    # Skip files under any node_modules plus common tooling dirs
    if [[ "$file" == *"/node_modules/"* ]]; then
        continue
    fi
    # Skip built artifacts under dist directories
    if [[ "$file" == *"/dist/"* ]]; then
        continue
    fi
    if [[ "$file" =~ (README|CHANGELOG|LICENSE|package\.json|tsconfig\.json|vendor/) ]]; then
        continue
    fi
    # Allow PascalCase React components and camelCase hooks in UI projects
    # React convention: components are PascalCase (.tsx/.jsx), hooks are camelCase (use*.ts)
    if [[ "$file" =~ ^\./(frontend-v2|admin-ui-v2)/.*\.(tsx|jsx)$ ]]; then
        continue
    fi
    if [[ "$file" =~ ^\./(frontend-v2|admin-ui-v2)/.*/(use[A-Z][a-zA-Z]*|runtime[Cc]onfig)\.(ts|tsx)$ ]]; then
        continue
    fi
    # Allow React conventions in tools UI projects (qa-platform, etc.)
    if [[ "$file" =~ ^\./(tools/.*/ui)/.*\.(tsx|jsx)$ ]]; then
        continue
    fi
    if [[ "$file" =~ [A-Z] ]]; then
        echo -e "${YELLOW}⚠️  File should use kebab-case: $file${NC}"
    fi
done

echo ""
echo "5. Checking API Route Consistency..."
echo "-----------------------------------"

# Check Traefik gateway configuration for consistent service prefixes
if [ -f "config/traefik/dynamic-development.yaml" ]; then
    # Check for services that should use service prefixes
    SERVICES=("auth-service" "inventory-service" "compliance-engine" "cbom-service" "sensor-manager" "admin-service" "resource-tracker-service" "tenant-health-service")

    for service in "${SERVICES[@]}"; do
        if ! grep -q "/api/v1/$service/" config/traefik/dynamic-development.yaml; then
            echo -e "${YELLOW}⚠️  Service $service should use service prefix in gateway config${NC}"
        fi
    done
    if ! grep -q "/api/v2/" config/traefik/dynamic-development.yaml; then
        echo -e "${YELLOW}⚠️  Gateway config missing v2 routes; run: make generate-gateway${NC}"
    fi
else
    echo -e "${RED}❌ Traefik gateway config not found (run: make generate-gateway)${NC}"
fi

echo ""
echo "6. Checking Environment Variable Usage..."
echo "----------------------------------------"

# Check for consistent environment variable naming
if [ -f "docker-compose.yml" ]; then
    # Check for mixed port naming
    if grep -q "SERVER_PORT" docker-compose.yml && grep -q "PORT=" docker-compose.yml; then
        echo -e "${YELLOW}⚠️  Mixed port naming detected: both PORT and SERVER_PORT used${NC}"
    fi
    
    # Check for consistent database variable naming
    if ! grep -q "DB_HOST" docker-compose.yml && ! grep -q "DATABASE_URL" docker-compose.yml; then
        echo -e "${YELLOW}⚠️  Consider using DB_HOST or DATABASE_URL for database configuration${NC}"
    fi
fi

echo ""
echo "7. Running TypeScript Type Checking..."
echo "-------------------------------------"

# Use the TypeScript binary from the installed node_modules to avoid relying
# on npx, which can pick up a wrong npm from the PATH in some IDE environments.
# Type-check the active admin UI (admin-ui-v2). node_modules is workspace-hoisted
# to the repo root, so check for tsc there.
if [ -f "node_modules/.bin/tsc" ] && [ -d "admin-ui-v2" ]; then
    run_command "TypeScript type checking (admin-ui-v2)" "(cd admin-ui-v2 && ../node_modules/.bin/tsc --noEmit)"
else
    echo -e "${YELLOW}⚠️  node_modules/.bin/tsc not found; run 'npm install' at repo root first; skipping admin-ui-v2 TypeScript check${NC}"
fi

echo ""
echo "8. Checking Documentation Standards..."
echo "-------------------------------------"

# Check for required documentation files
REQUIRED_DOCS=("README.md" "docsv4/internal/developer/standards/CODING_STANDARDS.md")
for doc in "${REQUIRED_DOCS[@]}"; do
    if [ -f "$doc" ]; then
        echo -e "${GREEN}✅ Found: $doc${NC}"
    else
        echo -e "${RED}❌ Missing: $doc${NC}"
    fi
done

echo ""
echo "================================="
echo -e "${GREEN}🎉 Standards enforcement complete!${NC}"
echo "================================="
