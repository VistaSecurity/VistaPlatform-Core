#!/bin/bash

# Fast Standards Enforcement Script
# This script runs only essential checks quickly

set -e

echo "🔧 Running Fast Standards Check..."
echo "================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 1. Quick file naming check
echo ""
echo "1. Checking File Naming Conventions..."
echo "-------------------------------------"
if find . -name "*.ts" -o -name "*.tsx" | grep -v node_modules | grep -v dist | grep -v __tests__ | grep -E '[A-Z]' | head -5; then
    echo -e "${YELLOW}⚠️  Some files may not use kebab-case${NC}"
else
    echo -e "${GREEN}✅ File naming looks good${NC}"
fi

# 2. Quick documentation check
echo ""
echo "2. Checking Documentation Standards..."
echo "-------------------------------------"
if [ -f "README.md" ]; then
    echo -e "${GREEN}✅ Found: README.md${NC}"
else
    echo -e "${YELLOW}⚠️  Missing: README.md${NC}"
fi

echo ""
echo "================================="
echo -e "${GREEN}🎉 Fast standards check complete!${NC}"
echo "================================="
