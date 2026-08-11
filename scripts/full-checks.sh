#!/bin/bash

# Full Checks Script
# Run this manually when you want comprehensive validation
# This is what the old pre-commit hooks used to do
#
# Documentation:
#   - See docsv4/development/standards/QUICK_REFERENCE.md for coding standards
#   - See docsv4/development/standards/GO_STANDARDS.md for Go-specific standards
#   - See Makefile for individual check targets

set -e

echo "🔍 Running FULL comprehensive checks..."
echo "======================================"

# Change to project root
cd "$(git rev-parse --show-toplevel)"

# 1. Registry validation
echo "📋 Step 1: Registry-First Validation..."
node ./scripts/validate-registry-first.mjs || {
    echo "❌ Registry validation failed!"
    exit 1
}

# 2. Generate artifacts
echo "📋 Step 2: Generating artifacts..."
make generate

# 3. Verify generated artifacts
echo "📋 Step 3: Verifying generated artifacts..."
make verify-generated

# 4. Run standards audit
echo "📋 Step 4: Running standards audit..."
make audit

# 5. TypeScript builds
echo "📋 Step 5: Running TypeScript builds..."
cd frontend-v2 && npm run build
cd ..
cd admin-ui-v2 && npm run build
cd ..

# 6. CORS tests
echo "📋 Step 6: Running CORS tests..."
if curl -s --max-time 5 http://localhost:8080/api/v1/health >/dev/null 2>&1; then
    make test-cors
else
    echo "ℹ️  Skipping CORS tests (API gateway not accessible)"
fi

# 7. Full standards check
echo "📋 Step 7: Running full standards check..."
./scripts/enforce-standards.sh

echo "======================================"
echo "✅ ALL comprehensive checks passed!"
echo "🎉 Your code is production ready!"
