#!/bin/bash

# Pre-Deployment Validation Script
# Run this before deploying to production to catch common issues
# Expected runtime: 2-3 minutes

set -euo pipefail

# Colors for output
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"; }
ok() { echo -e "${GREEN}✅${NC} $1"; }
warn() { echo -e "${YELLOW}⚠️${NC} $1"; }
err() { echo -e "${RED}❌${NC} $1"; }

# Configuration (prefer EC2-Smoke if present)
if [[ -f ".env.ec2-smoke" ]]; then
  ENV_FILE=".env.ec2-smoke"
  COMPOSE_FILE="docker-compose.ec2-smoke.yml"
else
  ENV_FILE=".env.prod"
  COMPOSE_FILE="docker-compose.prod.yml"
fi
TEST_COMPOSE_FILE="docker-compose.test.yml"

# Track validation results
VALIDATION_PASSED=true
ISSUES_FOUND=0

# Function to report issues
report_issue() {
    local issue="$1"
    err "$issue"
    VALIDATION_PASSED=false
    ((ISSUES_FOUND++))
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

log "🔍 Pre-Deployment Validation Starting..."
log "======================================"

# Step 0: Fast checks first (cache validation, quick checks)
log "0. Quick validation checks..."

# Cache validation
if command_exists go; then
    log "  Validating Go module cache..."
    if go mod verify ./shared 2>/dev/null && go mod verify ./shared/rbac 2>/dev/null; then
        ok "Go module cache is valid"
    else
        warn "Go module cache validation failed (non-critical)"
    fi
fi

# Docker layer cache status
if command_exists docker; then
    log "  Checking Docker build cache..."
    CACHE_SIZE=$(docker builder du 2>/dev/null | tail -1 | awk '{print $1}' || echo "unknown")
    if [[ "$CACHE_SIZE" != "unknown" ]]; then
        ok "Docker build cache: $CACHE_SIZE"
    fi
fi

# Step 1: Check prerequisites
log "1. Checking prerequisites..."

if ! command_exists docker; then
    report_issue "Docker is not installed"
else
    ok "Docker is available"
fi

if ! docker compose version >/dev/null 2>&1; then
    report_issue "Docker Compose v2 is not available"
else
    ok "Docker Compose v2 is available"
fi

# Step 2: Check environment file (fast check)
log "2. Checking environment configuration..."

if [[ ! -f "$ENV_FILE" ]]; then
    report_issue "Environment file $ENV_FILE not found. Run: node ./scripts/generate-prod-env.mjs"
else
    ok "Environment file $ENV_FILE exists"
fi

# Check for required environment variables
if [[ -f "$ENV_FILE" ]]; then
    required_vars=(
        "JWT_SECRET"
        "POSTGRES_PASSWORD"
        "REDIS_PASSWORD"
        "INFLUXDB_TOKEN"
        "NATS_PASSWORD"
        "API_GATEWAY_URL"
        "ECR_REGISTRY"
    )

    for var in "${required_vars[@]}"; do
        if ! grep -q "^${var}=" "$ENV_FILE" || [[ -z "$(grep "^${var}=" "$ENV_FILE" | cut -d'=' -f2)" ]]; then
            report_issue "Missing or empty environment variable: $var"
        else
            ok "Environment variable $var is set"
        fi
    done
fi

# Step 3: Validate Docker Compose configuration
log "3. Validating Docker Compose configuration..."

if [[ ! -f "$COMPOSE_FILE" ]]; then
    report_issue "Production compose file $COMPOSE_FILE not found"
else
    ok "Production compose file exists"

    # Test compose file syntax
    if docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" config >/dev/null 2>&1; then
        ok "Docker Compose configuration is valid"
    else
        report_issue "Docker Compose configuration has syntax errors"
        warn "Run: docker compose -f $COMPOSE_FILE --env-file $ENV_FILE config"
    fi
fi

# Step 4: Check database schema and seed files
log "4. Checking database schema and seed files..."

db_files=(
    "scripts/database/schema.sql"
    "scripts/database/seed.sql"
)

for file in "${db_files[@]}"; do
    if [[ -f "$file" ]]; then
        # Check file is not empty
        if [[ -s "$file" ]]; then
            ok "Database file exists and is not empty: $file"
        else
            report_issue "Database file is empty: $file"
        fi
    else
        report_issue "Missing database file: $file"
    fi
done

# Step 4.6: Check critical database tables/columns readiness
log "4.6. Checking critical database tables/columns readiness..."

if [[ -f "scripts/database-validation.sh" ]]; then
    source scripts/database-validation.sh

    # Check if we can validate (database may not be running in pre-deploy)
    if command_exists docker && docker ps >/dev/null 2>&1; then
        # Try to check if postgres container exists (may not be running)
        if docker ps -a --format '{{.Names}}' | grep -q "postgres"; then
            # Database exists but may not be running - skip actual checks
            ok "Database container found (validation will run during deployment)"
        else
            ok "Database validation will run during deployment"
        fi
    else
        ok "Database validation will run during deployment"
    fi
else
    warn "Database validation library not found (scripts/database-validation.sh)"
fi

# Step 5: Check Traefik gateway configuration
log "5. Checking Traefik gateway configuration..."

traefik_static="config/traefik/traefik-production.yaml"
traefik_dynamic="config/traefik/dynamic-production.yaml"
if [[ -f "$traefik_static" ]] && [[ -f "$traefik_dynamic" ]]; then
    ok "Traefik production configs exist (static + dynamic)"
else
    report_issue "Traefik production config not found. Run: DEPLOY_ENV=production node scripts/generate-traefik-config.mjs"
fi

# Step 5.5: Check sensor artifacts
# TEMPORARY: Only checking Linux x86_64 - cross-platform checks disabled until needed
log "5.5. Checking sensor artifacts (Linux x86_64 only)..."

sensor_artifacts=(
    "artifacts/sensor/linux/amd64/crypto-sensor"
    # Cross-platform artifacts temporarily disabled
    # "artifacts/sensor/linux/arm64/crypto-sensor"
    # "artifacts/sensor/windows/amd64/crypto-sensor.exe"
    # "artifacts/sensor/darwin/amd64/crypto-sensor"
    # "artifacts/sensor/darwin/arm64/crypto-sensor"
)

artifacts_missing=0
for artifact in "${sensor_artifacts[@]}"; do
    if [[ -f "$artifact" ]]; then
        ok "Sensor artifact exists: $artifact"
    else
        warn "Missing sensor artifact: $artifact"
        ((artifacts_missing++))
    fi
done

if [[ $artifacts_missing -gt 0 ]]; then
    warn "Missing Linux x86_64 sensor artifact - run 'make sensor-linux-amd64'"
else
    ok "Linux x86_64 sensor artifact present"
    warn "Cross-platform artifact checks temporarily disabled"
fi

# Step 6: Check ECR configuration (registry-only deployment)
log "6. Checking ECR configuration..."

if [[ -f "$ENV_FILE" ]]; then
    # Check if ECR_REGISTRY is set
    if grep -q "^ECR_REGISTRY=" "$ENV_FILE"; then
        ECR_REGISTRY=$(grep "^ECR_REGISTRY=" "$ENV_FILE" | cut -d'=' -f2 | tr -d '"' | tr -d "'")
        if [[ -n "$ECR_REGISTRY" ]]; then
            ok "ECR_REGISTRY is set: $ECR_REGISTRY"

            # Check if ECR_REGISTRY format is correct
            if [[ "$ECR_REGISTRY" =~ ^[0-9]+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com ]]; then
                ok "ECR_REGISTRY format is valid"
            else
                warn "ECR_REGISTRY format may be incorrect (should be: ACCOUNT.dkr.ecr.REGION.amazonaws.com)"
            fi

            # Check if IMAGE_TAG is set (optional, defaults to latest)
            if grep -q "^IMAGE_TAG=" "$ENV_FILE"; then
                IMAGE_TAG=$(grep "^IMAGE_TAG=" "$ENV_FILE" | cut -d'=' -f2 | tr -d '"' | tr -d "'")
                ok "IMAGE_TAG is set: $IMAGE_TAG"
            else
                warn "IMAGE_TAG not set (will use default: latest)"
            fi

            # Check for AWS credentials (if AWS CLI is available)
            if command_exists aws; then
                if aws sts get-caller-identity >/dev/null 2>&1; then
                    ok "AWS credentials are configured"
                else
                    warn "AWS credentials not configured (ECR login may fail)"
                fi
            else
                warn "AWS CLI not available (cannot verify ECR access)"
            fi
        else
            report_issue "ECR_REGISTRY is set but empty in $ENV_FILE"
        fi
    else
        report_issue "ECR_REGISTRY not set in $ENV_FILE (required for ECR-based deployment)"
    fi

    # Check that compose file doesn't have build sections (registry-only)
    if [[ -f "$COMPOSE_FILE" ]]; then
        if grep -q "^[[:space:]]*build:" "$COMPOSE_FILE"; then
            report_issue "Found 'build:' sections in $COMPOSE_FILE (should be ECR-only for production)"
        else
            ok "No build sections found in $COMPOSE_FILE (registry-only pattern)"
        fi
    fi
else
    warn "Skipping ECR checks (missing environment file)"
fi

# Step 7: Check for common deployment issues
log "7. Checking for common deployment issues..."

# Check if .dockerignore files exist
dockerignore_files=(".dockerignore")
for file in "${dockerignore_files[@]}"; do
    if [[ -f "$file" ]]; then
        ok "Docker ignore file exists: $file"
    else
        warn "Missing .dockerignore file: $file (may cause bloated images)"
    fi
done

# Check for hardcoded URLs in compose file
if [[ -f "$COMPOSE_FILE" ]]; then
    if grep -q "https://api.example.com" "$COMPOSE_FILE"; then
        warn "Found hardcoded URLs in $COMPOSE_FILE (should use environment variables)"
    else
        ok "No hardcoded URLs found in compose file"
    fi
fi

# Check for development files that shouldn't be in production
dev_files=("docker-compose.yml" "Dockerfile.dev")
for file in "${dev_files[@]}"; do
    if [[ -f "$file" ]]; then
        warn "Development file present: $file (ensure it's in .dockerignore)"
    fi
done

# Step 8: Resource requirements check
log "8. Checking resource requirements..."

# Check available disk space
available_space=$(df . | awk 'NR==2 {print $4}')
if [[ $available_space -lt 5242880 ]]; then  # Less than 5GB
    warn "Low disk space: $(($available_space / 1024 / 1024))GB available (recommend 5GB+)"
else
    ok "Sufficient disk space available"
fi

# Check available memory
if command_exists free; then
    total_memory=$(free -m | awk 'NR==2{print $2}')
    if [[ $total_memory -lt 2048 ]]; then  # Less than 2GB
        warn "Low memory: ${total_memory}MB total (recommend 2GB+)"
    else
        ok "Sufficient memory available"
    fi
fi

# Step 9: Port conflict check
log "9. Checking for port conflicts..."

# List of ports used by the application (from service-registry.yaml)
ports=(80 3000 3006 8081 8082 8083 8084 8085 8087 8088 8089 8090 8091 8092 8093 8095 8096 8097)

conflicting_ports=()
for port in "${ports[@]}"; do
    if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
        conflicting_ports+=("$port")
    fi
done

if [[ ${#conflicting_ports[@]} -gt 0 ]]; then
    warn "Port conflicts detected: ${conflicting_ports[*]}"
    warn "These ports may prevent services from starting"
else
    ok "No port conflicts detected"
fi

# Final validation summary
log ""
log "======================================"
log "📊 Validation Summary"
log "======================================"

if $VALIDATION_PASSED; then
    ok "All critical checks passed!"
    log ""
    log "🚀 Ready for deployment!"
    log ""
    log "Next steps:"
    log "1. Deploy to EC2: ./scripts/deploy-ec2-smoke.sh"
    log "2. Monitor deployment: docker compose -f docker-compose.ec2-smoke.yml logs -f"
    log "3. Check health: curl http://your-domain/health"
    exit 0
else
    err "Validation failed with $ISSUES_FOUND issue(s)"
    log ""
    log "🔧 Fix the issues above before deploying"
    log ""
    log "Common fixes:"
    log "• Generate environment: node ./scripts/generate-prod-env.mjs"
    log "• Fix compose syntax: docker compose -f $COMPOSE_FILE --env-file $ENV_FILE config"
    log "• Check logs: docker compose -f $COMPOSE_FILE logs"
    log ""
    log "For detailed troubleshooting, see:"
    log "  - docsv4/operations/deployment/ec2-troubleshooting.md"
    log "  - docsv4/operations/deployment/production-checklist.md"
    log "  - docsv4/development/standards/TROUBLESHOOTING.md"
    exit 1
fi
