#!/bin/bash

# SSL Setup Script for example.com
# Configures Let's Encrypt SSL certificates for production deployment
#
# Documentation:
#   - See docsv4/operations/deployment/production-checklist.md for deployment procedures
#   - See docsv4/operations/certificates.md for certificate management

set -euo pipefail

# Colors for output
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}$*${NC}"; }
ok() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}$*${NC}"; }
err() { echo -e "${RED}$*${NC}"; }

# Configuration
DOMAIN=${DOMAIN:-example.com}
SSL_EMAIL=${SSL_EMAIL:-admin@example.com}
WEBROOT_PATH="./config/acme/webroot"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    err "This script should not be run as root for security reasons"
    exit 1
fi

# Check if domain is provided
if [[ -z "${DOMAIN:-}" ]]; then
    err "DOMAIN environment variable is required"
    exit 1
fi

# Check if email is provided
if [[ -z "${SSL_EMAIL:-}" ]]; then
    err "SSL_EMAIL environment variable is required"
    exit 1
fi

log "Setting up SSL certificates for domain: $DOMAIN"
log "Email: $SSL_EMAIL"

# Detect Docker Compose command
if docker compose version >/dev/null 2>&1; then
    DCMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DCMD="docker-compose"
else
    err "Neither 'docker compose' nor 'docker-compose' is available"
    exit 1
fi

# Prefer EC2-smoke if present, otherwise use prod
if [[ -f ".env.ec2-smoke" ]]; then
    ENV_FILE=".env.ec2-smoke"
    COMPOSE_FILE="docker-compose.ec2-smoke.yml"
    log "Loading environment from .env.ec2-smoke"
    set -a
    # shellcheck disable=SC1091
    source .env.ec2-smoke
    set +a
elif [[ -f ".env.prod" ]]; then
    ENV_FILE=".env.prod"
    COMPOSE_FILE="docker-compose.prod.yml"
    log "Loading environment from .env.prod"
    set -a
    # shellcheck disable=SC1091
    source .env.prod
    set +a
else
    ENV_FILE=".env.prod"
    COMPOSE_FILE="docker-compose.prod.yml"
    warn ".env.prod or .env.ec2-smoke not found; proceeding with current shell environment"
fi

# If using ALB+ACM, skip certbot flow entirely
if [[ "${USE_ALB:-}" == "1" || "${USE_ALB:-}" == "true" ]]; then
    warn "USE_ALB is set; skipping local certbot and SSL provisioning."
    warn "Assuming TLS is terminated at the AWS ALB with ACM certificates."
    ok "Nothing to do."
    exit 0
fi

# Create webroot directory
log "Creating webroot directory for Let's Encrypt challenges..."
mkdir -p "$WEBROOT_PATH"

# Check if certificates already exist
if [[ -f "./ssl_certs/live/$DOMAIN/fullchain.pem" ]]; then
    warn "SSL certificates already exist for $DOMAIN"
    read -p "Do you want to renew them? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Renewing SSL certificates..."
        $DCMD -f "$COMPOSE_FILE" run --rm certbot renew
        ok "SSL certificates renewed successfully"
    else
        log "Skipping SSL certificate renewal"
    fi
else
    log "Requesting new SSL certificates from Let's Encrypt..."
    
    # Start Traefik API gateway temporarily for ACME challenge
    log "Starting Traefik API gateway for ACME challenge..."
    $DCMD -f "$COMPOSE_FILE" up -d --no-deps api-gateway

    # Wait for gateway to be ready
    sleep 10

    # Request certificates
    $DCMD -f "$COMPOSE_FILE" run --rm certbot

    # Restart gateway with SSL configuration
    log "Restarting Traefik API gateway with SSL configuration..."
    $DCMD -f "$COMPOSE_FILE" restart api-gateway
    
    ok "SSL certificates obtained successfully"
fi

# Set up automatic renewal
log "Setting up automatic certificate renewal..."
cat > ./scripts/ssl-renew.sh << EOF
#!/bin/bash
# SSL Certificate Renewal Script

set -euo pipefail

cd "\$(dirname "\$0")/.."

# Detect Docker Compose command
if docker compose version >/dev/null 2>&1; then
    DCMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DCMD="docker-compose"
else
    echo "Docker Compose not found" >&2
    exit 1
fi

# Prefer EC2-smoke if present, otherwise use prod
if [[ -f ".env.ec2-smoke" ]]; then
    COMPOSE_FILE="docker-compose.ec2-smoke.yml"
elif [[ -f ".env.prod" ]]; then
    COMPOSE_FILE="docker-compose.prod.yml"
else
    COMPOSE_FILE="docker-compose.prod.yml"
fi

# Renew certificates
\$DCMD -f "\$COMPOSE_FILE" run --rm certbot renew

# Traefik watches certificate files and reloads automatically
# Force a restart if needed
\$DCMD -f "\$COMPOSE_FILE" restart api-gateway

echo "SSL certificates renewed and API gateway restarted"
EOF

chmod +x ./scripts/ssl-renew.sh

# Add to crontab (run every Monday at 2 AM)
log "Adding SSL renewal to crontab..."
(crontab -l 2>/dev/null; echo "0 2 * * 1 $(pwd)/scripts/ssl-renew.sh >> $(pwd)/logs/ssl-renewal.log 2>&1") | crontab -

ok "SSL setup completed successfully!"
ok "Certificates are valid for:"
ok "  - $DOMAIN"
ok "  - app.$DOMAIN" 
ok "  - admin.$DOMAIN"
ok ""
ok "Automatic renewal is configured to run every Monday at 2 AM"
ok "Manual renewal: ./scripts/ssl-renew.sh"
