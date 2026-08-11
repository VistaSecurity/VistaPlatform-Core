#!/bin/bash
# Generate mTLS certificates for internal service-to-service communication
# Part of the registry-first development workflow

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CERTS_DIR="$PROJECT_ROOT/config/certs"

echo "🔐 Generating mTLS Certificates for Service-to-Service Communication"
echo "=================================================================="

# Create certs directory if it doesn't exist
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# Certificate validity period (days)
VALIDITY_DAYS=3650  # 10 years for development

echo ""
echo "📋 Step 1: Generating Platform CA (Certificate Authority)"
echo "-----------------------------------------------------------"
# Generate Platform CA private key
openssl genrsa -out platform-ca-key.pem 4096

# Generate Platform CA certificate (self-signed)
openssl req -new -x509 -days $VALIDITY_DAYS -key platform-ca-key.pem -out platform-ca-cert.pem \
    -subj "/C=US/ST=Florida/L=Orlando/O=VistaPlatform/OU=VistaPlatform/CN=Platform CA"

echo "✅ Platform CA certificate generated"

echo ""
echo "📋 Step 2: Generating API Gateway Client Certificate"
echo "-----------------------------------------------------------"
# Generate API Gateway client private key
openssl genrsa -out api-gateway-client-key.pem 4096

# Generate API Gateway client certificate signing request (CSR)
openssl req -new -key api-gateway-client-key.pem -out api-gateway-client.csr \
    -subj "/C=US/ST=Florida/L=Orlando/O=VistaPlatform/OU=VistaPlatform/CN=api-gateway"

# Sign the API Gateway client certificate with Platform CA
openssl x509 -req -days $VALIDITY_DAYS -in api-gateway-client.csr \
    -CA platform-ca-cert.pem -CAkey platform-ca-key.pem -CAcreateserial \
    -out api-gateway-client-cert.pem

# Clean up CSR
rm api-gateway-client.csr

echo "✅ API Gateway client certificate generated"

echo ""
echo "📋 Step 3: Generating Service Certificates"
echo "-----------------------------------------------------------"

# List of services that need mTLS certificates
SERVICES=(
    "device-interrogation-service"
    "audit-service"
    "inventory-service"
    "auth-service"
    "admin-service"
    "sensor-manager"
    "compliance-engine"
    "cbom-service"
    "monitoring-service"
    "tenant-health-service"
    "resource-tracker-service"
    "cluster-sensor-service"
    "mcp-service"
)

for service in "${SERVICES[@]}"; do
    echo "  → Generating certificate for $service..."

    # Generate service private key
    openssl genrsa -out "${service}-key.pem" 4096

    # Generate service certificate signing request (CSR)
    openssl req -new -key "${service}-key.pem" -out "${service}.csr" \
        -subj "/C=US/ST=Florida/L=Orlando/O=VistaPlatform/OU=VistaPlatform/CN=${service}"

    # Sign the service certificate with Platform CA
    openssl x509 -req -days $VALIDITY_DAYS -in "${service}.csr" \
        -CA platform-ca-cert.pem -CAkey platform-ca-key.pem -CAcreateserial \
        -out "${service}-cert.pem"

    # Clean up CSR
    rm "${service}.csr"
done

echo "✅ All service certificates generated"

echo ""
echo "📋 Step 4: Setting Permissions"
echo "-----------------------------------------------------------"
# Set appropriate permissions
chmod 644 *.pem
chmod 600 *-key.pem

echo "✅ Permissions set"

echo ""
echo "=================================================================="
echo "✅ mTLS Certificate Generation Complete!"
echo ""
echo "📁 Certificates location: $CERTS_DIR"
echo ""
echo "Generated certificates:"
echo "  • Platform CA: platform-ca-cert.pem (trusted by all services)"
echo "  • API Gateway client: api-gateway-client-cert.pem + api-gateway-client-key.pem"
echo "  • Service certificates: <service-name>-cert.pem + <service-name>-key.pem"
echo ""
echo "⚠️  IMPORTANT: These are development certificates. For production:"
echo "   1. Use proper CA-signed certificates"
echo "   2. Store private keys securely (e.g., HashiCorp Vault, AWS Secrets Manager)"
echo "   3. Rotate certificates regularly"
echo "   4. Never commit private keys to version control"
echo ""
echo "🔒 mTLS is now ready for service-to-service communication"
echo "=================================================================="
