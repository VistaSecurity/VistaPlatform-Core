---
render_macros: false
---

# Certificate Management Operations Guide

## Overview

The Crypto Inventory Platform uses mTLS (mutual TLS) for secure communication between:
1. **Sensors and the control plane** - Sensor-to-service authentication
2. **Platform services** - Service-to-service authentication (all backend services)

This guide covers certificate issuance, rotation, regeneration, and troubleshooting for both sensor certificates and platform service certificates.

## Certificate Architecture

### Certificate Hierarchy

```
Tenant CA Certificate (per-tenant, persistent)
├── Sensor Client Certificate (issued by Tenant CA)
├── Sensor Client Certificate (issued by Tenant CA)
└── ... (one per sensor)
```

### Certificate Types

1. **Tenant CA Certificate**: Persistent Certificate Authority per tenant (10-year validity)
   - Stored securely in database with encrypted private key
   - Used to sign all sensor and agent certificates for the tenant
   - Automatically created on first sensor/agent registration
   - Separate CAs for sensors (`sensor_ca_certificates`) and agents (`agent_ca_certificates`)
2. **Sensor Client Certificates**: Individual certificates for each sensor (1-year validity)
   - Generated via CSR (Certificate Signing Request) flow
   - Private key generated and stored only on sensor host
   - Certificate signed by tenant CA and returned to sensor
3. **Agent Client Certificates**: Individual certificates for device agents (1-year validity)
   - Generated via CSR flow (same as sensors)
   - Private key generated and stored only on agent host
   - Certificate signed by tenant CA and returned to agent
4. **Platform Bootstrap CA Certificate**: Platform-level CA for issuing bootstrap certificates (10-year validity)
   - Single CA for entire platform (not tenant-specific)
   - Used to issue bootstrap certificates for platform services
   - Stored securely in database with encrypted private key
   - See [Bootstrap Certificates](./bootstrap-certificates.md) for details
5. **Platform Bootstrap Certificates**: Short-lived certificates for platform services (90-day validity)
   - Issued by platform bootstrap CA
   - Used for initial authentication and registration
   - Automatically generated at deployment time
   - Replaced by tenant-specific certificates after registration
6. **Platform Sensor/Agent Certificates**: Certificates for platform-deployed sensors and agents
   - Automatically registered on service startup using bootstrap mTLS certificate authentication
   - Per-tenant certificates for proper isolation
   - Automatically rotated when expiring within 30 days
7. **Platform Service CA Certificate**: Platform-level CA for issuing service certificates (10-year validity)
   - Single CA for entire platform (not tenant-specific)
   - Used to sign all platform service certificates
   - Stored securely in database with encrypted private key
   - See [Platform Service mTLS](#platform-service-mtls) section for details
8. **Platform Service Certificates**: Certificates for service-to-service mTLS communication (1-year validity)
   - Server certificates for HTTPS API endpoints (port 8443)
   - Client certificates for inter-service communication
   - Automatically generated at deployment time
   - Stored in `service-certs/{service-name}/` directory
   - See [Platform Service mTLS](#platform-service-mtls) section for details

## Certificate Lifecycle

### 1. Initial Certificate Generation (CSR-Based Flow)

Certificates are generated using a secure CSR (Certificate Signing Request) flow where private keys never leave the sensor:

**Step 1: Sensor generates keypair and CSR locally**
```go
// Sensor-side: Generate RSA keypair
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

// Create CSR with sensor ID as Common Name
csrTemplate := x509.CertificateRequest{
    Subject: pkix.Name{
        CommonName:    sensorID.String(), // UUID as CN
        Organization:  []string{"Crypto Inventory Sensor"},
    },
    SignatureAlgorithm: x509.SHA256WithRSA,
}
csrPEM := createCSR(csrTemplate, privateKey)
```

**Step 2: Sensor sends CSR to platform during registration**
```bash
curl -X POST http://localhost:8080/api/v1/sensor-manager/sensors/register \
  -H "Content-Type: application/json" \
  -d '{
    "registration_key": "REG-...",
    "name": "sensor-dc01",
    "platform": "linux",
    "version": "0.5.1",
    "profile": "datacenter_host",
    "network_interfaces": ["eth0"],
    "ip_address": "192.168.1.100",
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
    "sensor_id": "550e8400-e29b-41d4-a716-446655440000"
  }'
```

**Step 3: Platform signs CSR and returns certificate**
```json
{
  "sensor_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_cert": "-----BEGIN CERTIFICATE-----\n...",
  "server_ca_cert": "-----BEGIN CERTIFICATE-----\n...",
  "certificate_expires_at": "2026-04-27T10:30:00Z"
}
```

**Note**: The `client_key` is NOT included in the response - it remains on the sensor host.

### 2. Certificate Validation

Sensors must present valid certificates for outbound communication. The platform performs comprehensive validation:

- **CN Validation**: Certificate Common Name must match sensor ID (UUID)
- **Chain Validation**: Certificate must be signed by the tenant's active CA
- **Expiration Check**: Certificate must not be expired
- **Revocation Check**: Certificate must not be revoked (checked against database)
- **Key Usage**: Certificate must have ClientAuth extended key usage

### 3. Certificate Rotation

Certificates can be rotated for security or operational reasons. Rotation uses the same CSR-based flow as initial registration.

#### Automatic Rotation (Sensor-Initiated)
Sensors automatically rotate certificates when they are expiring soon (within 30 days):
1. Sensor generates new keypair and CSR
2. Sensor sends rotation request with CSR to platform
3. Platform revokes old certificate and signs new CSR
4. Platform returns new certificate to sensor
5. Sensor updates its certificate configuration

#### Manual Rotation (Platform-Initiated)
1. Navigate to Sensor Management
2. Select sensor → "Certificates" tab
3. Click "Request Manual Rotation"
4. Sensor will rotate on next heartbeat or restart

#### Via API
```bash
# Sensor initiates rotation with new CSR
curl -X POST http://localhost:8080/api/v1/sensor-manager/sensors/{sensor_id}/certificates/rotate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\n..."
  }'
```

## Certificate Management Operations

### Certificate Issuance

#### Automatic Issuance
Certificates are automatically generated during sensor registration:

```go
// Backend certificate generation process
func (h *Handler) generateCACertificate() (string, string, error) {
    // Generate CA private key
    caKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return "", "", err
    }
    
    // Create CA certificate template
    caTemplate := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization:       []string{"VistaSecurity"},
            OrganizationalUnit: []string{"CryptoInventory"},
            Country:            []string{"US"},
            Province:           []string{"Florida"},
            Locality:           []string{"Orlando"},
        },
        NotBefore:             time.Now(),
        NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
        BasicConstraintsValid: true,
        IsCA:                  true,
    }
    
    // Sign CA certificate
    caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
    if err != nil {
        return "", "", err
    }
    
    return encodePEM(caCertDER, caKey)
}
```

#### CSR-Based Certificate Issuance
```go
// Platform-side: Issue certificate from CSR
func (s *CertificateService) IssueCertificate(tenantID, sensorID uuid.UUID, csrPEM string) (string, error) {
    // 1. Get or create active CA for tenant
    ca, err := s.caManager.GetActiveCA(tenantID)
    if err != nil {
        return "", fmt.Errorf("failed to get CA: %w", err)
    }
    
    // 2. Parse and validate CSR
    csr, err := x509.ParseCertificateRequest([]byte(csrPEM))
    if err != nil {
        return "", fmt.Errorf("invalid CSR: %w", err)
    }
    
    // 3. Validate CSR CN matches sensor ID
    if csr.Subject.CommonName != sensorID.String() {
        return "", fmt.Errorf("CSR CN mismatch")
    }
    
    // 4. Create certificate template
    certTemplate := x509.Certificate{
        SerialNumber: generateSerialNumber(),
        Subject:      csr.Subject,
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(1, 0, 0), // 1 year
        KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
    }
    
    // 5. Sign certificate with tenant CA
    certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCert, csr.PublicKey, caKey)
    if err != nil {
        return "", fmt.Errorf("failed to sign certificate: %w", err)
    }
    
    // 6. Store certificate in database (without private key)
    return pem.EncodeToString(certDER), nil
}
```

### Certificate Validation

#### Client Certificate Validation
```go
func SensorAuth(certService *CertificateService, caManager *CAManager) gin.HandlerFunc {
    return func(c *gin.Context) {
        sensorIDStr := c.Param("sensor_id")
        sensorID, _ := uuid.Parse(sensorIDStr)
        
        if c.Request.TLS != nil && len(c.Request.TLS.PeerCertificates) > 0 {
            clientCert := c.Request.TLS.PeerCertificates[0]
            
            // 1. Validate CN matches sensor ID
            if clientCert.Subject.CommonName != sensorIDStr {
                c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate CN does not match sensor_id"})
                c.Abort()
                return
            }
            
            // 2. Get stored certificate to retrieve tenant ID
            storedCert, err := certService.GetCertificate(sensorID)
            if err != nil || storedCert == nil {
                c.JSON(http.StatusUnauthorized, gin.H{"error": "Sensor certificate not found"})
                c.Abort()
                return
            }
            
            // 3. Validate certificate chain against tenant CA
            ca, err := caManager.GetActiveCA(storedCert.TenantID)
            if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve CA"})
                c.Abort()
                return
            }
            
            // Build certificate chain and verify
            roots := x509.NewCertPool()
            roots.AppendCertsFromPEM([]byte(ca.CACertPEM))
            opts := x509.VerifyOptions{
                Roots:     roots,
                KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
            }
            if _, err := clientCert.Verify(opts); err != nil {
                c.JSON(http.StatusUnauthorized, gin.H{"error": "Certificate chain validation failed"})
                c.Abort()
                return
            }
            
            // 4. Check expiration
            if time.Now().After(clientCert.NotAfter) {
                c.JSON(http.StatusUnauthorized, gin.H{"error": "Certificate has expired"})
                c.Abort()
                return
            }
            
            // 5. Check revocation
            if storedCert.RevokedAt.Valid && !storedCert.RevokedAt.Time.IsZero() {
                c.JSON(http.StatusUnauthorized, gin.H{"error": "Certificate has been revoked"})
                c.Abort()
                return
            }
        }
        
        c.Next()
    }
}
```

### Certificate Storage

#### Database Schema
```sql
-- Tenant CA certificates (persistent, one per tenant)
CREATE TABLE IF NOT EXISTS sensor_ca_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ca_cert_pem TEXT NOT NULL,
    ca_key_pem_encrypted TEXT NOT NULL, -- AES-256-GCM encrypted
    serial_number BIGINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    UNIQUE(tenant_id, is_active) WHERE is_active = TRUE
);

-- Sensor client certificates (issued from CSRs)
CREATE TABLE IF NOT EXISTS sensor_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sensor_id UUID NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    certificate_pem TEXT NOT NULL,
    -- Note: private_key_pem is NOT stored - keys remain on sensor host
    serial_number VARCHAR(255) NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(sensor_id, serial_number)
);

-- Indexes for certificate lookups
CREATE INDEX IF NOT EXISTS idx_sensor_certificates_sensor_id ON sensor_certificates(sensor_id);
CREATE INDEX IF NOT EXISTS idx_sensor_certificates_tenant_id ON sensor_certificates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sensor_certificates_expires_at ON sensor_certificates(expires_at);
CREATE INDEX IF NOT EXISTS idx_sensor_certificates_revoked_at ON sensor_certificates(revoked_at);
CREATE INDEX IF NOT EXISTS idx_sensor_ca_certificates_tenant_id ON sensor_ca_certificates(tenant_id);
```

## Certificate Operations

### Certificate Rotation

#### Process Overview (CSR-Based)
1. **Sensor Generates New Keypair**: Sensor creates new RSA keypair locally
2. **Sensor Creates CSR**: Sensor generates CSR with sensor ID as CN
3. **Sensor Sends Rotation Request**: Sensor sends CSR to platform rotation endpoint
4. **Platform Revokes Old Cert**: Platform marks old certificate as revoked
5. **Platform Signs New CSR**: Platform signs new CSR with tenant CA
6. **Platform Returns Certificate**: Platform returns signed certificate (no private key)
7. **Sensor Updates Config**: Sensor stores new certificate and continues operation

#### API Endpoint
```bash
# Rotate certificate (sensor-initiated with CSR)
curl -X POST http://localhost:8080/api/v1/sensor-manager/sensors/{sensor_id}/certificates/rotate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\n..."
  }'
```

#### Response
```json
{
  "sensor_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_cert": "-----BEGIN CERTIFICATE-----\n...",
  "server_ca_cert": "-----BEGIN CERTIFICATE-----\n...",
  "certificate_expires_at": "2026-04-27T10:30:00Z",
  "message": "Certificate rotated successfully"
}
```

**Note**: The `client_key` is NOT included - it remains on the sensor host.

### Certificate Revocation

#### Revocation Process
1. **Identify Certificate**: Find certificate to revoke
2. **Update Database**: Set `revoked_at` timestamp
3. **Update CRL**: Add to Certificate Revocation List
4. **Notify Services**: Update validation logic

#### Revocation API
```bash
# Revoke certificate for a sensor
curl -X POST http://localhost:8080/api/v1/sensor-manager/sensors/{sensor_id}/certificates/revoke \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "compromised"}'
```

#### Response
```json
{
  "message": "Certificate revoked successfully",
  "sensor_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Certificate Monitoring

#### Expiration Monitoring
```sql
-- Find certificates expiring in next 30 days
SELECT 
    s.name,
    s.id,
    sc.expires_at,
    sc.issued_at
FROM sensor_certificates sc
JOIN sensors s ON sc.sensor_id = s.id
WHERE sc.expires_at < NOW() + INTERVAL '30 days'
  AND sc.revoked_at IS NULL
ORDER BY sc.expires_at ASC;
```

#### Certificate Health Check
```bash
# Check certificate status for all sensors
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/sensor-manager/sensors/certificate-status
```

## Troubleshooting

### Common Certificate Issues

#### "Certificate CN does not match sensor ID"
- **Cause**: Certificate Common Name doesn't match route parameter
- **Solution**: Regenerate certificate or verify sensor ID

#### "Certificate has expired"
- **Cause**: Certificate past expiration date
- **Solution**: Regenerate certificate using management UI

#### "Certificate validation failed"
- **Cause**: Certificate not issued by our CA or corrupted
- **Solution**: Check certificate chain and regenerate if needed

#### "Certificate not found"
- **Cause**: Sensor doesn't have associated certificate
- **Solution**: Complete sensor registration process

#### "Platform sensor not registering"
- **Cause**: Service account token missing or invalid, database not ready, or service startup issue
- **Solution**: 
  1. Verify `CLUSTER_SENSOR_SERVICE_TOKEN` or `DEVICE_INTERROGATION_SERVICE_TOKEN` is set
  2. Check service logs for registration errors
  3. Verify service account exists in database and token hash matches
  4. Ensure database is accessible and tenants table has active tenants
  5. Check certificate files exist in `/app/certs/` or `/tmp/{service}-certs/`

#### "Platform sensor certificate expired"
- **Cause**: Certificate expired and auto-rotation failed
- **Solution**: 
  1. Check service logs for rotation errors
  2. Verify service account token is still valid
  3. Manually trigger re-registration by restarting the service
  4. Check certificate files on disk for expiration dates

### Debugging Commands

#### Certificate Inspection
```bash
# Inspect certificate details
openssl x509 -in sensor-cert.pem -text -noout

# Check certificate expiration
openssl x509 -in sensor-cert.pem -dates -noout

# Verify certificate chain
openssl verify -CAfile ca-cert.pem sensor-cert.pem
```

#### Certificate Testing
```bash
# Test mTLS connection
curl -v --cert sensor-cert.pem --key sensor-key.pem \
  --cacert ca-cert.pem \
  https://crypto-inventory.company.com/api/v1/sensor-manager/sensors/{sensor_id}/heartbeat

# Test certificate validation
openssl s_client -connect crypto-inventory.company.com:443 \
  -cert sensor-cert.pem -key sensor-key.pem -CAfile ca-cert.pem
```

### Certificate Logs

#### Backend Logs
```bash
# Check certificate generation logs
docker logs crypto-sensor-manager | grep -i certificate

# Check certificate validation logs
docker logs crypto-sensor-manager | grep -i "mTLS\|certificate"
```

#### Gateway Logs
```bash
# Check TLS termination logs
docker logs crypto-api-gateway | grep -i ssl

# Check client certificate logs
docker logs crypto-api-gateway | grep -i "client.*cert"
```

## Security Considerations

### Certificate Security
- **Key Storage**: Private keys generated and stored ONLY on sensor hosts (never transmitted to platform)
- **CSR-Based Flow**: Certificates issued via Certificate Signing Requests - private keys never leave sensor
- **CA Security**: Tenant CA private keys encrypted with AES-256-GCM and stored in database
- **Key Rotation**: Automatic rotation when certificates expire within 30 days
- **Access Control**: Certificate operations require admin authentication
- **Audit Logging**: All certificate operations logged

### Operational Security
- **Certificate Expiry**: Monitor and rotate before expiration
- **Revocation**: Immediate revocation for compromised certificates
- **Backup**: Secure backup of CA certificates
- **Recovery**: Documented certificate recovery procedures

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CERTIFICATE_EXPIRY_DAYS` | Certificate validity period | `365` |
| `CERTIFICATE_CA_PATH` | CA certificate storage path | `/app/certs/ca` |
| `CERTIFICATE_KEY_SIZE` | Certificate key size | `2048` |
| `CERTIFICATE_ALGORITHM` | Certificate algorithm | `RSA` |

### Admin Settings

| Setting | Description | Range | Default |
|---------|-------------|-------|---------|
| `certificate_expiry_days` | Certificate validity period | 30-365 | 365 |
| `auto_certificate_rotation` | Enable automatic rotation | true/false | false |
| `certificate_warning_days` | Days before expiry to warn | 7-90 | 30 |

## Best Practices

### Certificate Management
- **Regular Rotation**: Rotate certificates annually or when compromised
- **Monitoring**: Monitor certificate expiration dates
- **Documentation**: Maintain certificate inventory
- **Testing**: Test certificate regeneration procedures

### Security Operations
- **Access Control**: Limit certificate management access
- **Audit Trail**: Log all certificate operations
- **Backup Strategy**: Secure backup of CA certificates
- **Recovery Plan**: Document certificate recovery procedures

### Operational Excellence
- **Automation**: Automate certificate monitoring and alerts
- **Documentation**: Maintain certificate management procedures
- **Training**: Train operations team on certificate management
- **Testing**: Regular testing of certificate operations

## Platform Service mTLS

### Overview

All platform services use mTLS for secure service-to-service communication. Each service runs in dual-mode:
- **HTTP (port 8080)**: Health check endpoints (no authentication required)
- **HTTPS (port 8443)**: API endpoints with mTLS authentication

### Certificate Generation

#### Initial Setup

Generate the platform service CA (one-time operation):

```bash
./scripts/generate-service-ca.sh
```

This creates:
- Platform service CA certificate and encrypted private key (stored in database)
- CA certificate available for service configuration

#### Generate Service Certificates

Generate certificates for all platform services:

```bash
./scripts/generate-service-certificates.sh
```

This creates certificates for all services:
- `auth-service`
- `inventory-service`
- `compliance-engine`
- `report-generator`
- `sensor-manager`
- `cluster-sensor-service`
- `admin-service`
- `monitoring-service`
- `resource-tracker-service`
- `tenant-health-service`
- `device-interrogation-service`
- `audit-service`
- `notification-service`
- `discovery-processor-service`
- `api-gateway` (client certificate for backend connections)

Certificates are stored in:
- Database: `platform_service_certificates` table
- Filesystem: `./service-certs/{service-name}/` directory

### Certificate Files

After generation, each service has the following files:

```
service-certs/{service-name}/
├── server-cert.pem      # Server certificate for HTTPS API (port 8443)
├── server-key.pem       # Server private key
├── client-cert.pem      # Client certificate for inter-service calls
├── client-key.pem       # Client private key
└── platform-ca-cert.pem # Platform service CA certificate
```

### Deployment

#### Development Environment

Generate the certificates once (needs Postgres up and `ENCRYPTION_MASTER_KEY` set in `.env` — see `scripts/generate-service-ca.sh`'s prerequisites):

```bash
docker compose up -d postgres
./scripts/generate-service-ca.sh
./scripts/generate-service-certificates.sh
```

1. Service CA is created if it doesn't exist
2. Service certificates are generated for all services
3. Certificates are mounted into containers via docker-compose.yml

#### Production Environment

1. **Generate Certificates**:
   ```bash
   ./scripts/generate-service-ca.sh
   ./scripts/generate-service-certificates.sh
   ```

2. **Store Certificates Securely**:
   - Use secrets manager (AWS Secrets Manager, HashiCorp Vault)
   - Store in encrypted storage
   - Never commit to version control

3. **Mount Certificates**:
   - Update docker-compose.prod.yml with certificate volume mounts
   - Ensure certificates are available at container startup

4. **Set Permissions**:
   ```bash
   find service-certs -type d -exec chmod 755 {} \;
   find service-certs -type f -name "*.pem" -exec chmod 600 {} \;
   ```

### Service Configuration

Each service is configured with mTLS via environment variables:

```bash
USE_MTLS=true
TLS_PORT=8443
SERVICE_CERT_PATH=/app/certs/server-cert.pem
SERVICE_KEY_PATH=/app/certs/server-key.pem
CLIENT_CERT_PATH=/app/certs/client-cert.pem
CLIENT_KEY_PATH=/app/certs/client-key.pem
PLATFORM_CA_CERT_PATH=/app/certs/platform-ca-cert.pem
```

### API Gateway Configuration

The API Gateway (Traefik) uses mTLS client certificates when connecting to backend services via a `serversTransport` configuration:

```yaml
# Traefik dynamic config (config/traefik/dynamic-development.yaml)
http:
  serversTransports:
    mtls:
      certificates:
        - certFile: /etc/traefik/certs/api-gateway-client-cert.pem
          keyFile: /etc/traefik/certs/api-gateway-client-key.pem
      rootCAs:
        - /etc/traefik/certs/platform-ca-cert.pem
      serverName: ""
      insecureSkipVerify: false

  services:
    auth-service:
      loadBalancer:
        serversTransport: mtls
        servers:
          - url: "https://auth-service:8443"
```

### Testing mTLS

There is no bundled test script for this — verify each check by hand:

**Certificate files exist and are valid:**
```bash
for f in service-certs/auth-service/*.pem; do
  echo "== $f =="
  openssl x509 -in "$f" -noout -checkend 0 -dates 2>/dev/null \
    || echo "  (not a cert, or expired)"
done
```

**Health endpoint works on HTTP (port 8080), no certificate required:**
```bash
docker compose exec auth-service curl -sf http://localhost:8080/health
```

**API endpoint works on HTTPS with mTLS (port 8443), using the client cert:**
```bash
docker compose exec auth-service curl -sf --cacert /app/certs/platform-ca-cert.pem \
  --cert /app/certs/client-cert.pem --key /app/certs/client-key.pem \
  https://localhost:8443/health
```

**Services reject connections without a valid certificate:**
```bash
docker compose exec auth-service curl -sk https://localhost:8443/health
# expect a TLS handshake failure (curl exit 56), not a 200 response
```

### Troubleshooting Platform Service mTLS

#### "Failed to create mTLS server"

**Cause**: Certificate files missing or invalid

**Solution**:
1. Verify certificate files exist in `service-certs/{service-name}/`
2. Check file permissions (should be readable by service user)
3. Regenerate certificates if missing: `./scripts/generate-service-certificates.sh`

#### "mTLS certificate validation failed"

**Cause**: Certificate not signed by platform service CA

**Solution**:
1. Verify certificate is signed by platform service CA
2. Check certificate expiration date
3. Regenerate certificate if expired or invalid

#### "Service-to-service communication fails"

**Cause**: Client certificate missing or invalid

**Solution**:
1. Verify client certificates exist for both services
2. Check client certificate is signed by platform service CA
3. Verify service is using mTLS client when making calls
4. Check service logs for mTLS connection errors

#### "Health check fails"

**Cause**: Service not responding on HTTP port 8080

**Solution**:
1. Health checks use HTTP (not HTTPS) on port 8080
2. Verify service is listening on port 8080
3. Check service logs for startup errors

## Support & Resources

### Documentation
- **API Reference**: Certificate management endpoints
- **Security Guide**: mTLS implementation details
- **Troubleshooting**: Common certificate issues and solutions
- **Platform Service mTLS**: See [Platform Service mTLS](#platform-service-mtls) section above

### Tools
- **Certificate Inspector**: Built-in certificate validation tools
- **Monitoring Dashboard**: Certificate expiration monitoring
- **Alert System**: Automated certificate expiry alerts
- **mTLS verification**: see [Testing mTLS](#testing-mtls) above for the manual checks — there is no bundled test script

### Support
- **Internal Wiki**: [Certificate Management Wiki](https://wiki.company.com/certificates)
- **GitHub Issues**: [Certificate Issues](https://github.com/company/crypto-inventory/issues?q=label%3Acertificates)
- **Slack Channel**: #crypto-inventory-certificates
- **Email Support**: certificates-support@company.com
