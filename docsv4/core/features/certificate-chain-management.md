# Certificate Chain Management

**Version:** 1.0  
**Last Updated:** 2026-01-21

Certificate Chain Management enables the platform to automatically build, validate, and visualize certificate chains for discovered certificates.

---

## Overview

Certificate chains establish trust by linking end-entity (leaf) certificates through intermediate certificates to a trusted root Certificate Authority (CA). The platform can:

- Automatically build certificate chains by matching issuer/subject Distinguished Names (DNs)
- Cryptographically verify certificate signatures
- Visualize complete certificate chains
- Identify missing intermediates or broken chains
- Rebuild chains when new certificates are discovered

---

## Key Features

### Automatic Chain Building

When certificates are discovered or imported, the platform automatically attempts to build their chains by:

1. **Matching IssuerDN to SubjectDN**: Finding certificates whose Subject DN matches the target certificate's Issuer DN
2. **Cryptographic Verification**: Verifying that the candidate issuer actually signed the target certificate
3. **Linking Certificates**: Updating the `issuer_certificate_id` field to establish the chain relationship

### Chain Rebuilding

Chains can be rebuilt at any time to:
- Link newly discovered intermediate certificates
- Fix broken chains after certificate updates
- Re-evaluate chains after taxonomy changes

### Chain Visualization

The UI provides interactive chain visualization:
- Tree view showing certificate hierarchy
- Color-coded status (valid, expiring, expired, revoked)
- Click-through navigation to certificate details

---

## User Interface

### Certificate Details - Chain Tab

Access chain information from any certificate:

1. Navigate to **Crypto Inventory** → **Certificates** view
2. Click on a certificate to open details
3. Select the **Chain** tab

**Chain Tab Features:**
- **Chain Tree**: Visual hierarchy of the certificate chain
- **Chain Status**: Overall chain health indicator
- **Certificate Types**: Icons for Root CA, Intermediate CA, and Leaf certificates
- **Status Indicators**: Color-coded for expired, expiring, or revoked certificates
- **Navigation**: Click any certificate in the chain to view its details

### Chain Status Indicators

| Status | Color | Description |
|--------|-------|-------------|
| Complete | Green | Full chain to trusted root |
| Incomplete | Yellow | Missing intermediate(s) |
| Broken | Red | Cannot verify signature |
| Self-Signed | Blue | Self-signed certificate (no chain) |

---

## API Endpoints

### Get Certificate Chain

Retrieve the full certificate chain for a certificate.

```
GET /api/v1/inventory-service/certificates/:id/chain
```

**Response:**
```json
{
  "certificate_id": "cert-uuid",
  "chain": [
    {
      "id": "leaf-cert-uuid",
      "common_name": "www.example.com",
      "subject_dn": "CN=www.example.com, O=Example Corp",
      "issuer_dn": "CN=Example Intermediate CA, O=Example Corp",
      "is_ca_certificate": false,
      "is_self_signed": false,
      "not_after": "2026-12-31T00:00:00Z",
      "position": 0
    },
    {
      "id": "intermediate-cert-uuid",
      "common_name": "Example Intermediate CA",
      "subject_dn": "CN=Example Intermediate CA, O=Example Corp",
      "issuer_dn": "CN=Example Root CA, O=Example Corp",
      "is_ca_certificate": true,
      "is_self_signed": false,
      "not_after": "2030-12-31T00:00:00Z",
      "position": 1
    },
    {
      "id": "root-cert-uuid",
      "common_name": "Example Root CA",
      "subject_dn": "CN=Example Root CA, O=Example Corp",
      "issuer_dn": "CN=Example Root CA, O=Example Corp",
      "is_ca_certificate": true,
      "is_self_signed": true,
      "not_after": "2040-12-31T00:00:00Z",
      "position": 2
    }
  ],
  "chain_status": "complete",
  "chain_length": 3
}
```

### Rebuild Certificate Chain

Trigger chain rebuilding for a specific certificate.

```
POST /api/v1/inventory-service/certificates/:id/rebuild-chain
```

**Response:**
```json
{
  "message": "Certificate chain rebuild initiated successfully"
}
```

The operation:
1. Finds potential issuer certificates by matching Subject DNs
2. Cryptographically verifies each candidate
3. Updates the `issuer_certificate_id` if a valid issuer is found
4. Publishes a `certificate.changed` event

### Rebuild All Certificate Chains

Trigger chain rebuilding for all certificates in the tenant.

```
POST /api/v1/inventory-service/certificates/rebuild-all-chains
```

**Response:**
```json
{
  "message": "Rebuild of all certificate chains initiated successfully"
}
```

This operation runs in parallel for efficiency and is useful after:
- Bulk certificate imports
- Discovery of new intermediate certificates
- Migration from another system

---

## How Chain Building Works

### Step 1: Identify Target Certificate

The target certificate is the leaf certificate whose chain we want to build.

```
Target: CN=www.example.com
IssuerDN: CN=Example Intermediate CA, O=Example Corp
```

### Step 2: Find Candidate Issuers

Search for certificates whose SubjectDN matches the target's IssuerDN:

```sql
SELECT * FROM certificates
WHERE subject_dn = 'CN=Example Intermediate CA, O=Example Corp'
  AND tenant_id = :tenant_id
  AND is_ca_certificate = true
  AND deleted_at IS NULL
```

### Step 3: Cryptographic Verification

For each candidate issuer:
1. Parse the target certificate's PEM data
2. Parse the candidate issuer's PEM data
3. Verify the target's signature using the candidate's public key
4. Select the first candidate that successfully verifies

### Step 4: Link Certificates

Update the target certificate's `issuer_certificate_id`:

```sql
UPDATE certificates
SET issuer_certificate_id = :issuer_id,
    updated_at = NOW()
WHERE id = :target_id
```

### Step 5: Publish Event

Publish a `certificate.changed` event to trigger:
- Compliance re-evaluation
- Cache invalidation
- UI updates

---

## Use Cases

### Discovering Missing Intermediates

**Scenario**: A leaf certificate's chain is incomplete.

**Steps**:
1. Navigate to **Crypto Inventory** → **Certificates**
2. Filter certificates with incomplete chains
3. Note the missing intermediate's IssuerDN
4. Import the missing intermediate certificate
5. Click **Rebuild Chain** on the leaf certificate
6. Verify the chain is now complete

### Bulk Chain Repair

**Scenario**: After importing certificates from another system, chains are not linked.

**Steps**:
1. Navigate to **Crypto Inventory** → **Certificates**
2. Use bulk action or API: `POST /certificates/rebuild-all-chains`
3. Monitor progress in system logs
4. Review certificates with still-incomplete chains

### Verifying Trust Path

**Scenario**: Verify a certificate chains to a trusted root.

**Steps**:
1. Navigate to certificate details → **Chain** tab
2. Review the complete chain visualization
3. Verify the root is a known trusted CA
4. Check that all certificates in the chain are valid (not expired)

---

## Best Practices

### Certificate Import

1. **Import Complete Chains**: When manually importing certificates, include the full chain
2. **Import Intermediates First**: Import CA certificates before leaf certificates for automatic linking
3. **Verify After Import**: Use the Chain tab to verify chains are built correctly

### Chain Monitoring

1. **Regular Audits**: Periodically review certificates with incomplete chains
2. **Expiration Tracking**: Monitor intermediate and root expiration dates
3. **Trust Anchors**: Maintain a list of trusted root certificates

### Troubleshooting

1. **Missing Issuer**: If chain building fails, verify the intermediate certificate exists
2. **DN Mismatch**: Check for exact DN matching (case-sensitive)
3. **Signature Failure**: Verify certificates haven't been tampered with
4. **Self-Signed Detection**: Self-signed certificates correctly skip chain building

---

## Technical Details

### Database Schema

The certificate chain relationship is stored in the `certificates` table:

```sql
-- Certificate with issuer link
CREATE TABLE certificates (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL,
  common_name TEXT,
  subject_dn TEXT,
  issuer_dn TEXT,
  issuer_certificate_id UUID REFERENCES certificates(id),
  is_ca_certificate BOOLEAN DEFAULT FALSE,
  is_self_signed BOOLEAN DEFAULT FALSE,
  certificate_pem TEXT,
  -- ... other fields
);
```

### Chain Building Algorithm

```go
func RebuildCertificateChain(ctx, tenantID, certID) error {
    // 1. Get target certificate
    targetCert := GetCertificateByID(tenantID, certID)
    
    // 2. Skip if self-signed root
    if targetCert.IsCACertificate && targetCert.IsSelfSigned {
        return nil // No chain to build
    }
    
    // 3. Find issuer candidates by SubjectDN match
    candidates := FindCertificateBySubjectDN(tenantID, targetCert.IssuerDN)
    
    // 4. Verify cryptographically
    for _, candidate := range candidates {
        if VerifyCertificateSignature(targetCert.PEM, candidate.PEM) {
            // 5. Link certificates
            LinkCertificateIssuer(certID, candidate.ID)
            PublishCertificateChanged(ctx, tenantID, certID, "chain_rebuilt")
            return nil
        }
    }
    
    // No valid issuer found - clear any stale link
    ClearCertificateIssuer(certID)
    return nil
}
```

### Event Integration

Chain rebuilding publishes events for:
- **compliance-engine**: Re-evaluate certificate compliance
- **UI**: Update chain visualization
- **audit-service**: Log chain changes

---

## Related Features

- [Unified Crypto Inventory](./unified-crypto-inventory.md) - Certificate management interface
- [Compliance Frameworks](./compliance-frameworks.md) - Certificate compliance checks
- [Discovery](./discovery.md) - Certificate discovery from infrastructure assets

---

**Last Updated:** 2026-01-21
