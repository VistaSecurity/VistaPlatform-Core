# Unified Crypto Inventory

**Version:** 1.0  
**Last Updated:** 2026-04-30

The Unified Crypto Inventory feature provides a comprehensive view of assets, certificates, and cryptographic configurations as first-class entities, enabling cross-entity search, filtering, and relationship visualization.

---

## Overview

The Unified Crypto Inventory treats assets, certificates, and crypto configurations as equal entities in a unified view, allowing users to:

- Search and filter across all entity types simultaneously
- View relationships between assets and certificates
- Identify security issues across the entire cryptographic infrastructure
- Manage certificate lifecycle alongside asset management
- Detect deprecated algorithms and weak cryptography

---

## Key Features

### Unified View

The Crypto Inventory page provides three view modes:

1. **Assets View**: Traditional asset-only view
2. **Certificates View**: Certificate-focused view with asset relationships
3. **Unified View**: Combined view showing both assets and certificates in a single list

### Comprehensive Filtering

#### Entity-Agnostic Filters
- **Search**: Search across hostnames, IPs, certificate CNs, issuers, and more
- **Risk Level**: Filter by risk level across all entities
- **Environment**: Filter by environment (production, staging, development, test)

#### Asset-Specific Filters
- Asset type, business unit, operating system
- Owner email, asset ownership, asset status
- Certificate-based filters (has certificates, expiring certificates)

#### Certificate-Specific Filters
- Expiration date ranges
- Key size thresholds
- Algorithm filtering
- Issuer filtering

#### Crypto Configuration Filters
- Protocol version (TLS/SSL versions)
- Hash algorithm (SHA256, SHA1, MD5)
- Key size thresholds
- Deprecated algorithm detection

#### Cross-Entity Filters
- **Assets with Certificates**: Find assets that have associated certificates
- **Certificates Expiring Within X Days**: Find certificates expiring soon
- **Assets Using Deprecated Algorithms**: Find assets with weak cryptography
- **Certificates Used by Production Assets**: Find production certificates

### Smart Filters

Pre-configured filter sets for common security use cases:

- **TLS 1.0 Implementations**: Find all assets using deprecated TLS 1.0
- **Certificates Expiring in 30 Days**: Certificates that need renewal soon
- **Assets with Weak Cryptography**: Assets using deprecated algorithms or weak keys
- **Self-Signed Certificates**: Certificates that are self-signed
- **Certificates with Key Size < 2048**: Weak key size certificates

### Relationship Visualization

View relationships between entities:
- **Asset → Certificates**: See all certificates used by an asset
- **Certificate → Assets**: See all assets using a certificate
- **Crypto Configurations**: View cryptographic configurations linking assets and certificates

### Certificate Lifecycle Management

Comprehensive certificate management:
- **Expiration Tracking**: Monitor certificates expiring within configurable timeframes
- **Expiration Warnings**: Visual indicators for certificates expiring soon
- **Certificate Details**: Full certificate information including:
  - Subject and issuer DNs
  - Validity dates
  - Key information (size, algorithm)
  - Fingerprints
  - Key usage and extended key usage
  - Associated assets

### Bulk Operations

Select multiple entities for bulk operations:
- **Export CSV**: Export selected entities to CSV format
- **Export JSON**: Export selected entities to JSON format
- **Generate Report**: Create reports for selected entities
- **Bulk Tagging**: Apply tags to multiple entities (coming soon)

---

## Use Cases

### Certificate Expiration Management

**Scenario**: Identify all certificates expiring within 30 days across production assets.

**Steps**:
1. Navigate to **Crypto Inventory**
2. Select **Unified** view mode
3. Apply Smart Filter: "Certificates Expiring in 30 Days"
4. Add filter: `environment=production`
5. Review list of expiring certificates
6. Export to CSV for renewal planning

### Deprecated Algorithm Detection

**Scenario**: Find all assets using deprecated TLS versions or weak hash algorithms.

**Steps**:
1. Navigate to **Crypto Inventory**
2. Select **Assets** view mode
3. Apply Smart Filter: "Assets with Weak Cryptography"
4. Review assets with deprecated algorithms
5. Filter by environment to prioritize production issues
6. Export list for remediation planning

### Certificate-to-Asset Mapping

**Scenario**: Identify all assets using a specific certificate that needs to be renewed.

**Steps**:
1. Navigate to **Crypto Inventory** → **Certificates** view
2. Search for certificate by common name or issuer
3. Click on certificate to view details
4. Review "Associated Assets" section
5. Export asset list for certificate replacement planning

### Cross-Entity Security Audit

**Scenario**: Comprehensive security audit across assets and certificates.

**Steps**:
1. Navigate to **Crypto Inventory** → **Unified** view
2. Apply filters:
   - Risk Level: Critical, High
   - Environment: Production
   - Uses Deprecated Algorithms: Yes
3. Review unified list of high-risk entities
4. Export comprehensive report
5. Prioritize remediation based on risk scores

---

## User Interface

### Page Layout

The Crypto Inventory page consists of:

1. **Header**: Page title, export buttons
2. **View Mode Selector**: Tabs for Assets, Certificates, Unified
3. **Summary Statistics**: Key metrics (total assets, certificates, expiring certs, deprecated algorithms)
4. **Filter Panel** (left sidebar):
   - Smart Filters section
   - Unified Inventory Filters component
5. **Main Content Area**:
   - Entity list (cards or table view)
   - Pagination controls
   - Bulk actions bar (when entities selected)

### Entity Cards

Each entity is displayed as a card showing:
- **Entity Type Badge**: Visual indicator (Asset/Certificate)
- **Risk Level Badge**: Color-coded risk indicator
- **Key Information**: Hostname/CN, IP/Issuer, environment
- **Relationship Counts**: Number of associated certificates/assets
- **Expiration Warning**: Days until expiration (for certificates)
- **Quick Actions**: View details, export

### Certificate List View

In Certificates view mode, certificates are displayed in a sortable table:
- **Common Name**: Certificate common name with icon
- **Issuer**: Certificate issuer DN
- **Expiration**: Expiration date and days remaining
- **Key Size**: Public key size in bits
- **Algorithm**: Public key algorithm
- **Status**: Expiration status badge
- **Lifecycle**: Revocation status, data completeness, chain membership indicators
- **Source**: Data source badge (sensor, device_interrogation, integration, manual)
- **Actions**: Expand for details, view certificate

**Add Certificate Button**: Manual certificate addition with three input methods:
- **Paste PEM**: Copy and paste certificate in PEM format
- **File Upload**: Upload certificate files (PEM, DER, PKCS#12)
- **Manual Entry**: Form-based entry for partial certificate data

### Certificate Details Modal

Comprehensive certificate information with three tabs:

**Details Tab:**
- **Basic Information**: CN, serial number, subject/issuer DNs, SANs
- **Validity & Security**: Valid dates, key size, algorithms, fingerprints
- **Properties**: Self-signed status, CA status, key usage
- **Lifecycle Information**: Revocation status, data completeness, data source, last data update
- **Associated Assets**: List of assets using this certificate
- **Export Options**: Export as PEM or JSON

**Chain Tab:**
- **Certificate Chain Visualization**: Interactive tree view of certificate chain
- **Chain Relationships**: Visual display of issuer relationships
- **Certificate Types**: Visual indicators for root CA, intermediate CA, and leaf certificates
- **Status Indicators**: Color-coded status for expired, revoked, or expiring certificates
- **Chain Navigation**: Click to view details of certificates in the chain

**History Tab:**
- **Certificate History Timeline**: Chronological list of certificate events
- **Event Types**: Creation, updates, revocation, renewal events
- **Event Data**: Detailed information about each historical event
- **Timeline Visualization**: Visual timeline with event details

---

## API Integration

### Unified Inventory Endpoint

```
GET /api/v2/inventory-service/crypto-inventory
```

Supports comprehensive filtering across all entity types.

### Certificate Endpoints

- `GET /api/v2/inventory-service/certificates` - List certificates
- `GET /api/v2/inventory-service/certificates/:id` - Get certificate details
- `GET /api/v2/inventory-service/certificates/expiring` - Get expiring certificates

---

## Best Practices

### Certificate Management

1. **Regular Monitoring**: Review expiring certificates monthly
2. **Renewal Planning**: Export certificates 60 days before expiration
3. **Key Size Standards**: Enforce minimum 2048-bit keys
4. **Algorithm Standards**: Avoid SHA1, MD5, and weak algorithms
5. **Self-Signed Certificates**: Monitor and replace in production
6. **Certificate Inventory**: Maintain accurate inventory for compliance

### Security Auditing

1. **Regular Audits**: Use Smart Filters for monthly security audits
2. **Deprecated Algorithms**: Regularly check for deprecated algorithm usage
3. **Production Focus**: Prioritize production environment issues
4. **Risk-Based Remediation**: Address high-risk findings first
5. **Documentation**: Export and document findings for compliance

### Filter Usage

1. **Start Broad**: Begin with Smart Filters for common use cases
2. **Narrow Down**: Add specific filters to refine results
3. **Save Filters**: Use browser bookmarks for frequently used filter combinations
4. **Export Results**: Export filtered results for external tracking
5. **Cross-Reference**: Use cross-entity filters to find related issues

---

## Technical Details

### Data Model

The unified inventory uses a UNION ALL query strategy to combine:
- **Assets**: From `network_assets` table
- **Certificates**: From `certificates` table
- **Relationships**: Through `crypto_implementations` table

### Performance

- Database indexes on certificate expiration dates
- Indexes on certificate key size and algorithm
- Indexes on crypto configuration protocol version and hash algorithm
- Query result caching for expensive aggregations
- Pagination for large result sets

### Filtering Strategy

Filters are applied at the SQL level for performance:
- Entity-specific filters applied to respective queries
- Cross-entity filters use EXISTS subqueries
- Deprecated algorithm detection uses predefined lists
- Certificate expiration uses date range queries

---

## Related Features

- [Asset Management](./asset-lifecycle-management.md) - Asset lifecycle and stale asset management
- [Discovery](./discovery.md) - Asset discovery and approval workflows
- [Compliance Frameworks](./compliance-frameworks.md) - Compliance assessment and reporting
- [CBOM Artifacts](../cbom/cbom-artifacts.md) - Immutable, content-hashed inventory snapshots (the templated report builder was retired in favor of this)

---

## Algorithm Analysis Features

### Post-Quantum Cryptography (PQC) Support

The platform now includes comprehensive Post-Quantum Cryptography identification and analysis:

**PQC Algorithm Identification:**
- **NIST PQC Algorithm Coverage**: All five NIST PQC algorithm families are included — the three standards finalized in August 2024 plus the two NIST-selected families whose standards are still in progress:
  - **ML-KEM** (FIPS 203, formerly CRYSTALS-Kyber): Key encapsulation mechanisms (512, 768, 1024) — *NIST standardized*
  - **ML-DSA** (FIPS 204, formerly CRYSTALS-Dilithium): Digital signatures (44, 65, 87) — *NIST standardized*
  - **SLH-DSA** (FIPS 205, formerly SPHINCS+): Stateless hash-based signatures (128s, 128f, 192s, 192f, 256s, 256f) — *NIST standardized*
  - **FN-DSA** (draft FIPS 206, formerly FALCON): Alternative signatures (512, 1024) — *NIST-selected; standard not yet finalized*
  - **HQC**: Backup key encapsulation (128, 192, 256) — *NIST-selected March 2025; standard not yet finalized*

**PQC Features:**
- **PQC Filtering**: Filter algorithms by PQC status (All, PQC Only, Non-PQC Only, Standardized PQC)
- **PQC Badges**: Visual indicators showing PQC status and standardization level
- **Quantum Vulnerability Warnings**: Non-PQC algorithms display warnings about quantum vulnerability
- **PQC Migration Recommendations**: Non-PQC algorithms include PQC alternatives in recommendations
- **PQC Summary Statistics**: Dashboard shows counts of PQC vs non-PQC algorithms

**Use Cases:**
- Identify non-quantum-resistant algorithms in your infrastructure
- Plan migration to NIST standardized PQC algorithms
- Track PQC adoption across your cryptographic configurations
- Ensure compliance with future quantum computing security requirements

### Algorithm Usage Dashboard

Navigate to **Algorithms** page to access comprehensive algorithm analysis:

**Summary Statistics:**
- Total algorithms in taxonomy
- Deprecated algorithms count
- Weak algorithms count
- Recommended algorithms count
- **PQC algorithms count**
- **NIST Standardized PQC count**

**Algorithm Categories:**
- Hash algorithms (MD5, SHA1, SHA256, SHA512, etc.)
- Symmetric encryption (DES, 3DES, RC4, AES, ChaCha20)
- Key exchange (RSA, ECDHE, DHE)
- Signature algorithms (RSA-SHA1, RSA-SHA256, ECDSA, etc.)
- Protocol versions (SSLv2, SSLv3, TLS 1.0-1.3)
- Cipher suites

**Filtering and Search:**
- Filter by category, strength, deprecation status
- Search by algorithm name or code
- Sort by risk score, usage count, or name

**Algorithm Details:**
- Click any algorithm to view detailed information
- **Details Tab**: Algorithm metadata, strength, deprecation status, compliance mappings
- **PQC Information**: PQC status badge, standardization level, quantum vulnerability warnings for non-PQC algorithms
- **PQC Family Metadata**: PQC family, security level, variant group information
- **Usage Tab**: In-use vs configured counts, associated assets
- **Recommendations Tab**: Recommended alternatives, migration guidance, migration steps

### Algorithm Recommendations

**Recommendations Panel:**
- View algorithm recommendations with priority levels (high/medium/low)
- Filter by priority
- Dismiss recommendations
- View detailed migration guidance

**Recommendation Cards:**
- Current algorithm information
- Recommended alternatives with strength indicators
- Reason for recommendation
- Impact assessment
- Migration steps

### Configured vs In-Use Comparison

**Comparison View:**
- Side-by-side display of configured vs in-use algorithms
- Visual indicators for:
  - Algorithms in both (configured and in use)
  - Configured only (not currently in use)
  - In use only (not in configuration)
- Risk highlighting for weak/deprecated configured algorithms
- Category filtering

**Risk Indicators:**
- Highlight configured weak/deprecated algorithms
- Show which configured algorithms are never used
- Identify algorithms in use but not configured

## Reporting Features

### Certificate Expiration Report

**Features:**
- Certificates expiring within configurable timeframes (30, 60, 90, 180, 365 days)
- Grouped by expiration month
- Summary statistics (total expiring, expiring in 30 days, already expired)
- Export to CSV or JSON

**Use Cases:**
- Certificate renewal planning
- Compliance reporting
- Risk assessment

### Algorithm Usage Report

**Features:**
- Comprehensive algorithm usage across inventory
- Deprecated algorithms tracking (in-use and configured)
- Weak algorithms identification
- Export to CSV or JSON

**Summary Statistics:**
- Total algorithms
- Deprecated algorithms in use
- Deprecated algorithms configured
- Weak algorithms count

## Future Enhancements

Planned improvements:
- Relationship graph visualization
- Certificate renewal automation
- Integration with certificate management systems (Let's Encrypt, ACM, etc.)
- Certificate expiration notifications
- Bulk certificate operations
- AI-powered algorithm recommendations
- Automated compliance gap analysis

---

**Last Updated:** 2026-05-02 (Phase 5 Implementation Complete)
