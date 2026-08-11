# Infrastructure Assets and Crypto Configurations

This guide explains, in plain language, the difference between Infrastructure Assets and Crypto Configurations as shown in your dashboard. These terms are related but describe different parts of your crypto inventory.

## Quick Summary

**Infrastructure Assets** = Your infrastructure (servers, services, appliances)  
**Cryptographic Configurations** = How those assets USE cryptography  
**Certificates** = The identity documents used by those configurations

## Infrastructure Assets

Infrastructure Assets are the endpoints and services we discover in your environment. Each asset represents a unique networked thing, identified by details like hostname, IP address, and (optionally) port, along with business and technical metadata (asset type, environment, owner, tags).

**Think of it like your infrastructure:**
- Physical: Servers in racks, network appliances, firewalls
- Logical: Services, applications, API endpoints, databases

**What it measures:**  
The breadth of your inventory — how many endpoints/services exist.

**Examples:**
- `web-01.demo.local:443` (production web server)
- `10.0.5.12:22` (SSH server)
- `db-prod-01.internal:5432` (PostgreSQL database)
- `api-gateway.company.com:8443` (API service)

**Why it matters:**  
Asset visibility is the foundation for effective crypto risk management, compliance, and remediation. You can't secure what you don't know about.

## Cryptographic Configurations

Cryptographic Configurations are specific instances of cryptography observed on an Infrastructure Asset. Each implementation captures the protocol and its configuration — such as TLS version, cipher suite, key exchange, signature algorithm, key sizes, and any associated certificate — as well as how we discovered it and its analyzed risk/compliance status.

**Think of it like the crypto configuration:**
- The SSL/TLS settings in your nginx/apache config
- The cipher suites your load balancer negotiates
- The SSH algorithms your servers accept
- The encryption protocols your VPN uses

**What it measures:**  
Your cryptographic exposure surface — how and where crypto is used.

**What's captured in each implementation:**

| Component | Description | Examples |
|-----------|-------------|----------|
| **Protocol** | Type of cryptographic protocol | TLS, SSH, IPSec, VPN |
| **Protocol Version** | Specific version in use | TLSv1.3, TLSv1.2, SSH-2.0 |
| **Cipher Suite** | Negotiated cipher configuration | `TLS_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` |
| **Key Exchange** | Algorithm for key agreement | ECDHE, RSA, DH |
| **Signature Algorithm** | Digital signature method | RSA, ECDSA, Ed25519 |
| **Symmetric Encryption** | Bulk encryption algorithm | AES-256-GCM, AES-128-GCM, ChaCha20 |
| **Hash Algorithm** | Cryptographic hash function | SHA256, SHA384, SHA512 |
| **Key Size** | Length of cryptographic keys | 2048 bits, 3072 bits, 4096 bits |
| **Certificate** | Associated X.509 certificate | Link to certificate record |
| **Discovery Method** | How we found it | Sensor, Cloud API, Manual, Device Interrogation |
| **Risk Score** | Calculated risk level (0-100) | 10 (low) to 85 (critical) |

**Why it matters:**  
Security posture and compliance depend on the details. Modern TLS 1.3 with strong ciphers is secure. Legacy TLS 1.0 with RC4 and SHA1 is vulnerable. The implementation details determine your risk.

## Detailed Examples from Real Environments

### Example 1: Modern Production Web Server ✅

```
Asset: web-01.prod.company.com:443
├─ Asset Type: server
├─ IP: 10.0.1.15
├─ Port: 443
├─ Environment: production
└─ Crypto Configuration:
   ├─ Protocol: TLS 1.3
   ├─ Cipher Suite: TLS_AES_256_GCM_SHA384
   ├─ Key Exchange: ECDHE (ephemeral, provides PFS)
   ├─ Hash: SHA384
   ├─ Key Size: 4096 bits
   ├─ Certificate: "*.company.com" (expires 2026-05-01)
   ├─ Discovery Method: sensor (network scan)
   └─ Risk Score: 10 (low - modern, secure configuration)
```

**Why this is secure:**
- TLS 1.3 (latest protocol version)
- Strong cipher suite with AEAD encryption
- Perfect Forward Secrecy (PFS) via ECDHE
- Strong key size (4096 bits)
- Valid certificate

### Example 2: Legacy Database Server ⚠️

```
Asset: db-legacy-01.prod.company.com:5432
├─ Asset Type: server
├─ IP: 10.0.2.50
├─ Port: 5432 (PostgreSQL)
├─ Environment: production
└─ Crypto Configuration:
   ├─ Protocol: TLS 1.0  ⚠️ DEPRECATED
   ├─ Cipher Suite: TLS_RSA_WITH_RC4_128_SHA  ⚠️ WEAK
   ├─ Key Exchange: RSA (no PFS)
   ├─ Hash: SHA1  ⚠️ DEPRECATED
   ├─ Key Size: 1024 bits  ⚠️ TOO SMALL
   ├─ Certificate: "db-legacy-01" (expired 2026-04-16)  ⚠️ EXPIRED
   ├─ Discovery Method: manual
   └─ Risk Score: 85 (critical - multiple vulnerabilities)
```

**Why this is risky:**
- TLS 1.0 vulnerable to BEAST, POODLE attacks
- RC4 cipher is cryptographically broken
- SHA1 hash has known collision attacks
- 1024-bit keys breakable by nation-states
- Expired certificate = no trust validation
- No Perfect Forward Secrecy (past sessions compromised if key stolen)

### Example 3: API Gateway with Mixed Security 🟡

```
Asset: api-gateway.internal.company.com:8443
├─ Asset Type: service
├─ IP: 10.0.3.100
├─ Port: 8443
├─ Environment: production
└─ Crypto Configuration:
   ├─ Protocol: TLS 1.2  🟡 ACCEPTABLE
   ├─ Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
   ├─ Key Exchange: ECDHE (provides PFS)
   ├─ Hash: SHA384
   ├─ Key Size: 2048 bits  🟡 MINIMUM
   ├─ Certificate: "internal-api.company.com" (expires 2026-04-25)
   ├─ Discovery Method: cloud_api (AWS ALB)
   └─ Risk Score: 30 (medium - acceptable but not optimal)
```

**Why this is medium risk:**
- TLS 1.2 still acceptable but not latest (should migrate to 1.3)
- Strong cipher suite with GCM mode
- Has Perfect Forward Secrecy
- 2048-bit keys are minimum acceptable (3072+ recommended)
- Valid certificate

## How They Relate

```
Your Data Center / Cloud Environment
    └─ Network Segment: DMZ
        └─ Server Rack A
            └─ web-01.prod.company.com
                ├─ Infrastructure Asset Record (the server itself)
                │   • Hostname: web-01.prod.company.com
                │   • IP Address: 10.0.1.15
                │   • Port: 443
                │   • Type: server
                │   • Environment: production
                │   • Owner: Platform Team
                │
                └─ Crypto Configuration (HTTPS on port 443)
                    ├─ Protocol: TLS 1.3
                    ├─ Cipher: TLS_AES_256_GCM_SHA384
                    ├─ Certificate → *.company.com
                    ├─ Risk Score: 10
                    └─ Compliance Status: ✓ PCI-DSS, ✓ SOC2, ✓ ISO27001
```

**Key Relationships:**
- **One Asset → Multiple Implementations**: A web server might have TLS on port 443 AND SSH on port 22 (that's 2 implementations)
- **One Certificate → Multiple Assets**: A wildcard cert `*.company.com` can be used by many servers
- **One Asset → Multiple Certificates**: An asset might use different certs for different services/endpoints

**Dashboard Metrics:**
- **Infrastructure Assets**: Counts unique endpoints/services discovered (265 in demo)
- **Crypto Configurations**: Counts distinct protocol instances attached to those assets (145 in demo)
- **Coverage Ratio**: ~54% of assets have crypto configurations (145/265)

## How We Discover and Build Implementations

### 1. Network Sensors (Most Common)
- Deploy sensors in your network segments
- Sensors perform TLS/SSH handshakes with discovered services
- Extract full crypto configuration during negotiation
- Create asset record + crypto configuration automatically

**What it captures:**
- Protocol version negotiated
- Cipher suite selected
- Certificate chain presented
- Exact algorithms in use

### 2. Cloud API Discovery
- Query AWS/Azure/GCP APIs for infrastructure
- Extract SSL/TLS policies from cloud configuration (ALBs, App Services, etc.)
- Perform TLS handshake with public endpoints (if reachable)
- Create device → asset → crypto configuration

**What it captures:**
- Cloud-configured SSL policies
- ACM/Key Vault certificate metadata
- Actual TLS handshake (if publicly accessible)
- Cloud provider settings

### 3. Device Interrogation (Agentless)
- SSH/SNMP into network devices (routers, firewalls, load balancers)
- Extract crypto configuration from device CLI/API
- Parse crypto settings from device config
- Create asset + crypto configuration

**What it captures:**
- Device-native crypto configuration
- Supported protocols and cipher lists
- Certificate installations
- Device-specific settings

### 4. Manual Entry
- User manually documents assets
- User specifies crypto configurations
- Creates implementation records in system

**What it captures:**
- User-provided configuration details
- Documentation of known crypto settings
- Lower confidence score (manual vs automated)

## Assets WITHOUT Crypto Configurations

Not every asset has cryptographic configurations. Common scenarios:

### 1. Non-Encrypted Services
Services that don't use cryptography:
- Pure HTTP services (port 80, no TLS)
- Redis without TLS (`redis://localhost:6379`)
- MySQL without SSL (`mysql://db:3306`)
- Internal-only services without encryption

**Why:** The service doesn't implement cryptographic protocols for transport security.

### 2. Pending Discovery
Assets discovered but not yet fully scanned:
- Network ACLs preventing sensor connection
- Service not responding to crypto handshakes
- Discovery job still in progress
- Firewall blocking interrogation ports

**Why:** We know the asset exists but haven't been able to determine its crypto configuration yet.

### 3. Application-Layer Encryption Only
Assets using crypto at a different layer:
- Database with column-level encryption (not connection encryption)
- Storage systems with encryption at rest (not in-transit)
- Application-level encryption (not transport-level)

**Why:** We track transport-layer crypto (TLS, SSH, IPSec). Application-layer crypto is internal to the app.

### 4. Discovery Limitations
Technical barriers to discovery:
- Air-gapped environments (no network access)
- Offline systems (powered down or unreachable)
- Physical appliances not yet interrogated
- Services behind strict network segmentation

**Why:** Physical or network limitations prevent discovery.

### 5. Protocol-Specific Limitations
Some protocols are harder to analyze:
- UDP-based services (no handshake to analyze)
- Custom proprietary protocols
- Encrypted tunnels (can't inspect inner protocol)
- QUIC/HTTP3 (emerging protocol support)

**Why:** Technical limitations in protocol analysis.

## Understanding Risk Scores

Risk scores (0-100) are calculated based on multiple security factors:

| Risk Level | Score Range | Description | Examples |
|------------|-------------|-------------|----------|
| **Low** | 0-29 | Modern, secure configurations | TLS 1.3, strong ciphers, large keys, valid certs |
| **Medium** | 30-59 | Acceptable but not optimal | TLS 1.2, 2048-bit keys, approaching cert expiration |
| **High** | 60-79 | Significant weaknesses | TLS 1.1, weak ciphers, small keys, expiring soon |
| **Critical** | 80-100 | Severe vulnerabilities | TLS 1.0, RC4, SHA1, expired certs, 1024-bit keys |

**Risk Score Factors:**
- Protocol version (TLS 1.0/1.1 = high penalty)
- Cipher strength (RC4, 3DES = critical)
- Key size (< 2048 bits = high penalty)
- Hash algorithm (SHA1/MD5 = critical)
- Certificate status (expired = critical)
- Perfect Forward Secrecy (missing = penalty)
- Known vulnerabilities (CVEs = penalty)

## Practical Takeaways

### For Asset Management
**Use Infrastructure Assets to:**
- Ensure complete inventory coverage across your infrastructure
- Track physical and logical infrastructure components
- Organize assets by environment (prod, staging, dev)
- Assign ownership and business context
- Monitor asset lifecycle (creation, updates, stale detection)

### For Security Posture
**Use Cryptographic Configurations to:**
- Identify weak or deprecated crypto configurations
- Prioritize remediation by risk score
- Track TLS version adoption (migration from 1.2 to 1.3)
- Find assets using insecure ciphers (RC4, 3DES)
- Monitor certificate expirations
- Validate compliance requirements (PCI-DSS, SOC2, etc.)

### For Compliance Reporting
**Combined view provides:**
- Complete audit trail of crypto usage
- Evidence of secure configuration
- Tracking of remediation efforts
- Compliance framework alignment
- Historical trend analysis

### Common Use Cases

**Scenario 1: TLS Version Upgrade**
1. Filter for "TLS 1.0 Implementations"
2. View list of all assets still using TLS 1.0
3. Sort by risk score (highest first)
4. Export list for remediation planning
5. Track progress as implementations are upgraded

**Scenario 2: Certificate Expiration Management**
1. View "Certificates Expiring in 30 Days"
2. See which assets use each expiring certificate
3. Check crypto configuration details
4. Plan certificate rotation
5. Monitor affected assets after renewal

**Scenario 3: Compliance Audit**
1. Generate report showing all crypto configurations
2. Filter by compliance framework (PCI-DSS, SOC2)
3. Identify non-compliant configurations
4. Document remediation timeline
5. Track compliance posture over time

## FAQ

**Q: Can one asset have multiple crypto configurations?**  
A: Yes! A web server might have TLS on port 443 and SSH on port 22 - that's 2 implementations.

**Q: Can one certificate be used by multiple assets?**  
A: Yes! A wildcard certificate like `*.company.com` can be installed on many servers.

**Q: What if I have an asset but no crypto configuration?**  
A: This is normal for non-encrypted services (HTTP, Redis without TLS, etc.) or assets that haven't been fully scanned yet.

**Q: How often are crypto configurations updated?**  
A: Sensors scan on a schedule (hourly/daily). Manual scans can be triggered anytime. Cloud APIs are polled regularly.

**Q: What's the difference between "discovered" and "last verified"?**  
A: "First discovered" is when we first saw this configuration. "Last verified" is the most recent scan confirming it's still active.

**Q: Why does my risk score keep changing?**  
A: Risk scores adjust as threat intelligence evolves, certificate expiration approaches, or new vulnerabilities are discovered.

## Related Documentation

- **User Interface**: See [Tenant User Guide → Crypto Inventory](../guides/tenant-user-guide.md#crypto-inventory) for UI walkthrough
- **Discovery Setup**: See [Discovery Guide](./discovery.md) for configuring asset discovery
- **Compliance**: See [Compliance Frameworks](./compliance-frameworks.md) for compliance evaluation
