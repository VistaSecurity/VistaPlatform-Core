# Infrastructure Assets and Crypto Configurations

This guide explains, in plain language, the difference between Infrastructure Assets and Crypto Configurations as shown in your dashboard. These terms are related but describe different parts of your crypto inventory.

## Quick Summary

**Infrastructure Assets** = The things in your estate — one row per thing, whatever it is  
**Endpoints** = The network faces a thing listens on (an address, a port, a service)  
**Cryptographic Configurations** = How those assets USE cryptography  
**Certificates** = The identity documents used by those configurations

## Infrastructure Assets

An Infrastructure Asset is **one thing** — a server, a switch, a virtual machine, an S3 bucket, a business service. Not one row per open port: a host running HTTPS, SSH and a database is **one asset with three endpoints**, so when you look at it you see the whole machine rather than three unrelated-looking rows.

Every asset has three things:

- **A class.** What kind of thing it is — Server, Switch, Firewall, Virtual Machine, Object Storage, Business Service, and so on. Classes form a tree: `hardware → computer → server`, so filtering by **Hardware** includes every server, switch and firewall beneath it. The class also decides which attributes the asset carries — a server has an operating system, an S3 bucket has a region and a bucket name — and which columns the list shows.
- **Identifiers.** How the thing is known: FQDN, hostname, IP address, MAC address, serial number, a CMDB sys_id, an agent id. Identifiers are what let two sightings of one machine become one asset instead of two, and each one records where it came from and when it was last seen. A serial you typed in is as much identity as one a scanner read.
- **Endpoints.** Each network face it listens on: an address, a port, and the service identified there. An asset can have many, one, or none — an S3 bucket or a business service has no listening port at all, and that is a real answer rather than a gap.

**Think of it like your estate:**
- Physical: servers in racks, switches, firewalls, OT devices
- Virtual: virtual machines, containers, clusters
- Cloud: buckets, managed databases, key stores, load balancers
- Logical: applications, databases, business services

**What it measures:**  
The breadth of your inventory — how many *things* exist.

**Examples:**
- `web-01.demo.local` — class **Server**, endpoints on 443 (HTTPS) and 22 (SSH)
- `db-prod-01.internal` — class **Server**, endpoint on 5432 (PostgreSQL)
- `api-gateway.company.com` — class **API Gateway**, endpoint on 8443
- `payments-prod` — class **Object Storage** (an S3 bucket), no endpoints: nothing dials it on a port

**Why it matters:**  
Asset visibility is the foundation for effective crypto risk management, compliance, and remediation. You can't secure what you don't know about — and you can't count what you're counting twice.

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
| **Protocol** | Type of cryptographic protocol | TLS, SSH, IPSec, VPN, QUIC, PPTP, and the OT/ICS protocols (Modbus, DNP3, OPC UA, …) |
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
Asset: web-01.prod.company.com
├─ Class: Server  (hardware → computer → server)
├─ Identifiers: FQDN web-01.prod.company.com · IP 10.0.1.15 · serial J7K2QX1
├─ Environment: production
├─ Endpoint: 10.0.1.15:443  (HTTPS)
└─ Crypto Configuration (on that endpoint):
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
Asset: db-legacy-01.prod.company.com
├─ Class: Server
├─ Identifiers: FQDN db-legacy-01.prod.company.com · IP 10.0.2.50
├─ Environment: production
├─ Endpoint: 10.0.2.50:5432  (PostgreSQL)
└─ Crypto Configuration (on that endpoint):
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
Asset: api-gateway.internal.company.com
├─ Class: API Gateway  (cloud_resource → api_gateway)
├─ Identifiers: FQDN api-gateway.internal.company.com · cloud resource id arn:aws:apigateway:…
├─ Environment: production
├─ Endpoint: 10.0.3.100:8443
└─ Crypto Configuration (on that endpoint):
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
            └─ Infrastructure Asset: web-01.prod.company.com   ← ONE asset
                ├─ Class: Server
                ├─ Identifiers
                │   • FQDN: web-01.prod.company.com
                │   • IP:   10.0.1.15
                │   • MAC:  00:1b:44:11:3a:b7
                ├─ Context
                │   • Environment: production
                │   • Owner: Platform Team
                │
                ├─ Endpoint 10.0.1.15:443 (HTTPS)
                │   └─ Crypto Configuration
                │       ├─ Protocol: TLS 1.3
                │       ├─ Cipher: TLS_AES_256_GCM_SHA384
                │       ├─ Certificate → *.company.com
                │       ├─ Risk Score: 10
                │       └─ Compliance Status: ✓ PCI-DSS, ✓ SOC2, ✓ ISO27001
                │
                └─ Endpoint 10.0.1.15:22 (SSH)
                    └─ Crypto Configuration
                        ├─ Protocol: SSH-2.0
                        └─ Risk Score: 15
```

**Key Relationships:**
- **One Asset → Multiple Endpoints**: the machine above listens on 443 and on 22. It is one row in Inventory, not two.
- **One Endpoint → Its Crypto Configuration**: the configuration hangs off the face it was measured on, which is why the asset page can tell you *where* the weak TLS is.
- **One Certificate → Multiple Assets**: a wildcard cert `*.company.com` can be installed on many servers.
- **One Asset → Multiple Certificates**: different endpoints on one asset can present different certificates.
- **An asset with no endpoints is normal**: an S3 bucket, a KMS key or a business service has nothing listening on a port. Its protection is recorded as at-rest posture, not as a listener.

**Dashboard Metrics:**
- **Infrastructure Assets**: counts *things* — one per asset, however many endpoints it has.
- **Crypto Configurations**: counts distinct protocol instances on those assets' endpoints.
- **Coverage**: what share of your assets have any cryptography observed on them. Because an asset is a thing rather than a port, this ratio no longer flatters a busy host: a server with six TLS listeners counts once.

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
- Create the asset and its crypto configuration

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
- You record an asset you already know about, from **Inventory → All assets → New asset**
- You upload a certificate PEM, from **Inventory → Certificates → Upload cert**
- Both are matched against existing inventory rather than blindly inserted, so typing in a host a sensor already found updates that asset instead of creating a second one

**What it captures:**
- The class, identifiers, attributes and business context you type
- The certificate's own contents, read out of the PEM rather than taken on trust

A crypto configuration is never typed in by hand — it is what was measured on an
endpoint, so it only ever comes from one of the three discovery paths above. See
[Adding assets manually](./adding-assets-manually.md).

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
- QUIC/HTTP-3 — see below

**Why:** Technical limitations in protocol analysis.

**A note on QUIC.** QUIC connections are recorded as their own protocol rather
than being reported as TLS, because although a QUIC handshake uses TLS 1.3 for
key establishment, it runs over UDP with its own transport and record layer —
describing it as TLS would imply a TCP endpoint that does not exist. How much
detail a QUIC connection carries depends on where it was observed. For a
third-party destination the record is deliberately limited to the protocol and
version: we observe those connections passively and never send traffic to a
third party to learn more. For endpoints you own, monitor and have elevated, more
detail is recoverable — see the QUIC/HTTP-3 sections of
[Third-party and external connections](third-party-and-external-connections.md)
and [Discovery](discovery.md).

**A note on VPN protocols.** A vendor's own name for a service is mapped to the
cryptography it actually uses, so an SSL-VPN portal is recorded as TLS (and is
therefore evaluated by every TLS control, including the deprecated-version ones)
and an L2TP/IPsec tunnel is recorded as IPsec, which is the half of that pairing
that provides the encryption. **PPTP is the exception** and is kept as its own
protocol: it has no cryptography worth grouping with anything else — its
authentication and its encryption are both broken — so detecting an enabled PPTP
server is itself a Critical finding, and it is deliberately not filed alongside
modern VPNs such as WireGuard.

## Understanding Risk Scores

Risk scores (0-100) are calculated based on multiple security factors:

| Risk Level | Score Range | Description | Examples |
|------------|-------------|-------------|----------|
| **Informational** | 0 | Not assessed — nothing has evaluated this yet. It is not a clean bill of health. | A newly discovered asset before any producer has looked at it |
| **Low** | 1-39 | Modern, secure configurations | TLS 1.3, strong ciphers, large keys, valid certs |
| **Medium** | 40-69 | Acceptable but not optimal | TLS 1.2, 2048-bit keys, approaching cert expiration |
| **High** | 70-89 | Significant weaknesses | TLS 1.1, weak ciphers, small keys, expiring soon |
| **Critical** | 90-100 | Severe vulnerabilities | TLS 1.0, RC4, SHA1, expired certs, 1024-bit keys |

The bands are the CVSS v3.1 qualitative severity ratings on a 0–100 scale, so a "High" here means the same thing it means in a CVE advisory.

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
- Ensure complete inventory coverage across your estate
- Track physical, virtual, cloud and logical things in one list, told apart by class
- Organize assets by environment (prod, staging, dev), site, business unit and owner
- Assign ownership and business context
- Monitor asset lifecycle (creation, updates, stale detection, archival)
- Find a machine by any identifier it has ever been known by — a hostname, an IP it used to hold, a serial from a spreadsheet

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
A: Yes. A web server with TLS on port 443 and SSH on port 22 is **one asset with two endpoints**, and a configuration on each.

**Q: I used to see one row per port. Where did they go?**  
A: They became endpoints of the thing they were always part of. The host is the row; open its asset page and **Services & Endpoints** lists every face it presents, each with its own crypto configuration. If two rows for one machine have merged into one, that is the intended outcome — and if the platform is unsure whether two records are the same thing, it proposes a merge in Discovery → Approvals rather than deciding for you.

**Q: What decides an asset's class?**  
A: Whatever discovered it says what it is, and the platform records *how* it knows — measured, declared, imported or inferred. You can change a class by hand on the asset page; that records you as the source.

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

- **The screens themselves**: [Inventory and lenses](./inventory-and-lenses.md) — the asset list, the lenses, the asset page and its tabs
- **Adding one by hand**: [Adding assets manually](./adding-assets-manually.md)
- **A walkthrough**: [Tenant User Guide → Inventory](../guides/tenant-user-guide.md#inventory)
- **Discovery Setup**: See [Discovery Guide](./discovery.md) for configuring asset discovery
- **Compliance**: See [Compliance Frameworks](./compliance-frameworks.md) for compliance evaluation
