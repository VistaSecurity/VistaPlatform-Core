# Crypto Risks Dashboard

**Version:** 2.0  
**Last Updated:** 2026-04-07

The Crypto Risks Dashboard provides a focused view of cryptographic weaknesses across your network, with detailed remediation guidance to help you prioritize and fix security issues.

---

## Overview

The Crypto Risks feature enables security teams to:

- Identify critical cryptographic weaknesses at a glance
- Prioritize remediation based on severity
- Get detailed, actionable remediation guidance
- **Create tickets directly from risks** for tracking and assignment
- Track remediation progress via the Remediation Progress dashboard
- Monitor PQC (Post-Quantum Cryptography) migration readiness
- Export risk data for reporting and compliance

**Location:** Risk & Compliance page → Crypto Risks tab

---

## Key Features

### Severity-Based Summary

The dashboard displays summary cards showing the count of risks by severity:

| Severity | Score | Description | Examples |
|----------|-------|-------------|----------|
| **Critical** | 90–100 | Immediate action required | SSLv2, SSLv3, RC4, DES, MD5 signatures |
| **High** | 70–89 | High priority remediation | TLS 1.0, TLS 1.1, 3DES, SHA-1, RSA-1024 |
| **Medium** | 40–69 | Medium priority | Expiring certificates, weak key sizes |
| **Low** | 1–39 | Low priority | Minor configuration improvements |
| **Informational** | 0 | Not assessed — we did not recognise the cryptography in use | — |

Severity is derived from the risk score using the CVSS qualitative severity
bands; see [Risk Score Calculation](#risk-score-calculation) below for where the
score itself comes from.

Click on any severity card to filter the detailed risk list by that severity.

### Category Breakdown

Risks are categorized by type:

- **Protocol Issues**: Outdated TLS/SSL protocol versions, and SSH servers still speaking (or falling back to) the obsolete SSH-1 protocol
- **Algorithm Issues**: Weak or deprecated cipher suites and hash algorithms
- **Certificate Issues**: Certificate-related problems (expiration, weak signatures)
- **Key Size Issues**: Insufficient key lengths

### Fast-Path Detection

The platform performs **fast-path weak crypto detection** during asset import, identifying issues immediately:

1. **Protocol Detection**: Flags SSLv2, SSLv3, TLS 1.0, TLS 1.1, SSH v1
2. **Cipher Detection**: Flags RC4, DES, 3DES cipher suites
3. **Hash Detection**: Flags MD5, SHA-1 hash algorithms
4. **Key Size Detection**: Flags RSA/DSA keys under 2048 bits

This ensures new discoveries are immediately assessed for cryptographic weaknesses.

---

## Remediation Guidance

### Remediation Panel

Click on any risk row to open the Remediation Panel, which provides:

1. **Risk Score**: Overall risk assessment (0-100)
2. **Affected Item**: Asset and protocol details
3. **Recommendations**: Detailed breakdown of each issue with:
   - Algorithm code and description
   - Step-by-step remediation instructions
   - Recommended alternative technologies
   - Severity assessment

### Algorithm Taxonomy Integration

Remediation guidance is sourced from the **Algorithm Taxonomy**, a database of:

- Cryptographic algorithms with strength ratings
- Deprecation status and timelines
- NIST and industry compliance mappings
- Recommended migration paths
- Post-Quantum Cryptography (PQC) alternatives

### Example Remediation Guidance

| Algorithm | Issue | Guidance |
|-----------|-------|----------|
| TLSv1.0 | Outdated protocol | Upgrade to TLS 1.2 or higher. Ensure all clients and servers support modern TLS versions. |
| TLSv1.1 | Outdated protocol | Upgrade to TLS 1.2 or higher. Ensure all clients and servers support modern TLS versions. |
| SSLv3 | Broken protocol | Disable SSLv3 immediately. This protocol is cryptographically broken and highly vulnerable. |
| RC4 | Weak cipher | Disable RC4 cipher suites. RC4 is cryptographically broken and should not be used. |
| DES/3DES | Weak cipher | Disable DES/3DES cipher suites. These ciphers are considered weak and vulnerable to attacks. |
| MD5 | Weak hash | Migrate from MD5 to SHA-256 or SHA-512 for all hashing purposes. MD5 is cryptographically broken. |
| SHA-1 | Weak hash | Migrate from SHA-1 to SHA-256 or SHA-512 for all hashing and digital signature purposes. |
| RSA-1024 | Weak key | Increase RSA key size to at least 2048 bits, preferably 3072 or 4096 bits. |

---

## User Interface

### Page Layout

The Crypto Risks page consists of:

1. **Header**: Page title, refresh button
2. **Summary Cards**: Severity-based risk counts (clickable for filtering)
3. **Filter Bar**: Dropdown filters for severity and category
4. **Risk Table**: Detailed list of cryptographic risks with:
   - Asset information (hostname, IP, port)
   - Protocol and cipher suite
   - Issue description
   - Severity badge
   - Last verified timestamp
5. **Pagination**: Navigate through large result sets
6. **Remediation Panel**: Slide-over panel with detailed guidance

### Ticket Integration

Each risk row includes an **Action** column with ticket controls:
- **Create Ticket** (blue button): Opens a pre-filled ticket creation modal with risk details
- **View Ticket** (green button): Opens the existing ticket for this risk

Tickets link back to the specific `crypto_implementation_id`, enabling precise tracking of which risks are being remediated. Created tickets appear in **Remediation → Queue** and are tracked in the Remediation Progress dashboard.

### Risk Table Columns

| Column | Description |
|--------|-------------|
| **Asset** | Hostname or IP address of affected asset |
| **Issue** | Description of the cryptographic weakness |
| **Severity** | Risk severity (Critical, High, Medium, Low) |
| **Last Verified** | When the configuration was last verified |
| **Action** | Create or view remediation ticket |

### Filtering

- **Severity Filter**: All, Critical, High, Medium, Low, Informational
- **Category Filter**: All, Protocol, Algorithm, Certificate, Key Size
- **Search**: Search by hostname, IP, protocol, or cipher suite

---

## API Endpoints

### Get Crypto Risks Summary

```
GET /api/v1/inventory-service/crypto-risks/summary
```

Returns aggregated counts by severity.

**Response:**
```json
{
  "summary": {
    "critical": 10,
    "high": 25,
    "medium": 50,
    "low": 15,
    "informational": 5,
    "total_assets_affected": 80
  }
}
```

### List Crypto Risks

```
GET /api/v1/inventory-service/crypto-risks
```

**Query Parameters:**
- `severity` (optional): critical, high, medium, low, informational, all
- `category` (optional): protocol, algorithm, certificate, key_size, all
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Items per page (default: 10)

**Response:**
```json
{
  "risks": [
    {
      "id": "impl-uuid",
      "tenant_id": "tenant-uuid",
      "asset_id": "asset-uuid",
      "protocol": "TLS",
      "protocol_version": "TLSv1.0",
      "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
      "risk_score": 80,
      "compliance_status": {
        "weak_protocol_version": "Outdated TLS protocol version: TLSv1.0"
      },
      "Metadata": {
        "asset_hostname": "webserver.example.com",
        "asset_ip_address": "192.168.1.100",
        "asset_port": 443
      }
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 10,
    "total": 100,
    "total_pages": 10,
    "has_next": true,
    "has_prev": false
  }
}
```

### Get Remediation Guidance

```
GET /api/v1/inventory-service/crypto-implementations/:id/remediation
```

Returns remediation guidance for a specific crypto implementation.

**Response:**
```json
{
  "remediation_guidance": {
    "crypto_implementation_id": "impl-uuid",
    "recommendations": [
      {
        "algorithm_code": "TLSv1.0",
        "description": "Upgrade to TLS 1.2 or higher...",
        "recommended_action": "Follow the migration guidance...",
        "severity": "High",
        "alternatives": ["TLSv1.2", "TLSv1.3"]
      }
    ]
  }
}
```

### Get Algorithm Remediation

```
GET /api/v1/inventory-service/remediation/algorithm/:code
```

Returns remediation guidance for a specific algorithm by code.

---

## Use Cases

### Security Audit

**Scenario**: Conduct a security audit of cryptographic configurations.

**Steps**:
1. Navigate to **Crypto Risks**
2. Review summary cards for overall risk posture
3. Click **Critical** to see the most urgent issues
4. Click on each risk to view remediation guidance
5. Export to CSV for audit documentation

### Compliance Remediation

**Scenario**: Remediate all TLS 1.0/1.1 usage for PCI-DSS compliance.

**Steps**:
1. Navigate to **Crypto Risks**
2. Filter by **Category**: Protocol
3. Review all protocol-related risks
4. Click on each risk to get specific remediation steps
5. Track remediation progress by re-running discovery

### Risk Prioritization

**Scenario**: Prioritize cryptographic weaknesses for remediation sprint.

**Steps**:
1. Navigate to **Crypto Risks**
2. Note the counts in severity cards
3. Filter by **Critical** first
4. Review affected assets and remediation complexity
5. Export filtered list for sprint planning

---

## Best Practices

### Regular Monitoring

1. **Daily Review**: Check Critical and High severity counts daily
2. **Weekly Trending**: Compare week-over-week risk counts
3. **Monthly Reporting**: Export and archive monthly risk summaries

### Remediation Workflow

1. **Prioritize by Severity**: Address Critical issues first
2. **Group by Asset**: Remediate all issues on an asset together
3. **Test Changes**: Verify configurations after remediation
4. **Re-scan**: Run discovery to confirm fixes

### Integration with Compliance

1. **Map to Frameworks**: Correlate risks with compliance control failures
2. **Document Evidence**: Export remediation evidence for auditors
3. **Track Progress**: Use compliance workspace alongside crypto risks

---

## Technical Details

### Risk Score Calculation

Risk scores run 0–100 and come from the **algorithm catalogue** — the same
assessments you can read yourself under
[Risk & Compliance → Posture → Algorithm Reference](algorithm-reference.md).

For each crypto configuration we score every component we identified — the
protocol version, the cipher suite, and the individual key exchange, signature,
symmetric and hash algorithms — and **the worst component sets the score**. A
service is only as strong as the weakest thing it negotiates, so a strong
AES-256 cipher does not offset an RC4 fallback or a TLS 1.0 protocol version.

Because the score is read from the catalogue, you can always trace a number back
to a published assessment. Look up the algorithm in the Algorithm Reference and
you will see the same strength rating, deprecation status and risk score that
produced the finding.

Two things are scored outside the catalogue, because they depend on how an
algorithm was *used* rather than on the algorithm itself:

- **Key size** — an RSA key below the NIST SP 800-131A 2048-bit floor is flagged
  regardless of the algorithm's own rating.
- **Certificate lifecycle** — expiry and validity problems are their own findings.

A score of **0 means "not assessed"** — we did not recognise the cryptography in
use — which is deliberately different from "assessed and found safe". Those
configurations show as *Informational* and are worth investigating rather than
assuming clean.

### Seeing why a configuration scored what it did

You do not have to take the number on trust. Open any crypto configuration —
from **Inventory**, click a row, or open an asset and pick one of its
configurations — and the drawer's **Why this score** section lists every
component we resolved against the catalogue, worst first.

For each component you get:

- the **component's role** (protocol version, cipher suite, key exchange,
  signature, symmetric, hash) and its algorithm code;
- its **catalogue risk score and severity band**, plus the strength and
  deprecation status the catalogue records;
- whether it was **observed in use** or only **offered, not observed** (see the
  SSH section below — offered algorithms still count);
- and, on the component that set the score, the catalogue's **migration
  guidance** and **recommended alternatives**.

The component that set the score is marked **sets the score**. Because the panel
reads the catalogue live, correcting an assessment in the catalogue changes the
explanation everywhere it appears — there is no separately stored copy to go
stale.

Two honest-answer cases to expect:

- **"Not assessed."** If nothing on the configuration resolved against the
  catalogue, the panel says so plainly. That is not a clean bill of health — it
  means we did not recognise the cryptography in use and could not judge it.
- **A score higher than any single component.** When the stored score exceeds
  every catalogue component, the panel says the remainder comes from checks the
  per-algorithm catalogue cannot express — chiefly key size — rather than
  implying the component list is the whole story.

### How SSH services are scored

SSH configurations are scored from the same catalogue as TLS, but SSH tells us
something TLS does not, so there is one extra distinction worth understanding.

An SSH server advertises **lists** of the key exchange, cipher and MAC
algorithms it will accept, and then one of each is chosen. We record both, and
they mean different things:

- **In use** — the protocol version (read from the server's version banner), the
  host key algorithm the server actually presented, and — when the discovery saw
  both sides of the handshake — the algorithms the handshake genuinely selected.
  These are what the crypto configuration's Key Exchange / Signature / Cipher /
  MAC fields show.
- **Offered** — everything else on the server's lists, shown as *inferred*. The
  server did not use it on this connection, but it will accept it.

**Offered algorithms count toward the risk score.** A server that still offers
`3des-cbc` or `diffie-hellman-group1-sha1` for legacy compatibility scores on
that offer, even if the connection we observed used something modern — because
any client can simply ask for the weak option. This matches how SSH auditing
tools report, and it is why hardening usually means *removing* algorithms from
the server's configuration rather than changing a preferred one.

Where a discovery only saw one side of the handshake (an active probe, or a
passive capture that started mid-connection), nothing is recorded as "in use"
beyond the banner and host key — everything else stays an offer rather than
being guessed at.

Algorithms are named exactly as SSH names them on the wire (`ssh-ed25519`,
`curve25519-sha256`, `aes256-gcm@openssh.com`, `hmac-sha2-256-etm@openssh.com`),
so a finding can be pasted straight into an `sshd_config` audit.

### Severity Bands

A score becomes a severity using the **CVSS qualitative severity ratings**
(the standard 0.0–10.0 scale, ×10):

| Severity | Score |
|----------|-------|
| **Critical** | 90–100 |
| **High** | 70–89 |
| **Medium** | 40–69 |
| **Low** | 1–39 |
| **Informational** | 0 (not assessed) |

The same bands are used everywhere a risk level appears — the badges in
Inventory, the risk facet filter, the dashboard distribution, and the summary
counts — so a given score always reads the same way, whichever screen you are
on.

### Data Sources

Risk data is aggregated from:

- **algorithms** table: the authoritative strength, deprecation status and risk score for each algorithm — this is what drives the score
- **crypto_implementations** table: Protocol, cipher, key details
- **crypto_implementation_algorithms**: which catalogue algorithms each configuration actually uses
- **network_assets** table: Asset context

### Event-Driven Updates

Risks are automatically updated when:

- New assets are discovered
- Asset configurations change
- Discovery jobs complete
- Compliance engine re-evaluates

---

## Remediation Progress Dashboard

The **Remediation** tab (on the same Risk & Compliance page) replaced the former remediation queue with a progress-oriented dashboard. It provides:

- **Summary cards**: Open tickets, resolved (30d), overdue, avg resolution time
- **Trend chart**: 30-day bar chart of tickets opened vs. resolved (recharts)
- **PQC Migration Progress**: Stacked progress bar showing PQC-ready, quantum-safe symmetric, and needs-migration percentages with a per-family breakdown table
- **Category breakdown**: Per-category (compliance, certificate, remediation, etc.) open/resolved counts with links to **Remediation → Queue**

Data sources:
- `GET /api/v1/compliance-engine/tickets/progress` — ticket trends and summary
- `GET /api/v1/inventory-service/pqc/progress` — PQC readiness metrics from `crypto_implementation_algorithms` junction table

## Related Features

- [Unified Crypto Inventory](./unified-crypto-inventory.md) - Comprehensive asset and certificate view
- [Compliance Frameworks](./compliance-frameworks.md) - Framework-based compliance assessment
- [Discovery](./discovery.md) - Asset discovery and configuration collection
- [Algorithm Analysis](./unified-crypto-inventory.md#algorithm-analysis-features) - Algorithm taxonomy and recommendations
- [Remediation](./remediation.md) - Alerts, the ticket Queue, and migration Plans

---

**Last Updated:** 2026-04-07
