# Vista Platform Platform Overview

## What Is Vista Platform?

Vista Platform is a multi-tenant SaaS platform that gives organizations complete visibility into their cryptographic assets — certificates, TLS configurations, cipher suites, and key material — across on-premises infrastructure, network devices, and cloud environments. It continuously discovers, inventories, and assesses cryptographic implementations against compliance frameworks such as FIPS, NIST SP 800-175, SOC 2, and PCI-DSS, and provides actionable remediation guidance to eliminate weak or deprecated cryptography.

In short: Vista Platform answers the question *"What cryptography is running in my environment, and is any of it putting us at risk?"*

## Why It Matters

Most organizations have no reliable inventory of the cryptographic algorithms, protocols, and certificates deployed across their infrastructure. Certificates expire without warning, deprecated algorithms like MD5, SHA-1, RC4, and TLS 1.0/1.1 persist undetected, and proving compliance to auditors requires weeks of manual evidence gathering. With quantum computing on the horizon, identifying non-quantum-resistant cryptography is becoming an urgent planning requirement.

Vista Platform solves these problems with a single platform that automates discovery, tracks risk, and generates audit-ready compliance evidence.

## Who Uses It

- **Security and compliance teams** responsible for cryptographic posture and audit readiness
- **Infrastructure and cloud engineering teams** managing certificates and TLS configurations at scale
- **CISOs and risk managers** who need dashboards showing cryptographic risk across the organization
- **Platform administrators** who onboard tenants and manage the deployment

Vista Platform serves enterprises in financial services, healthcare, government, and any regulated industry where cryptographic compliance is mandatory.

## Core Capabilities

### Unified Cryptographic Inventory
A single pane of glass for all infrastructure assets, crypto configurations, and certificates. Smart filters surface high-priority items — certificates expiring within 30 days, assets using weak cryptography, self-signed certificates, and deprecated protocol versions.

### Multi-Source Discovery
Vista Platform discovers cryptographic assets through several channels that feed a unified processing pipeline:

- **Network sensors** deployed into customer environments capture live TLS, SSH, and IPSec traffic
- **Device interrogation** queries network appliances directly (F5, Cisco, Fortinet, Palo Alto, UniFi)
- **Cloud discovery** connects to AWS, Azure, and GCP to extract certificates and TLS configurations from load balancers, API gateways, CDNs, and other managed services
- **PCAP ingestion** parses uploaded packet captures for offline TLS analysis

All discoveries flow through automatic classification and approval rules based on network segmentation policies.

### Inventory Onboarding
Already have an inventory? Bring it in without re-typing:

- **Spreadsheet import** — upload a CSV or Excel file to bulk-create network segments (scan targets) or infrastructure assets, with column mapping and duplicate-safe validation
- **CMDB pull** — import server records from a connected CMDB (ServiceNow, Device42, SolarWinds, Oomnitza) as pending-approval assets

Imported assets are then enriched by discovery just like anything else.

### Compliance Management
Define or import compliance frameworks, map controls to cryptographic requirements, run assessments, and generate evidence packages. The platform supports overrides and waivers with full audit trails. Compliance findings are generated automatically as new assets are discovered. Tenants activate the frameworks relevant to them — Best Practices (free), SOC 2, PCI-DSS, ISO 27001, NIST CSF, IEC 62351-3, certificate-focused frameworks, and a **Post-Quantum Readiness** framework that scores quantum exposure across both certificates and crypto-configurations — and posture is materialized continuously rather than billed per framework.

### Risk Assessment and Remediation
A built-in algorithm taxonomy covering 100+ cryptographic algorithms provides deprecation status, strength ratings, and NIST mappings. The Crypto Risks dashboard summarizes findings by severity and provides step-by-step remediation guidance, including recommendations for post-quantum cryptography (PQC) migration covering all five NIST PQC algorithm families — the finalized ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) standards, plus the NIST-selected FN-DSA and HQC families ahead of their finalization.

### CBOM Artifacts and Exports
Generate immutable, content-hashed Cryptographic Bills of Materials (CBOM) in CycloneDX 1.7 format for supply-chain risk management, audit submissions, and regulatory filings. Each artifact is scoped to a named boundary, optionally signed with HMAC, and can include compliance attestation layers. Compare two artifacts to show how your cryptographic posture changed over time. For convenience exports of current page views, each Inventory lens provides a one-click CSV export.

### Integrations
Synchronize inventory data with CMDBs such as ServiceNow, Device42, SolarWinds, and Oomnitza — **push** cryptographic metadata (optionally with a one-line crypto-posture summary appended to each CI's description) and **pull** server records back into the platform. Authenticate users via SSO/SAML. Store integration credentials with AES-256-GCM encryption.

## Architecture at a Glance

Vista Platform is a microservices platform built with Go 1.26 on the backend and React 18 (TypeScript, Vite, Tailwind CSS) on the frontend.

**Frontend applications:**
- **web-ui** — the tenant-facing application for inventory, compliance, and reporting
- **admin-ui** — the platform administration console with an operations-first Command Center dashboard, workflow-oriented navigation, fleet-wide crypto posture monitoring, and integrated support ticket management

**Backend services** (16) handle authentication and RBAC, inventory management, compliance evaluation, CBOM artifact generation, sensor management, device interrogation, cloud discovery processing, audit logging, notifications, and system health monitoring.

**Data and messaging:**
- PostgreSQL 17 with row-level security for multi-tenant data isolation
- Redis for caching and session management
- NATS JetStream for event-driven workflows (discovery processing, compliance finding generation)
- InfluxDB for time-series metrics
- S3-compatible storage for artifacts and reports

**Networking and security:**
- All client traffic routes through a Traefik v3 API gateway with per-service circuit breakers
- Service-to-service communication uses HMAC-SHA256 authentication
- mTLS certificates secure internal service communication
- Authentication uses httpOnly cookies with JWT tokens

**Deployment:** Docker Compose for development; all service definitions and routing are generated from a central service registry (`standards/service-registry.yaml`) to ensure consistency.

## Pricing

| Tier | Price | Highlights |
|------|-------|------------|
| Trial | Free for 30 days | Full Professional features |
| Professional | $99/month | Unlimited assets, 100K API calls, 10 GB storage |
| Enterprise | $510/month | Unlimited API calls, 100 GB storage, dedicated support, SLA |

---

*Vista Platform — June 2026*
