# Vista Platform Overview

## What Is Vista Platform?

Vista Platform is a multi-tenant, discovery-driven **asset inventory and
map** — it finds the things in your environment, keeps a record you can
attest to, and tracks what's wrong with them. Cryptographic posture is its
first and most complete **posture module**: certificates, TLS and SSH
configurations, cipher suites and key material, continuously discovered and
assessed against a Post-Quantum Readiness framework, NIST-aligned baselines,
and the free frameworks that ship with Core —
with remediation guidance to eliminate weak or deprecated cryptography.

In short: Vista Platform answers two questions at once — *"What do I
have, and what does it connect to?"* and *"Is any of it putting us at
risk?"* The crypto module answers the second question first; every other
posture module (software, vulnerabilities, end-of-life, configuration)
answers it in its own way, on the same asset.

New to the platform's vocabulary? [Concepts](./concepts.md) defines asset,
endpoint, class, relationship, and the other terms used throughout this
documentation, in plain language with examples.

## Why It Matters

Most organizations have no reliable inventory of what's actually running —
or, narrower, of the cryptographic algorithms, protocols, and certificates
deployed across their infrastructure. Certificates expire without warning,
deprecated algorithms like MD5, SHA-1, RC4, and TLS 1.0/1.1 persist
undetected, and proving compliance to auditors requires weeks of manual
evidence gathering. With quantum computing on the horizon, identifying
non-quantum-resistant cryptography is becoming an urgent planning
requirement.

Discovery tools alone produce lists nobody can attest to. CMDBs hold
attestable records nobody keeps current. Vista Platform combines both:
assets flow in through approval — nothing enters inventory unreviewed unless
you've explicitly told it to — and every artifact you export is
content-hashed
so what you hand an auditor is exactly what the platform found.

## Who Uses It

- **Security and compliance teams** responsible for cryptographic posture and
  audit readiness
- **IT and infrastructure operations teams** who need a reliable asset
  inventory and a map of what connects to what, independent of
  cryptography — the crypto module is a value-add they get on top of the
  inventory they already needed
- **Infrastructure and cloud engineering teams** managing certificates and
  TLS configurations at scale
- **CISOs and risk managers** who need dashboards showing risk across the
  organization
- **Platform administrators** who onboard tenants and manage the deployment

Vista Platform serves enterprises in financial services, healthcare,
government, and any regulated industry where cryptographic compliance is
mandatory, as well as any IT organization that wants a discovery-driven
inventory it can trust.

## Core Capabilities

### A unified inventory, not a crypto silo
Every discovered thing — a server, a switch, a certificate, a cloud
resource, a business application — becomes one asset with a class, its
endpoints, and its posture facts. Inventory switches between lenses (all
assets, the map, software, certificates, keys, TLS/SSH configuration, data
protection, third-party connections, and lifecycle/stale) rather than
juggling separate pages for each kind of thing. Smart filters surface
high-priority items — certificates expiring within 30 days, assets using
weak cryptography, self-signed certificates, and deprecated protocol
versions.

### Multi-Source Discovery
Vista Platform discovers assets through several channels that feed one
processing pipeline, so a passively observed host and one an operator
uploaded evidence for go through the same approval and posture logic:

- **Network sensors** deployed into customer environments capture live TLS,
  SSH, and IPSec traffic, and passively observe hosts on the segment
- **A host agent** installed on a machine reports its own OS, hardware
  identity, installed packages, and listening sockets as host inventory —
  including what's bound to localhost, which a network scan can't see
- **Device interrogation** queries network appliances directly (F5, Cisco,
  Fortinet, Palo Alto, UniFi)
- **Cloud discovery** connects to AWS, Azure, and GCP to extract certificates
  and TLS configurations from load balancers, API gateways, CDNs, and other
  managed services
- **PCAP ingestion** parses uploaded packet captures for offline TLS analysis
- **SBOM upload** turns a CycloneDX or SPDX document your build already
  produces into software inventory on the asset it describes

All discoveries flow through automatic classification and approval rules
based on network segmentation policies.

### Inventory Onboarding
Already have an inventory? Bring it in without re-typing:

- **Spreadsheet import** — upload a CSV or Excel file to bulk-create network
  segments (scan targets) or infrastructure assets, with column mapping and
  duplicate-safe validation
- **CMDB pull** *(Enterprise)* — import server records from a connected CMDB
  (ServiceNow, Device42, SolarWinds, Oomnitza) as pending-approval assets
- **NetBox** *(Enterprise)* — pull sites, prefixes, VLANs, device types and
  devices from a NetBox source of truth (read-only), and see where
  discovered inventory has drifted from it

Imported assets are then enriched by discovery just like anything else.

### Compliance Management
Map controls to requirements, run assessments, and generate evidence
packages. The platform supports overrides and waivers with full audit
trails. Findings are generated automatically as new assets are discovered,
and posture is materialized continuously rather than billed per framework.
Tenants activate the frameworks relevant to them. Core ships eight, always
available: **Security Best Practices**, a **Post-Quantum Readiness**
framework that scores quantum exposure across both certificates and crypto
configurations, **Certificate Hygiene**, three certificate-expiry policies,
**Inventory Hygiene** (is every asset owned, classified, located and
recently seen?) and **Lifecycle** (what has outlived its vendor support?).

### Risk Assessment and Remediation
A built-in algorithm taxonomy covering 100+ cryptographic algorithms
provides deprecation status, strength ratings, and NIST mappings. Findings
are produced by several independent producers — compliance, end-of-life,
vulnerability, and more — and Risk & Compliance → Findings lists every one
of them, filterable by producer, with step-by-step remediation guidance,
including recommendations for post-quantum cryptography (PQC) migration
covering all five NIST PQC algorithm families — the finalized ML-KEM (FIPS
203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) standards, plus the
NIST-selected FN-DSA and HQC families ahead of their finalization.

### Bills of Materials and Exports
Generate immutable, content-hashed Bills of Materials — cryptographic,
software, hardware, or a full-inventory snapshot — in CycloneDX 1.7 format
for supply-chain risk management, audit submissions, and regulatory
filings. Each artifact is scoped to a named boundary.
For convenience exports of current page views, each Inventory lens provides
a one-click CSV export.

### Integrations
Store integration credentials with AES-256-GCM encryption.


## Architecture at a Glance

Vista Platform is a microservices platform built with Go 1.26 on the backend
and React 19 (TypeScript, Vite, Tailwind CSS) on the frontend.

**Frontend applications:**
- **The tenant console** (titled **Vista Console** by default; renameable
  under Custom Branding) — Dashboard, Discovery, Inventory, Risk &
  Compliance, and Remediation, plus Settings and My Profile
- **The operations console** (**VISTA Operations** by default) — Mission
  Control, Tenants, Support, Fleet, Jobs & Queues, System Health, Catalog,
  Settings, Staff & Access, and Security & Trust (plus Billing & Revenue on
  editions that ship it)

**Backend services** (16) handle authentication and RBAC, inventory
management, compliance evaluation, CBOM artifact generation, sensor
management, device interrogation, cloud discovery processing, audit logging,
notifications, and system health monitoring.

**Data and messaging:**
- PostgreSQL 17 with row-level security for multi-tenant data isolation
- Redis for caching and session management
- NATS JetStream for event-driven workflows (discovery processing, finding
  generation)
- InfluxDB for time-series metrics
- S3-compatible storage for artifacts and reports

**Networking and security:**
- All client traffic routes through a Traefik v3 API gateway with
  per-service circuit breakers
- Service-to-service communication uses HMAC-SHA256 authentication
- An opt-in mTLS service mesh secures internal service communication
- Authentication uses httpOnly cookies with JWT tokens

**Deployment:** the **Helm chart is the production path** — every service
definition and routing rule is generated from a central service registry to
ensure consistency. Docker Compose is for local development and evaluation
only.

---

*Vista Platform — updated for 1.0.0*
