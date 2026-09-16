# Customer Documentation

Documentation for **tenants** and **tenant admins** — people who use Vista Platform to manage their organization's asset inventory and cryptographic posture.

## Quick Start

| I want to… | Start here |
|------------|-----------|
| Get an overview of the platform | [Platform Overview](./platform-overview.md) |
| Learn the vocabulary (asset, endpoint, class, relationship, …) | [Concepts](./concepts.md) |
| Understand how the platform itself is secured | [Security Posture](./security-posture.md) |
| Learn the platform as an end user | [Tenant User Guide](./guides/tenant-user-guide.md) |
| Administer my organization's settings | [Tenant Admin Guide](./guides/tenant-admin-guide.md) |
| Understand CBOM artifacts | [CBOM Artifacts](./cbom/cbom-artifacts.md) |
| Generate a software, hardware or full-inventory BOM, or export to a SIEM | [Bills of Materials](./cbom/xbom.md) |
| Learn about a specific feature | [Feature Guides](features/) |

## Contents

### Release notes
- [1.0.0](./releases/1.0.0.md) — the full, per-change record for the 1.0.0 release. The summary for each release is in `CHANGELOG.md` at the root of the repository; an unusually large release keeps its detail here.

### Security
- [Security Posture](./security-posture.md) — tenant isolation, supply chain, scanning, and the guarantees behind them

### Guides
- [Tenant User Guide](./guides/tenant-user-guide.md) — the console section by section: Dashboard, Discovery, Inventory, Risk & Compliance, Remediation, search, notifications and your profile
- [Tenant Admin Guide](./guides/tenant-admin-guide.md) — User management, SSO, billing, settings
- [Device Interrogation Guide](./guides/device-interrogation-user-guide.md) — Interrogating network devices
- [Device Auto-Discovery Troubleshooting](./guides/device-auto-discovery-troubleshooting.md)

### Features

The core surfaces, in the order a tenant meets them:

- [Concepts](./concepts.md) — the vocabulary: asset, endpoint, class, relationship, fact, finding, risk, alert, and more
- [Getting Started](./features/getting-started.md) — the onboarding checklist
- [The Dashboard](./features/dashboard.md) — the two heroes (cryptographic posture and inventory health) and what each number means
- [Inventory & Lenses](./features/inventory-and-lenses.md) — the unified inventory and its switchable lenses
- [Asset Classes & Identification Rules](./features/asset-classes.md) — the class taxonomy, identifier precedence, and the auto-accept threshold
- [Asset Approval](./features/asset-approval.md)
- [Asset Lifecycle Management](./features/asset-lifecycle-management.md)
- [Assets and Crypto Configurations](./features/assets-and-crypto-configurations.md)
- [Cryptographic Keys](./features/cryptographic-keys.md) — the Keys lens: algorithm, size, lifecycle state, and where each key is used
- [Query](./features/query.md) — the one-line predicate the filter rail, saved views, scopes and approval rules all speak
- [Global Search](./features/global-search.md) — the ⌘K quick-find palette
- [The Map](./features/map.md) — two views: the neighbourhood graph around one asset (with the impact overlay and GraphML/Cytoscape export) and the tenant-wide topology tree
- [Relationships](./features/relationships.md) — how assets are connected, and what breaks if one changes
- [Findings](./features/findings.md) — what a finding is, who produces them, and what "open" means
- [Remediation](./features/remediation.md) — Alerts, the ticket Queue, and migration Plans

Discovery sources — how assets get into inventory:

- [Discovery](./features/discovery.md)
- [Sensor Registration & Management](./features/SENSOR_REGISTRATION.md)
- [Host Inventory](./features/host-inventory.md) — what an agent collects about a host, and how it becomes an asset
- [Device Interrogation](./features/device-interrogation.md)
- [Fortinet Device Interrogation](./features/fortinet-device-interrogation.md)
- [AWS Cloud Discovery](./features/aws-cloud-discovery.md)
- [Azure Cloud Discovery](./features/azure-cloud-discovery.md)
- [GCP Cloud Discovery](./features/gcp-cloud-discovery.md)
- [PCAP Ingestion](./features/pcap-ingestion.md)
- [SBOM Upload](./features/sbom.md) — CycloneDX / SPDX documents become software inventory
- [Spreadsheet Import](./features/spreadsheet-import.md)
- [Adding Assets Manually](./features/adding-assets-manually.md) — the New asset form and the class picker
- [CMDB Integrations](./features/cmdb-integrations.md)
- [CMDB Terminology Glossary](./features/cmdb-terminology-glossary.md)
- [Third-Party & External Connections](./features/third-party-and-external-connections.md)
- [Certificate Chain Management](./features/certificate-chain-management.md)
- [Operational Context](./features/operational-context.md)

Posture and compliance:

- [Compliance Frameworks](./features/compliance-frameworks.md)
- [Framework Transparency](./features/framework-transparency.md) — Browse any published framework's controls & measurements (Posture)
- [Algorithm Reference](./features/algorithm-reference.md) — Browse every known algorithm and our assessment (Posture)
- [Crypto Risks](./features/crypto-risks.md)
- [Page-Local Exports](./features/page-local-exports.md)
- [Scopes](./features/scopes.md)

Admin and settings:

- [AI assistant](./features/ai-assistant.md) — which AI capabilities this deployment has, what answers without them, and your organization's two switches
- [Roles & Permissions](./features/roles-and-permissions.md) — built-in and custom roles, and what each grants
- [Member Invitations](./features/member-invitations.md) — one invitation flow for every sign-in method
- [API Tokens & MCP Server](./features/api-tokens-and-mcp.md)
- [Audit Logging](./guides/audit-logging.md)

### Bills of Materials
- [Bills of Materials](./cbom/xbom.md) — The four kinds (CBOM, SBOM, HBOM, full inventory), what each contains, and the OCSF event export
- [CBOM Artifacts](./cbom/cbom-artifacts.md) — Generate and manage immutable crypto snapshots
