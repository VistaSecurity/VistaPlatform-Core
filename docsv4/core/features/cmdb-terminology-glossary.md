# CMDB Terminology Glossary

This glossary maps the Vista Platform's internal terminology to the corresponding concepts and CI types used by each supported CMDB platform. Use this as a reference when configuring field mappings, CI type mappings, or troubleshooting sync issues.

## Entity Type Mapping

### Infrastructure Asset

An infrastructure asset represents a discoverable network endpoint — a server, workstation, network appliance, or service — that hosts or uses cryptographic configurations.

| Context | Term / CI Type |
|---------|---------------|
| **Platform (internal DB table)** | `network_assets` |
| **Platform (display name)** | Infrastructure Asset |
| **Platform (CI category)** | `infrastructure_asset` |
| **ServiceNow** | `cmdb_ci_server` (servers), `cmdb_ci_computer` (endpoints), `cmdb_ci_service` (services), `cmdb_ci_hardware` (appliances) |
| **Device42** | Device (`/api/1.0/devices/`) |
| **SolarWinds** | Node (`Orion.Nodes`) |
| **Oomnitza** | Asset (`/api/v3/assets`) |
| **Unified View** | `v_infrastructure_assets`, `v_ci_inventory` (category: `infrastructure_asset`) |

**Sub-type mapping (ServiceNow):**

| Asset Type (Platform) | ServiceNow CI Class |
|-----------------------|---------------------|
| `server` | `cmdb_ci_server` |
| `endpoint` | `cmdb_ci_computer` |
| `service` | `cmdb_ci_service` |
| `appliance` | `cmdb_ci_hardware` |
| (other) | `cmdb_ci_hardware` |

---

### Certificate

A digital certificate (X.509) discovered on an infrastructure asset, including TLS/SSL certificates, code signing certificates, and CA certificates.

| Context | Term / CI Type |
|---------|---------------|
| **Platform (internal DB table)** | `certificates` |
| **Platform (display name)** | Certificate |
| **Platform (CI category)** | `certificate` |
| **ServiceNow** | `cmdb_ci_certificate` |
| **Device42** | Certificate (`/api/2.0/certificates/`) |
| **SolarWinds** | Custom property on Node |
| **Oomnitza** | Asset with certificate-specific custom fields |
| **Unified View** | `v_ci_inventory` (category: `certificate`) |

---

### Key

A cryptographic key discovered or tracked by the platform, including TLS private keys, SSH keys, and API signing keys.

| Context | Term / CI Type |
|---------|---------------|
| **Platform (internal DB table)** | `keys` |
| **Platform (display name)** | Cryptographic Key |
| **Platform (CI category)** | `key` |
| **ServiceNow** | `cmdb_ci_credential` |
| **Device42** | Custom field on Device |
| **SolarWinds** | Custom property on Node |
| **Oomnitza** | Asset with key-specific custom fields |
| **Unified View** | `v_ci_inventory` (category: `key`, cmdb_ci_type: `cmdb_ci_crypto_key`) |

---

### Crypto Configuration

A specific cryptographic protocol/cipher configuration observed on an infrastructure asset — for example, a TLS 1.2 connection using `ECDHE-RSA-AES256-GCM-SHA384`.

| Context | Term / CI Type |
|---------|---------------|
| **Platform (internal DB table)** | `crypto_implementations` |
| **Platform (display name)** | Crypto Configuration |
| **Platform (CI category)** | `crypto_configuration` |
| **ServiceNow** | `u_crypto_configuration` (custom table) |
| **Device42** | Custom field on Device |
| **SolarWinds** | Custom property on Node |
| **Oomnitza** | Asset with crypto config custom fields |
| **Unified View** | `v_crypto_configurations`, `v_ci_inventory` (category: `crypto_configuration`) |

> **Note:** ServiceNow requires creating the custom table `u_crypto_configuration` in your instance. The platform provides guidance on the schema for this table.

---

### Crypto Library

A software library that provides cryptographic functionality (e.g., OpenSSL, BoringSSL, LibreSSL, NSS).

| Context | Term / CI Type |
|---------|---------------|
| **Platform (internal DB table)** | `crypto_libraries` |
| **Platform (display name)** | Crypto Library |
| **Platform (CI category)** | `crypto_library` |
| **ServiceNow** | `cmdb_ci_spkg` (software package) |
| **Device42** | Custom field on Device |
| **SolarWinds** | Custom property on Node |
| **Oomnitza** | Asset with library-specific custom fields |
| **Unified View** | `v_ci_inventory` (category: `crypto_library`) |

---

## CMDB Concepts

### Configuration Item (CI)

A **Configuration Item** is the fundamental unit in any CMDB. It represents a managed entity — a server, application, certificate, or any other IT resource. In the Vista Platform, the following entity types are treated as CIs for CMDB sync:

- Infrastructure Assets
- Certificates
- Cryptographic Keys
- Crypto Configurations
- Crypto Libraries

All of these are unified in the `v_ci_inventory` database view, which provides a single-table representation of all CIs for export.

### CI Relationships

CI relationships describe how Configuration Items relate to each other. The platform tracks and can push the following relationship types:

| Relationship Type | Description | Example |
|-------------------|-------------|---------|
| `uses` | One CI uses another | Server *uses* Certificate |
| `installed_on` | Software is installed on hardware | Library *installed_on* Server |
| `contains` | Parent contains child | Server *contains* Crypto Config |
| `issued_by` | Certificate issued by CA | Certificate *issued_by* CA Certificate |
| `depends_on` | Operational dependency | Service *depends_on* Server |
| `protects` | Security relationship | Certificate *protects* Service |
| `associated_with` | General association | Key *associated_with* Certificate |
| `configured_with` | Configuration link | Server *configured_with* Crypto Config |
| `runs_on` | Process runs on infrastructure | Service *runs_on* Server |
| `hosts` | Infrastructure hosts a service | Server *hosts* Service |

**Platform-specific mapping (ServiceNow `cmdb_rel_ci`):**

| Platform Relationship | ServiceNow Relationship Type |
|----------------------|------------------------------|
| `uses` | `Used by::Uses` |
| `installed_on` | `Installed on::Has installed` |
| `runs_on` | `Runs on::Runs` |
| `depends_on` | `Depends on::Used by` |
| `contains` | `Contains::Contained by` |

### CMDB Class

A CMDB class defines the schema (attributes and relationships) for a type of CI. Each CMDB platform has its own class hierarchy:

**ServiceNow class hierarchy (relevant classes):**

```
cmdb_ci (base class)
├── cmdb_ci_server         ← Infrastructure Asset (server)
├── cmdb_ci_computer       ← Infrastructure Asset (endpoint)
├── cmdb_ci_service        ← Infrastructure Asset (service)
├── cmdb_ci_hardware       ← Infrastructure Asset (appliance)
├── cmdb_ci_certificate    ← Certificate
├── cmdb_ci_credential     ← Key
├── cmdb_ci_spkg           ← Crypto Library
└── u_crypto_configuration ← Crypto Configuration (custom)
```

**Device42 entity types:**

```
Device        ← Infrastructure Asset
Certificate   ← Certificate
Custom Fields ← Key, Crypto Configuration, Crypto Library
```

**SolarWinds entity types:**

```
Orion.Nodes         ← Infrastructure Asset
Custom Properties   ← Certificate, Key, Crypto Configuration, Crypto Library
```

**Oomnitza entity types:**

```
Assets              ← All entity types (differentiated by custom fields)
  ci_category field ← Distinguishes infrastructure_asset, certificate, key, etc.
```

### Sync Profile

A **sync profile** is a tenant-scoped configuration that defines how data is pushed to a specific CMDB instance. Each profile includes:

- **Platform type** — Which CMDB platform (ServiceNow, Device42, SolarWinds, Oomnitza)
- **Connection config** — URL, authentication credentials
- **Field mapping config** — How platform fields map to CMDB fields
- **Sync config** — Schedule, batch size, conflict resolution
- **CI type mapping** — Which CMDB CI class each entity category maps to

### Sync Job

A **sync job** represents a single execution of the sync process for a profile. Jobs are created when:

- A user manually triggers a sync
- The scheduler fires based on the profile's schedule
- An event triggers a sync (e.g., new discovery completed)
- A retry is attempted after a previous failure

### Entity Mapping

An **entity mapping** links a local entity (e.g., an infrastructure asset with UUID `abc-123`) to its corresponding CMDB record (e.g., ServiceNow CI with `sys_id` `def-456`). Entity mappings are stored in the `cmdb_entity_mappings` table and include:

- Local entity type and ID
- CMDB platform, CI type, and external ID
- Sync status (`pending`, `synced`, `error`, `stale`, `deleted`)
- Last sync timestamp
- External URL (direct link to the CMDB record)

### Reconciliation

**Reconciliation** is the process of pulling back external metadata (IDs, status) from the CMDB after a push. This ensures that:

- Entity mappings have accurate external IDs
- The platform can detect if a CI was deleted or modified externally
- Direct links to CMDB records remain valid

## Terminology Change Log

The following terminology changes were made to align the platform with CMDB industry standards:

| Previous Term | New Term | Reason |
|--------------|----------|--------|
| Network Asset | Infrastructure Asset | Aligns with CMDB CI classification; "infrastructure" is the standard term across ServiceNow, Device42, and SolarWinds. |
| Crypto Implementation | Crypto Configuration | "Configuration" better describes the observed cipher/protocol settings on an asset and matches CMDB configuration item semantics. |

Both the old and new terms are supported in the API:
- **v1 API** uses the original terms (`assets`, `crypto-implementations`)
- **v2 API** uses the CMDB-aligned terms (`infrastructure-assets`, `crypto-configurations`)

Database views provide the mapping:
- `v_infrastructure_assets` → alias for `network_assets`
- `v_crypto_configurations` → alias for `crypto_implementations`
- `v_ci_inventory` → unified view of all CI types for CMDB export
