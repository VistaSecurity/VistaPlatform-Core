# CMDB Terminology Glossary

This glossary maps the Vista Platform's internal terminology to the corresponding concepts and CI types used by each supported CMDB platform. Use this as a reference when configuring field mappings, CI type mappings, or troubleshooting sync issues.

## Entity Type Mapping

### Infrastructure Asset

An infrastructure asset represents **one thing** in your estate — a server, a workstation, a switch, a virtual machine, a cloud resource, a business service. Its network faces are **endpoints** (address, port, service) hanging off it, and its cryptographic configurations hang off those, so a host with three listeners is one CI with three endpoints rather than three CIs.

| Context | Term / CI Type |
|---------|---------------|
| **Platform (internal DB table)** | `assets` (with `asset_endpoints` and `asset_identifiers`) |
| **Platform (display name)** | Infrastructure Asset |
| **Platform (CI category)** | `infrastructure_asset` |
| **ServiceNow** | `cmdb_ci_server`, `cmdb_ci_computer`, `cmdb_ci_netgear`, `cmdb_ci_vm_instance`, `cmdb_ci_service` — by class, see below |
| **Device42** | Device (`/api/1.0/devices/`) |
| **SolarWinds** | Node (`Orion.Nodes`) |
| **Oomnitza** | Asset (`/api/v3/assets`) |
| **Unified View** | `v_ci_inventory` (category: `infrastructure_asset`) |

**Class mapping (ServiceNow).** The platform's class — what kind of thing the asset is — chooses the CI class. Classes form a tree, so a class with no mapping of its own uses its nearest mapped ancestor.

| Class (Platform) | ServiceNow CI Class |
|------------------|---------------------|
| `server` | `cmdb_ci_server` |
| `workstation`, `laptop` | `cmdb_ci_computer` |
| `switch`, `router`, `firewall`, `load_balancer` (under `network_device`) | `cmdb_ci_netgear` |
| `virtual_machine` | `cmdb_ci_vm_instance` |
| `object_storage`, `managed_database`, `key_store`, … (under `cloud_resource`) | `cmdb_ci_cloud_service_account` |
| `business_service`, `technical_service` (under `service`) | `cmdb_ci_service` |
| (anything else under `hardware`) | `cmdb_ci_hardware` |

---

### Certificate

A digital certificate (X.509) discovered on an infrastructure asset, including TLS/SSL certificates, code signing certificates, and CA certificates.

| Context | Term / CI Type |
|---------|---------------|
| **Platform (internal DB table)** | `certificates` |
| **Platform (display name)** | Certificate |
| **Platform (CI category)** | `certificate` |
| **ServiceNow** | Not pushed — its posture goes on the asset's description ([why](cmdb-integrations.md#servicenow)) |
| **Device42** | Not sent — a certificate is not a device |
| **SolarWinds** | Not applicable — SolarWinds is pull only |
| **Oomnitza** | Not sent — a certificate is not an asset in an asset register |
| **Unified View** | `v_ci_inventory` (category: `certificate`) |

---

### Key

A cryptographic key discovered or tracked by the platform, including TLS private keys, SSH keys, and API signing keys.

| Context | Term / CI Type |
|---------|---------------|
| **Platform (internal DB table)** | `keys` |
| **Platform (display name)** | Cryptographic Key |
| **Platform (CI category)** | `key` |
| **ServiceNow** | Not pushed — not a CI in ServiceNow's model |
| **Device42** | Not sent — a key is not a device |
| **SolarWinds** | Not applicable — SolarWinds is pull only |
| **Oomnitza** | Not sent — a key is not an asset in an asset register |
| **Unified View** | `v_ci_inventory` (category: `key`, cmdb_ci_type: `cmdb_ci_crypto_key`) |

---

### Crypto Configuration

A specific cryptographic protocol/cipher configuration observed on an infrastructure asset — for example, a TLS 1.2 connection using `ECDHE-RSA-AES256-GCM-SHA384`.

| Context | Term / CI Type |
|---------|---------------|
| **Platform (internal DB table)** | `crypto_implementations` |
| **Platform (display name)** | Crypto Configuration |
| **Platform (CI category)** | `crypto_configuration` |
| **ServiceNow** | Not pushed — its posture goes on the asset's description |
| **Device42** | Not sent — a crypto configuration is not a device |
| **SolarWinds** | Not applicable — SolarWinds is pull only |
| **Oomnitza** | Not sent — a crypto configuration is not an asset in an asset register |
| **Unified View** | `v_ci_inventory` (category: `crypto_configuration`) |

> **Note:** No custom ServiceNow table is needed. Earlier documentation asked for a `u_crypto_configuration` table; nothing writes to it.

---

### Crypto Library

A software library that provides cryptographic functionality (e.g., OpenSSL, BoringSSL, LibreSSL, NSS).

| Context | Term / CI Type |
|---------|---------------|
| **Platform (internal DB table)** | `crypto_libraries` |
| **Platform (display name)** | Crypto Library |
| **Platform (CI category)** | `crypto_library` |
| **ServiceNow** | Not pushed |
| **Device42** | Not sent — a library is not a device |
| **SolarWinds** | Not applicable — SolarWinds is pull only |
| **Oomnitza** | Not sent — a library is not an asset in an asset register |
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

**ServiceNow:** approved relationships between synced assets are pushed as
standard ServiceNow relationship types (`Runs on::Runs`, `Depends on::Used by`,
`Members::Member of`, …) — the full table is in
[CMDB Integrations → ServiceNow → Relationships](cmdb-integrations.md#servicenow-relationships).

### CMDB Class

A CMDB class defines the schema (attributes and relationships) for a type of CI. Each CMDB platform has its own class hierarchy:

**ServiceNow classes Vista pushes:**

```
cmdb_ci_server          ← servers (Linux, Windows and other server subclasses are pulled too)
cmdb_ci_computer        ← computers
cmdb_ci_pc_hardware     ← workstations, laptops
cmdb_ci_netgear         ← network devices
cmdb_ci_ip_switch       ← switches
cmdb_ci_ip_router       ← routers
cmdb_ci_ip_firewall     ← firewalls
cmdb_ci_lb              ← load balancers
cmdb_ci_wap_network     ← access points
cmdb_ci_storage_device  ← storage devices
cmdb_ci_printer         ← printers
cmdb_ci_hardware        ← any other hardware
```

Certificates, keys, crypto configurations and crypto libraries are not pushed to
ServiceNow. The full class table, including what a pull reads, is in
[CMDB Integrations → ServiceNow](cmdb-integrations.md#servicenow).

**Device42 entity types:**

```
Device        ← Infrastructure Asset (the only thing sent)
```

**SolarWinds entity types** (pull only — nothing is sent):

```
Orion.Nodes         → Infrastructure Asset
```

**Oomnitza entity types:**

```
Assets              ← Infrastructure Asset (the only thing sent)
  ci_category field ← always infrastructure_asset
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

A database view provides the mapping:
- `v_ci_inventory` → unified view of all CI types for CMDB export

(The former per-type alias views `v_infrastructure_assets` and
`v_crypto_configurations` were retired — nothing read them; CMDB export goes
through `v_ci_inventory`.)
