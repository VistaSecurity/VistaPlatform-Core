# CMDB Integrations

Sync your cryptographic inventory with external Configuration Management Database (CMDB) platforms for unified IT asset management. The CMDB integration feature lets organizations both **push** infrastructure assets, certificates, cryptographic keys, and crypto configurations discovered by the platform into their existing CMDB systems, and **pull** server inventory from those systems into the platform.

## Overview

The Vista Platform discovers and tracks cryptographic posture across your infrastructure. CMDB integration closes the loop with your IT operations teams: push cryptographic posture into the CMDB tools they already use, and pull the servers they already track into the platform to be enriched with cryptographic discovery.

**Key capabilities:**

- **Push-with-reconciliation sync** — Data flows from the platform to your CMDB. External IDs and sync status are pulled back for linking. Your CMDB remains the system of record.
- **Pull (inbound import)** — Import server CIs from your CMDB into the platform as pending-approval assets, so you don't re-enter inventory the CMDB already has. See [Pull Inventory From Your CMDB](#pull-inventory-from-your-cmdb).
- **Cryptographic context write-back** — Optionally append a plain-language crypto-posture summary to each pushed CI's description, on any platform with no custom-field setup. See [Cryptographic Context in Your CMDB](#cryptographic-context-in-your-cmdb).
- **Four supported platforms** — ServiceNow, Device42, SolarWinds, and Oomnitza.
- **Configurable field mapping** — Map platform entity fields to CMDB CI attributes with full control over which data is synced.
- **Flexible scheduling** — Sync manually, hourly, daily, or weekly.
- **Conflict resolution policies** — Choose how to handle conflicts when data differs between systems.
- **CI type mapping** — Infrastructure assets, certificates, keys, crypto configurations, and libraries are each mapped to the appropriate CMDB CI class for the target platform.
- **Entity-level tracking** — Every synced entity is tracked with its external CMDB ID, sync status, and an external URL linking back to the CMDB record.

## Supported Platforms

| Platform | API Used | Authentication | Notes |
|----------|----------|----------------|-------|
| **ServiceNow** | Table API + CMDB API | OAuth 2.0, Basic Auth, API Token | Full CMDB CI class support. Relationships via `cmdb_rel_ci`. |
| **Device42** | REST API v1/v2 | API Token, Basic Auth | Devices, certificates, and custom fields. |
| **SolarWinds** | SWIS REST API (Orion SDK) | API Key, OAuth, Basic Auth | Orion Nodes and custom properties. |
| **Oomnitza** | REST API v3 | API Token (Authorization2 header) | Flat asset model with custom fields for crypto metadata. |

## Setting Up a CMDB Integration

### Prerequisites

- Organization admin or platform admin role
- Network connectivity from the platform to your CMDB instance
- API credentials for the target CMDB platform
- (Recommended) A dedicated service account on the CMDB side with appropriate write permissions

### Step 1: Navigate to CMDB Integrations

1. Open the profile menu and go to **Settings → Integrations**.
2. Scroll to the **CMDB / ITSM sync** section.
3. Click **Add CMDB sync**.

Each connection appears as a card showing its platform and last-sync status. From a
card you can **Test** the connection, **Sync** (push inventory now), view **Sync history**,
edit the configuration, or remove it. Managing CMDB sync requires the **Update Settings**
permission.

### Step 2: Select a Platform

Choose from the four supported platforms:

- **ServiceNow** — ServiceNow CMDB via Table API and CMDB API.
- **Device42** — Device42 IT Asset Management via REST API.
- **SolarWinds** — SolarWinds Orion CMDB via SWIS REST API.
- **Oomnitza** — Oomnitza IT Asset Management via REST API.

### Step 3: Configure Connection

Provide the connection details for your CMDB instance:

#### ServiceNow

| Field | Description | Example |
|-------|-------------|---------|
| **Instance URL** | Your ServiceNow instance URL | `https://yourinstance.service-now.com` |
| **Authentication** | OAuth 2.0, Basic Auth, or API Token | Select from dropdown |
| **Username** | ServiceNow username (Basic Auth) | `svc_crypto_sync` |
| **Password** | ServiceNow password (Basic Auth) | `••••••••` |
| **Client ID** | OAuth 2.0 client ID | `abc123...` |
| **Client Secret** | OAuth 2.0 client secret | `••••••••` |

#### Device42

| Field | Description | Example |
|-------|-------------|---------|
| **API Base URL** | Device42 API URL | `https://device42.yourcompany.com` |
| **Authentication** | API Token or Basic Auth | Select from dropdown |
| **API Token** | Device42 API token | `d42_tok_...` |

#### SolarWinds

| Field | Description | Example |
|-------|-------------|---------|
| **API Base URL** | SolarWinds Orion server URL | `https://solarwinds.yourcompany.com:17778` |
| **Authentication** | API Key, OAuth, or Basic Auth | Select from dropdown |
| **API Token** | SolarWinds API key | `sw_key_...` |

#### Oomnitza

| Field | Description | Example |
|-------|-------------|---------|
| **API Base URL** | Oomnitza API URL | `https://yourcompany.oomnitza.com` |
| **Authentication** | API Token | Select from dropdown |
| **API Token** | Oomnitza API token (sent via `Authorization2` header) | `oom_tok_...` |

### Step 4: Test the Connection

After entering credentials, click the **Test Connection** button (signal icon) on the profile card. The platform will attempt to reach your CMDB instance and validate credentials.

- **Success**: A green "Connection test successful" toast appears.
- **Failure**: An error message describes what went wrong (e.g., authentication failure, network unreachable).

### Step 5: Configure Sync Options

#### Sync Schedule

| Schedule | Description |
|----------|-------------|
| **Manual Only** | Sync only when you click the sync button. |
| **Hourly** | Automatically sync every hour. |
| **Daily** | Automatically sync once per day (default). |
| **Weekly** | Automatically sync once per week. |

#### Conflict Resolution

| Policy | Description |
|--------|-------------|
| **Source Wins** | Platform data always overwrites CMDB data. This is the default for push-with-reconciliation. |
| **Target Wins** | CMDB data is preserved; platform data is skipped if a conflict is detected. |
| **Skip** | Conflicting items are skipped and logged for manual review. |

#### Additional Options

| Option | Default | Description |
|--------|---------|-------------|
| **Batch Size** | 100 | Number of CIs pushed per API call batch. |
| **Sync Deletions** | Off | Whether to propagate soft-deletes to the CMDB. |
| **Include Relations** | Off | Whether to push CI-to-CI relationship edges. |

### Step 6: Enable and Sync

1. Check the **Enable this integration** checkbox.
2. Click **Create** (or **Update** for existing profiles).
3. Click the **Sync** button (circular arrow icon) on the profile card to trigger the first sync.

## Configuration Options

### Field Mapping

Field mapping controls how platform entity attributes are translated to CMDB CI fields. The platform provides sensible defaults, but you can customize mappings per profile.

**Default field mappings:**

| Platform Field | CMDB Field | Description |
|---------------|------------|-------------|
| `asset_name` | `ci_name` | Configuration item display name |
| `asset_id` | `ci_id` | Unique configuration item identifier |
| `asset_type` | `ci_class` | CI classification (Server, Application, etc.) |
| `ip_address` | `ip_address` | Primary IP address |
| `fqdn` | `fqdn` | Fully qualified domain name |
| `operating_system` | `os_name` | Operating system name and version |
| `environment` | `environment` | Deployment environment (prod, staging, dev) |
| `owner_id` | `owner` | Asset owner or responsible party |
| `algorithm` | `crypto_algorithm` | Cryptographic algorithm identifier |
| `key_length` | `crypto_key_length` | Cryptographic key length in bits |
| `protocol` | `crypto_protocol` | Cryptographic protocol (TLS, SSH, etc.) |
| `last_seen` | `last_discovered` | Last discovery or scan timestamp |

### CI Type Mapping

Each entity category in the platform is mapped to a platform-specific CI class:

| Platform Entity | ServiceNow | Device42 | SolarWinds | Oomnitza |
|----------------|------------|----------|------------|----------|
| Infrastructure Asset (server) | `cmdb_ci_server` | `device` | `Orion.Nodes` | `assets` |
| Infrastructure Asset (endpoint) | `cmdb_ci_computer` | `device` | `Orion.Nodes` | `assets` |
| Infrastructure Asset (service) | `cmdb_ci_service` | `device` | `Orion.Nodes` | `assets` |
| Certificate | `cmdb_ci_certificate` | `certificate` | Custom property | `assets` (custom fields) |
| Key | `cmdb_ci_credential` | Custom field on device | Custom property | `assets` (custom fields) |
| Crypto Configuration | `u_crypto_configuration` (custom) | Custom field on device | Custom property | `assets` (custom fields) |
| Crypto Library | `cmdb_ci_spkg` | Custom field on device | Custom property | `assets` (custom fields) |

### Sync Schedule

Configure how often the platform pushes data to your CMDB. Schedules can be set per profile, so you can have different cadences for different CMDB instances.


## Pull Inventory From Your CMDB

If your CMDB already tracks your servers, you can import them into Vista instead of
re-entering them. On a connected profile card (Settings → Integrations → CMDB / ITSM
sync) click **Pull**. Vista fetches the platform's **server CIs** and creates them as
**pending-approval infrastructure assets** — hostname, IP address, and operating system
are carried over. They then appear in Discovery → Approvals and Inventory, where normal
discovery enriches them with cryptographic detail.

- **Duplicate-safe.** A pull skips any asset whose hostname or IP already exists, so you
  can re-pull without creating duplicates. The result toast reports how many were created
  vs. already present.
- **Server CIs only** in this version (the most common case). Other CI classes and custom
  field mapping are planned enhancements.
- **Up to 1000 servers per pull** in this version; if your CMDB has more, run discovery to
  fill the gap or contact us — paginated pulls are a planned enhancement.
- A pull respects your plan's **asset limit**: if importing the pulled servers would exceed
  it, the pull is declined and nothing is created (upgrade your plan, then retry).
- Requires the **Manage assets** permission.

## Cryptographic Context in Your CMDB

When editing or creating a CMDB profile, enable **Include cryptographic summary**. With it
on, every asset Vista pushes carries a one-line, plain-language summary of its
cryptographic posture appended to the CI's description/notes field — for example:

> `Vista crypto posture — risk=high · protocols: TLS 1.2 · algorithms: RSA-2048, AES-256-GCM · PQC: classical (migration recommended)`

This works on **any** CMDB with no custom-field setup, because it writes to a standard
free-text field (ServiceNow `short_description`, Device42/Oomnitza `notes`, SolarWinds
`Comments`). It gives your IT teams visibility into cryptographic risk right alongside the
asset record. The toggle is **off by default**.

## Monitoring Sync Jobs

After triggering a sync (manually or on schedule), you can monitor progress:

1. Each sync creates a **sync job** with a status:
   - `pending` — Queued for execution
   - `in_progress` — Currently running
   - `success` — All items synced successfully
   - `partial` — Some items synced, some failed
   - `failed` — Sync failed entirely
   - `cancelled` — Sync was cancelled

2. Job metrics are tracked:
   - **Items Pushed** — Number of CIs successfully created or updated
   - **Items Reconciled** — Number of CIs with external IDs confirmed
   - **Items Failed** — Number of CIs that encountered errors
   - **Items Skipped** — Number of CIs skipped (e.g., due to conflict resolution)

3. **View sync history in the UI**: Click the history icon (clipboard list icon) on any profile card to open the **Sync History** panel. It shows the last 20 jobs with status, trigger type (manual/scheduled), start time, duration, and item counts. The **Failed** count is highlighted in red when non-zero.

4. Each profile card also shows the last sync time and status inline (Synced / Partial / Failed) without opening the history panel.

**API:** `GET /api/v1/inventory-service/cmdb/profiles/{id}/jobs?limit=20`

## Troubleshooting

### Connection Test Fails

| Symptom | Possible Cause | Solution |
|---------|---------------|----------|
| "Connection failed" | Network connectivity issue | Verify the platform can reach the CMDB URL. Check firewall rules and DNS resolution. |
| "Authentication failed (HTTP 401)" | Invalid credentials | Verify username/password or API token. For OAuth2, check client ID and secret. |
| "Authentication failed (HTTP 403)" | Insufficient permissions | Ensure the service account has read/write access to the target CMDB tables. |
| "HTTP 404" | Wrong base URL or instance URL | Verify the URL format for your platform (e.g., ServiceNow uses `https://instance.service-now.com`). |

### Sync Fails or is Partial

| Symptom | Possible Cause | Solution |
|---------|---------------|----------|
| All items fail | API token expired | Refresh or rotate the API token and update the profile. |
| Some items fail | Missing required fields | Check the CMDB's required fields for the target CI class and update field mappings. |
| "Profile is disabled" | Profile not enabled | Edit the profile and check "Enable this integration". |
| Slow sync | Large inventory + small batch size | Increase the batch size in sync config (default: 100). |

### Entity Mapping Issues

| Symptom | Possible Cause | Solution |
|---------|---------------|----------|
| Duplicate CIs in CMDB | Reconciliation not matching | Ensure your CMDB has a correlation field that stores the platform's local entity ID. |
| Stale mappings | Entity deleted locally but not in CMDB | Enable "Sync Deletions" in the sync config. |
| Missing external URLs | Platform returned no `sys_id` | Check CMDB API response format; some custom tables may not return `sys_id`. |

### Platform-Specific Issues

**ServiceNow:**
- Ensure the `u_crypto_configuration` custom table exists if syncing crypto configurations.
- For OAuth2, the ServiceNow instance must have an OAuth application configured.

**Device42:**
- Certificate sync uses the v2 API (`/api/2.0/certificates/`); ensure your Device42 version supports it.
- Keys and crypto configurations are stored as custom fields on the parent device.

**SolarWinds:**
- The SWIS API endpoint typically runs on port `17778`.
- Certificate, key, and crypto configuration data is stored as custom properties on Orion Nodes.

**Oomnitza:**
- Oomnitza uses the `Authorization2` header (not `Authorization`) for API token auth.
- All entity types map to the flat `assets` endpoint with custom fields for differentiation.

## FAQ

**Q: Can I sync data from the CMDB back into the platform?**
A: Yes — use **Pull** on a connected profile to import server CIs from your CMDB as pending-approval assets (see [Pull Inventory From Your CMDB](#pull-inventory-from-your-cmdb)). This version pulls **server CIs only**; importing other CI classes (certificates, software, etc.) and a configurable inbound field mapping are on the roadmap.

**Q: How many CMDB profiles can I create?**
A: There is no hard limit. You can create multiple profiles for different CMDB instances or even multiple profiles for the same platform (e.g., separate ServiceNow instances for different environments).

**Q: What happens if I delete a profile?**
A: Deleting a profile is a soft-delete. The profile and its entity mappings are retained in the database for audit purposes but are no longer active. Existing CIs in the CMDB are not affected.

**Q: Are credentials stored securely?**
A: Connection credentials are stored as encrypted JSONB in the `cmdb_sync_profiles` table. For enhanced security, you can use Vault references (`api_token_ref`, `client_secret_ref`) instead of storing secrets directly.

**Q: What entities are included in a sync?**
A: The sync includes all non-deleted entities from the unified `v_ci_inventory` view: infrastructure assets (servers, endpoints, services, appliances), certificates, cryptographic keys, and crypto configurations.

**Q: Can I sync only specific entity types?**
A: CI type mapping configuration on the profile controls which entity types are mapped. To exclude a type, remove its mapping from the `ci_type_mapping` configuration.

**Q: What triggers a scheduled sync?**
A: Scheduled syncs are managed by the platform's job scheduler. The schedule configured on the profile (hourly, daily, weekly) determines the cadence. Manual syncs can be triggered at any time regardless of schedule.

**Q: How do I know if a sync succeeded?**
A: Check the profile card in the UI — it shows the last sync time and status (Synced, Partial, Failed). For details, click the history icon (clipboard list) on the profile card to open the **Sync History** panel, which shows the last 20 jobs with full item counts and timing.
