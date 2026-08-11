# Discovery Feature

The Discovery feature enables automated network scanning to discover cryptographic configurations across networks.

## Overview

Discovery allows tenants to:
- Scan networks for cryptographic configurations (TLS, SSH, IPSec, VPN)
- Interrogate network devices directly (Fortinet, Cisco, F5, etc.)
- Discover cloud resources via provider APIs (AWS, Azure, GCP)
- **Automatically process all discoveries** through unified pipeline (sensor and cloud discoveries)
- Review discovery results before importing (for discovery jobs)
- Approve or deny discovered assets
- Automatically classify assets into network segments (see [Operational Context](./operational-context.md))
- **Auto-approve discoveries** based on network segment rules (sensor and cloud discoveries)
- Link assets to parent devices (one device → many assets)

**Unified Processing Pipeline:**
All discovery sources (sensor discoveries and cloud discoveries) now flow through the same unified `sensor_discoveries` pipeline. The `discovery-processor-service` automatically processes both sensor and cloud discoveries, applies network segment classification, evaluates auto-approval rules, and creates assets with appropriate status (`monitoring` or `pending_approval`).

**Deployable sensor efficiency:** Tenant administrators can set an **observation rest period** (default one hour) so passive sensors do not re-send the same endpoint observation on every connection. Configure under **Organization Settings → Infrastructure → Sensor Configuration**. The setting is exposed to sensors as `dedup_ttl_minutes` in the discovery capabilities and as part of the tenant capture defaults.

## Workflow

### 1. Create Discovery Job

Create a discovery job with target networks, protocols, and ports, OR interrogate devices/cloud resources.

**UI:** Navigate to Assets → Discover Assets

**API:** `POST /api/v2/inventory-service/discovery/jobs` (network scanning)
**API:** `POST /api/v2/device-interrogation-service/devices/:id/interrogate` (device interrogation)
**API:** `POST /api/v2/device-interrogation-service/cloud/discover` (cloud discovery)

**Parameters (Network Scanning):**
- Targets: IP addresses, CIDR ranges, or hostnames
- Execution mode: `async` (default) or `sync`
- Protocols: TLS, SSH, IPSec, VPN
- Ports: Specific ports to scan (default: common ports)
- Preferred sensors: Specific sensors to use (optional)

**Parameters (Device Interrogation):**
- Device ID: UUID of registered device
- Automatically creates discovery job and findings

**Parameters (Cloud Discovery):**
- Integration ID: UUID of cloud provider integration
- Resource types: `["alb", "elb", "nlb", "api_gateway", "cloudfront", "kms", "s3", "rds"]` (AWS), `["application_gateway", "load_balancer", "key_vault", "storage_account", "sql_database"]` (Azure), or `["load_balancer", "ssl_proxy", "kms", "storage", "cloudsql"]` (GCP) — covering TLS front ends, key-management inventory, and at-rest encryption
- Regions: AWS regions to scan (optional, uses integration default)
- **Note:** Cloud discoveries are automatically written to `sensor_discoveries` and processed by `discovery-processor-service` - no manual import required
- **Certificate Extraction:** For publicly accessible cloud endpoints, the platform performs a **TLS handshake** to extract full certificate chains. For AWS resources, certificates are enriched with ACM metadata (ARN, renewal eligibility). Private endpoints fall back to API-only metadata.

### 2. Monitor Job Progress

Monitor discovery job status and progress.

**UI:** Discovery job status is displayed with real-time updates

**API:** `GET /api/v2/inventory-service/discovery/jobs/:id`

**Status Values:**
- `queued` - Job is queued for processing
- `running` - Job is currently running
- `completed` - Job completed successfully
- `failed` - Job failed
- `cancelled` - Job was cancelled

### 3. Review Results

Review discovery findings before importing.

**UI:** Results table shows:
- Hostname
- IP Address
- Port
- Protocol
- TLS Version (if applicable)
- Certificate information

**API:** `GET /api/v2/inventory-service/discovery/jobs/:id/results`

### 4. Import Results

Import discovery results as assets.

**UI:** Click "Import Selected" or "Import All"

**API:** `POST /api/v2/inventory-service/discovery/jobs/:id/import`

**Options:**
- Select specific findings to import
- Auto-approve: Automatically approve imported assets (skips approval workflow)
- Asset status: Set initial status (`monitoring` or `pending_approval`)

**Note:** Sensor discoveries are **automatically processed** by the `discovery-processor-service` - no manual import required. See [Sensor Discovery Processing](#sensor-discovery-processing) below.

### 5. Asset Approval

Review and approve/deny imported assets.

**UI:** Assets appear in "Pending Approval" section

**API:**
- `POST /api/v2/inventory-service/assets/approve` - Approve assets
- `POST /api/v2/inventory-service/assets/deny` - Deny assets

**Asset Status Flow:**
1. `pending_approval` - After import (if not auto-approved)
2. `monitoring` - After approval
3. `denied` - After denial (suppressed from rediscovery)

## Unified Discovery Processing

All discoveries (sensor and cloud) are **automatically processed** by the `discovery-processor-service` through a unified pipeline:

### Sensor Discoveries
1. **Sensor Submission**: Sensors submit discoveries to `sensor-manager`
2. **Storage**: Discoveries stored in `sensor_discoveries` table

### Cloud Discoveries
1. **Cloud API Discovery**: Device-interrogation-service discovers cloud resources via provider APIs
2. **TLS Handshake**: For publicly accessible endpoints, the service performs a TLS handshake to extract the full certificate chain (leaf + intermediates), negotiated TLS version, cipher suite, and ALPN protocol
3. **Certificate Enrichment**: For AWS resources, handshake-discovered certificates are enriched with ACM metadata (ARN, certificate type, renewal eligibility, validation status)
4. **Storage**: Discoveries (including certificate arrays and `handshake_verified` flag) written to `sensor_discoveries` table (unified pipeline)

### Automatic Processing (Both Sources)
5. **Automatic Processing**: `discovery-processor-service` polls for unprocessed batches from `sensor_discoveries`
6. **Network Classification**: Discoveries classified by network space
7. **Auto-Approval Evaluation**: Auto-approval rules evaluated based on network space
8. **Asset Creation**: Assets created with appropriate status (`monitoring` or `pending_approval`)
9. **Certificate Creation**: For findings containing certificate data, `inventory-service` creates `certificates` records (with `data_source = 'cloud_api'` for cloud discoveries), builds chain linkage, and links the leaf certificate to the `crypto_implementation`
10. **Compliance Integration**: Compliance findings automatically generated via events

**Benefits:**
- No manual intervention required for sensor or cloud discoveries
- Automatic processing within seconds
- Network space-based auto-approval for all discovery sources
- Unified approval workflow - cloud and sensor discoveries appear together in Discovery Approvals modal
- Full certificate chain extraction for cloud resources via TLS handshake, achieving parity with sensor-based discoveries
- Cloud-specific metadata enrichment (e.g., ACM ARN, renewal status) preserved on certificate records
- Resilient (missed batches automatically picked up)

## Integration with Cluster Sensor Service

Discovery jobs are processed by the `cluster-sensor-service`:

1. **Job Creation**: `inventory-service` creates job and sends to `cluster-sensor-service`
2. **Job Processing**: `cluster-sensor-service` distributes work to available sensors
3. **Result Collection**: Sensors submit findings to `cluster-sensor-service`
4. **Result Retrieval**: `inventory-service` retrieves results from `cluster-sensor-service`
5. **Manual Import**: User reviews and imports results via UI

## Network Space Classification

After importing discovery results, assets can be automatically classified into network spaces based on IP address matching:

**UI:** Network Spaces → Classify Assets

**API:** `POST /api/v2/inventory-service/network-spaces/classify-assets`

Assets are matched to network spaces based on:
- IP address falls within network space CIDR ranges
- Network space priority (if multiple matches)

## Discovery Job Management

### Cancel Job

Cancel a running discovery job.

**API:** `POST /api/v2/inventory-service/discovery/jobs/:id/cancel`

### Rerun Job

Rerun a completed or failed discovery job.

**API:** `POST /api/v2/inventory-service/discovery/jobs/:id/rerun`

## Re-validation of Existing Assets

Discovery jobs can be used to re-validate existing assets in inventory:

1. **Stale Asset Re-validation**: Automatically re-validate assets that haven't been seen recently
2. **Manual Re-validation**: Create discovery jobs targeting specific assets to verify they're still alive
3. **Result Processing**: If assets are found, `last_seen_at` is updated and stale status is cleared

**API:** `POST /api/v2/inventory-service/assets/revalidate`

**Use Cases:**
- Verify stale assets are still on the network
- Periodic re-validation of critical assets
- Validate assets before removing from inventory

See [Asset Lifecycle Management](./asset-lifecycle-management.md) for more details.

## Best Practices

1. **Start Small**: Begin with small target ranges to test discovery
2. **Review Results**: Always review results before importing
3. **Network Spaces**: Set up network spaces before discovery for automatic classification
4. **Approval Workflow**: Use approval workflow for production environments
5. **Scheduled Discovery**: Set up recurring discovery jobs for continuous monitoring
6. **Re-validation**: Periodically re-validate existing assets to keep inventory current

## Limitations

- Maximum 1000 targets per job
- Async execution recommended for large scans
- Results retained for 24 hours (configurable)
- Rate limiting applies to prevent abuse

## Troubleshooting

### Job Stuck in "Running" Status

- Check sensor health: `GET /api/v2/sensor-manager/sensors/:id/health`
- Retry job: `POST /api/v2/inventory-service/discovery/jobs/:id/rerun`
- Check cluster-sensor-service logs

### No Results Returned

- Verify targets are reachable
- Check protocol/port configuration
- Verify sensors are active and healthy
- Check network connectivity

### Import Fails

- Verify asset data format
- Check for duplicate assets
- Review asset approval workflow settings
- Check database connection

## Related Documentation

- [Network Spaces Feature](./network-spaces.md) - Network space management
- [Asset Approval Feature](./asset-approval.md) - Asset approval workflow
- [Asset Lifecycle Management](./asset-lifecycle-management.md) - Stale asset detection and management
