# Discovery Feature

The Discovery feature enables automated network scanning to discover cryptographic configurations across networks.

## Overview

Discovery allows tenants to:
- Scan networks for cryptographic configurations (TLS, SSH, IPSec, VPN)
- Interrogate network devices directly (Fortinet, Cisco, F5, etc.)
- Discover cloud resources via provider APIs (AWS, Azure, GCP)
- **Automatically process all discoveries** through one pipeline (discovery jobs, sensors and cloud alike)
- Review what a job found, with a report of where each finding went
- Approve or deny discovered assets
- Automatically classify assets into network segments (see [Operational Context](./operational-context.md))
- **Auto-approve discoveries** on network segments with auto-approve enabled — the only rule that skips the approval queue
- Link assets to parent devices (one device → many assets)

**Unified Processing Pipeline:**
Every discovery source — discovery jobs, sensors and cloud discovery — flows
through the same `sensor_discoveries` pipeline. The `discovery-processor-service`
classifies each discovery, evaluates the auto-approval rules and creates the
asset as `monitoring` or `pending_approval`. Nothing is imported from a browser,
and no client chooses an asset's approval status.

**One auto-approval rule.** An asset is auto-approved only when it is on a
network segment you defined with auto-approve enabled (Settings →
Infrastructure). That is the whole rule, and it applies to every path into
inventory — scans, sensors, cloud, manual creation, spreadsheet import and CMDB
pull. See [Asset Approval](./asset-approval.md).

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
- **Note:** Cloud discoveries are automatically written to `sensor_discoveries` and processed by `discovery-processor-service`
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

Review what the job found. The findings are already on their way to inventory —
this step is a record of the run, not a decision point.

**UI:** Results table shows:
- Hostname
- IP Address
- Port
- Protocol
- TLS Version (if applicable)
- Certificate information

**API:** `GET /api/v2/inventory-service/discovery/jobs/:id/results`

### 4. Where the findings went

The wizard's results step reports the split — "N found · X auto-approved · Y
awaiting approval" — and links to **Discovery → Approvals**. There is no import
step and nothing to click to move findings into inventory; that already happened
server-side.

The two numbers are reported separately on purpose. **Found** is what the scan
saw. The split is what reached your inventory. They can differ: connections to
external third parties are recorded under **Inventory → Connections** rather than
as assets, a finding with no resolvable address cannot be anchored to one, and
processing is asynchronous, so a count may still be settling when the scan
finishes.

### 5. Asset Approval

Review and approve/deny discovered assets.

**UI:** Assets appear in "Pending Approval" section

**API:**
- `POST /api/v2/inventory-service/assets/approve` - Approve assets
- `POST /api/v2/inventory-service/assets/deny` - Deny assets

**Asset Status Flow:**
1. `pending_approval` - Unless the asset is on an auto-approve segment
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

## What discovery records

Discovery collects cryptographic **posture** — algorithms, key sizes, protocol
versions, cipher suites, certificate identity and validity — and not key
material. Device management APIs routinely return secrets alongside the
configuration being inventoried (VPN pre-shared keys, certificate private keys,
wireless and relay passwords), so each collector projects the vendor response
onto an explicit list of fields the platform uses, discarding the rest at the
point of collection. Cloud key discovery reads key metadata only.

See [Device Interrogation User Guide](../guides/device-interrogation-user-guide.md#what-the-platform-records-from-your-devices)
for the detail.

## Passive host observation

Beyond cryptographic sessions, a sensor also records **host presence and
names**. Devices on a network announce themselves constantly without being
asked — ARP when they claim an address, DHCP when they lease one, mDNS and
NetBIOS when they advertise a name or a service, LLDP and CDP when a switch
describes itself to its neighbours. The sensor decodes those announcements and
records what the device said about itself: its hardware (MAC) address, the IP
addresses bound to it, the names it answers to, the manufacturer registered to
its MAC prefix, and — for switches and phones that advertise themselves — the
model they report.

An announcement from a switch is recorded as an observation of **that switch**.
It is not recorded as a cable between the switch and the sensor: sensors are
usually fed by a mirror or SPAN port, so a frame reaching the sensor does not
mean the two are plugged into each other, and the platform does not claim
otherwise.

This is how the inventory finds devices that never open a TLS connection past
the sensor: printers, cameras, phones, controllers, and anything else that is on
the network but not talking to anything the crypto pipeline watches. Uploaded
PCAP files are decoded the same way, which often makes a capture the only
practical way to inventory a segment that cannot host a sensor.

Observation is **passive**: the sensor decodes frames the network interface
already receives and sends nothing onto the wire. It is on by default for every
sensor profile, including air-gapped ones, and can be turned off per sensor.
Changing the setting takes effect the next time the sensor restarts.

**No traffic content is recorded.** The sensor reads the announcement headers
that carry identity and nothing else:

- **MAC addresses and host names are device identifiers**, and the platform
  stores them as such. Some phones and laptops rotate a randomised MAC for
  privacy; the platform marks those as not stable and does not treat them as a
  device's permanent identity.
- **DNS decoding is off unless you turn it on.** With it off — the default —
  the sensor does not look at UDP 53 at all. Turning it on is a setting on the
  sensor host itself, not something the platform can switch on for you.

  When it is on, the sensor decodes DNS *answers* — "this name resolves to this
  address" — and never the question section. That still means the names being
  answered for are recorded, so the platform would hold a record of which names
  the network resolved. That is why it is a deliberate choice rather than a
  default. Device announcements over mDNS are unaffected and always decoded:
  a device advertising itself is not somebody looking something up.
- **Service announcements are recorded by type, not by name.** "This device
  offers printing" is kept; the user-chosen instance name attached to it is not.
- **A device's model is recorded only where it says so in a dedicated field.**
  Switch and phone announcements carry a model field; free-text descriptions are
  never mined for one, because a model guessed out of prose would be wrong
  without looking wrong.
- Free-text device descriptions from switches are truncated, and any private key
  pasted into one is masked before storage.

### What a passively observed device looks like in Approvals

A passively observed device proposes an asset exactly like any other discovery,
and waits in **Discovery → Approvals** until you accept it. What is different is
how little it may know, and the platform says so rather than filling the gaps
in:

- **Its name is whatever it called itself**, over DHCP, mDNS or NetBIOS — not a
  name looked up for it. The platform performs no reverse lookup on these
  devices: your internal host names are never sent to a resolver.
- **A device with no name at all shows as its address, or as its MAC.** An ARP
  frame from a camera that answers nothing tells you the camera is there and
  which manufacturer made the network chip, and that is the whole row. It is
  still worth approving — it is a device on your network — but it will look
  sparse next to something discovered by a scan.
- **Its type is "Unknown host".** The platform does not guess what a device is
  from its announcements. A device advertising printing is almost certainly a
  printer, but "almost certainly" is not an inventory entry; set the type when
  you approve it, or leave it and let a later interrogation fill it in.
- **The manufacturer is filled in** from the MAC prefix, where the prefix is one
  the registry knows. A blank manufacturer means *not determined*, not
  "unknown brand".
- **It has no ports, no services and no certificates.** Nothing connected to it,
  so there is nothing to report. A blank crypto section on one of these devices
  means nobody looked, not that it came back clean.
- **The same device seen again is the same row.** Its MAC is what ties the
  sightings together, so a device that later gets a name, or moves to a new
  address, updates the row you already approved rather than appearing twice. The
  exception is a phone or laptop using a randomised MAC: those cannot be tracked
  across rotations, and the platform will not pretend otherwise.

Once approved, these devices sit in the inventory like any other asset — they
can be tagged, assigned an owner, given a type, and picked up by a later
interrogation or scan that fills in what passive observation could not see.

Sensor detail (**Discovery → Sensors & Agents →** a sensor **→ Health**) shows
how many devices a sensor has seen this way over the selected period, and how
many observations it had to shed. A non-zero shed count means the segment is
busier than the sensor is sized for, and some devices on it may be missing.

## Integration with Cluster Sensor Service

Discovery jobs are processed by the `cluster-sensor-service`:

1. **Job Creation**: `inventory-service` creates job and sends to `cluster-sensor-service`
2. **Job Processing**: `cluster-sensor-service` distributes work to available sensors
3. **Result Collection**: Sensors submit findings to `cluster-sensor-service`
4. **Result Retrieval**: `inventory-service` retrieves results from `cluster-sensor-service`
5. **Ingestion**: `cluster-sensor-service` also mirrors every finding into the
   `sensor_discoveries` queue, where `discovery-processor-service` classifies it,
   evaluates the auto-approval rules and materializes the asset

## Network Space Classification

Discovered assets can be automatically classified into network spaces based on IP address matching:

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
2. **Review Results**: Check the results step's split — what was found versus what reached inventory
3. **Network Spaces**: Set up network spaces before discovery for automatic classification
4. **Approval Workflow**: Use approval workflow for production environments
5. **Scheduled Discovery**: Set up recurring discovery jobs for continuous monitoring
6. **Re-validation**: Periodically re-validate existing assets to keep inventory current

## Limitations

- Maximum 1000 targets per job
- Async execution recommended for large scans
- Results retained for 24 hours (configurable)
- Rate limiting applies to prevent abuse
- **QUIC / HTTP-3 connections yield very little when observed passively.** QUIC
  encrypts its own handshake, so a passive sensor records the QUIC version and
  destination but not the negotiated cryptography or the server certificate. Server
  name (SNI), ALPN and a client fingerprint are readable only from a connection's
  opening packet, which a sensor rarely witnesses for long-lived HTTP/3 connections —
  expect them on a small minority of QUIC connections. Active probing recovers the
  full picture, and is performed only against assets you own or have elevated to
  monitored — never against third-party destinations your systems merely connected
  to. See
  [Third-Party Systems and External Connections](./third-party-and-external-connections.md#http3-and-quic-connections).

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

### Findings Do Not Appear in Inventory

- Check **Discovery → Approvals** first: unless the address is on a network
  segment with auto-approve enabled, the asset is waiting there by design
- Connections to external third parties are recorded under **Inventory →
  Connections**, not as assets
- Findings with no resolvable IP address cannot be turned into an asset
- Processing is asynchronous — the results step reports how many are still being
  processed

## Related Documentation

- [Network Spaces Feature](./network-spaces.md) - Network space management
- [Asset Approval Feature](./asset-approval.md) - Asset approval workflow
- [Asset Lifecycle Management](./asset-lifecycle-management.md) - Stale asset detection and management
