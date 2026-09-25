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

**One pipeline.** Discovery jobs, sensors, cloud integrations, interrogated
devices, uploaded captures and host inventories all flow through the same
processing path: each discovery is placed into a network segment, the
auto-approval rules are evaluated, and the asset is created as `monitoring` or
`pending_approval`. Nothing is imported from a browser, and no client chooses an
asset's approval status.

**One auto-approval rule.** An asset is auto-approved only when it is on a
network segment you defined with auto-approve enabled (Settings →
Infrastructure). That is the whole rule, and it applies to every path into
inventory — scans, sensors, cloud, manual creation, spreadsheet import and CMDB
pull. See [Asset Approval](./asset-approval.md).

**Scans you did not start.** Most discovery jobs are ones somebody asked for.
Automatic active scanning is the exception: a new internal host is probed as
soon as it appears, and every internal host is probed again on a schedule (24
hours by default). Tenant admins control it — including turning it off — at
**Settings → Discovery → Active Scanning**. Only your own internal addresses are
ever scanned that way. See [Automatic Active Scanning](./active-scanning.md).

**Observation rest period.** A passive sensor does not re-send the same
observation on every connection it sees; it rests for **one hour** between
repeats of the same sighting. That default is **not adjustable from the console
today** — no page exposes it, including the sensor's own Control tab. It can be
changed through the API (`dedup_ttl_minutes`), either on one sensor's
configuration or as the organization-wide capture default, and the sensor
applies the new value on its next check-in.

## Workflow

### 1. Create Discovery Job

Create a discovery job with target networks, protocols, and ports, OR interrogate devices/cloud resources.

**UI:** **Discovery → Command Center → Discover assets**

**API:** `POST /api/v2/inventory-service/discovery/jobs` (network scanning)
**API:** `POST /api/v2/device-interrogation-service/devices/:id/interrogate` (device interrogation)
**API:** `POST /api/v2/device-interrogation-service/cloud/discover` (cloud discovery)

**Parameters (Network Scanning):**
- Targets: IP addresses, CIDR ranges, `a-b` ranges, hostnames or URLs. Targets
  outside your registered networks need your confirmation, and some ranges are
  never scanned — see
  [Scanning outside your networks](./active-scanning.md#scanning-outside-your-networks)
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

**UI:** **Discovery → Discovery Jobs** lists every run — discovery jobs (Active
Scan, the Discover wizard, the automatic-scan sweep) alongside device
interrogations — with its kind, executor, status and duration; filter by Kind,
Status or Executor. Click a discovery/automatic-scan row for its dispatch
timeline, targets, and findings split; click an interrogation row for the same
detail **Discovery → Job Logs** also carries.

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

**UI:** The wizard's results step shows:
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
external third parties are recorded under **Inventory → 3rd Party** rather than
as assets, a finding with no resolvable address cannot be anchored to one, and
processing is asynchronous, so a count may still be settling when the scan
finishes.

### 5. Asset Approval

Review and approve/deny discovered assets.

**UI:** **Discovery → Approvals**

**API:**
- `POST /api/v2/inventory-service/assets/approve` - Approve assets
- `POST /api/v2/inventory-service/assets/deny` - Deny assets

**Asset Status Flow:**
1. `pending_approval` - Unless the asset is on an auto-approve segment
2. `monitoring` - After approval
3. `denied` - After denial (suppressed from rediscovery)

## How a discovery reaches your inventory

Every source — a scan you ran, a sensor watching a segment, a cloud integration,
an interrogated device, an uploaded capture, a host inventory — lands in the same
queue and is processed the same way. Nothing is imported from a browser, and no
client gets to choose an asset's approval status.

1. **The finding is recorded.** Sensors submit continuously; jobs submit when
   they finish.
2. **It is placed.** The address is matched against the network segments you
   have defined, which is what decides the asset's segment and whether an
   auto-approval rule applies.
3. **The asset is created** as either `monitoring` (auto-approved) or
   `pending_approval`.
4. **Certificates are built out.** Findings carrying certificate data become
   certificate records with their chain linked, and the leaf is attached to the
   crypto configuration it was seen on. Cloud-discovered certificates keep their
   provider metadata.
5. **Compliance catches up.** Findings are re-evaluated against your activated
   frameworks as the inventory changes.

A missed batch is picked up on the next pass, so a brief outage delays results
rather than losing them.

**What cloud discovery adds.** For publicly reachable cloud endpoints the
platform performs a real TLS handshake, so a cloud-discovered asset carries the
same certificate detail a sensor would have seen — the full chain, the negotiated
version, the cipher suite — rather than API metadata alone. Private endpoints
that cannot be reached fall back to API metadata, and say so.

## Host inventory

A discovery agent can also describe a **host** rather than interrogate a device:
its operating system, hardware, installed software, listening sockets and
certificate stores — locally on the machine the agent runs on, or remotely over
SSH as a queued job. A listening socket the host itself reports is the only
evidence that ties a service to that machine, and it finds the loopback-only and
firewalled services no scan can reach.

It is off by default, and the resulting host waits in **Discovery → Approvals**
like any other discovery. See [Host Inventory](./host-inventory.md).

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

## Segment classification

A discovered asset is placed into one of the **network segments** you have
defined, by matching its address against each segment's ranges. The segment is
what auto-approval rules read, and what the inventory facets on. Segments are
maintained under **Settings → Infrastructure → Network Segments**; see
[Operational Context](./operational-context.md).

## Discovery Job Management

### Cancel Job

Cancel a running discovery job.

**API:** `POST /api/v2/inventory-service/discovery/jobs/:id/cancel`

### Rerun Job

Rerun a completed or failed discovery job.

**API:** `POST /api/v2/inventory-service/discovery/jobs/:id/rerun`

## Active Scan: choosing where it runs

An active scan has to run from somewhere that can reach the host. The platform
sensor inside the cluster reaches what the platform can route to; a host that is
only reachable from inside your own network is reachable only from a sensor you
deployed there. **Discovery → Active Scan** lets you choose, with the **Run
from** control beside the scan buttons:

| Run from | What happens |
|---|---|
| **Auto (observing sensor)** — the default | Each asset is scanned from the sensor of yours that most recently observed it. If none of your sensors has, a sensor on the same network segment is used; failing that, the platform sensor. |
| **Platform sensor** | Everything is scanned from inside the cluster — what every scan did before this control existed. |
| *A named sensor* | Everything is scanned from that one sensor. |

"The observing sensor" is the one of your sensors whose passive capture last
recorded the host — the best evidence anything can reach it. Sensors that are
offline are listed but cannot be chosen; the platform's own sensors are the
"Platform sensor" entry and are never listed by name. If no sensor of yours is
registered, the control offers the platform sensor only and points you to
**Sensors & Agents**.

The permission is the same whichever you pick: running a scan needs
`assets.update`, and running it from a sensor needs nothing more. Choosing a
sensor does not change the sensor's configuration and does not restart it.

**When the sensor is offline.** A scan sent to a sensor that has not checked in
recently fails immediately and says so — nothing is scanned, and the job is
never run from the platform instead, because a scan from somewhere that cannot
see the host would come back empty and look like an answer. Under **Auto**, an
asset whose observing sensor is offline is left unscanned and reported in the
result; scan it again when the sensor is back, or choose another executor. A
sensor that was online when the scan was created and then went quiet before
collecting it fails the job the same way, once the time the sensor's own
reporting cadence allows has passed. The failure names the sensor and its last
check-in.

**Following a scan.** The Active Scan page keeps a **Scans started from this
page** panel under the controls: each scan you start appears there with its
executor — *Platform sensor* or the sensor's name — its state (*Queued*,
*Awaiting <sensor>* while the sensor has not yet collected the job, *Running on
<sensor>*, *Completed*, or *Failed: sensor offline* with the sensor's last
check-in) and the timeline queued → dispatched → picked up → completed,
updating while the scan runs. It is cleared when you leave the page. Automatic
scans show the same executor and state in the run list on **Settings →
Discovery → Active Scanning**. Every scan also lands on **Discovery →
Discovery Jobs**, filterable by Kind (Discovery / Automatic scan), so it stays
visible after you leave the page that started it.

Results from a sensor take the same path as everything else that sensor sends
(see [How a discovery reaches your inventory](#how-a-discovery-reaches-your-inventory))
and land on the asset's Cryptography tab as **active** observations, exactly as
a platform-run scan's do.

Automatic scans choose the same way, governed by the **Prefer the observing
sensor** switch on **Settings → Discovery → Active Scanning** — see
[Automatic Active Scanning](./active-scanning.md).

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
3. **Network segments**: Define your segments before discovering, so assets are placed — and auto-approved — correctly from the first run
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

### Job stuck in "Running"

- Check the sensor's **Health** tab (**Discovery → Sensors & Agents →** the
  sensor) — a sensor that stopped heartbeating cannot finish the work it was
  given
- Retry or cancel the job from **Discovery → Discovery Jobs**
- The run's own detail, including any processing errors, is on **Discovery → Job
  Logs**

### No Results Returned

- Verify targets are reachable
- Check protocol/port configuration
- Verify sensors are active and healthy
- Check network connectivity

### Findings Do Not Appear in Inventory

- Check **Discovery → Approvals** first: unless the address is on a network
  segment with auto-approve enabled, the asset is waiting there by design
- Connections to external third parties are recorded under **Inventory → 3rd
  Party**, not as assets
- Findings with no resolvable IP address cannot be turned into an asset
- Processing is asynchronous — the results step reports how many are still being
  processed

## Related Documentation

- [Asset Approval](./asset-approval.md) — the approval queue and its rules
- [Asset Lifecycle Management](./asset-lifecycle-management.md) — stale assets and what happens to them
- [Host Inventory](./host-inventory.md) — describing a host rather than scanning it
- [Sensor & Agent Registration](./SENSOR_REGISTRATION.md) — deploying what does the discovering
- [PCAP Ingestion](./pcap-ingestion.md) — a capture file as a discovery source
- [Operational Context](./operational-context.md) — locations and network segments
