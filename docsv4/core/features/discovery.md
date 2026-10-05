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
repeats of the same sighting. Change it as **Dedup TTL** (in minutes) on one
sensor's **Control** tab, or for every sensor under **Sensor defaults** on
Discovery → Sensors & Agents; the sensor applies the new value at its next
check-in. Through the API it is `dedup_ttl_minutes`. See
[Agent and sensor settings](./agent-and-sensor-settings.md).

## Workflow

### 1. Create Discovery Job

Create a discovery job with target networks, protocols, and ports, OR interrogate devices/cloud resources.

**UI:** **Discovery → Command Center → Discover assets**. The dialog describes a scan the
way the API's [scan-depth shape](#scan-depth-ports-pace-and-where-it-runs-api)
does:

- **Targets**, and a **Scan depth** — *Quick*, *Standard* (the default),
  *Thorough* or *Custom*. No protocol is picked: services are identified from
  what answers.
- **Run from** — *Auto*, the *Platform sensor*, or one of your sensors by name
  (one that has stopped checking in is listed but cannot be chosen).
- **Advanced**, closed until opened — *Custom*'s TCP and UDP ports (ranges such
  as `8000-8100` mean the whole range, and a mistake is pointed out in the
  platform's own words before you start), the **Pace**, and the **Probe
  industrial (OT/ICS) devices** opt-in, which is off unless ticked, part of no
  depth, and absent when the tenant's `ot_active_probing` switch is off.
- A **Preview** — a dry run of exactly the request Start would send: addresses
  and ports, a duration *range* with the assumptions behind it, where the scan
  runs and why, the targets that will be scanned at less depth, and the
  confirmation targets outside your registered networks will need. It refreshes
  once the form stops changing; a scan the server would refuse (too large, over
  the budget, a sensor that is offline) is refused here in the server's words,
  and a preview that cannot be worked out never stops you starting.
- **Start** hands the scan to the platform and says what started, with **View
  in Discovery Jobs**. The dialog can be closed at any moment and does not
  follow the scan: progress, results and Cancel are on **Discovery → Discovery
  Jobs**. An address that sends nothing back is reported as *no answer* — it
  may be down, filtered or out of reach of where the scan ran from — never as
  empty.

The tenant user guide walks through it:
[Discovery → Command Center](../guides/tenant-user-guide.md#command-center).

**API:** `POST /api/v2/inventory-service/discovery/jobs` (network scanning)
**API:** `POST /api/v2/device-interrogation-service/devices/:id/interrogate` (device interrogation)
**API:** `POST /api/v2/device-interrogation-service/cloud/discover` (cloud discovery)

**Parameters (Network Scanning):**
- Targets: IP addresses, CIDR ranges, `a-b` ranges, hostnames or URLs. Targets
  outside your registered networks need your confirmation, and some ranges are
  never scanned — see
  [Scanning outside your networks](./active-scanning.md#scanning-outside-your-networks)
- Execution mode: `auto` (default; the platform sensor), `async` or `cloud`
  (the platform sensor — `cloud` is accepted for compatibility and runs
  in-cluster, it does not start a cloud-account discovery), or `sensors` with
  one preferred sensor
- Protocols (**deprecated, ignored**): the scan engine identifies the service
  from what answers on each port, so a request naming `protocols` and `ports`
  is scanned as a `scan_depth: custom` scan on exactly those ports. The field is
  still validated — `TLS` (and the TLS-wrapped names `HTTPS`, `SSL`, `LDAPS`,
  `SMTPS`, `IMAPS`, `POP3S`, `FTPS`), `SSH`, `SMB` are the only values accepted;
  anything else, including industrial (OT/ICS) protocol names, is refused with a
  `validation_error` that lists them — and still used when the job runs on a
  sensor older than this release. Send `scan_depth: custom` with `tcp_ports`
  instead (below)
- Ports: Specific ports to scan, with `protocols` (default: common ports)
- Industrial (OT/ICS) probes (`ot_probe_protocols`), alone or beside the
  ports: each probe your installation allows adds its one standard port to
  the scan (Modbus TCP 502, OPC UA TCP 4840, EtherNet/IP UDP 44818, BACnet UDP
  47808) and is probed there. A request naming only OT probes, all of them
  switched off, is refused rather than run as a scan of nothing
- Preferred sensors: Specific sensors to use (optional)

#### Scan depth, ports, pace and where it runs (API)

`POST /discovery/jobs` has a second request shape that describes the scan by
**depth** rather than by protocols and ports. It is what the **Discover
assets** wizard sends; a job sent this way runs in per-host work units — from
the platform sensor, or from one of your sensors (see *How a scan by depth runs*
and *From one of your sensors* below).
Send these
fields **instead of** `protocols` and `ports` — a request carrying both is
refused with a `validation_error` that names the conflict. Services are
identified from what answers, so no protocol is requested.

| Field | Values | Meaning |
|---|---|---|
| `scan_depth` | `quick` · `standard` (default) · `thorough` · `custom` | **Quick**: the curated crypto and infrastructure TCP ports (41). **Standard**: every TCP port from 1 to 1024 plus a curated list of common service ports above it (1,364 in all) and the curated UDP services (DNS, NTP, SNMP, IKE, OpenVPN, SSDP, mDNS, DTLS/QUIC; 11 ports). **Thorough**: all 65,535 TCP ports plus the curated UDP services. **Custom**: exactly `tcp_ports` and `udp_ports`. |
| `tcp_ports`, `udp_ports` | e.g. `22,80,8000-8100` | Custom depth only. Ports and inclusive ranges, comma-separated. A bad entry is refused naming it. |
| `pace` | `polite` · `normal` (default) · `fast` | How many connections at once and how long each may wait. |
| `run_from` | `auto` (default) · `platform` · `sensor` | Where the scan runs; `sensor` needs `sensor_id`. |
| `ot_probe_protocols` | `Modbus`, `OPC_UA`, `EtherNet_IP`, `BACnet` | The explicit opt-in to industrial (OT/ICS) probes, as on the legacy shape. Never part of a depth. |

If neither shape's fields are present, the request is in this shape and asks
for a **Standard** scan.

**The plan.** The server decides what each target actually gets and returns it
as `job.plan` on the create response and on `GET /discovery/jobs/{id}`: the
depth and pace, the port counts, where the job runs and why
(`executor_resolved`, `executor_reason`), and per target its class —
`private`, `registered_segment` (with the `segment_id` of the network segment
that made it yours) or `external` — the depth applied and the estimated probes.

**Targets outside your networks are scanned at Standard at most.** A target
that is neither in private address space nor inside a network segment you
registered is scanned at **Standard** even when the job asks for Thorough, and a
custom scan probes at most 1,024 TCP ports and only the curated UDP services
there. The rest of the job runs at the depth you asked for — a job naming one of
your /24s and a public host scans the /24 deeply and the host at Standard. Each
such downgrade is listed in `plan.depth_adjustments` with the reason. This is a
guardrail for targets nobody has claimed, **not an access control**: if the range
is yours, register it as a network segment (**Settings → Infrastructure →
Network Segments**) and it is scanned at the depth you ask for. The job records
which segment made each target yours.

**Run from Auto** picks one of your sensors when exactly one online,
non-air-gapped sensor serves **every** target — every target is inside a network
the sensor reports, or (for a single address) the sensor is the one that last
observed it — and the platform sensor otherwise: when the targets are spread
over different sensors' networks, when a target is on no sensor's network, when
the sensor that would serve them is offline, or when any target is outside your
registered networks. A job runs from one place; the plan says which, and why.
Split a scan per sensor to run each part from its own sensor.

**A scan by depth runs only on a sensor whose software supports it.** A sensor
reports what it can do on every heartbeat, and a job with a scan depth is handed
only to one that says it can run it. Auto never picks a sensor that cannot — the
plan then says the platform sensor runs the job, and why — and naming such a
sensor with `run_from: sensor` is refused with **409**
`sensor_scan_plan_unsupported`: upgrade the sensor, or run the scan from the
platform. Nothing is created, and nothing is scanned. A sensor supports it from
the release that introduced per-host sensor reporting (see *From one of your
sensors* below); upgrade older sensors to run such scans from them. Active
Scan, automatic scans and identity checks, and API jobs that name `protocols`
and `ports`, still run on an older sensor: the platform sends it the older
protocols × ports form of the same scan, and **Discovery → Sensors & Agents**
marks the sensor *Needs upgrading to run scans on the current engine*.

**The budget.** A scan's estimated size is the sum, over its targets, of
addresses × (TCP ports + UDP ports); a hostname counts as one address. A scan
above the installation's budget — **25,000,000** by default, which admits a
Thorough scan of one `/24` (about 16.8 million) and a Standard scan of the
largest job the address limits allow (about 22.5 million) — is refused with
**422** `scan_budget_exceeded`, naming the estimate, the limit and the largest
target. Lower the depth, or split the targets across scans. Operators set the
budget with the chart value `discovery.maxJobProbes`.

**Sharing the platform sensor.** Every organization's scans from the platform
sensor share its capacity, so it is shared out host by host: one replica scans
at most `discovery.maxConcurrentUnits` hosts at once (default 16) and any one
organization at most `discovery.maxConcurrentUnitsPerTenant` (default 4),
however many scans it runs. A large scan therefore takes longer when others are
scanning too, instead of making theirs wait for it.

**Preview before you start (`dry_run`).** Add `"dry_run": true` to a request in
this shape to see what it would do without creating it. The server answers
**200** with:

- `plan` — exactly the plan a real create of the same request would store;
- `estimate` — `probes` and `addresses`, and a duration as a range:
  `seconds_best` (every address answers at once) and `seconds_worst` (every
  address is up but drops every probe, so each batch waits out the connect
  timeout), in whole seconds, with a `basis` sentence saying what that assumes.
  It is an estimate, not a promise: liveness checks usually remove many
  addresses of a sparse range before any port is probed, so a scan of a sparse
  range usually finishes well under the best case, and UDP is paced separately
  and is counted in `probes` but not in the seconds;
- `confirmation_required` and `external_targets` — whether targets outside your
  registered networks still need `external_targets_confirmed: true`, and which.
  A real create answers **422** `external_targets_unconfirmed` there; a preview
  answers 200 so you can see what you would be confirming, and the `plan`
  already shows the downgrades that apply once you do.

A dry run goes through the same checks as a real create — validation, target
authorization, the Standard cap on external targets, Run from Auto, the budget
— and is refused with the same status and code where a real create would be
(400, 403, 404, 409, 422 `scan_target_too_large`, `scan_budget_exceeded`,
`targets_refused`, and 429 when the tenant is at its scan allowance). It needs
the same `discovery.create` permission. It creates **nothing**: no job, no
sensor command, no use of your job allowance, no job-created audit entry. A
request that names `protocols` and `ports` has no plan to preview and is refused
with a `validation_error`. The **Discover assets** wizard shows this preview
before every scan.

**How a scan by depth runs.** Run from the platform sensor, the job is split
into one **unit per address** its targets name, and each address is checked
against your registered networks and exclusions before anything is sent to it —
again just before its scan starts, so a range you mark sensitive while a scan is
queued or running is not touched. Then, per address:

1. **Is anything there?** For a CIDR or range, each address is first asked on a
   handful of common TCP ports (SSH, DNS, HTTP/S, RPC, SMB, RDP and alternates);
   an accepted *or refused* connection means something is there. An address that
   gives **no answer** is not port-scanned. A target you named on its own — one
   address, or a hostname — is always port-scanned.
2. **Which TCP ports are open**, at the job's pace — only the ports planned for
   that target. Industrial (OT/ICS) ports are touched one connection at a time.
   A host that seems to accept *every* port (a tarpit, or a firewall answering
   for everything) is stopped early and reported once, with a sample.
3. **What is listening.** Each open port is read for a greeting, then sent at
   most one TLS hello. A port that cannot be named is still recorded — as an
   open, unidentified port on that host — never dropped.
4. **UDP**, for the planned UDP ports: a service that replies is recorded; a
   silent port is counted, never reported as a finding.

What a host yields is stored, and sent on to inventory, **as soon as that host
is finished** — not when the whole job ends. Stop the job and what was found so
far stays; a Retry, or a restart of the platform, carries on with the hosts not
yet done. If the platform sensor running a scan stops unexpectedly (a crash
rather than a restart), the scan is picked up again automatically about five
minutes later, by another replica, from the hosts not yet done — up to three
times; after that the job is marked failed, saying how many times it was
resumed, and a Retry carries on from where it stopped.

**Progress and coverage.** For such a job, `GET /discovery/jobs/{id}` reports
`progress` per **host** (the share of its addresses finished) and a `coverage`
summary: how many addresses **responded**, gave **no answer**, could not be
scanned (with the reason), and are still to do; ports open, closed, filtered and
not probed; and `warnings` to read beside the numbers.

**No answer is not "down".** A firewall that drops everything looks exactly
like an empty address, so a host that did not answer is reported as *no
answer*, never as absent. When **none** of the addresses answered, the coverage
says so and suggests the likely reason: the platform sensor may not be able to
reach that network — run the scan from a sensor on it.

**From one of your sensors.** A scan by depth that runs from one of your
sensors — *Run from: Auto* chose it, or you named it — works the same way and
reads the same in the job: the platform splits it into units and checks every
address against your registered networks and exclusions **before** handing the
plan to the sensor, and the sensor scans with the same engine, the same pace
and the same steps 1–4 above. In addition, the sensor applies its own rules: it
never contacts a loopback, link-local, multicast or broadcast address, an
address in a range you excluded from probing, or one outside your networks as
the platform last told it — such an address is reported as *could not be
scanned*, with the reason, and nothing is sent to it.

- **Progress as it goes.** The sensor reports each host the moment it is done,
  so `progress`, `coverage` and the results by host fill in while the scan runs,
  and each host's findings reach inventory right away. The sensor holds nothing
  back for the end of the job.
- **No time limit, but it must keep reporting.** A scan from a sensor runs as
  long as it needs — a Thorough scan of a /24 can take hours. The sensor checks
  in at least once a minute while it works; if the platform hears **nothing**
  from it for **15 minutes** (the sensor was switched off, or lost its network),
  the job is marked failed — "stopped reporting progress … retry to scan the
  rest". Hosts it finished keep their results, and a **Retry** sends the sensor
  only the hosts not done.
- **Cancel reaches the sensor.** Cancelling the job stops the sensor at its next
  report, or at its next heartbeat when it is between reports; a job still
  waiting on the sensor is dropped unstarted. Hosts finished before the cancel
  keep their results.
- **Sensor version.** Only a sensor whose software supports scan depth is
  handed such a scan (see above). Older sensors keep running protocols ×
  ports jobs on their own software until they are upgraded. A sensor that
  supports scan depth runs nothing else: a protocols × ports job created for
  it before it was upgraded fails with that reason; run the scan again.

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

A scan described by depth shows, while it runs, a progress bar on its row and a
live line ("112 of 254 hosts · 31 responded · 9 open ports"), with its executor
and depth; the page refreshes itself while any job is unfinished. Its detail
refreshes until the scan ends and shows what the scan does and why (depth,
pace, targets, where it ran and why, every per-target depth adjustment), its
**coverage** — responded, *no answer* (never "down"), ports open/closed/filtered,
reachability guidance when nothing answered, and where and why a scan that ended
early stopped — then its **results by host** and where the findings went.

**API:** `GET /api/v2/inventory-service/discovery/jobs/:id`

**Status Values:**
- `queued` - Job is queued for processing
- `running` - Job is currently running
- `completed` - Job completed successfully
- `failed` - Job failed
- `cancelled` - Job was cancelled

`progress` is the share of the job's targets finished. For a scan described by
depth it is the share of its **addresses** finished, and the job also carries a
`coverage` summary — see
[How a scan by depth runs](#scan-depth-ports-pace-and-where-it-runs-api). The job
list (`GET .../discovery/jobs`) carries each such scan's `plan`, and — while it
has not ended — its `progress` and `coverage` too.

### 3. Review Results

Review what the job found. The findings are already on their way to inventory —
this step is a record of the run, not a decision point.

**UI:** **Discovery → Discovery Jobs** → click the job. The Discover dialog
does not show results: it hands the scan off when it starts. The job's detail
shows what it found — for a scan described by depth, host by host (below) — and
where it went; the assets themselves are in **Inventory** or waiting in
**Discovery → Approvals**.

Each finding records:
- Hostname
- IP Address
- Port
- Protocol
- TLS Version (if applicable)
- Certificate information

**API:** `GET /api/v2/inventory-service/discovery/jobs/:id/results`

Add `?group=host` to get the results **by host**: each host with all its ports
together — identified services with their protocol, and open ports nothing could
name as `tcp` with `identified: false` — and, for a scan described by depth, how
the scan of that address went (`unit`). For a scan described by depth **every
host that responded is listed**, including a host that answered with nothing
open: it comes back with no ports, `nothing_open: true`, and its refused and
filtered counts in `unit`. `total_hosts` therefore equals the coverage's
"responded" once the scan has finished. An address that never answered is not
listed. Pages count hosts (`page_size` up to 100), so a host's ports are never
split across pages. A host that accepted connections on almost every port
appears once, with a sample.

**UI:** for a scan described by depth, the job's detail on **Discovery →
Discovery Jobs** lists these hosts a page at a time; click a host for its ports —
the service on each, or **open, unidentified** (with the service's hint when it
greeted us), and the certificate and cipher detail for TLS. A host that answers
on every port is one line with a few sample ports. A host that **answered, but
had nothing open** is one quieter line saying how its ports answered — for
example "answered, nothing open (78 ports scanned: all refused)". Refused means
the host sent a reset: it is there, nothing is listening. It is never reported
as "down". So a /24 where 25 addresses responded lists 25 hosts — say 10 with
open ports and 15 that answered with nothing open.

### 4. Where the findings went

The job's detail on **Discovery → Discovery Jobs** reports **Open ports found**
— the findings, "15 open ports on 10 hosts" — and what became of them: how many
were auto-approved, are pending approval, or are still being processed (these
count findings too, not assets), with a link to **Discovery → Approvals**. There
is no import step and nothing to click to move findings into inventory; that
already happened server-side.

The two numbers are reported separately on purpose. **Open ports found** is what
the scan saw. The split is what reached your inventory. They can differ:
connections to external third parties are recorded under **Inventory → 3rd
Party** rather than as assets, a finding with no resolvable address cannot be
anchored to one, and processing is asynchronous, so a count may still be
settling when the scan finishes.

Findings that could not be tied to an asset yet are **kept as observations**,
and the job's detail says so — "15 findings on 10 hosts were kept as
observations" — with a link to **Discovery → Observations**, where you confirm,
link or dismiss each one. They are not added to inventory and do not appear in
Approvals. The usual reason is identity: on a network that uses DHCP an address
alone does not identify a device, and a scan by address sees nothing else (no
MAC address, no host key yet), so the platform will not create an asset from
the address alone. The count also includes findings recorded only as evidence
for other reasons (a host observation, a third-party endpoint recorded as a
connection). When nothing was kept as an observation the detail shows no
notice.

#### Reviewing observations

**Discovery → Observations** is a review table. It opens on **Ready to
confirm** and groups the rest by what each observation needs, with a count on
each chip:

| Needs | What was seen | Suggested |
|---|---|---|
| **Ready to confirm** | A device answered at an address on a network that uses DHCP, and no existing asset owns it | **Confirm** |
| **Matches an asset** | Exactly one existing asset already owns an identifier of the observation | **Link to** that asset |
| **Several match** | More than one existing asset owns identifiers of it, or the one that does cannot take a link | none: compare the assets, link it yourself, or dismiss |
| **Needs a network** | The address is not inside any network segment you have set up | **Add network** (Settings → Network Segments) |
| **Needs a sensor** | Another device advertised the name, or no sensor reaches that network | **See options**: add a sensor there, link, or dismiss |
| **Likely noise** | Only a name, no address or service, or nothing seen for 30 days | **Dismiss** |

**All** shows every group, and its **State** control reaches observations that
are linked, dismissed, expired or in conflict. Rows show the network's and the
sensor's names. Opening a row shows all of its evidence beside **What this
needs** — why the platform did not create an asset itself and what will fix
it.

Tick rows to decide many at once: **Confirm** is offered only when every
selected row is Ready to confirm, **Link to existing** only when every selected
row Matches an asset (each goes to the asset that already owns it), **Dismiss**
for any selection, and linking to an asset you pick stays one row at a time. One reason covers the batch, prefilled from what was
seen and editable. Each row reports its own outcome; a row that fails (asset
allowance reached, changed since you looked) stays in the table with its
reason.

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

Cancel a discovery job that has not finished. A running scan stops before its
next target or host once the scanner notices the cancel, so it can keep going
briefly after you click; the findings it had already stored are kept. A job
that has already completed or failed cannot be cancelled and the request is
refused with the reason. Cancelling an already-cancelled job succeeds. A job
handed to one of your own sensors is marked cancelled, but a scan the sensor
has already started is not recalled; its late result is recorded without
changing the job's status.

**UI:** **Cancel** on the job's row, or in its detail, on **Discovery → Discovery
Jobs**. A refused cancel shows the reason.

**API:** `POST /api/v2/inventory-service/discovery/jobs/:id/cancel`

### Rerun Job

Re-queue a job that is `queued` or `failed`. A job that is running, completed
or cancelled cannot be re-run this way (the request is refused with a 409);
start a new scan instead. Only what the job had not finished runs again — for a
scan described by depth, the hosts not yet scanned; otherwise, the targets not
completed — and what finished, with its findings, is kept.

**UI:** **Resume scan** on a failed or queued scan's row on **Discovery →
Discovery Jobs**. The route needs `discovery.create`; the scanner also checks
`discovery.update`, so a role without it is refused (403) and the dialog shows
the reason.

**API:** `POST /api/v2/inventory-service/discovery/jobs/:id/rerun`

## Active Scan: choosing where it runs

An active scan has to run from somewhere that can reach the host. The platform
sensor inside the cluster reaches what the platform can route to; a host that is
only reachable from inside your own network is reachable only from a sensor you
deployed there. The scan dialog — opened by **Scan** in Inventory's bulk bar,
or **Active Scan** on an asset — lets you choose, with its **Run from**
control:

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
asset whose observing sensor is offline is scanned from another of your
sensors that is online and on the same network, if there is one. If there is
not, it is left unscanned and reported in the result — it is never moved to
the platform sensor; scan it again when the sensor is back, or choose another
executor. A
sensor that was online when the scan was created and then went quiet before
collecting it fails the job the same way, once the time the sensor's own
reporting cadence allows has passed. The failure names the sensor and its last
check-in.

**Following a scan.** Inventory keeps a **Scans started here** panel under the
bulk bar: each scan you start appears there with its
executor — *Platform sensor* or the sensor's name — its state (*Queued*,
*Awaiting <sensor>* while the sensor has not yet collected the job, *Running on
<sensor>*, *Completed*, or *Failed: sensor offline* with the sensor's last
check-in) and the timeline queued → dispatched → picked up → completed,
updating while the scan runs, and every asset that was not scanned is listed
with its reason. It is cleared when you leave the page. Automatic
scans show the same executor and state in the run list on **Settings →
Discovery → Active Scanning**. Every scan also lands on **Discovery →
Discovery Jobs**, filterable by Kind (Discovery / Automatic scan), so it stays
visible after you leave the page that started it.

Results from a sensor take the same path as everything else that sensor sends
(see [How a discovery reaches your inventory](#how-a-discovery-reaches-your-inventory))
and land on the asset's Cryptography tab as **active** observations, exactly as
a platform-run scan's do.

**The result belongs to the asset you scanned.** When you press **Scan** on an
asset, the platform probes the address it has for that asset, and what answers
there is recorded on that asset — even on a DHCP network, where a scan nobody
asked for is kept as an observation instead (see
[Identity evidence](./identity-evidence.md)). There is one exception: if the
scan meets a device that contradicts what the asset is known to be — a
different MAC address, SSH host key or serial number than the asset has, or an
identifier another asset already holds — the result is not attached and waits
under **Discovery → Observations** like any other sighting, because the address
now answers as something else. Automatic scans and identity probes are not
attributed this way.

Automatic scans choose the same way, governed by the **Prefer the observing
sensor** switch on **Settings → Discovery → Active Scanning** — see
[Automatic Active Scanning](./active-scanning.md).

## Re-validation of Existing Assets

Discovery jobs can be used to re-validate existing assets in inventory:

1. **Stale Asset Re-validation**: Automatically re-validate assets that haven't been seen recently
2. **Manual Re-validation**: Create discovery jobs targeting specific assets to verify they're still alive
3. **Result Processing**: If assets are found, `last_seen_at` is updated and stale status is cleared

**API:** `POST /api/v2/inventory-service/infrastructure-assets/scan` — the
Active Scan endpoint, which takes asset ids or a query selection and where to
run from. The older `POST …/revalidate` and `…/stale/rescan` are **deprecated**:
they still work, and their responses carry a `Deprecation` header and a `Link`
to the scan endpoint.

**Use Cases:**
- Verify stale assets are still on the network
- Periodic re-validation of critical assets
- Validate assets before removing from inventory

See [Asset Lifecycle Management](./asset-lifecycle-management.md) for more details.

## Best Practices

1. **Start Small**: Begin with small target ranges to test discovery
2. **Review Results**: Check the job's split on **Discovery → Discovery Jobs** — what was found versus what reached inventory
3. **Network segments**: Define your segments before discovering, so assets are placed — and auto-approved — correctly from the first run
4. **Approval Workflow**: Use approval workflow for production environments
5. **Scheduled Discovery**: Set up recurring discovery jobs for continuous monitoring
6. **Re-validation**: Periodically re-validate existing assets to keep inventory current

## Limitations

- Maximum 1000 targets per job
- One CIDR or `a-b` range may name at most **4,096 addresses** (an IPv4 `/20`),
  and one job's targets at most **16,384** together. A larger network is refused
  with the count and the limit rather than scanned in part — split it into
  smaller blocks, or scan it as several jobs
- A scan planned by depth may send at most the installation's probe budget
  (default 25,000,000 addresses × ports) — see
  [Scan depth, ports, pace and where it runs](#scan-depth-ports-pace-and-where-it-runs-api)
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
- Retry or cancel the job from **Discovery → Discovery Jobs**. A scan whose
  scanner stopped heartbeating is failed as *stopped responding*; **Resume scan**
  on its row runs the hosts it had not finished
- The run's own detail, including any processing errors, is on **Discovery → Job
  Logs**

### No Results Returned

- Verify targets are reachable — an address that gives *no answer* may be
  filtered or out of reach of where the scan ran from; run the scan from a
  sensor on that network
- Check the scan depth, or the ports a *Custom* scan names
- Verify sensors are active and healthy
- Check network connectivity

### Findings Do Not Appear in Inventory

- Check **Discovery → Approvals** first: unless the address is on a network
  segment with auto-approve enabled, the asset is waiting there by design
- Connections to external third parties are recorded under **Inventory → 3rd
  Party**, not as assets
- Findings with no resolvable IP address cannot be turned into an asset
- Processing is asynchronous — the job's detail on **Discovery → Discovery Jobs**
  reports how many are still being processed

## Related Documentation

- [Asset Approval](./asset-approval.md) — the approval queue and its rules
- [Asset Lifecycle Management](./asset-lifecycle-management.md) — stale assets and what happens to them
- [Host Inventory](./host-inventory.md) — describing a host rather than scanning it
- [Sensor & Agent Registration](./SENSOR_REGISTRATION.md) — deploying what does the discovering
- [PCAP Ingestion](./pcap-ingestion.md) — a capture file as a discovery source
- [Operational Context](./operational-context.md) — locations and network segments
