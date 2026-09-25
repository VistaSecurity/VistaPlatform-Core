# Automatic Active Scanning

The platform builds your inventory without being asked. When a new internal host
appears — a sensor saw it, an agent interrogated a device that reported it, a
scan found it, you imported it — the platform actively scans that address for
the cryptography it presents. It then scans it again on a schedule, so the
inventory describes what is running today rather than what was running the day
it was discovered.

You control all of it from **Settings → Discovery → Active Scanning**.

## What gets scanned

Only your own internal hosts. An address is in scope when it is:

- inside a private range (RFC 1918 — `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16` — or an IPv6 unique-local address), **or**
- inside a network segment you registered under **Settings → Infrastructure →
  Network Segments** whose type is **Private**, **VPN** or **Cloud** — your own
  statement that the range is yours.

A segment typed **Public** is not scanned automatically, even though you
registered it. Registering a range says "this is mine"; typing it public says
what is on it, and an unattended daily scan of a public range is the one thing
this feature must never do. You can still scan it whenever you like from
**Discovery** — that is a scan with a person behind it.

Everything else is refused, and refused before anything else is considered:

| Never scanned | Why |
|---|---|
| Public addresses | An unattended daily scan of an address you have not declared as an internal range of yours is a third party being port-scanned on a schedule. |
| Segments typed **Public** | As above — the type is your own description of what is on the range. |
| Organizations whose account is cancelled or suspended | Scanning is something we do *to* your network. When the relationship ends it stops, even if your sensors keep reporting. |
| Assets marked third-party | The same reason, decided by the asset's own ownership field. |
| Loopback, link-local, multicast, the unspecified address | Not hosts on your network. |
| Carrier-grade NAT space (`100.64.0.0/10`) | Shared address space reaches other operators' customers. Register it as a network segment if it really is yours. |
| The platform's own addresses | The platform does not scan itself. |
| Archived or denied assets | You decided they are not part of the inventory; continuing to probe them would be the platform disagreeing with you on a schedule. |

Assets waiting in **Approvals** *are* scanned. A host you have not approved yet
is still a host on your network, and the inventory you make the approval
decision from should be the fuller one. Its findings are held until you approve
the asset, exactly as they are for any other discovery.

This page governs the scheduled sweep. A sensor also makes one narrower kind of
active connection on its own: when it sees a TLS connection whose certificate it
could not read (TLS 1.3 encrypts it), it can connect to that one server to read
it. That *enrichment* goes only to your own endpoints by default — private
addresses, registered network segments of any type, and connections you elevated —
and reaches third parties only if you turn on **Actively enrich third-party TLS
connections**. See
[Certificates of third-party TLS connections](./third-party-and-external-connections.md#certificates-of-third-party-tls-connections).

## What each scan does

An automatic scan is the same active probe the **Discover** wizard runs: a TCP
connect to each configured port, then a TLS or SSH handshake on the ports that
answer, recording the certificate, protocol version, cipher suite and key
exchange it is offered. Results join the normal discovery pipeline, so they
appear in Inventory and Findings like any other discovery.

Only **TLS** and **SSH** can be scanned automatically. Industrial (OT/ICS)
probes — Modbus, OPC UA, EtherNet/IP, BACnet — are never run unattended, whatever
your entitlements: those are opt-in, per-job decisions you make in the Discover
wizard.

## The controls

| Control | Default | What it does |
|---|---|---|
| **Automatic scanning** | On | The master switch. Off means nothing is scanned unless you start a scan yourself from Discovery. |
| **Scan on first observation** | On | Scan a new internal host as soon as it appears, instead of waiting for the next scheduled pass. |
| **Rescan every** | 24 hours | How long a host's last automatic scan may age before it is scanned again. 1–720 hours. |
| **Protocols** | TLS, SSH | What each scan probes for. |
| **Ports** | The well-known TLS and SSH ports | The ports each scan tries. At most 64. "Reset ports to the defaults" restores the built-in list. |
| **Prefer the observing sensor** | On | Run each automatic scan from the sensor of yours that most recently observed the host, or one on the same network segment, instead of the platform sensor — so hosts only reachable from inside your network are scanned from there. Off runs every automatic scan from the platform sensor. |

**Prefer the observing sensor** decides *where* each scan runs, not whether it
runs. With it on, a host one of your sensors has observed is scanned from that
sensor; a host only the platform has seen is scanned from the platform sensor.
If the observing sensor is offline when a pass runs, that host is skipped for
the pass and stays due — it is not scanned from somewhere that cannot see it.
Manual scans choose per run with **Run from** on **Discovery → Active Scan** and
are not governed by this switch. See
[Active Scan: choosing where it runs](./discovery.md#active-scan-choosing-where-it-runs).

The default port list is deliberately **narrower** than the one the Discover
wizard offers. The wizard's list also carries the file-sharing ports (139, 445)
and the industrial-control ports (502 Modbus, 4840 OPC UA, 44818 EtherNet/IP,
47808 BACnet). Those are reasonable for a scan you chose, aimed somewhere
specific, once — they are not reasonable for a connect attempt repeated against
every host in scope on every interval. If you want them scanned automatically,
add them to the list yourself; that is a decision with a person behind it.

**Automatic scanning** and **Scan on first observation** are independent. Turning
the second off keeps the schedule and drops the immediate scan — useful if you
would rather a burst of newly discovered hosts were picked up in the next pass
than the moment they appear.

Changing the interval takes effect on the next pass. Nothing is rescanned
retroactively and nothing is cancelled; a host simply becomes due sooner or
later than it would have.

### Who can change it

Viewing the page needs the **`settings.read`** permission, which every role that
can see the inventory has. Changing the policy needs **`settings.update`** —
Tenant Admin, and any custom role you have granted it. Without it the page is
read-only and says so.

## Where it runs

Each automatic scan is run either by the platform sensor inside the cluster or
by one of your own sensors — see **Prefer the observing sensor** above. The
**Recent automatic scans** table on the page shows, beside each scan, the
executor and its state: *Queued*, *Awaiting <sensor>* (handed to the sensor,
not yet collected), *Running on <sensor>*, *Completed*, or *Failed: sensor
offline* with the sensor's last check-in. Scans you start yourself show the
same on **Discovery → Active Scan**.

## What it has been doing

The lower half of the page is the record, and it is the only place in the
product where scans the platform ran on its own are listed:

- **Last pass** — when the platform last looked for hosts that were due, and how
  many scans it started.
- **Next pass** — when it will look again. A host is only scanned once its own
  interval has elapsed, so a pass often starts nothing.
- **Assets in scope** — how many assets automatic scanning covers today.
- **Recent automatic scans** — the last runs, each tagged **Automatic**, with how
  many hosts it covered and its status.

"No pass has run yet" and "the last pass found nothing due" are shown
differently, on purpose. They are different facts.

### Not scanned

Beneath the record is a **Not scanned** panel: every host the last pass looked at
and refused, grouped by why, with a count. It exists because "Automatic
scanning: on" over an inventory the platform will never scan is the worst
outcome this page could produce — and it is the likely one for an organization
whose estate lives in an address range the platform does not treat as internal.

| Row | Meaning | What to do |
|---|---|---|
| **Public addresses** | Hosts whose address is neither private nor inside a registered segment. | If the range really is yours, register it as a network segment typed Private, VPN or Cloud — the link on the row takes you there. Otherwise nothing: this is the feature refusing to scan a third party. |
| **Carrier-grade NAT (100.64.0.0/10)** | Shared address space (RFC 6598). **Tailscale, ZeroTier and mobile carriers use this range**, so an estate built on an overlay network lands here in full. | Register the range as a network segment. That is your explicit statement that those addresses are yours; without it the platform cannot tell your overlay from another operator's subscribers. |
| **Excluded by your operator** | The platform's own addresses. | Nothing — the platform does not scan itself. |
| **Link-local**, **loopback**, **multicast**, **unspecified** | Not hosts on your network. | Nothing. |
| **Unparseable** / **zoned** | An address the inventory holds that is not a routable address (a zone identifier such as `fe80::1%eth0`, or a value that did not parse). | Look at the asset — it was recorded from somewhere other than a measured address. |

"Every eligible host was scanned" is the empty state. It means the last pass
refused nothing — not that no pass has run; that is a separate line above.

## What it will not do

- **It will not scan from somewhere that cannot see the host.** With **Prefer
  the observing sensor** on, a host one of your sensors observed is scanned from
  that sensor, and if that sensor is offline the host waits for the next pass.
  With it off, automatic scans run from the platform and reach what the platform
  can reach; a host only reachable from inside your network is then not scanned
  automatically — scan it from **Discovery → Active Scan** with **Run from** set
  to your sensor.
- **It will not scan an asset with no address.** A cloud resource with nothing to
  connect to has nothing to probe.
- **It will not scan the same address twice at once.** An address that already
  has an automatic scan queued or running is skipped until that one finishes.
- **It will not scan an unbounded number of hosts at once.** Each pass starts at
  most a bounded number of scans per organization; anything left over is first in
  line on the next pass.

## Scanning outside your networks

Everything above is about scans the platform runs **on its own**, and those
never touch an address you have not declared as yours. A scan **you** start is
different: you may scan any public IP address, CIDR block, range, hostname or URL
you name, including ones outside every network segment you registered — a
partner's endpoint you are allowed to test, a SaaS login page, your own public
estate before you have registered it. The platform does not judge why; it asks
you to confirm.

**Where:**

- **Discovery → Active Scan → Scan addresses or hostnames**, or **Discovery →
  Command Center → Discover assets** — the same wizard, for targets you type.
  Needs the **`discovery.create`** permission, as any scan does.
- **Discovery → Active Scan → Scan** on an asset already in your inventory whose
  address is outside your registered networks. Pressing Scan on an asset you
  chose is the same explicit choice, so the page asks rather than refuses.
  Confirming needs **`discovery.create`** as well as the **`assets.update`**
  that scanning an asset always needs.

**What you can enter** (in the wizard): one target per line or
comma-separated — `93.184.216.34`, `93.184.216.0/28`,
`93.184.216.10-93.184.216.20`, `www.example.com`, `www.example.com:8443` or
`https://www.example.com:8443/login`. A URL is scanned at its host; a port
written in it is added to the ports the scan tries.

**What happens:**

1. You start the scan. If every target is inside your private ranges or a
   network segment you registered, it runs as it always has.
2. If any target is outside them, nothing runs yet and you are asked: *"N
   targets are outside your registered networks. Only scan systems you are
   authorized to test."* The list shows each one — for a hostname, the
   addresses it resolved to; for an asset, its name and address.
3. **Scan anyway** starts the scan. **Cancel** changes nothing.

Each scan you confirm is recorded in your organization's audit log: who
confirmed it, when, the targets and the addresses they named.

Your confirmation covers exactly what you were shown. A hostname is looked up
**once**, when you start the scan; every address it resolves to is checked, and
the scan connects to exactly those addresses (the name is still sent for TLS,
so the right certificate comes back). If the name's DNS answer changes a moment
later, the scan does not follow it. If a range you had registered stops being
yours before the scan runs, that range is not scanned on the strength of your
confirmation for something else.

Targets outside your registered networks always run from the **platform
sensor**. A scan that would hand them to one of your own sensors is refused
with that reason: run it from the platform.

### What is never scanned, confirmed or not

| Never scanned | Why |
|---|---|
| Loopback, link-local, multicast, the unspecified and broadcast addresses | Not hosts. Link-local includes the cloud instance-metadata service (169.254.169.254). |
| Carrier-grade NAT (`100.64.0.0/10`) | Shared between operators. Register it as a network segment if it really is yours. |
| Documentation ranges | Not routable. |
| IPv6 forms that carry an IPv4 address — NAT64, IPv4-compatible, IPv4-mapped and translated addresses; 6to4 and Teredo addresses whose embedded IPv4 is itself never scanned | They lead to that IPv4 address. Name the IPv4 address instead. |
| The platform's own addresses and ranges | The platform does not scan itself. |
| Ranges you excluded, and segments marked sensitive | Your own decision, which a confirmation does not override. |
| A hostname that resolves to any of the above | Every address a name resolves to is checked; one refused address refuses the name. The refusal does not say which address it was. |
| Single-label names (`web01`), and names under `.svc`, `.cluster.local`, `.internal` or `.localhost` | From the platform these resolve in the platform's own DNS, not yours. Use the full name or the address. |
| A hostname that does not resolve | There is no address to check. |

If a target is refused, you see each one and why. Remove them to scan the rest;
confirming does not help.

The same rule holds for what a scanned server tells the platform to fetch. When
the platform checks a certificate's revocation status, it contacts the OCSP
responder named in that certificate only at a **public** address, and never
follows a redirect — a server being scanned cannot point the platform at its own
network or at cloud metadata.

### How big a scan can be

One target outside your registered networks may name at most **4,096 addresses**
— an IPv4 `/20` or an IPv6 `/116` — and one scan at most **16,384** such
addresses across all its targets. Split a larger block across scans, or register
it as a network segment if it is yours: private ranges and registered segments
are not bounded by this. Your operator may set lower limits.

A network segment wider than `/8` (IPv4) or `/16` (IPv6) never counts as yours,
whatever its type, unless it lies wholly inside private space: nobody owns that
much of the internet, and a segment like `0.0.0.0/0` would otherwise make every
address "registered". IPv6 blocks that carry IPv4 addresses (6to4 `2002::/16`,
Teredo, NAT64) count by the IPv4 space they carry, so `2002::/16` — every IPv4
address in 6to4 form — is as wide as `0.0.0.0/0`. New segments that wide cannot
be saved; addresses under one saved earlier are treated as outside your
registered networks.

Your operator can also lower the limits after a scan was started; a scan still
waiting to run is then checked against the new limits and stops if it no longer
fits.

### If your operator has turned it off

An installation's operator can turn scanning outside registered networks off
entirely (some hosted services must). You are then told so instead of being
asked, and those targets are refused as they were before this existed; a scan
already queued stops too. Register the range as a network segment if it is
yours, or ask your operator.

### Using the API

`POST /api/v1/inventory-service/discovery/jobs` accepts the same targets, and
`POST /api/v1/inventory-service/infrastructure-assets/scan` the same assets. A
request that reaches outside your registered networks must carry
`"external_targets_confirmed": true`; without it the answer is **422**
`external_targets_unconfirmed` listing the targets (for the asset scan, with
each asset's id and name), and nothing is scanned or changed. A refused target is
**400** `targets_refused` with each reason, and the operator's switch is **403**
`external_targets_disabled`.

For operators, in the chart:

```yaml
discovery:
  explicitExternalTargets:
    enabled: true              # false turns the capability off
    maxAddressesPerTarget: 4096  # 1-4096, lower only
    maxAddressesPerJob: 16384    # 1-16384, lower only
```

These render `DISCOVERY_EXPLICIT_EXTERNAL_TARGETS_ENABLED`,
`DISCOVERY_EXTERNAL_TARGET_MAX_ADDRESSES` and
`DISCOVERY_EXTERNAL_JOB_MAX_ADDRESSES` on cluster-sensor-service. They are not
part of `extraEnv`, so replacing that list in your own values cannot drop them,
and an `extraEnv` entry naming any `DISCOVERY_EXTERNAL_*` or
`DISCOVERY_EXPLICIT_EXTERNAL_*` variable fails the install with a message
pointing here — it would otherwise silently override these values.
The switch fails **closed**: if the variable is missing or not a recognisable
boolean, scanning outside registered networks is off.

## Turning it off

Set **Automatic scanning** to off and save. Nothing is scanned unless you start
a scan yourself from **Discovery → Command Center → Discover assets** or
**Discovery → Active Scan**. Scans already running are not cancelled — cancel
those from the job itself.

## Related

- [Discovery](./discovery.md) — the pipeline an automatic scan's findings join
- [Asset Approval](./asset-approval.md) — what happens to what it finds
- [Operational Context](./operational-context.md) — network segments, which decide what counts as yours
- [Assets and Crypto Configurations](./assets-and-crypto-configurations.md) — what a scan records
