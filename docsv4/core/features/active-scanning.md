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
