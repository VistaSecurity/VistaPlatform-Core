# Operational Context

A discovery tells you an address answered. It does not tell you *whose* address,
*where* it is, or whether anyone should be worried about it. Operational context
is the small amount of information you supply once — where your networks are and
what they are for — that turns every subsequent discovery from a fact into
something actionable.

Two registries carry it: **Sites** (and the locations inside them), under
**Settings → Organization → Sites**, and your **networks** — IPAM prefixes — under
**Inventory → Networks**.

## Sites and locations

A hierarchical registry of the places your estate physically or logically sits:
regions, site groups, sites, and the locations inside each site (a hall, a cage, a
row), including cloud accounts and regions.

**Settings → Organization → Sites** shows the tree with how many assets each site
and location holds. Creating, editing and deleting need the `dcim.manage`
permission; everyone with `dcim.read` can see the tree. See
[Sites and locations](../inventory/sites.md) for the full guide.

A prefix can be scoped to a site, which assets in it then take.

## Networks

Your networks are **prefixes** — a CIDR such as `10.4.0.0/16` or
`2001:db8:10::/64` — in **Inventory → Networks**, the same IPAM tree that holds
your VLANs, VRFs and addresses (see [Networks](../inventory/networks.md)).
**Add prefix** creates one, and the spreadsheet import (**Discovery → Command
Center → Import**, target **Networks (prefixes)**) brings a batch in. Devices you
interrogate, sensors and cloud integrations add the prefixes they observe, as
*pending* and *learned* until you approve or claim them.

Open a prefix to see and edit what discovery reads from it, under **Discovery**:

| Setting | What it decides |
|---|---|
| **Network type** | Private, Public, VPN or Cloud. Left unset, the address decides — private space reads private, everything else public. Automatic scans honour Private, VPN and Cloud. |
| **Environment** | Production, staging, development or test — what assets placed in the prefix take. |
| **Addresses handed out by DHCP** | Yes, No or Unknown. On a DHCP network an address does not identify a device; **No** lets an address decide identity there. A device that measured it fills it in when nobody has said. |
| **Auto-approve** | Sensor discoveries in the prefix join active inventory without review. |
| **Never actively scan** / **Sensitive** | Excludes the prefix from every active scan; sensitive also asks for review before anything acts on it. |
| **Gateway** | The device an interrogation reported routing the prefix, linked — or *gateway not recorded*. Never guessed from the addresses. |
| **Sensor coverage** | The sensor of yours that can reach the prefix, or *No sensor on this network*. |
| **FHRP** | VRRP, HSRP or other redundancy groups whose virtual address is in the prefix. |

A prefix you add must be a range you could plausibly own: IPv4 **/8 or
narrower**, IPv6 **/16 or narrower** (ranges wholly inside private space, such
as `fd00::/8`, are exempt). Anything wider — `0.0.0.0/0` above all — never counts
as yours (a NetBox import or a cloud integration reports and skips such a range),
because a declared prefix tells your sensors the range is yours to probe (see
[Certificates of third-party TLS connections](./third-party-and-external-connections.md#certificates-of-third-party-tls-connections)).

Anyone who can read IPAM can see the prefixes; adding, editing, approving and
claiming them needs **Manage IPAM** (`ipam.manage`).

### What prefixes decide

Defining your prefixes is not bookkeeping. Four things fall out of it:

1. **Environment and location on every asset.** An asset inherits both from the
   prefix its address falls in. That is where `environment:production` in a
   query gets its answer, and how the inventory can be sliced by site.
2. **Internal versus third party.** An address inside one of your prefixes is
   *yours*. An address outside them is somebody else's — which is what the
   3rd Party lens is a list of, and what the ownership filters on the
   Certificates lens sort by. With no prefixes defined, that distinction is a
   guess. See
   [Third-party and external connections](./third-party-and-external-connections.md).
3. **What gets approved without you.** A prefix with **auto-approve** on is
   the way a newly *discovered* asset joins active inventory without a person
   accepting it. The one other automatic path is a host your own device agent
   is installed on, which its first host inventory admits. Everything else waits
   in **Discovery → Approvals** — including assets you type in by hand. See
   [Asset approval](./asset-approval.md).
4. **What discovery scans.** Prefixes are what a scan is scoped against.

Define your prefixes before your first discovery. Running one first works, but
you will spend the afternoon approving things and re-tagging them afterwards.

## Service identification

Separately from the two registries, the platform tries to name the service behind
each endpoint it finds — and it says how sure it is, which is the part that
matters.

An endpoint's service name on the **Services & Endpoints** tab is labelled with
how it was determined. A name read directly out of a service banner reads as
**Confirmed**; a name deduced from the port number alone reads as a **best
guess**. Port 8443 is *probably* HTTPS and might be anything; the label is what
stops that guess being quoted back at you later as a finding.

## History

Earlier versions kept your networks in a separate registry under **Settings →
Infrastructure**, with its own types for IP ranges, domains and cloud VPCs. In
5.0 that registry is gone and a network is a prefix: an IP range is an IPAM
**IP range** (it does not scope identity), a domain no longer scopes hostnames
(a name scopes to your whole organization), and a cloud network's address
ranges are prefixes that name the network they belong to. A bookmark to the old settings
page lands on **Inventory → Networks**.

## Related

- [Asset approval](./asset-approval.md) — the two auto-approval rules, and the queue
- [Third-party and external connections](./third-party-and-external-connections.md) — what internal-versus-external buys you
- [Discovery](./discovery.md) — what prefixes scope
- [Inventory and lenses](./inventory-and-lenses.md) — the Prefix, Site and Environment filters
- [Spreadsheet import](./spreadsheet-import.md) — importing prefixes in bulk
