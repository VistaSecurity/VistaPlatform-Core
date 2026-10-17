# Networks, VLANs and IP addresses (IPAM)

Vista Platform keeps an IP address management (IPAM) record of your networks
alongside the asset inventory: the **prefixes** you run, the **IP addresses** in
them, the **VLANs** that carry them and the **VRFs** that separate one routing
table from another. The model follows NetBox, so a NetBox user will recognise
every object.

## Where to find it

| Page | What it is for |
|---|---|
| **Inventory → Networks** | Your prefixes as a tree, one VRF at a time, with how full each one is; the panel for one prefix; the **Find** box |
| **Inventory → VLANs** | VLAN groups and the VLANs in them, with the prefixes each carries |
| **Settings → Infrastructure → IPAM** | The catalogues the tree builds on: VRFs, aggregates, RIRs, prefix roles and AS numbers |

Reading needs the **IPAM read** permission; adding, editing and deleting need
**IPAM manage**. Tenant Administrators and Security Administrators hold both;
Viewers can read.

## The prefix tree

Pick a VRF at the top of **Networks** — or **Global (no VRF)** for addresses that
are not in any VRF. Each row is a prefix, nested under the prefix that contains
it: `10.10.0.0/24` sits under `10.10.0.0/16`, and if you later add
`10.10.0.0/22` it appears between them by itself. Nothing is stored about who is
whose parent; the nesting is worked out from the addresses every time, so it
cannot go stale.

Each row shows:

- **Status** — *Container* (a block that holds other prefixes), *Active*,
  *Reserved* or *Deprecated*.
- **Role** and **VLAN**, when set.
- **Utilisation** — how full the prefix is (see below).
- **Counts** — how many prefixes and addresses are inside it.

A prefix discovery found but nobody has approved yet carries a **Pending
approval** chip.

### What utilisation means

- For a **container**, utilisation is the share of its space covered by the
  prefixes inside it: a /22 holding one /24 is 25 % used.
- For any other prefix, it is the share of its usable addresses that have an IP
  address record, plus any IP range marked as fully used. In an IPv4 prefix the
  network and broadcast addresses are not usable — except in a /31 or /32, or a
  prefix marked as a **pool**, where every address is.
- A prefix marked **Treat as fully used** shows 100 %.

An empty prefix shows **0 %** of a known size, never a blank: the size is
arithmetic, not something anyone has to measure.

## One prefix

Click a prefix to open its panel:

- **Utilisation** with the exact counts (`1 of 254`), the **parent** prefix and
  what the prefix **contains**.
- **Child prefixes** — the ones directly inside it.
- **Free space** — the largest free blocks, or every free block of a size you
  pick (say, every free /26), each with a **+** to add it as a child; and how many
  addresses are still free, with the first few. In IPv6 the all-zeros address of
  a prefix is the subnet-router anycast address: it is free, but every router on
  the link answers it, so the panel says so.
- **IP ranges** inside the prefix.
- **Discovery** — what discovery reads from the prefix: whether it is
  declared by you or learned from a device, its network type,
  environment, DHCP posture (DHCP, Static or Unknown), auto-approval, the
  **gateway** an interrogated router reported, the **sensor** that reaches it,
  and any **FHRP** group (VRRP, HSRP, …) whose virtual address is in it. A
  learned prefix offers **Claim as ours**. See
  [Operational context](../features/operational-context.md#networks).
- **IP addresses** — each with its status, DNS name and, where Vista knows it,
  the asset that holds it (as its primary or out-of-band address). **Add
  address** suggests the first free one.
- **Changes** — every edit to the prefix: what changed, who changed it and when.
- **Journal** — dated notes anyone with access can add.

## Find

Type an address into **Find** — `10.10.0.5` — and Vista tells you, for every VRF
that has it:

- the most specific prefix containing it,
- the IP address record, if there is one, with its DNS name, and
- the asset holding it.

Addresses in different VRFs are different addresses: `10.10.0.5` in VRF *blue*
and `10.10.0.5` in the global table are answered separately, and a prefix in one
never answers for an address in another.

## Rules Vista enforces

- **A prefix is stored as its network.** Typing `10.10.0.7/24` stores
  `10.10.0.0/24`.
- **One prefix once per VRF.** The same prefix in two VRFs is two networks; twice
  in one VRF is refused.
- **Addresses are unique within a VRF** that enforces it (the default, and always
  for the global table). Addresses with an anycast, VIP, VRRP, HSRP, GLBP or CARP
  role may be shared with other such addresses, because that is what those roles
  are for. A VRF can be set not to enforce uniqueness.
- **A VLAN ID is unique within its VLAN group**, and must sit inside the group's
  VLAN ID ranges (1–4094 by default).
- **IP ranges** must start and end in the same address family, start before they
  end, and not overlap another range in the same VRF.
- **Something still in use cannot be deleted.** A VRF that prefixes or addresses
  are in, or a VLAN group with VLANs, is refused with the reason.
- **Built-in catalogue rows** — the regional internet registries and private
  address authorities, and the standard prefix roles — are listed as *Built in*
  and cannot be edited or deleted. Add your own beside them.

## Discovered networks and addresses

Discovery and cloud enumeration record the prefixes and addresses they see. A cloud
account's networks are prefixes here — an AWS VPC's or Azure virtual network's
address ranges and the ranges inside them, a GCP network's regional ranges — each
naming the cloud network it belongs to, and the network a cloud instance is in is
the prefix its address falls in. A new
one arrives **pending approval**; approving it is setting its status to approved.
When discovery sees an existing address again it refreshes what it measured — the
MAC address, how it was seen, when — and fills in a DNS name only if none is
recorded. It never overwrites a description, role, status or DNS name a person
set.

## Querying the inventory by network

The inventory query box understands an asset's addresses and networks:

| Write | To find assets |
|---|---|
| `ip.address:10.10.0.0/24` | with an address in 10.10.0.0/24 |
| `ip.dns_name="pbx.corp"` | with that DNS name on an address |
| `prefix.prefix:10.10.0.0/16` | whose address's most specific prefix is in 10.10.0.0/16 |
| `prefix.status:deprecated` | with an address in a deprecated prefix |
| `vlan.vid=10` | with an address in a prefix carried on VLAN 10 |
| `vrf.name:blue` | with an address in VRF *blue* |

"The asset's addresses" are, today, its primary IPv4, primary IPv6 and
out-of-band management addresses. The prefix is always the most specific one in
the address's own VRF.

