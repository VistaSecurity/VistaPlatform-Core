# Interfaces

An **interface** is a network attachment point of an asset: a switch's `GigabitEthernet1/0/24`, a server's `eth0`, a firewall's `port1`, a link aggregation group (`Port-channel1`), a VLAN interface, a loopback, a virtual machine's network adapter. Physical and virtual interfaces live in one list, on whatever asset owns them.

Interfaces are where an asset meets the network. Each IP address is an address on one of an asset's interfaces (see [Networks, VLANs and IP addresses](./networks.md)); cables connect them to other ports (see [Cabling](./cabling.md)). You can record interfaces, see them, and search the inventory by them.

## Where to find them

**Inventory → open any asset → Interfaces tab.**

The table shows each interface's name, type, whether it is enabled, its MAC address, speed, MTU, 802.1Q mode and VLANs, the state the device last reported (up, down, testing) and its description. A LAG member says which LAG it belongs to.

You need the **DCIM read** permission to see the tab and **DCIM manage** to add, edit or delete interfaces. Both are part of the Tenant Administrator and Security Administrator roles; Viewers can read.

## An empty tab

"No interfaces reported yet" means exactly that: nothing has told the platform about this asset's interfaces, and nobody has declared any. It does not mean the asset has none. Discovery fills this tab with the MAC and IP addresses it identifies the asset by: each address is an IP address on one of the asset's interfaces. When the source did not say which interface carried a value — a sensor watching traffic never knows — it is listed under an interface named `observed-1`, `observed-2`, … of type *Other*, and that interface is renamed when the device later reports the real name for the same MAC. The device agent's host inventory fills in the rest for the host it runs on (or collects from): one interface per real network interface the operating system reports, with its MAC, addresses (with their prefix length), MTU, link speed (Windows) and state; a VLAN sub-interface such as `bond0.100` under its parent with its VLAN, and a bond's members under the bond. Virtual interfaces — loopback, container bridges and veths, tunnels — are not listed. The address the agent reports for itself becomes the asset's primary IP. A sensor does the same for the host it runs on — its interfaces by name, with MAC and addresses — and names the interface it captures on in the asset's discovery details. A device a sensor only watched shows its MAC and address on one `observed-1` interface; each address records whether it was last seen over DHCP, ARP or another announcement. Generic SNMP devices (any vendor's switch, router or appliance) fill the tab the same way: every port and virtual interface with its type, MAC, MTU, speed and state, the addresses on it with their prefix length, a LAG's members, a sub-interface's parent and, where the device answers the bridge VLAN tables, each port's native and trunked VLANs. A UniFi controller's interrogation fills in the ports, LAGs and VLANs of every switch it manages, the radios of every access point and the gateway's interfaces with its addresses (see the Device Interrogation guide). A cloud discovery lists each instance's network interfaces — AWS ENIs (named `eni-…`), Azure network interfaces, GCE `nic0`, … — as *Virtual* interfaces with their MAC (where the provider states one) and private addresses at their range's prefix length. Interfaces you state also land here: a NetBox import's device interfaces with their addresses, a spreadsheet row's interface, and the MAC and interface given when a device is added by hand; these show as declared or imported. Cisco, Palo Alto, Fortinet and F5 interrogation fills the tab the same way: the device's ports, their addresses, the VLANs defined on it and the ARP table it can see.

An asset is recognised by a MAC on any of its interfaces, including one you add by hand, and its primary IPv4 and IPv6 addresses are chosen from its interface addresses (a management interface's first, never a link-local one) unless you have set them.

## The interface page

Click an interface's name in its drawer (Asset → Interfaces) to **open the interface's own page**
(`/inventory/interfaces/<id>`), which you can bookmark and share. It shows the asset it belongs to, its type,
speed, duplex, MTU, MAC and mode, its untagged and tagged VLANs and its IP addresses (each linking
onward; VLAN names and addresses need the IPAM read permission), the cable on it with the far end, and the
trace, followed by custom fields, tags, contacts, images, changes and journal. **Edit on the asset** takes you
back to the Interfaces tab, where interfaces are edited. An interface that nothing has reported on shows
"State not reported" rather than a status.

## Adding and editing an interface

Click **Add interface** (or the edit button on a row). The drawer asks for:

- **Name** — use the device's own long form, e.g. `GigabitEthernet1/0/24` rather than `Gi1/0/24`. Names are unique on an asset and case-sensitive.
- **Type** — the interface type list (1000BASE-T, 10GBASE-X SFP+, LAG, Virtual, Bridge, 802.11ax and the rest), the same list NetBox uses.
- **Enabled**, **Management only**, **MAC address**, **MTU**, **Speed**, **Duplex**, **Label**, **Description**.
- **LAG** — the link aggregation group this interface is a member of. Only interfaces of type *LAG* on the same asset are offered; a LAG cannot itself be a member of another LAG, and a virtual interface cannot be a member at all.
- **Parent** and **Bridge** — another interface of the same asset. Choices that would make a loop are not offered.
- **802.1Q mode** — *Access* (an untagged VLAN), *Tagged* (an untagged VLAN plus at least one tagged VLAN), *Tagged (All)* (every VLAN; no list) or *Q-in-Q*. The VLAN fields switch on and off with the mode. VLANs are picked from the ones defined under IPAM (this needs the IPAM read permission; without it, a VLAN is entered by its id).

Each interface's own change record — who changed what, and when — is at the bottom of its drawer.

Deleting an interface asks first. Its LAG members and child interfaces are detached, not deleted.

## What the device says versus what you say

Some fields are **measured** — what a device reports about itself — and some are **declared** by a person. They are kept apart on purpose:

- **Enabled** is declared. The device's own administrative state is recorded separately, and a later observation never switches *Enabled* back on behind your back.
- **State** (up / down / testing) is measured, from the device. It is shown as reported and never edited.
- **Description** is declared. A description a device reports seeds a new interface once and is never written over yours.

When discovery reports an interface under a short name (`Gi1/0/24`, `Et1`, `Po10`), the platform folds it onto the long name (`GigabitEthernet1/0/24`, `Ethernet1`, `Port-channel10`) so the same interface is never listed twice. An interface that stops being reported is marked **Stale** after the asset's stale window, not removed. An interface found on an asset still waiting in Approvals is **Pending** and follows the asset once it is approved.

## Virtual device contexts

Many devices partition themselves into logical devices that each own some of the
interfaces: a Fortinet **VDOM**, a Palo Alto **vsys**, a Cisco Nexus **VDC**, an
F5 **route domain**. Vista Platform records them as **virtual device
contexts** (NetBox's VirtualDeviceContext).

- **Where they live.** On the asset page, **Hardware** tab, the **Virtual device
  contexts** card lists the device's contexts: name, identifier (the device's
  number for the context, if it has one), status (*Active*, *Planned* or
  *Offline*), business unit, primary IPv4 and IPv6 addresses, and how many of
  the asset's interfaces belong to each. With the DCIM manage permission you can
  add, edit and delete them there. An empty card means none has been recorded,
  not that the device has none.
- **Which interfaces belong to which.** On the **Interfaces** tab, the
  **Context** column names each interface's contexts. Open an interface and tick
  its contexts under **Virtual device contexts**; only the asset's own contexts
  are offered, and the server refuses a context of another asset.
- **Primary addresses.** A context's primary IPv4 must be an IPv4 address (and
  its primary IPv6 an IPv6 address) assigned to one of the asset's interfaces.
  Deleting the address clears it from the context.
- **Rules.** A name is 1–64 characters and unique on the asset; an identifier is
  a whole number from 0 to 32767 and unique on the asset when set. Deleting a
  context takes its interfaces out of it; the interfaces and their addresses stay.

Every change is in the context's change record.

### Discovered contexts

Interrogating a device records its contexts and which interfaces each owns:

| Device | Context | Identifier |
|---|---|---|
| Fortinet FortiGate | each VDOM an interface is in, `root` included | none (a VDOM has no number) |
| Palo Alto | the virtual system that owns the interface (`vsys1`, `vsys2`, …) | the vsys number |
| F5 BIG-IP | the route domain of each VLAN, named as BIG-IP names it (the default route domain is `0`) | the route-domain id |
| Cisco Nexus (NX-OS) | the VDC each port is allocated to (`show vdc membership`) | the VDC id |

Only the context's name and number are collected, plus, on a Palo Alto firewall,
the display name its administrator gave the virtual system: it becomes the
context's **description** (for example *Tenant B Edge* on `vsys2`). The
description of a discovered context follows the device, so a rename on the
firewall is picked up; a firewall that states no display name, or that refuses
the read, leaves the description as it was. Other devices, and SNMP, do not
report contexts.

- **New contexts** are *Pending* while the asset waits in Discovery →
  Approvals, and become *Active* at the first interrogation after the asset is
  approved.
- **What you declared wins.** A context you created, or one NetBox synced, with
  the same name is matched, never overwritten: its identifier, status, business
  unit, primary addresses and description stay as you set them. An interface you
  put in a context yourself stays in it.
- **Moves.** When the device reports an interface in a different context, the
  interface leaves the discovered context it was in and joins the new one.
- **Contexts that disappear** are marked **Stale** after the asset's stale
  window (the tenant's asset lifecycle policy, 30 days by default), and only by
  a device that still reports contexts. A discovered context is never deleted
  by discovery; delete it on the Hardware tab if it is gone for good.

## Finding assets by interface

The inventory query language reaches interfaces with `interface:( … )`:

```
interface:(mac_address:"00:11:22:33:44:55")
interface:(name = "GigabitEthernet1/0/24" and mode:tagged)
interface:(speed_kbps >= 10000000)
exists(interface) and not interface:(enabled = true)
interface:(virtual_device_context:"vsys2")
```

Fields: `name`, `type`, `mac_address`, `enabled`, `mgmt_only`, `mtu`, `speed_kbps`, `mode`, `status`, `operational_status`, `description`, `virtual_device_context` (the name of a context the interface belongs to). See [Query](../features/query.md).

## API

`/api/v2/inventory-service/dcim/interfaces` lists, creates, reads, changes (JSON merge-patch) and deletes interfaces, and `POST /dcim/interfaces/bulk` creates several at once (all or none, so a LAG and its members can arrive together). `GET /dcim/assets/{id}/interfaces` lists one asset's. Filters: `asset_id`, `name`, `type`, `enabled`, `mgmt_only`, `mac_address` (any of an interface's MAC addresses), `lag_id`, `vlan`, `status`, `q`.

An interface carries its contexts as `virtual_device_contexts` (id and name), `virtual_device_context_ids` and `vdcs` (the names). A create or PATCH sets them with `virtual_device_context_ids` — or, by name, `vdcs` — and replaces the interface's memberships. Contexts are at `/api/v2/inventory-service/dcim/virtual-device-contexts` (list, create, read, change, delete; filters `asset_id`, `name`, `identifier`, `status`, `operational_status`, `business_unit_id`, `q`) and `/dcim/assets/{id}/virtual-device-contexts` (one asset's; create on it). Reads need DCIM read, writes DCIM manage.
