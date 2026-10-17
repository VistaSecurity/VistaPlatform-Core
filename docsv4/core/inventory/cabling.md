# Cabling

A **cable** joins two ends: a port on one asset and a port on another (or on the same one). Each end is an interface, a console port, a console server port, a front port, a rear port or a circuit termination. Vista Platform follows NetBox here: a patch panel's front and rear ports carry a connection through the panel, and a circuit's two ends carry it across a provider's network, so a **cable path** can run from a switch port through several panels and a circuit to a device in another building.

You can record cables by hand, paste a whole switch's cabling from a spreadsheet, or let discovery propose them from what devices report about their neighbours. Cabling is first-class inventory, and the platform draws the cryptography it has seen behind each port on top of it.

## Where to find it

| You want | Go to |
|---|---|
| Every cable in the estate | **Inventory → Cabling** |
| One device's ports, drawn as its front panel | **Inventory → open the asset → Ports tab** (the **Faceplate**). The **Interfaces** tab has a **Faceplate** button that jumps to it. |
| Where a map line physically runs | **Inventory → Map**, then **Show physical path** (see below) |
| Neighbour-reported cables waiting for a decision | **Discovery → Approvals → Proposed cables** |

You need the **DCIM read** permission (`dcim.read`) to see any of this and **DCIM manage** (`dcim.manage`) to connect, change, disconnect, approve or reject cables. Both are part of the Tenant Administrator and Security Administrator roles; Viewers can read.

## The Cabling lens

**Inventory → Cabling** lists every cable. Each row shows:

- **Label**
- **A end** and **B end**, each as `asset:port`. Click one to open that asset's Ports tab. A circuit end links to the circuit in [Inventory → Circuits](./circuits.md).
- **Type** (CAT6, OM4, single-mode and the rest of NetBox's cable types)
- **Status**: *Connected*, *Planned*, *Decommissioning* or **Proposed**. A proposed cable has a dashed marker on its row.
- **Length** and **Colour** (a swatch)
- **Site / rack** of the ends

Filter by **site**, **rack**, **asset**, **cable type**, **status** (*Proposed (awaiting approval)* is one of the choices) and **port kind** (interface, front port, rear port, console port, console server port, circuit termination). The search box matches a cable's label or description. **Export** downloads the rows on screen as a CSV file.

The lens is a place to look and to correct. A new cable is made from a port (see **Connect** below), not from the lens.

### The cable drawer

Click a row to open the cable. The drawer shows:

- **Ends**: both ends with their site and rack, each with a **Trace** button.
- **Cable**: edit the **Type**, **Status**, **Label**, **Colour** (six hex digits) and **Length** with its unit, then **Save**. Only the fields you changed are sent. Everything is read-only without `dcim.manage`.
- **Trace**: the path from either end (see [Trace a cable](#trace-a-cable)).
- **Changes**: who changed the cable, and when.
- **Disconnect** (top right) deletes the cable after you confirm. Both ports become free and the Changes log keeps the cable's history.

A proposed cable's drawer says it is waiting for approval in **Discovery → Approvals**.

## The Ports tab and the faceplate

**Inventory → open an asset → Ports** opens with the **Faceplate**, a picture of the device's ports followed by tables of its port components.

The faceplate draws:

- the asset's physical **Interfaces** (virtual and wireless interfaces are not drawn; the legend says how many were left out),
- then its **Console ports**, **Console server ports**, **Front ports** and **Rear ports**, each kind in its own row group.

Ports appear in the order of the asset's device type templates (see [Device types](./device-types.md)), or in natural name order when there is no template. Each row holds 24 ports, so a 48-port switch is two rows.

Each port tile shows:

- **Link state** on its border: coloured for *Up*, *Down* and *Disabled*. Console, front and rear ports have no link state and are drawn neutral.
- A **dot** when the port has a cable. A dashed border and hollow dot mean the cable is **proposed** or **planned**.
- A **tint** from the crypto overlay (below).

Hover a tile for its name and state. Click it (or focus it and press Enter) to open the port panel; the arrow keys, Home and End move between tiles. The panel shows the port's name, type and state, its **Cable** cell (the far end as `asset:port`, with **Connect** or **Disconnect** and a **Trace** button), and the crypto behind it.

An empty faceplate ("No ports to draw") means nothing has reported or declared a physical port, not that the device has none. **Apply templates** on the Ports tab creates the ports and interfaces from the asset's device type; nothing already set is overwritten.

### The crypto overlay

The **Crypto overlay** checkbox above the faceplate (on by default) tints each interface by the cryptography Vista has observed behind its addresses. This is the platform's differentiator: you can see a weak TLS configuration sitting on a particular switch port.

- **Colour** is the highest certified risk score among the crypto configurations on endpoints bound to the interface's addresses, banded Critical, High, Medium, Low or Informational like every other risk badge (see [Assets and crypto configurations](../features/assets-and-crypto-configurations.md)). The legend under the faceplate shows the colours.
- **Grey** means *Not assessed*: configurations were seen but no certified score exists. It is never drawn as clean.
- **No tint** means nothing cryptographic has been observed behind the port. That is not the same as safe.
- A **lock** marks a weak protocol version in use.
- Hover a tile (or open its panel) to see how many configurations sit behind it and which one is worst, with its protocol, version, cipher suite and port.

Only the asset's own endpoints count, so a neighbour's configuration never tints this device's port. The legend also names the **worst open finding on this asset**. If the overlay cannot load, the legend says so rather than drawing every port as clean.

The overlay tints interfaces only; console, front and rear ports are not tinted.

## Connect a port

1. Click a port on the faceplate (or use the **Cable** column on the **Interfaces** tab or the tables on the **Ports** tab) and choose **Connect**.
2. **Far end is**: the kind of port at the other end: *Interface*, *Front port*, *Rear port*, *Console port*, *Console server port* or *Circuit termination*. Kinds that cannot be cabled to this port are labelled **(not compatible)**, and **Connect** stays disabled with the reason shown.
3. For a port on an asset, optionally narrow by **Site** and **Rack** (picking a rack lists the assets placed in it), then search for the **Asset** by name, hostname or identifier and choose the **Port**. For a circuit termination, search by circuit ID and choose the side.
4. Optionally set **Cable type**, **Status**, **Label**, **Colour** (six hex digits) and **Length** with a unit. A length needs its unit.
5. Click **Connect**.

The rules:

- **One cable per port.** A port that already has a cable (or is marked connected) cannot take another; disconnect first.
- **Compatibility.** Interfaces, front ports, rear ports and circuit terminations can be cabled to each other; a console port cables to a console server port, a front port or a rear port. An interface cannot be cabled to a console port, for example. The Connect dialog shows the matrix as you choose.
- A cable can join two ports of the **same asset**.
- Virtual and wireless interfaces cannot be cabled.

**Disconnect** (the unplug button in the Cable cell) asks first, then deletes the cable.

You need `dcim.manage`, and the asset must not be archived or deleted.

## Edit cables as a table

For a whole switch, **Ports tab → Edit cables as table** opens a grid with one row per cable: **Local port**, **Far asset**, **Far port**, **Cable type**, **Label**.

1. Paste a block from a spreadsheet into any cell. Tab-separated text is expected (comma-separated is accepted), and a header row is dropped. Or type the rows; **Add row** adds more.
2. Click **Check rows**. Far assets are found by exact name and their ports are loaded. Each row says **Ready** or lists what is wrong: an unknown or already-cabled port, a missing or ambiguous far asset, an incompatible pair, an unknown cable type, or the same local or far port used twice.
3. Click **Apply** *N* **cables**. Valid rows are connected one after another and each row reports **Connected** or why it was refused. A refused row does not stop the others.

## Trace a cable

A **Trace** answers "where does this port really go?". It is available from the port panel and the Cable cell on an asset, from either end in the cable drawer, and from the map.

The trace window shows a left-to-right diagram of port, cable, port, with the in-device hops between them: a patch panel's **front to rear** or **rear to front**, and a circuit's **A to Z**. The far end is highlighted, a planned or not-connected cable is drawn dashed, and every asset or circuit is a link. Below the diagram is the same path as a hop list, and **Copy as text** copies it.

Each path is labelled *complete* or *incomplete*. An incomplete path ends before it reaches a far port. A note appears when *not every cable is connected* or when the path *splits*: a rear port carrying several front-port positions, or a circuit with several terminations, cannot be followed as one line. A front or rear port can lie on several paths, and the trace then lists each. A port with no cable says *Not cabled*.

Paths are worked out when cables change and follow at most 64 cables. A proposed cable carries no path until someone approves it.

## Port components

Besides interfaces, an asset can hold **console ports**, **console server ports**, **front ports**, **rear ports** and **device bays**. They live below the faceplate on the Ports tab, one tab per kind with its count; you need `dcim.read` to see them and `dcim.manage` to change them.

- **Add console port** and the other add buttons open a drawer. A console port has a **Name**, **Type** and **Speed (baud)**; a **rear port** has **Positions** (how many front-port positions it carries; a 12-fibre trunk has 12); a **front port** names the **Rear port** it belongs to and its **Position** on it. Declare rear ports first. Every kind also takes a **Label** and **Description**.
- The rear ports table shows how many of its positions are **Mapped** to front ports. A rear port cannot be made smaller than a position that is already mapped.
- A **device bay** holds one child asset, such as a blade in a chassis. The drawer takes the **Installed asset**'s id; the table shows *Empty* or a link to the installed asset. A device bay takes no cable.
- **Apply templates** instantiates every component kind from the asset's device type, interfaces included.

A patch panel is simply an asset whose device type has rear ports and front ports: cable a switch to a front port, cable the panel's rear port onward, and the trace follows the mapping through it.

## Cables from circuits

A circuit termination is a cable end like any other. In **Connect**, choose **Circuit termination** as the far end, search for the circuit and pick its A or Z side. A trace through it crosses the circuit from one side to the other. See [Circuits](./circuits.md).

## Neighbours become proposed cables

Switches, routers and firewalls report which device sits on the other end of each port with **LLDP** or **CDP**. Vista Platform reads those neighbour tables when it interrogates **Cisco** devices (CDP and LLDP), **Palo Alto** firewalls (LLDP), any **SNMP** device that answers the LLDP or CDP tables, and **UniFi** controllers (the LLDP table and each device's wired uplink), and turns each into a cable instead of a loose fact. The device has to be interrogated for this; sensor captures do not currently produce cables.

For each neighbour the platform finds the far device by its chassis ID, else its system name, else its management address, and the far port by MAC address, else by name. If more than one candidate matches it does not guess.

- **Both ends known and free**: a **proposed** cable is created between the two interfaces. It is marked as measured, appears with a dashed **Proposed** marker in the Cabling lens and on both ports, and waits for a person.
- **Far end not in the inventory yet**: no cable can be made yet. The platform parks the observation as an **unresolved termination**, remembering what the neighbour announced (chassis ID, port, system name, management address). When that device or port later arrives, through discovery, an import or by hand, the cable is created as proposed. Unresolved terminations are matched after every batch of discovered interfaces and again hourly, and one that nothing matches is dropped after 30 days without a new sighting. They are not listed in the interface, so a missing far end shows up only as the absence of a cable.
- **Already agrees with a cable**: nothing is proposed; the cable is stamped as confirmed by the neighbour.

### Approve or reject

Proposed cables are listed in **Discovery → Approvals** under **Proposed cables**, with both ends as links, the protocol that saw them and the number of observations. They count in the queue and under the **Discovered** source filter.

- **Approve** makes the cable one of record and computes its paths (needs `dcim.manage`).
- **Reject** keeps the cable marked as rejected, so the same pairing is not proposed again. Its ports show **Rejected**; disconnect it to free them.

A proposal is only made between ports that are both free, so a cable you drew yourself is not replaced.

### When a cable is contradicted: `topology/cable_drift`

When a neighbour on a port contradicts an **active** cable, either because the cable's far end (followed through any patch panels) is a different device or port, or because the far port the neighbour names is cabled to something else, the platform raises a **`topology/cable_drift`** finding on the local asset. It is medium severity and, being an inventory-accuracy finding rather than an exposure, does not feed risk scores.

Open it in **Risk & Compliance → Findings**: the **Cabling versus neighbours** panel lists each contradicted port with the cable of record beside what LLDP or CDP reports. The fix is on the asset's **Interfaces** tab. If the device really was re-patched, update the cable; if the record is right, find out what is plugged in. The finding resolves by itself when a later interrogation shows the neighbours agreeing with the cables, or as soon as one of those cables is changed. A neighbour whose far device is not in the inventory never counts as a contradiction.

## Cables on the map

In **Inventory → Map**, the **Neighbourhood** view has a **Physical cabling** toggle. It draws the cable runs between the assets on screen as thick lines, dashed while proposed and faded when not connected. The toggle is disabled, with the reason as its hover text, when no cables run between the assets shown. The legend names the relationship, cable and proposed-cable line styles.

- Hover a cable to see its ports, its label and how many cables and patch panels it passes through.
- Click a relationship line and choose **Show physical path** to trace the cable from that line's port. The item is disabled, with the reason, when no port can be named for the relationship, for example a line drawn from a cloud region rather than observed on a port.
- Click a cable to open the trace, with **Open cable** to reach it in the Cabling lens.

The **Topology** view adds a **Physical cabling** toggle between prefixes, summing the cable runs between each pair of prefixes. In the Network view, a device's detail has a **Faceplate** link to the asset's Ports tab. See [Map](../features/map.md).


## API

`/api/v2/inventory-service/dcim/cables` lists, creates, reads, changes and deletes cables, with the filters `asset_id`, `site_id`, `rack_id`, `location_id`, `type`, `operational_status`, `status`, `termination_kind`, `termination_id`, `label` and `q`. `POST /dcim/cables/{id}/approve` and `/reject` decide a proposed cable. `GET /dcim/{interfaces,front-ports,rear-ports,console-ports,console-server-ports,circuit-terminations}/{id}/trace` answers a path's steps. `GET /dcim/assets/{id}/interface-posture` feeds the crypto overlay. Components are under `/dcim/{console-ports,console-server-ports,front-ports,rear-ports,device-bays}` and `/dcim/assets/{id}/{kind}`. Reads need `dcim.read`; writes need `dcim.manage`.

The inventory query language reaches cables with `cable.type`, `cable.status` and `cabled_to`. See [Query](../features/query.md).
