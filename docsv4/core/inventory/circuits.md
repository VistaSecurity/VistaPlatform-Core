# Circuits

A **circuit** is a link you buy from someone else: an internet connection, an MPLS service, a stretch of dark fibre, a wavelength, a leased line. It has a **circuit ID** (the provider's reference), a **circuit provider**, a **circuit type**, a status and a commit rate, and up to two ends, **A** and **Z**. A NetBox *provider*, *provider account*, *provider network*, *circuit type*, *circuit*, *circuit termination* and *circuit group* map onto these one to one. A **virtual circuit** is the other kind: a circuit a provider delivers over its own network (see [Virtual circuits](#virtual-circuits)).

Circuits answer "what do my sites run on, from whom, and at what rate?". A circuit end is also a cable end, so a cable trace can carry on through a circuit to the other side (see [Cabling](./cabling.md)).

## Where to find them

| You want | Go to |
|---|---|
| The list of circuits and each one's ends | **Inventory → Circuits** |
| Virtual circuits and the interfaces that terminate them | **Inventory → Circuits → Virtual circuits** |
| Providers, accounts, provider networks, circuit types, virtual circuit types and circuit groups | **Settings → Infrastructure → Circuit Providers** |

You need the **Circuits read** permission (`circuits.read`) to see both and **Circuits manage** (`circuits.manage`) to add, change or delete anything. Both are part of the Tenant Administrator and Security Administrator roles; Viewers can read. Cabling a circuit termination to a port is a cable, so it needs `dcim.manage`.

## Keep the catalogues: Settings → Circuit Providers

The page has six sections, each a table with an **Add** button and edit and delete buttons on each row you own. Build these before your first circuit.

- **Circuit Providers**: the companies your circuits come from. A provider has a **Name**, a **Slug** (made from the name when left blank), **AS numbers** (comma-separated, shown as `AS3356`) and a **Description**.
- **Provider Accounts**: your accounts with a provider, so a circuit can say which contract it is billed under. Each has the **Circuit Provider**, an **Account number**, a **Name** and a **Description**.
- **Provider Networks**: a provider's own network that a circuit can end on instead of a site, such as an MPLS cloud or an internet exchange fabric. Each has the **Circuit Provider**, a **Name**, a **Service ID** and a **Description**.
- **Circuit Types**: what kind of service a circuit is. Seven ship with the platform and are marked **Built in**, which makes them read-only: Internet, MPLS, Dark Fibre, Wavelength, Point-to-Point, Broadband and Cellular. Add your own with a **Name**, a **Slug**, a **Colour** (six hex digits) and a **Description**.
- **Virtual Circuit Types**: what kind of overlay a virtual circuit is, such as SD-WAN, MPLS L3VPN or Metro Ethernet. None ship with the platform. Each has a **Name**, a **Slug**, a **Colour** and a **Description**.
- **Circuit Groups**: a name for a set of circuits that belong together, such as the primary and backup links to one office. Each has a **Name**, a **Slug** and a **Description**.

An account or provider network belongs to one provider, and deleting a provider takes its accounts and networks with it. A provider, circuit type, provider network or virtual circuit type that circuits or virtual circuits still use cannot be deleted.

## The Circuits lens

**Inventory → Circuits** lists every circuit with its **Circuit ID**, **Circuit Provider**, **Type**, **Status**, **A end**, **Z end** and **Commit rate**. Search by circuit ID, filter by **Status**, and use the **Circuit Providers** button to jump to the catalogues.

Click **Add circuit** and fill in:

- **Circuit ID**: the provider's reference. Unique per provider.
- **Circuit Provider** and **Circuit Type** (both required), and optionally a **Provider Account**.
- **Status**: *Planned*, *Provisioning*, *Active* (the default for a new circuit), *Offline*, *Deprovisioning* or *Decommissioned*.
- **Commit rate (kbps)**, **Installed** and **Contract ends** (dates as `YYYY-MM-DD`), and a **Description**.

### The circuit drawer

Click a row to open the circuit. The drawer has:

- **Details**: status, commit rate, installed and contract dates, description. The pencil and bin buttons at the top edit and delete the circuit.
- **Terminations**: the **A** and **Z** ends. Click **Set** (or **Edit**) beside an end. **Lands on** names the provider network the end sits on, or leave it as *Not connected*. **Port speed (kbps)**, **Cross-connect ID** and **Patch panel / port** record the handoff.
- **Circuit Groups**: the groups the circuit belongs to, each with an optional priority (*Primary*, *Secondary*, *Tertiary* or *Inactive*). **Add to group** adds one; the cross removes it.
- **Custom fields**: any custom fields your organisation defined for circuits (Settings → Infrastructure → Custom Fields).
- **Changes** and **Journal**: who changed the circuit and when, and notes people have written about it.

Deleting a circuit asks first. Its terminations and group memberships go with it.

### The circuit page

A circuit row opens **the circuit's own page** (`/inventory/circuits/<id>`), which you can bookmark and share.
It shows the same details, A and Z terminations (editable with `circuits.manage`) and groups as the
drawer, adds a **trace** from each cabled end, and ends with custom fields, tags, contacts, images, changes
and journal. **Back** returns to the Circuits lens with its filters.

## Virtual circuits

A **virtual circuit** is a circuit a provider delivers over one of its **provider networks** rather than as a physical link of its own: an SD-WAN overlay, an MPLS L3VPN, a Metro Ethernet virtual connection. Its ends are **interfaces** (the interface on each of your devices where the overlay lands), each with a **role**: *Peer*, *Hub* or *Spoke*. The model is NetBox 4.2's *virtual circuit*, *virtual circuit type* and *virtual circuit termination*.

**Inventory → Circuits**, then **Virtual circuits** at the top of the lens, lists every virtual circuit with its **Circuit ID**, **Circuit Provider**, **Provider Network**, **Type**, **Status** and its **Terminations** (each as role, asset and interface). Search by circuit ID and filter by **Status**.

Click **Add virtual circuit** and fill in:

- **Circuit ID**: the provider's reference. Unique per provider network.
- **Provider Network** and **Virtual Circuit Type** (both required), and optionally a **Provider Account**, which must be an account of the network's provider.
- **Status**: the same six as a circuit's, *Active* by default.
- A **Description**.

Click a row to open the virtual circuit: its status and description, its **terminations** (each links to the interface's page; the cross removes one) and its **Changes**. The pencil and bin buttons edit and delete it; deleting a virtual circuit removes its terminations.

An interface joins a virtual circuit from **its own page** (`/inventory/interfaces/<id>`): under **Virtual circuit**, **Add to a virtual circuit** asks for the virtual circuit and the role. An interface terminates at most one virtual circuit; the page shows which, with a link to it, and the cross takes the interface out. Deleting the interface removes its termination.

The inventory query language finds assets by the virtual circuits their interfaces terminate: `virtual_circuit` (the circuit ID, or the virtual circuit type's name or slug), `virtual_circuit.cid`, `virtual_circuit.provider` (by name or slug) and `virtual_circuit.role` (`peer`, `hub` or `spoke`). `virtual_circuit.role != hub` also matches an asset that terminates no virtual circuit. See [Query](../features/query.md).

## Circuit terminations as cable ends

Each side of a circuit is a **circuit termination**, and a termination can be cabled like a port: from a switch's or router's port (or a patch panel's front or rear port), choose **Connect**, set **Far end is** to *Circuit termination*, search for the circuit by circuit ID and pick the side. A termination takes one cable and can be cabled to an interface, a front port, a rear port or another circuit termination.

Once a cable reaches a termination, **Trace** on the port follows the path across the circuit from its A side to its Z side and onward. A circuit with several terminations on one side splits the path, and the trace says so. The Cabling lens links a circuit end straight to the circuit in this lens. See [Cabling](./cabling.md).


## API

`/api/v2/inventory-service/circuits/{providers,provider-accounts,provider-networks,circuit-types,circuits,circuit-terminations,circuit-groups,circuit-group-assignments,virtual-circuit-types,virtual-circuits,virtual-circuit-terminations}` list, create, read, change and delete each object. The circuits and virtual circuits lists take `operational_status` and `q`; terminations and group assignments filter by `circuit_id`; virtual circuits by `provider_network_id` and `provider_id`; virtual circuit terminations by `virtual_circuit_id` and `interface_id`. Reads need `circuits.read`; writes need `circuits.manage`. `GET /dcim/circuit-terminations/{id}/trace` answers the cable path through a termination and needs `dcim.read`.
