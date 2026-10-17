# Circuits

A **circuit** is a link you buy from someone else: an internet connection, an MPLS service, a stretch of dark fibre, a wavelength, a leased line. It has a **circuit ID** (the provider's reference), a **circuit provider**, a **circuit type**, a status and a commit rate, and up to two ends, **A** and **Z**. A NetBox *provider*, *provider account*, *provider network*, *circuit type*, *circuit*, *circuit termination* and *circuit group* map onto these one to one.

Circuits answer "what do my sites run on, from whom, and at what rate?". A circuit end is also a cable end, so a cable trace can carry on through a circuit to the other side (see [Cabling](./cabling.md)).

## Where to find them

| You want | Go to |
|---|---|
| The list of circuits and each one's ends | **Inventory → Circuits** |
| Providers, accounts, provider networks, circuit types and circuit groups | **Settings → Infrastructure → Circuit Providers** |

You need the **Circuits read** permission (`circuits.read`) to see both and **Circuits manage** (`circuits.manage`) to add, change or delete anything. Both are part of the Tenant Administrator and Security Administrator roles; Viewers can read. Cabling a circuit termination to a port is a cable, so it needs `dcim.manage`.

## Keep the catalogues: Settings → Circuit Providers

The page has five sections, each a table with an **Add** button and edit and delete buttons on each row you own. Build these before your first circuit.

- **Circuit Providers**: the companies your circuits come from. A provider has a **Name**, a **Slug** (made from the name when left blank), **AS numbers** (comma-separated, shown as `AS3356`) and a **Description**.
- **Provider Accounts**: your accounts with a provider, so a circuit can say which contract it is billed under. Each has the **Circuit Provider**, an **Account number**, a **Name** and a **Description**.
- **Provider Networks**: a provider's own network that a circuit can end on instead of a site, such as an MPLS cloud or an internet exchange fabric. Each has the **Circuit Provider**, a **Name**, a **Service ID** and a **Description**.
- **Circuit Types**: what kind of service a circuit is. Seven ship with the platform and are marked **Built in**, which makes them read-only: Internet, MPLS, Dark Fibre, Wavelength, Point-to-Point, Broadband and Cellular. Add your own with a **Name**, a **Slug**, a **Colour** (six hex digits) and a **Description**.
- **Circuit Groups**: a name for a set of circuits that belong together, such as the primary and backup links to one office. Each has a **Name**, a **Slug** and a **Description**.

An account or provider network belongs to one provider, and deleting a provider takes its accounts and networks with it. A provider or circuit type that circuits still use cannot be deleted.

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

## Circuit terminations as cable ends

Each side of a circuit is a **circuit termination**, and a termination can be cabled like a port: from a switch's or router's port (or a patch panel's front or rear port), choose **Connect**, set **Far end is** to *Circuit termination*, search for the circuit by circuit ID and pick the side. A termination takes one cable and can be cabled to an interface, a front port, a rear port or another circuit termination.

Once a cable reaches a termination, **Trace** on the port follows the path across the circuit from its A side to its Z side and onward. A circuit with several terminations on one side splits the path, and the trace says so. The Cabling lens links a circuit end straight to the circuit in this lens. See [Cabling](./cabling.md).


## API

`/api/v2/inventory-service/circuits/{providers,provider-accounts,provider-networks,circuit-types,circuits,circuit-terminations,circuit-groups,circuit-group-assignments}` list, create, read, change and delete each object. The circuits list takes `operational_status` and `q`; terminations and group assignments filter by `circuit_id`. Reads need `circuits.read`; writes need `circuits.manage`. `GET /dcim/circuit-terminations/{id}/trace` answers the cable path through a termination and needs `dcim.read`.
