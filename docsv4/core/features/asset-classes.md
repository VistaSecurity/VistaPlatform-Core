# Asset Classes and Identification Rules

Two pages in **Organization Settings → Policies** explain how your inventory is
decided: **Classes** says what kinds of thing the platform knows about, and
**Identification rules** says how a new sighting is matched to something you
already have.

Neither page changes your data. They are there because the answers they give —
*why is this row a Server and not a Switch?*, *why did these two become one
asset?* — are questions you will ask about the inventory, and you should not
have to ask us.

## Where to find them

Open the **profile chip** at the bottom of the left navigation rail →
**Organization Settings**, then **Policies → Classes** or **Policies →
Identification rules**.

Both pages need the **View network assets** permission — the same permission
that lets you see the inventory itself. That is deliberate: these pages explain
how the inventory is decided, so anyone who can read the inventory can read the
rules behind it.

---

## Classes

Every asset has **exactly one class** — the kind of thing it is. The class is
drawn from a fixed tree of **49 classes** under **7 top-level branches**:

| Branch | What it covers |
|---|---|
| **Hardware** | Anything with a chassis — computers, servers, workstations, laptops, mobiles, network devices (switch, router, firewall, load balancer, wireless controller, access point, VPN gateway), storage, printers, OT devices (PLC, RTU, HMI, IED), IoT devices, and BMCs. |
| **Virtual** | Virtual machines, containers, clusters, hypervisors. |
| **Cloud resource** | Compute instances, managed databases, object storage, key stores, cloud load balancers, API gateways, CDN distributions, serverless functions, virtual networks, subnets. |
| **Application** | Web applications, database instances, service daemons, middleware. |
| **Service** | A declared capability rather than a machine — business services and technical services. |
| **External party** | Someone else's endpoint that your assets talk to. |
| **Unknown host** | An address inside your own space you have not identified further. |

The tree is **platform-wide and fixed**. That is what lets a query, a Bill of
Materials or the map mean the same thing in every organization: `class:server`
is the same set of things everywhere.

### What a class decides

Picking a class is not cosmetic. It decides three things:

1. **Which attributes the asset can carry.** A Computer has operating system,
   OS version, architecture, CPU count and memory; a Server adds server role; a
   Printer has none of those. Attributes are **inherited**, so a Server also
   carries everything Computer and Hardware declare. The page shows each class's
   *own* attributes as chips, plus a "+ N inherited" note for what it takes from
   its parents — hover a chip for the attribute's description.
2. **How the asset is exported to a Bill of Materials.** Each class carries a
   CycloneDX component type — `device`, `platform`, `container`, `application`,
   `data`, or `service`. Classes typed `service` are emitted into the CycloneDX
   *services* array rather than as components. See
   [Bills of Materials](../cbom/xbom.md).
3. **Which CMDB configuration-item type it maps to.** Classes with a confident
   default show it (Server → `cmdb_ci_server`, Firewall → `cmdb_ci_ip_firewall`).
   Some classes show none — that is honest rather than incomplete: a wrong
   default is worse than none, so a branch we have not verified against a real
   CMDB is left blank and the sync resolves to the nearest ancestor that has one.

### Reading the page

The tree expands and collapses. Each row shows the class label, its key, its
CycloneDX type, its CMDB type where it has one, a one-line description, and its
attribute chips.

Intermediate classes are **assignable too**. Classifying something as `hardware`
when nothing narrows it further is the honest answer — the class is part of what
tells you how much is known about a thing.

> **Read-only in this release.** You cannot add, rename or remove classes today.
> The page says so on the card. Adding your own **subclasses** — a "Dell
> PowerEdge" beneath Server, with its own attributes — is planned; the top level
> will stay fixed so the shared meaning survives.

---

## Identification rules

When something is discovered, the platform has to decide whether it is a thing
it already knows about or a new one. It decides **by identifier, strongest
first**: the first identifier that matches an existing asset wins, and nothing
matching means a new asset.

This is why a host seen by a sensor, pulled from your CMDB and typed in by hand
becomes **one** asset rather than three.

### The order is per class

There is no single ladder. Each class has its own order, because a server can be
known by the agent installed on it and a printer cannot. Pick a class from the
selector at the top of the page to see the order used for it, numbered, with the
reason each identifier sits where it does.

For example, a **Server** resolves in this order: agent ID, serial number, CMDB
sys_id, SSH host key, MAC address, FQDN, hostname, IP address. A **Cloud
resource** resolves on cloud resource ID, CMDB sys_id, FQDN — and never on MAC
or serial, which it does not have.

### Scoped and global identifiers

Every identifier is marked **Global** or **Scoped**:

| Identifier | Uniqueness | Why it sits where it does |
|---|---|---|
| **Agent ID** | Global | Minted by the platform when an agent enrols. Names exactly one installation. |
| **Cloud resource ID** | Global | The provider's own ARN/ID. Unique by construction, stable across restarts and address changes. |
| **Serial number** | Global | Burned in by the manufacturer. Survives reimaging, renaming and re-addressing. |
| **CMDB sys_id** | Scoped | The connected CMDB's own key. Scoped to the sync profile it came from, because two CMDBs can issue the same sys_id. |
| **SSH host key** | Global | The host's own key. Changes only when the host is rebuilt — which is itself worth knowing. |
| **MAC address** | Global | Unique per interface. Weaker than a serial: virtual machines and containers can be given one. |
| **FQDN** | Global | Unique across the organization on its own, because the domain is part of it. |
| **Hostname** | Scoped | A short name, unique only inside a network segment. Two segments can each have a "db01". |
| **IP address** | Scoped | Weakest: addresses are reassigned. Matched inside a segment, never across the organization. |
| **Name** | Scoped | For declared services, which have no address or serial. Scoped by class. |

A **scoped** identifier is matched inside its scope — the network segment, the
class, or the CMDB sync profile. An organization with no segments defined uses
one default scope. **Global** identifiers are unique on their own, and the
platform rejects a scope on one: a scope nobody asked for would split the very
thing that makes the identifier unique.

> The order itself is **read-only in this release**. Editing it per class arrives
> in a later one.

---

## When the evidence is ambiguous

When identifiers disagree — one says this is the database server you already
have, another says it is something else — the platform **does not guess**. It
raises a **merge proposal** in **Discovery → Approvals** and a person decides.

A matcher scores each candidate, puts the strongest first, and shows its
reasons. The card at the bottom of **Identification rules** is where you decide
whether a high enough score may settle one without you.

### The auto-accept threshold

The control offers six steps: **Never · 70% · 80% · 90% · 95% · 99%**.

**"Never" is not 0% confidence — it is off**, and it is the default. No score
bypasses it; every ambiguous sighting waits for a person. At any other setting,
a merge the matcher scores at or above the line is accepted without asking, and
anything below it still waits.

**The threshold covers every intake path** — discovery, spreadsheet imports,
SBOM uploads, passively observed hosts, device interrogation and cloud
collectors. One host seen two ways is one question, so which collector happened
to see it does not change the answer.

Two things are **never** auto-accepted, whatever the score:

- a sighting whose **serial number, cloud resource ID, agent ID or CMDB sys_id
  disagrees** with the candidate's;
- anything involving an asset **still waiting for approval** — admitting an asset
  and merging two assets are two different decisions.

> ⚠️ **An auto-accepted merge cannot be undone from this page.** The sighting is
> written into the asset the matcher chose, and putting it back is manual work.
> Everything the threshold does is listed under **"Auto-merged by the matcher"**
> in **Discovery → Approvals**, with the score and the reasons — check its work
> there. Turn this on only once you have watched the proposals the matcher raises
> and agree with how it ranks them.

The card names the matcher that scores the proposals. If this deployment has no
matcher configured, it says so plainly: nothing is scored, the threshold cannot
take effect whatever it is set to, and merge proposals still appear in Approvals
for a person to decide.

Changing the threshold needs **both** the settings-update and the asset-update
permission, because it authorizes the platform to merge two of your assets
without asking — the same act as accepting a merge proposal by hand. Without
both, the card is read-only and says so.

Full detail on how proposals are scored, and what approving one does, is in
[Asset Approval](./asset-approval.md#letting-a-high-score-settle-it).

---

## Where class shows up elsewhere

- **Inventory → All assets** — the left filter rail shows the taxonomy as a tree
  with a count beside each class. Picking a parent selects everything beneath it,
  and the table's columns follow the class you pick. See
  [Inventory & Lenses](./inventory-and-lenses.md).
- **Discovery → Approvals** — when the platform works out what a thing is from
  evidence, it raises a **class proposal**. Accepting it sets what the asset is
  and records which rule decided it. A class a person set is never overwritten.
- **The asset page → History** — a **Class history** section lists every class
  the asset has held and who decided each one, so a reclassification is never
  silent.
- **Creating an asset by hand** — the class picker comes first, and the form's
  fields are the ones that class declares.
- **CMDB sync and Bills of Materials** — both read the class to decide the
  configuration-item type and the CycloneDX component type.

## Related

- [Concepts](../concepts.md) — asset, endpoint, class, identifier, relationship
- [Asset Approval](./asset-approval.md) — the approval queue, merge proposals and class proposals
- [Inventory & Lenses](./inventory-and-lenses.md) — the class facet and the query box
- [Query](./query.md) — `class:` and the rest of the query language
- [Bills of Materials](../cbom/xbom.md) — how a class becomes a BOM component
