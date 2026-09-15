# Relationships

A **relationship** records how two assets are connected: which server an application runs on, which hypervisor hosts a virtual machine, which database a service depends on, which controller manages an access point.

Relationships are what turn an inventory into a map. A list of two thousand assets tells you what you own; relationships tell you what happens when one of them changes.

## Where to find them

**Inventory → open any asset → Relationships tab.**

The tab has three parts: what depends on this asset, the relationships themselves, and a button to add one.

Relationships that nothing has confirmed also appear in **Discovery → Approvals**, alongside newly discovered assets and merge proposals. There is one review queue, not three.

## What the tab shows

### "What depends on this"

The panel at the top answers the question people actually open this tab for: *if I take this asset down, what goes with it?*

It shows how many assets are affected, how far away each one is ("4 at 1 hop · 2 at 2 hops"), and the first dozen by name so you can click through. Use the **Show upstream** button to flip the question round and see what this asset itself rests on.

Two things about this number are worth knowing.

**It only counts dependency relationships, not network connections.** Nine of the ten relationship types carry impact. `connects_to` — an observed network conversation — is the one that does not. Two machines exchanging packets tells you nothing about whether one stops working when the other does, and because almost every asset connects to something, counting those would make nearly every answer "the entire estate," which is the same as no answer at all.

**Each relationship is followed the way its own meaning points.** Ask what breaks if a wireless controller dies and you get the access points it manages; ask it of a virtual network and you get the subnets it contains; ask it of a server and you get the applications that run on it. That sounds obvious, and it is the point: the platform tracks which way round each relationship type works, rather than assuming they all point the same way (ADR-0003 D5 as amended 2026-09-12 — before that amendment, asking what depended on a controller or a network returned nothing at all).

**A business service you have declared is included, and the answer stops there.** If you have recorded that an asset `impacts` a business service, that service appears in the blast radius. The platform does not carry on through it into everything else the service touches — a blast-radius answer that ends at "…and therefore the whole company" helps nobody.

**It only counts confirmed relationships.** A proposed relationship nobody has accepted is not included. You should not plan a maintenance window around a guess.

If the closure is very large, the panel says so and the number is reported as a floor ("At least 500 assets…") rather than as a total.

### The relationships

Below the panel, the asset's relationships are listed in two groups:

- **This asset** — relationships where this asset is the subject. "This application *runs on* that server."
- **Other assets** — relationships pointing at this asset. "That application *runs on* this server."

It is the same information from two sides. A relationship is recorded once, and each asset's page shows it from its own point of view — so the application's page reads "runs on" and the server's page reads "runs."

Each row shows:

| | |
|---|---|
| **The relationship** | How it reads from this asset's side. |
| **The other asset** | Click through to its page. A deleted or merged-away asset is still named, struck through, rather than silently disappearing. |
| **Where it came from** | Measured, Declared, Imported or Inferred — see below. |
| **Status** | Only shown when it is not confirmed: pending, rejected or stale. |

### Where a relationship came from

This is the most important column, because the four sources are not worth the same:

| | |
|---|---|
| **Measured** | A sensor, a cloud API or a device interrogation observed it. |
| **Declared** | Someone in your organization asserted it. |
| **Imported** | It came from a connected CMDB or a spreadsheet import. |
| **Inferred** | The platform worked it out from a pattern. **Nothing has confirmed it.** |

Inferred relationships are highlighted, and they are the only kind that always waits for a person.

## The ten relationship types

| Type | Reads from the other side | Typical use | In "what breaks if this dies" |
|---|---|---|---|
| **runs on** | runs | An application or container, and the machine that runs it | the machine's answer lists the application |
| **hosted on** | hosts | A virtual machine and its hypervisor; a cloud resource and its account or region | the hypervisor's answer lists the machine |
| **virtualized by** | virtualizes | A virtual machine and the hypervisor or cluster that virtualizes it | the hypervisor's answer lists the machine |
| **depends on** | used by | An application and its database | the database's answer lists the application |
| **connects to** | connected from | An observed network connection | not counted |
| **member of** | members | A node in a cluster, an access point on its controller | the cluster's answer lists the node |
| **contains** | contained by | A virtual network and its subnets | the network's answer lists the subnets |
| **manages** | managed by | A controller and the things it manages | the controller's answer lists what it manages |
| **sends data to** | receives data from | A declared data flow between applications | the receiver's answer lists the sender |
| **impacts** | impacted by | An asset and a business service | the asset's answer lists the service, and stops there |

A pair of assets can carry several relationships at once — a machine can both host and manage another — but only one of each type.

## What "pending" means

A relationship is **pending** when nothing has confirmed it yet. Pending relationships are shown on the tab but are not counted in impact analysis.

There are two reasons a relationship can be pending, and they resolve differently:

**The other asset is still awaiting approval.** A sensor saw a connection to something that has not been admitted to your inventory yet. Approving that asset in Discovery → Approvals confirms the relationship too — approving an asset approves what was observed about it. There is nothing to decide separately.

**The platform inferred it.** Both assets are already in your inventory, and the platform worked out from a pattern that they are probably related — an application that always talks to one database, for example. Nothing observed this relationship; it is a conclusion. These appear in **Discovery → Approvals** as *relationship proposals*, and they wait there until a person decides.

### Deciding a relationship proposal

In Discovery → Approvals, a relationship proposal shows both assets side by side with the proposed relationship between them, where the proposal came from, and how confident its producer was.

- **Accept** confirms the relationship. It starts counting in impact analysis immediately.
- **Reject** records that the claim was wrong. The decision is kept, so the same conclusion is not proposed to you again next week.

Either decision is recorded in the asset's History with who made it and when.

Deciding a relationship needs the **assets.update** permission — the same permission as approving an asset.

## Adding a relationship yourself

**Relationships tab → Add relationship.**

Pick the type, pick which way it points, and search for the other asset. Before you save, the modal shows you the whole sentence:

> `payments-api` **runs on** `app-server-04`

Read it. Direction is the easiest thing to get backwards, and a relationship pointing the wrong way is not obviously wrong on the page — it just quietly inverts every impact answer built on top of it.

A relationship you declare between two approved assets is confirmed straight away; there is no queue for your own assertions. If the other asset is still awaiting approval, the relationship waits with it.

Adding a relationship needs the **assets.update** permission.

## Removing a relationship

Only relationships **you declared** can be deleted, and only by someone with **assets.update**.

Measured relationships cannot be deleted, and the platform will tell you so rather than pretending. The reason is simple: a collector saw it, so the next collection run would create it again. The delete would appear to work and then silently undo itself, which is worse than either outcome on its own.

A measured relationship goes away when the thing that saw it stops seeing it. It is marked **stale** and then archived by the lifecycle policy, the same way a stale asset is.

## Where relationships come from

You do not have to create relationships by hand. They arrive from:

- **Sensors and cloud discovery** — observed connections, cloud containment (a resource in its account, a subnet in its network), controller-to-device adoption.
- **Device interrogation** — uplinks and neighbour tables from switches and controllers.
- **CMDB imports** — if you sync a CMDB, its relationship types map onto these ten.
- **The platform's own inference** — as proposals, never applied automatically.
- **You** — declared on the tab.

## Asking about relationships in a query

The query language traverses relationships, so you can select assets by what they are connected to rather than by their own fields:

```
depends_on:(class=managed_database)
```

— everything that depends on a database.

```
any_rel(2):(environment:production)
```

— everything within two relationships of anything in production.

See [Query language](query.md) for the full grammar.

## Asking an AI agent

If you use the platform's MCP server, three tools cover this area: one for an asset's relationships, one for its neighbourhood, and one for impact. They are read-only and cannot change anything.

Their descriptions tell the agent the same things this page tells you — that inferred relationships are not confirmed fact, that impact covers nine types and not all ten, and that an empty impact result means nothing is *recorded*, which is not the same as nothing depending on the asset. See [API tokens and MCP](api-tokens-and-mcp.md).

## Limits

- **Impact analysis** follows up to 10 hops and reports at most 500 assets. Past that it tells you the answer is a floor.
- **The neighbourhood** reaches up to 3 hops, and at most 500 assets and 2000 relationships. Past that it says it could not show you everything, with the real totals.

Both caps report honestly rather than quietly returning less than they found.
