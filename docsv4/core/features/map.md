# The Map

The map answers two different questions, and it has a view for each.

| View | The question | What you get |
|---|---|---|
| **Neighbourhood** | *What is this one thing attached to?* | A graph around one asset, out to three hops, with the impact overlay. |
| **Topology** | *Where is everything?* | A tree of your whole estate by site, segment and class, with counts and the connections between segments. |

The switch between them sits at the top of the page, and the view you are in is in the address bar — so either one is a link you can paste into a ticket.

Most of this page is about the neighbourhood view, which is the one people open most. [Topology](#the-topology-view) is at the bottom.

## The neighbourhood view

The **neighbourhood** draws one asset and everything around it: what it runs on, what depends on it, what it talks to, and how far away each of those is. It is the same information the [Relationships](./relationships.md) tab lists, drawn as a picture instead of as two lists.

A list is better for deciding about one relationship. A picture is better for seeing a shape — that three applications all rest on the same host, that a controller sits between you and forty access points, that the database you were about to reboot has four things hanging off it.

## Where to find it

**Inventory → Map.**

The map opens on the neighbourhood view with a search box rather than a graph, because a map has to be a map *of* something. Find the asset you want at the centre and click it. The search box speaks the same [query language](./query.md) as the inventory list, so `class:server and environment:production` works here exactly as it does there.

Two other ways in:

- **From an asset.** Inventory → open any asset → **Relationships** tab → **View on map**. This is the usual route: you are already looking at an asset and want to see its surroundings.
- **Full screen.** The **Full screen** button gives the graph the whole window with no navigation rail. **Exit** returns you to the lens with your depth and pending settings intact.

The address bar always describes what you are looking at, so a map is a link you can paste into a ticket.

## Reading the map

### The nodes

Each box is an asset. Two things are shown at once and they are deliberately separate:

| | |
|---|---|
| **Colour and icon** | What kind of thing it is — hardware, virtual, cloud resource, application, service, external party, or an unidentified host. These are the top-level [asset classes](./inventory-and-lenses.md). |
| **The ring** | Its lifecycle status: monitored (green), waiting for approval (amber), or archived and out of service (grey). |

Keeping them separate matters: an asset waiting for approval is still a server, and should still look like one.

The asset the map is drawn around is outlined in its own colour and labelled **Focus**.

A node whose class this version of the platform does not recognise is drawn as **Other**, in grey. That is not the same as **Unknown host** — an unknown host is a real address in your estate that nothing has identified, which is a gap worth closing. "Other" just means a class name we have no icon for, usually one of your own subclasses.

### The edges

Each line is a relationship, labelled with what it means — *runs on*, *depends on*, *contains*, *manages*. The arrow points the way the relationship reads.

- **Solid** lines are confirmed relationships.
- **Dashed amber** lines are *pending* — proposed by a collector or by a person, and not yet accepted. They are only drawn when you switch **Pending** on.
- **Rejected** relationships are never drawn, in any mode. Someone decided that relationship was wrong; the map does not put that decision back up for grabs.

Hover a line to see where it came from: measured, declared, imported or inferred; how confident the platform is; how many times it has been observed; and when it was first and last seen. An inferred relationship is the platform's own guess and has not been confirmed by anything.

Two assets can be joined by more than one relationship — an application both *runs on* and *connects to* its host is ordinary — and each is drawn as its own line, curved apart from the others between that pair, so every one of them can be hovered for its own provenance.

### Depth

The **Depth** slider controls how many hops out from the focus asset the map reaches, from 1 to 3. Two is the default and is usually the readable one — at three hops a well-connected asset in a busy estate can pull in most of a data centre.

Depth is the shortest path, so an asset reachable two different ways is drawn once, at the distance you would say it is.

### Layout

The **LR / TB** button switches between left-to-right and top-to-bottom. Which one reads better depends on the shape of the neighbourhood; nothing else changes.

The layout is deterministic: the same neighbourhood is drawn the same way every time, so a screenshot in a ticket matches what the person reading it sees.

## The impact overlay

**Show impact of focus** answers the question people open this page for: *if I take this down, what goes with it?*

Switch it on and the map highlights everything that depends on the focus asset, tinted by distance — the first hop strongest, fading outwards. Everything outside the blast radius is dimmed rather than hidden, because "nothing else is affected" is only readable if the something-else is still on screen.

**Downstream / Upstream** flips the question: what depends on this, or what this itself rests on.

Three things about this answer are worth knowing, and they are the same three that apply to the impact panel on the Relationships tab:

- **Observed network connections do not count.** Two machines exchanging packets tells you nothing about whether one stops working when the other does. Nine of the ten relationship types carry impact; `connects_to` is the one that does not.
- **Only confirmed relationships count.** A pending proposal is a guess, and you should not plan a maintenance window around a guess. Turning **Pending** on draws those lines but does not add them to the blast radius.
- **A very large answer is reported as a floor.** If the closure is capped you will see "At least 500 assets…" rather than a total, because a number somebody schedules an outage around must not quietly be the smaller of two possibilities.

## When the map is truncated

A neighbourhood can be bigger than a picture is useful at. The map draws at most 500 assets and 2,000 relationships; past that, a banner appears saying exactly how much was left out — "Showing 500 of 812 assets and 2000 of 3104 relationships."

The graph you are looking at is then a *piece* of the neighbourhood, not a small one. Reduce the depth, or click through to a node nearer whatever you were actually looking for and use **Focus here** to redraw around it.

## Clicking a node

Clicking an asset opens a panel with its class, status, risk score and every relationship it has *on the current map*, plus two actions:

- **Open asset** — its full page.
- **Focus here** — redraw the neighbourhood around it. This is how you walk an estate: focus, look, step, look again.

A risk score of **0** on this panel means *not assessed*, not *safe*.

## Exporting

**Export** writes the graph currently on screen to a file:

| | |
|---|---|
| **GraphML** | The interchange format Visio, yEd and Gephi read. |
| **Cytoscape JSON** | Loads directly into Cytoscape.js. |

Both carry the node and edge attributes the map shows — class, status, depth, relationship type, provenance, confidence and the first- and last-seen dates — so the picture is still readable after it leaves here.

The menu closes on **Esc**, on a click outside it, or once you choose a format.

**These exports are convenience, not evidence.** They are written in your browser from the graph you are looking at, which means they carry no provenance, no content hash and no record of what selected them — and when the map is truncated, the file is truncated with it. For audit-grade output with a hash and a stated scope, generate a [CBOM artifact](../cbom/cbom-artifacts.md) instead. The same distinction applies to the inventory's [page-local exports](./page-local-exports.md).

## "No relationships yet"

Most assets in most inventories are leaves — nothing runs on them and nothing depends on them — so an empty map is an ordinary answer rather than a sign something is broken. It does mean impact analysis has nothing to go on for that asset.

Relationships arrive four ways, and the empty state links to the first of them:

| | |
|---|---|
| **Measured** | Sensors, cloud APIs and device interrogation observe them. See [Discovery](./discovery.md). |
| **Imported** | A CMDB or spreadsheet import brings them with the assets. See [Spreadsheet Import](./spreadsheet-import.md) and [CMDB Integrations](./cmdb-integrations.md). |
| **Inferred** | The platform proposes one from what it has seen. These always wait for a person in **Discovery → Approvals**. |
| **Declared** | Someone records one by hand, on the asset's **Relationships** tab. |

## What you need to see it

The map reads the same data as the inventory, so anyone who can view assets can open it. Declaring a new relationship needs the **assets.update** permission, and is done from the asset's Relationships tab rather than from the map — see [Roles & Permissions](./roles-and-permissions.md).

## The topology view

**Inventory → Map → Topology**, or straight to `/inventory?lens=map&view=topology`. The **Inventory health** panel on the Dashboard links here too.

Topology answers *where is everything*. It is deliberately **not** a graph of every asset: a picture of several thousand nodes is unreadable everywhere it has been tried, and tells you less than the inventory list already does. It is a tree instead.

### What it shows

Four numbers across the top: how many configuration items you have, how many sites they are spread across, **how many have no site recorded**, and how many confirmed relationships cross a segment boundary.

The third of those is the one to read first. It tells you whether the tree below is your estate or a tidy corner of it.

Under them, the tree:

- **Site** — each site you have recorded, and an explicit **Unassigned** node for everything that has none. Sites are read from the asset's own site field, falling back to a `location.site` or `site` tag, so an estate labelled by a CMDB import groups correctly.
- **Segment** — each [network segment](./operational-context.md) within the site, and an explicit **Unsegmented** node for assets that belong to none. The unsegmented node is drawn in a lighter style, because it is an absence rather than something somebody drew.
- **Class** — expand a segment and you get one chip per [asset class](./inventory-and-lenses.md) present in it, coloured the same way the neighbourhood colours its nodes, with a count.

**Nothing is left out.** On a fresh inventory most assets have neither a site nor a segment, and a topology that quietly omitted them would draw the curated minority and look complete. If the tree does not add up to the total at the top, the page says so rather than letting you assume it does.

### Clicking through

Every count is a link into the inventory list, filtered to exactly the rows it counted:

| Click | What opens |
|---|---|
| A segment's count | Every configuration item in that segment |
| A class chip | Every item of that class in that segment |

The filter arrives as a [query](./query.md) in the address bar, so you can widen or narrow it from there. The unsegmented bucket becomes `not exists(segment_id)` — "no segment recorded", which is a different question from any particular segment.

### Between segments

Beside the tree, the connections that cross a segment boundary, aggregated per pair of segments and per kind — observed *connections* and declared *dependencies* are counted separately, because they are different claims.

Two things are deliberately not counted here:

- **Pending relationships.** An aggregate is the one place a single unconfirmed observation is invisible, so drawing it would state a guess as fact with nothing on screen to qualify it. Accept it in **Discovery → Approvals** and it appears.
- **Containment.** A virtual machine and its hypervisor sitting in two segments is one thing described twice, not a connection between those segments.

An empty list here means nothing has observed or declared a link between your segments — not that they are isolated.

### When it is truncated

Very large estates are capped. Past the cap a banner says how much is shown against how much there is — the real totals, never a quiet shortening. The **cross-segment links** headline is one of those totals: it counts every link your estate has, and says how many of them were drawn when the list beside it is short of that.

### What it does not have

No full-screen mode and no export. The tree is a way into the list rather than a document; for something with a hash and a stated scope, generate a [CBOM artifact](../cbom/cbom-artifacts.md).

## See also

- [Relationships](./relationships.md) — the vocabulary, the four provenances, and how to declare one
- [Inventory & Lenses](./inventory-and-lenses.md) — the list the map is an alternative view of
- [Query](./query.md) — the language the asset picker speaks
- [Page-Local Exports](./page-local-exports.md) — the same convenience-not-evidence rule, for lists
- [Operational Context](./operational-context.md) — the network segments the topology groups by
- [The Dashboard](./dashboard.md) — the Inventory health panel that links here
