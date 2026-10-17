# Changes, journal and tags

Every create, change and delete of an inventory object is recorded: who made it, where it came from, when, and which fields moved. That record is the **change log**. Alongside it, people leave **journal entries** (dated notes on an object) and attach **tags** (labels). Together they answer "what happened to this estate, and why?". A NetBox *object change*, *journal entry* and *tag* map onto these one to one.

## The change log, across everything

**Inventory → Changes** (in the *Lifecycle* group of lenses) lists every recorded change, newest first, 50 to a page. Reading it needs the `dcim.read` permission.

Each row shows **When**, **Who**, **Source**, **Kind**, **Object**, **Action** (*Created*, *Updated* or *Deleted*) and the **Fields changed**. Narrow the list with the filters above it:

| Filter | Narrows to |
|---|---|
| **Object kind** | one kind of object (asset, interface, rack, prefix, circuit…) |
| **Object name** | objects whose name contains the text |
| **User** | changes by a person whose name or email contains the text |
| **Source** | *Web UI*, *API*, *System*, *Discovery* or *Sync* |
| **Action** | created, updated or deleted |
| **From** / **To** | a range of days, both days included |

**Clear** removes the filters. The filters live in the page address, so a filtered view can be shared as a link. **Export page** downloads the rows on screen as `change-log.csv` (when, who, source, kind, object, object id, action, fields changed); it exports the page you are looking at, not the whole log.

Click a row to open its **drawer**: when, who, source, the object (a link, when it is an asset that still exists), the object it belongs to (an interface's asset, for example), the request id, and **What changed** — a table of *Field*, *Before* and *After*. Fields that did not exist before or do not exist after read as an em dash. A secret (a password or key field) is redacted when the change is recorded, so the table shows that it moved, never what it was.

## The change log of one object

An object's own page carries the same record, limited to that object:

- **Inventory → open an asset → Changes tab.** It lists the asset's own changes **and** those of its interfaces, IP addresses, tags and journal, each line naming what changed, and the journal below it.
- Racks (Settings → Organization → Racks, and Inventory → Racks), sites, VLANs, prefixes, circuits, clusters, tunnels, cables, ports, interfaces and business units show a **Changes** panel in their dialog, drawer or page.

On each line, **Show changes** expands the same *Field / Before / After* diff; **Hide changes** collapses it. A long history shows the latest changes and says how many there are in all.

(The asset's separate **History** tab is the older record of reclassifications, context edits, merges and approvals; the Changes tab is the DCIM record.)

## A person's edit and a collector's measured value

The **Who** and **Source** of a change tell you whether a person or the platform made it:

| Source | Meaning | Who reads as |
|---|---|---|
| **Web UI** | a person edited it in the web UI | the person's email |
| **API** | a person or token wrote it through the API | the person |
| **Discovery (…)** | a collector reported it, named after the collector | the source |
| **Sync (…)** | a connector brought it in, named after the connector | the source |
| **System** | a platform job | *System* |

Filter **Source** to *Discovery* to see only what collectors measured, or to *Web UI* to see only what people declared. The two are kept apart on purpose: a value a collector measured is never overwritten by an import or a sync, and a person's edit is never overwritten by a collector. See [Interfaces](./interfaces.md) for how this looks on a field.

CSV imports are recorded with the source `intake:import` and so appear under *Discovery*.

## Journal entries

A **journal entry** is a dated, attributed note on one object — a repair, a move, a decision. Everyone in your organization who can read DCIM objects (`dcim.read`) sees them.

Journals are on the **Changes tab** of an asset and in the **Journal** panel of racks, sites, VLANs, prefixes, circuits, clusters and business units. People with `dcim.manage` get an add form: write the note (up to 10,000 characters), choose its kind — *Info*, *Success*, *Warning* or *Danger* — and press **Add entry**. Each entry shows its kind, author, time and text. Adding an entry also appears in the change log, as a change to the journal.

Entries are added, not edited or deleted, from the web UI.

## Tags

A **tag** is a label — `pci-scope`, `decommission-q3` — that you attach to an object. The tags on an asset appear as chips under its name at the top of the asset page.

With `dcim.manage`, **Edit tags** opens a checklist of your organization's tags. Tick the ones that apply, or type a name under **New tag** and **Create** to add one to the list, then **Save tags**. The change is recorded on the asset as one change. A tag that is restricted to certain kinds of object is offered only on those kinds.

Config contexts can be assigned by tag; see [Config contexts](./config-contexts.md).

## How long the log is kept

The change log is stored in monthly slices, and a slice is dropped whole once it is older than the retention period. The period is set once by the platform administrator for all tenants; without a setting it follows the longest general audit retention. There is no per-tenant setting: export the Changes page to keep a copy beyond it.

## API

`GET /api/v2/inventory-service/dcim/changes` lists the log with the filters `object_kind`, `object_id`, `action`, `source` (a value such as `ui`, or a family such as `intake:`), `q` (object name), `user_name`, `since` and `until`; `include_related=true` adds an object's interfaces, addresses and journal. `GET /dcim/changes/{id}` returns one change with its field diff. Journal: `GET` and `POST /dcim/objects/{kind}/{id}/journal`. Tags: `GET` and `PUT /dcim/objects/{kind}/{id}/tags`, and `/dcim/tags` to list, create, rename and delete the tags themselves. Reads need `dcim.read`, writes `dcim.manage`.
