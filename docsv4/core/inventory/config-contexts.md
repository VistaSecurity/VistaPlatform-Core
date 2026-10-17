# Config contexts

A **config context** is a named piece of JSON — NTP servers, a syslog target, a login banner — that applies to every asset matching a set of criteria. Each asset's page shows the **rendered** result: all the contexts that apply to it, merged by weight into one document. Use it to keep the settings your devices should share in one place instead of repeating them per asset. A NetBox *config context* maps onto this one to one.

## Where to find them

**Settings → Infrastructure → Config Contexts** lists every context with its weight, whether it is **Active**, and what it **Applies to**. Everyone who can read DCIM objects (`dcim.read`) can open the page; adding, editing and deleting needs `dcim.manage`.

## Add a config context

**Add config context** opens a dialog:

- **Name** (required) — unique in your organization.
- **Weight** — a whole number from 0 to 32767 (default 1000). Lower weights merge first; a heavier context wins a conflicting key.
- **Active** — only active contexts are used when an asset's config is rendered. Switch it off to keep a context without applying it.
- **Data (JSON object)** — the document itself. It must be a JSON object, like `{"ntp": ["10.0.0.1", "10.0.0.2"]}`; the dialog refuses anything else and says what is wrong.
- **Applies to** — see below.

The pencil icon edits a context and the cross deletes it. A deleted context stops applying to assets; the deletion is recorded in the change log (see [Changes, journal and tags](./changes-and-journal.md)).

## Who a context applies to

**Applies to** has one collapsible list per criterion:

| Criterion | Matches an asset when… |
|---|---|
| **Locations** | the asset is in the location, or in a location inside it |
| **Device types** | its device type is one of those picked |
| **Device roles** | its device role is one of those picked |
| **Platforms** | its platform is one of those picked |
| **Business units** | it belongs to one of those business units |
| **Tags** | it carries one of those tags |

The rules:

- Pick any number of values in a list; an asset matches the list if it matches **any one** of them.
- An asset must match **every list you fill in**.
- A context with **every list empty applies to all assets** (the table shows **All assets**).

Sites, regions, site groups and clusters are not yet available as criteria.

## How the merge works

For an asset, the platform takes every **active** context that applies and merges them lightest weight first (ties are ordered by name):

- JSON objects are merged key by key, going as deep as the objects go.
- Where two contexts set the same key, the heavier context wins.
- Lists, numbers, text and `null` are **replaced**, not combined. A list in a heavier context swaps out the whole list from a lighter one.

For example, a context of weight 100 with `{"ntp": ["10.0.0.1"], "banner": "Authorized use only"}` and one of weight 500 with `{"ntp": ["10.9.0.1"], "syslog": {"host": "10.0.0.9"}}` render as `{"ntp": ["10.9.0.1"], "banner": "Authorized use only", "syslog": {"host": "10.0.0.9"}}`.

## See the result on an asset

**Inventory → open any asset → Config Context tab.** It shows the **Rendered config** as JSON and, under **Contributed by**, the contexts that produced it in merge order with each one's weight. **Manage config contexts** links to the settings page. If no active context matches the asset, the tab says so; that means nothing applies, not that the asset has no configuration.

The tab needs `dcim.read`. It is read-only: to change what an asset receives, change the contexts or the asset's location, device type, role, platform, business unit or tags.

## API

`/api/v2/inventory-service/dcim/config-contexts` (list, create, read, edit, delete) and `GET /dcim/assets/{id}/config-context`, which returns the merged document and the contributing contexts. Reads need `dcim.read`, writes `dcim.manage`.
