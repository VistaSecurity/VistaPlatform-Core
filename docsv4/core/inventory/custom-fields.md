# Custom fields

A **custom field** is a field you add to inventory objects of your own choosing: an owner team on every asset, a cost centre on every prefix, a service tier on every circuit. You define it once, say which kinds of object carry it, and from then on the object's page shows it, edits it, checks it on every save, and the inventory query language can search on it. A NetBox *custom field* and *custom field choice set* map onto these one to one.

## Define a field

**Settings → Infrastructure → Custom Fields** has two tabs, **Fields** and **Choice sets**. Everyone who can read DCIM objects (`dcim.read`) can see the definitions. Creating, editing and deleting them needs the `custom_fields.manage` permission, which tenant admins hold.

On the **Fields** tab, **Add field** opens a dialog:

| Field | What it does |
|---|---|
| **Name** * | Lowercase letters, digits and underscores, starting with a letter. It is how a query names the field: `cf.<name>`. |
| **Label** | The words shown on pages. Without one the name is shown. |
| **Type** * | See the table below. |
| **Object kinds** * | The kinds of object that carry the field. A filterable checklist of every object kind. |
| **Choice set** * | For *Selection* and *Multiple selection* only: the set the choices come from. |
| **Related object kind** * | For *Object* and *Multiple objects* only: the kind the value points at. |
| **Required** | A person saving an object must fill it in. |
| **Default** | A new object starts with this value. For *Multiple selection*, separate values with a vertical bar (`\|`). |
| **Minimum** / **Maximum** | For *Integer* and *Decimal*. |
| **Validation regex** | For *Text*, *Text (long)* and *URL*: a value must match it. |
| **Shown** | *Always*, *If set* (hidden while empty) or *Hidden*. |
| **Editable** | *Yes*, *Read-only*, or *Not in the form*. |
| **Group** and **Weight** | Fields with the same group are listed under a heading; lower weights come first (default 100). |
| **Cloneable** | Copied when an object is cloned. |
| **Description** | Shown as a tooltip on the field's label. |

The available types are Text, Text (long), Integer, Decimal, Boolean (true/false), Date, Date & time, URL, JSON, Selection, Multiple selection, Object and Multiple objects.

The table lists each field with its `cf.<name>`, its type, the kinds it applies to and its group. The pencil icon edits a field and the cross deletes it. Deleting a field does not erase the values objects already hold, but they are no longer shown, checked or searchable. The deletion is recorded in the change log (see [Changes, journal and tags](./changes-and-journal.md)).

### Choice sets

A selection field draws its choices from a **choice set**. On the **Choice sets** tab, **Add choice set** takes a **Name**, the **Choices** (one per line, either `value` or `value|Label`), an **Order alphabetically** switch and a description. A set that a field uses cannot be deleted.

## Which objects carry them

The **Object kinds** checklist offers every object kind in the vocabulary, but a value can be seen and edited in the web UI where the object's page has a **Custom fields** panel. Today that is:

- an **asset** — Inventory → open the asset → **Overview** tab, under **Custom fields**;
- an **interface** — in the interface's drawer on the asset's **Interfaces** tab;
- a **prefix** — in the prefix's panel on Inventory → **Networks**;
- a **VLAN** — in its detail on Inventory → **VLANs**;
- a **circuit** — in its drawer on Inventory → **Circuits**;
- a **business unit** — in its dialog under Settings → Organization → **Business Units**.

If no field applies to the kind, the panel says so and points to Settings → Custom Fields.

## Fill in a field

On any of those pages, **Edit custom fields** turns the panel into a form, with a control that fits each type (a date picker, a drop-down for *Selection*, checkboxes for *Multiple selection*, a text area for *JSON*, and so on; *Object* and *Multiple objects* take object ids). **Save** stores only the fields you changed. Editing needs the permission to edit the object itself: `assets.update` for an asset, `ipam.manage` for a prefix or VLAN, `circuits.manage` for a circuit, `business_units.manage` for a business unit, `dcim.manage` for an interface. Fields marked **Required** carry an asterisk.

## How values are checked

Values are checked on **every write**, whichever way it arrives: the page, the API or a CSV import. A write is refused, with the reason in words, when:

- the value does not fit the type (text in an integer field, a malformed date or URL, invalid JSON);
- it is not one of the choice set's choices;
- a number is outside the **Minimum** / **Maximum**, or text does not match the **Validation regex**;
- an *Object* value points at an object that does not exist;
- a **Required** field is empty.

Two rules keep the checks from getting in discovery's way. **Required** is enforced for writes by people (the page, the API, CSV import) but **not** for discovery, sync or system writes, so a new required field can never stop a scan. And an update that does not mention custom fields at all is not re-checked.

## Import and export columns

A custom field is a CSV column named `cf.<name>`, for example `cf.owner_team`. On import, a blank cell leaves the stored value alone and `-` clears it, as with every other column (see [Import and export](./import-export.md)); a column naming a field that does not apply to the kind is reported as an error on the row. Export writes one `cf.<name>` column for each field that applies to the kind, so an exported file imports as no change.

Custom field columns are available for the kinds the importer handles directly (the IPAM kinds and the device catalogue kinds that carry custom fields, such as prefixes, VLANs and IP addresses). They are not yet available for business units, sites, locations, assets or interfaces.

## Find objects by a custom field

In the inventory query bar, a custom field is `cf.<name>`, on assets and on interfaces:

```
cf.owner_team:payments
cf.tier in (gold, silver)
exists(cf.owner_team)
```

The query bar completes the names of your own fields. A value is compared as text: `:` ignores case, `=` does not. Ordering comparisons (`<`, `>`, ranges) on a custom field are refused. A name no field uses matches nothing rather than failing. See [Query](../features/query.md) for the language.

## API

`/api/v2/inventory-service/dcim/custom-fields` and `/dcim/custom-field-choice-sets` (list, create, read, edit, delete). Reads need `dcim.read`, writes `custom_fields.manage`. An object's values travel in its `custom_fields` property on that object's own route; a PATCH names only the fields it changes.
