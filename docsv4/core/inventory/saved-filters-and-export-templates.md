---
render_macros: false
---
# Saved filters and export templates

Two tools for reusing work. A **saved filter** keeps a query so you, or everyone in your organization, can apply it again in one click. An **export template** turns the rows of a list into a text format of your choosing — a hosts file, a configuration snippet, an XML feed — instead of CSV.

## Saved filters

A **saved filter** is exactly its query text, written in the inventory [query language](../features/query.md). Applying one puts its query into the query bar, so you can read what it says and change it. A NetBox *saved filter* maps onto this.

### Save a filter

1. On **Inventory → All assets**, build a query in the query bar.
2. Open the **Filters** menu beside it and choose **Save current filter…**. The button is disabled until the query is valid.
3. Give the filter a **Name**. The dialog shows the query in its canonical form, the same predicate however you spelled it.
4. Tick **Share with my organization** if everyone should see it, then **Save filter**.

### Use a filter

The **Filters** menu on the All assets lens lists the filters **Shared** with your organization first, then **Mine**, plus the built-in **Never scanned**. Choosing one fills the query bar. A shared filter shows a people icon; the trash icon deletes a filter you may delete.

### Shared and personal

- A **personal** filter is yours. No one else can see or change it.
- A **shared** filter is available to everyone in your organization. Creating, editing or deleting a shared filter, or sharing a personal one, needs permission to change organization settings (`settings.update`). Without it the **Share with my organization** switch is disabled and the filter stays yours alone.

### Manage them in Settings

**Settings → Organization → Saved Filters** lists every filter you can use: its name, the object kinds it **Applies to**, its query, and whether it is **Shared** or **Personal**. The pencil icon opens **Save changes** (name, query, kinds, sharing); the trash icon deletes. A shared filter you cannot change shows a lock instead. The query is checked against every kind you pick before it is saved. Listing needs the `assets.read` permission.

### Which kinds can have a filter

A filter can apply to **Assets**, **Endpoints** and **Interfaces**, the objects the query language can search. Only the All assets lens has the Filters menu today, so filters for endpoints and interfaces are set through **Settings → Organization → Saved Filters** (the **Applies to** checkboxes) or the API. Networks, VLANs, Circuits, Tunnels and Sites have no query bar and no Filters menu.

## Export templates

An **export template** is a short text template, run over the rows of a list export. The rows are the same ones the CSV export would give, with the same columns.

### Define a template

**Settings → Infrastructure → Export Templates** lists each template with the kinds it is **Offered on** and its file extension and MIME type. Everyone who can read DCIM objects (`dcim.read`) can see them; **Add export template**, the pencil and the cross need `dcim.manage`. The dialog asks for:

- **Name** (required).
- **Offered on** (required) — the kinds whose lists should offer the template.
- **MIME type** (default `text/plain`) and **File extension** (default `txt`) of the downloaded file.
- **Template** (required) — the text. A new template starts with `{{range .Rows}}{{.name}}` followed by a line break and `{{end}}`: one line per row.

**Preview on 5 rows** renders the template over the first five rows of the first kind you ticked and shows the output or the error, before you save.

### Write the template

Templates use Go's `text/template` syntax. The data you can read:

| Name | What it is |
|---|---|
| `.Kind` | the kind being exported |
| `.Columns` | the list of column names |
| `.Rows` | the rows; each is a map from column name to text |
| `.Count` | the number of rows |

Inside `{{range .Rows}}`, `.name` reads that row's `name` column. A custom field is a column named `cf.<name>`, which a dot cannot spell, so read it with `index`: `{{index . "cf.owner_team"}}`. The column names are the kind's import columns, listed on **Settings → Infrastructure → Import**. For example, a plain list of names under a heading:

```
# {{.Count}} {{.Kind}}
{{range .Rows}}{{upper .name}}
{{end}}
```

Alongside the usual `if`, `range` and `with`, you can use these helpers: `upper`, `lower`, `trim`, `replace`, `join`, `split`, `contains`, `hasPrefix`, `hasSuffix`, `default`, `quote`, `json`, `csv`, `int`, `float`, `add`, `sub`, `mul`, `div`, `mod` and `date`, plus the standard `and`, `or`, `not`, `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `len`, `index`, `slice`, `print`, `println`, `html`, `js` and `urlquery`.

### What the sandbox forbids

A template is text written by your users, so it runs in a closed box. It is checked when you save it, and again each time it runs. These are refused, with the reason shown:

- any function not listed above — there is no file, command, environment or network access, and no `call` or `printf`;
- `template`, `define` and `block` — templates cannot include or call each other;
- reading any top-level field other than `Kind`, `Columns`, `Rows` and `Count`;
- names such as `readfile`, `exec`, `env` or `system`, wherever they appear.

A render also stops after **10 seconds**, or when its output passes **10 MB**.

### Download with a template

On a list with an **Export** button, the arrow beside the button opens **Export with template…**: a menu of the templates offered for that kind, each with its file extension. Choosing one downloads the list's rows (honouring the filters you have on screen) through that template. If no template is offered for the kind, the menu says so and links to Settings → Export Templates. Exporting needs the permission to read that kind.

The Export button today is on **Inventory → Networks** (prefixes), **Inventory → VLANs** and **Settings → Organization → Business Units**. Offering a template on a kind whose list has no Export button does nothing yet.

## API

- Saved filters: `/api/v2/inventory-service/dcim/saved-filters` (list with `?kind=`, create, edit, delete), behind `assets.read`; sharing needs `settings.update`.
- Export templates: `/dcim/export-templates` (list, create, read, edit, delete; writes need `dcim.manage`), `GET /dcim/export?kind=<kind>&format=template&template_id=<id>` to render one, and `POST /dcim/export/preview` for a five-row preview.
