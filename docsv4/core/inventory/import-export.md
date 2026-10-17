# Import and export (CSV)

Bring objects in from a spreadsheet, or take them out, one **kind** at a time. The same file
format does both: an export re-imports to no change, so you can export, edit in a spreadsheet,
and import the result.

## Import

**Settings -> Infrastructure -> Import.**

1. Pick the kind (Business units, Sites, Locations, Manufacturers, Device roles, Platforms, Device
   types, Assets, Interfaces, RIRs, Aggregates, VRFs, VLAN groups, VLANs, Prefixes, IP ranges,
   IP addresses). The page lists the kind's columns; required ones are starred.
2. **Download template** gives the header row and one example row.
3. Drop your CSV on the page. Nothing is written yet: every row is checked and the page shows
   what it would do - **Create**, **Update** (with the columns it changes), **Unchanged**, or
   **Error** with the reason in words.
4. Fix the file and drop it again, or press **Apply**. Rows with errors are skipped and
   reported; every other row is applied. Applying needs the permission to edit that kind
   (`ipam.manage` for IPAM kinds, `business_units.manage` for business units, `dcim.manage` for
   sites, locations, the device catalogue and interfaces, `assets.update` for assets); without
   it you can still check a file.

### How rows are matched

A row is matched to an existing object by its **name**, not an id, so a file is portable
between organisations. A device type is a manufacturer plus a model; a prefix, IP range or
address is matched inside its VRF (a blank `vrf` is the global table); a VLAN by its group and
VID; an asset by `asset_tag`, else its class with `hostname` or `display_name`; an interface by
its asset and name; a site by its name; a location by its site and its path inside that site.
Business units and locations name their parent by path (`Corporate/Finance`, `Floor 2` or
`Floor 2 / Cage A` inside the row's `site`).

Reference columns (`vrf`, `rir`, `group`, `manufacturer`, `business_unit`, ...) take the
referenced object's name. A row may refer to an object created later in the same file.

### Blank cells

A blank cell **leaves an existing value alone**. A cell holding `-` **clears** it. Export writes
a blank for "no value", which is why an exported file imports as no change.

### What an import records

Objects created by an import are marked as imported, and every change appears in the object's
Changes panel with the source `intake:import`. The IPAM and device-catalogue kinds are checked
by running the real import and rolling it back, so the dry run shows exactly the errors the
apply would. Business units, sites, locations, assets and interfaces are written by their own
services: the dry run checks references and values, and a rule only the service knows (for
example a duplicate slug) is reported on that row when you apply.

A file may have up to 10,000 rows and 8 MiB.

## Export

**Export** buttons on **Inventory -> Networks** (prefixes in the VRF you are looking at),
**Inventory -> VLANs** (the selected group) and **Settings -> Business Units** download the
rows as CSV. The columns are the kind's import columns. Through the API,
`GET /api/v2/inventory-service/dcim/export?kind=<kind>&format=csv|json` streams any kind and
accepts the list filters of that kind.

Exporting needs the permission to read the kind (`ipam.read`, `assets.read`, otherwise
`dcim.read`).
