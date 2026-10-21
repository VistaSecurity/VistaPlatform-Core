# Sites and locations

Every asset can say **where it is**: the **site** it is in and, optionally, the
**location** inside that site.

| Object | What it is | Examples |
|---|---|---|
| **Region** | Geography. Regions nest. | Europe › Netherlands › Amsterdam |
| **Site group** | A functional grouping, independent of geography. Groups nest. | Branches, Colo, Labs |
| **Site** | One place. In at most one region and one site group. | AMS-1, the Boston office, an AWS account |
| **Location** | A place inside one site. Locations nest. | Hall 2 › Cage 7 › Row C |

A NetBox *region*, *site group*, *site* and *location* map onto these one to one.

## Build the tree

**Settings → Organization → Sites** shows the tree — regions, then the sites in each
(under their site group), then the locations inside each site — with the number of assets
in each site and location. Tenant admins (the `dcim.manage` permission) can:

- **Create** a region or site group (a name, an optional slug, an optional parent), a
  **site** (name, status, region, site group, facility, time zone, physical and shipping
  address, latitude and longitude), or a **location** inside a site (the *+* on a site or
  location row adds one beneath it).
- **Edit** any of them. The edit dialog shows the object's **Changes** (who changed what,
  when) and its **Journal**. A location cannot move to another site, and nothing can be
  moved beneath itself. Trees are at most eight levels deep.
- **Delete** them:
  - a region or site group: what was in it moves up to its parent;
  - a location: the locations inside it go with it; their assets stay in the site;
  - a **site**: its locations go with it. While assets are in the site you choose another
    site to move them to (they lose their location, which no longer exists), and the site's
    VLANs and the prefixes scoped to it move with them.

Names and slugs are unique: a site name across the tenant, a location name among its
siblings in a site.

## Place assets

- **One asset:** the asset form's **Site** and **Location** controls. The location list is
  the chosen site's; choosing another site clears the location. Choosing only a location
  places the asset in that location's site.
- **Imports:** a *Site* column holding a name is matched to the site of that name (ignoring
  case) or creates it. A NetBox import places each device in its NetBox site.
- **Networks:** a prefix scoped to a location places the assets whose addresses fall in it
  in that location and its site, unless the asset is already in another site.
- **Cloud:** connecting a cloud account creates a site for the account (its facility is the
  provider). Each region the account's resources are in becomes a location of that site,
  and the account's network prefixes are scoped to their region's location. Resources
  are placed in their region's location.

The asset page shows **Site › Location** under the asset's name; click it to open the site.

## The site page

**Inventory → Sites** lists every site with its region, group, facility and asset count.
A site opens its page, which shows where it is (address, time zone, coordinates), what it
holds (assets, locations, racks, prefixes, VLANs), its
locations, its findings by environment, and its change log and journal. The asset count
opens the asset list filtered to the site.

## Floor plans

A location — a hall, a room, a cage — can carry a **floor plan**: a rectangle of a width
and a depth in metres or feet, drawn as a grid, with the location's racks placed on it.
Open the site, then the **Floor plan** tab, and pick the location.

- **Set up a plan.** For a location without one, a person with `dcim.manage` enters the
  width, depth and unit and presses **Create plan**. **Edit plan size** changes it later.
  A plan cannot be removed, change its unit or shrink past a rack placed on it; move or
  take off those racks first.
- **Place racks.** The racks of the location that are not on the plan wait in the
  **Unplaced racks** tray. Drag one onto the plan, or press **Place** to put it in the
  middle. Drag a placed rack to move it; a position that runs past the edge of the plan
  is drawn in red and not saved. With a rack focused, the arrow keys nudge it (a tenth of
  the unit; Shift for a whole one), **R** turns it a quarter turn and Enter opens it. The
  **On this plan** list turns a rack or takes it off the plan.
- **Read it.** Each rack is drawn at its outer width and depth, turned the way its front
  faces (the thick edge). A rack with no recorded outer size is drawn at 600 × 1000 mm and
  marked `*`. **Utilisation** colours racks by the units in use, **Power** by the share of
  the power their feeds can supply that is allocated: the accent colour up to 80 %, amber
  over 80 %, red over 95 % — the Facilities dashboard's thresholds. A rack whose figure is
  not recorded is drawn dashed, never as 0 %. Click a rack to open its page.

A rack is placed only on its own location's plan; moving a rack to another location takes
it off the old plan, and deleting a location takes its racks off. A rack's place is part
of its change log. Floor plans are not exchanged with NetBox, which has no floor plan of
its own.

## Filter by place

The **Site** facet in the Inventory filter rail lists sites by name. In the query box:

| Query | Finds |
|---|---|
| `site = "AMS-1"` | assets in the site named (or with the slug) AMS-1 |
| `site.id = "<id>"` | assets in the site with that id |
| `site.region = Europe` | assets in a site in Europe **or any region beneath it** |
| `site.group = Branches` | assets in a site in the Branches group or any group beneath it |
| `location = "Hall 2"` | assets in Hall 2 **or any location inside it** |
| `location = "AMS-1 / Hall 2 / Cage 7"` | the same by path |
| `not exists(site)` | assets with no site |

`region` and `zone` on their own are the text a cloud provider or an import states (for
example `us-east-1`); they are not the Region tree.

## API

`/api/v2/inventory-service/dcim/regions`, `/site-groups`, `/sites` and `/locations`
(list, get, create, update, delete). Reads need `dcim.read`, writes `dcim.manage`.
`DELETE /dcim/sites/{id}?reassign_to=<site id>` moves a site's assets before deleting it;
without it a site holding assets answers 409.

Floor plans: a location's `floor_plan_width`, `floor_plan_depth` and `floor_plan_unit`
are set with `PUT /dcim/locations/{id}`; a rack's `floor_x`, `floor_y` (the centre of its
footprint, in the plan's unit) and `floor_rotation` (0, 90, 180, 270) with
`PATCH /dcim/racks/{id}`. `GET /dcim/locations/{id}/floor-plan` returns the plan and every
rack in the location with its footprint, utilisation and power budget.
