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
