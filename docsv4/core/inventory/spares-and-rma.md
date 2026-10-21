# Spares and RMA

A spare part is an **inventory item** that is not in an asset. Vista Platform keeps spares where it keeps the parts inside your equipment, so a power supply, a line card or a box of optics is one kind of record whether it is installed, on a shelf or out for repair.

Each inventory item has a **stock state**:

| State | Meaning | Where it is |
|---|---|---|
| **Installed** | In an asset. Every part a collector reports is installed. | On its asset |
| **In stock** | On a shelf, ready to use. | At a stock location |
| **Reserved** | On a shelf, set aside for a job. | At a stock location |
| **Out for RMA** | Being returned to its vendor under a return case. | Still in its asset, on the shelf, or with the vendor once it has shipped |
| **Retired** | Gone from your estate. | Nowhere |

A **stock location** is any location of a site (a hall, a cage, a store room) — see [Sites and locations](./sites.md). A spare also has a **quantity**: a box of twelve identical, unserialised optics is one row of twelve. A serialised part is a row of its own, so two spare line cards of one model sit side by side with their own serial numbers.

## Where to find it

| You want | Go to |
|---|---|
| Every spare, and the return cases in progress | **Infrastructure → Catalog & Data → Spares & RMA** |
| The spares stocked at one site | **Infrastructure → Sites & locations → open the site → Spares** |
| Take a part out of an asset, or open a return for it | **Inventory → open the asset → Hardware tab → Inventory items → To stock** or **RMA** |

You need the **DCIM read** permission (`dcim.read`) to see spares and return cases, and **DCIM manage** (`dcim.manage`) to add, install, remove, reserve, retire or return them.

## Adding spares

On **Spares & RMA**, **Add spare** asks for a name, the part number, a serial (leave it empty for a box of identical parts), the quantity and the stock location; tick **Reserved** to set the parts aside. A serialised spare always counts one.

From the Stock table you can **Reserve** or **Release** a spare, or **Retire** it. Filter the table by state to see only what is reserved, out for RMA or retired.

## Installing a spare

**Install** on a spare that is in stock or reserved asks for the asset (search by name or hostname), the name the part takes on the asset, and — for a row of several — how many units to install. The units you install become an item on the asset; the rest stay on the shelf with the count reduced. The asset's Hardware tab lists the part straight away.

Through the API an install can also name a **module bay** of the asset: the part is then the module in that bay, or, when the bay is empty, a module of the module type whose part number the spare carries is installed there first (with the spare's serial), and its interfaces are created as for any module.

## Removing a part to stock

On an asset's Hardware tab, **To stock** on an inventory item asks for the stock location. The part leaves the asset. An unserialised part joins a spare of the same name and part number already at that location, adding to its count; otherwise it becomes a spare of its own. A part with child items (a line card with optics in it) has to have the children removed first.

## Return cases (RMA)

**RMA** opens a **return case** for a part, with the vendor, the vendor's case number and notes:

- On a part in an asset, the part is marked out for RMA and stays in the asset until it ships — the usual order when the vendor sends the replacement first. Choose a stock location in the dialog to take it out of the asset now instead.
- On a spare, the spare is marked out for RMA. On a row of several, one unit splits off and goes out; the rest stay in stock.

A part has one open case at a time. The **RMA cases** table on **Spares & RMA** lists the open cases (tick **Show closed cases** for all of them) with the vendor, case number, the dates it was opened, shipped and received, where the replacement goes, and its state. Move a case on with its buttons:

| Step | What happens |
|---|---|
| **Shipped** | The shipped date is recorded (today) and the failed unit leaves its asset or shelf: it is with the vendor. |
| **Received** | The received date is recorded and the **replacement lands in stock**, at the location where the failed unit was when the case opened (its shelf, or its asset's location). It joins a spare of the same name and part there, or becomes a new spare. |
| **Close** | The case is final. A unit that shipped is retired; a unit that never shipped (still in its asset or on the shelf) goes back into service. |

Shipped and received can come in either order. A case with nowhere to put the replacement (the failed unit had no shelf and its asset has no location) is refused with the reason; give the case a replacement location through the API, or add the replacement as a spare yourself.

Every add, install, removal, reservation, return step and retirement is recorded in the item's **Changes**, with who did it and when.


## Searching

The inventory search understands `inventory_item.stock_state`: `inventory_item.stock_state = rma` finds the assets with a part out for RMA still in them, and `inventory_item.stock_state != rma` the assets with none.

## API

Spares are inventory items: `/api/v2/inventory-service/dcim/inventory-items` lists, creates, reads, changes and deletes them, with the filters `stock_state`, `location_id`, `site_id` and `asset_id=null` (the items in no asset) beside the existing ones. A create names an `asset_id` or a `location_id`, never both; a change may move a spare between stock locations and between *in stock*, *reserved* and *retired*, and never between an asset and a shelf. The transitions are their own calls: `POST /dcim/inventory-items/{id}/install` (`asset_id`, and optionally `module_bay_id`, `parent_id`, `name`, `quantity`), `POST /dcim/inventory-items/{id}/remove` (`location_id`, and optionally `name`, `stock_state`) and `POST /dcim/inventory-items/{id}/rma` (optionally `vendor`, `case_number`, `opened_at`, `notes`, `location_id`). Return cases are `GET /dcim/rma-cases` (filters `state`, `inventory_item_id`, `open`, `q`), `GET /dcim/rma-cases/{id}` and `PATCH /dcim/rma-cases/{id}` (`state`, the dates, `vendor`, `case_number`, `replacement_item_id`, `replacement_location_id`, `notes`). Reads need `dcim.read`; writes need `dcim.manage`.
