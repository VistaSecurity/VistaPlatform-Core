# Racks and placement

A **rack** is a frame of numbered units (**U**) in a site, optionally in a location inside
it (a row, hall or cage). An asset is **placed** in a rack at a **position** — the lowest
unit it occupies — on the rack's **front** or **rear** face. A NetBox *rack*, *rack role*,
*rack type* and *rack reservation* map onto these one to one.

## Maintain racks

**Settings → Organization → Racks** lists every rack with its site and location, role,
status, utilisation and the number of devices in it. Tenant admins (the `dcim.manage`
permission) can:

- **Create** a rack: a name (unique within its site and location), the site, an optional
  location of that site, a role, a status (`active`, `planned`, `reserved`, `available`,
  `deprecated`), its height (1–100 U, default 42), its starting unit (default 1), whether
  its units are numbered top-down, its width, and its facility ID, serial and asset tag.
- Pick a **rack type** — a model of rack — and the rack copies the type's height,
  numbering, width and dimensions when you save.
- **Edit** a rack. Its dialog has a **Changes** tab (who changed what, when) and its
  journal. A rack cannot be made shorter than the devices in it reach. Moving a rack to
  another site or location moves its devices with it.
- **Reserve units** on the rack's **Reservations** tab: the units (`1-2, 7`) and who or
  what they are held for. Reserved units cannot overlap another reservation or a device.
- **Delete** a rack: its reservations go with it, and its devices leave the rack and stay
  in the site.

Five rack roles are provided — compute, network, storage, patching and power — and you can
add your own. A rack type that a rack uses cannot be deleted; deleting a role you added
clears it from its racks.

## Place an asset

The asset page's **Placement** card shows *Site › Location › Rack › U · Face*. **Place in a
rack** (or **Edit placement**) opens a dialog: choose the site, optionally the location
(it narrows the racks), the rack, the position (in half units) and the face. The asset
moves to the rack's site and location. **Remove from rack** takes it out; it stays in the
site.

The placement rules:

- A device occupies its **device type's height** from its position upward — a 2U device
  at U10 takes U10 and U11. Positions step in half units. An asset with no device type is
  treated as **1U and full depth**.
- A device must fit the rack: from the starting unit up to the top unit.
- A device is mounted on one face. A **full-depth** device (the device type says so) takes
  both faces; two half-depth devices can share a unit, one on each face.
- A placement over units another device holds is refused, and the message names the
  device in the way with a link to it. So is a placement over **reserved** units.
- A device in a parent device's **device bay** takes no rack units of its own, and a 0U
  device (a PDU strip mounted on the side) takes no position.
- A racked asset's site and location are its rack's: change them by moving the asset to
  another rack, or remove it from the rack first.
- Changing a racked asset's **device type** is refused when the new height no longer fits
  or overlaps a neighbour.

Two people placing devices into the same units at the same moment cannot both succeed:
one placement is saved and the other is refused.

## Utilisation

A rack's utilisation is the units its devices occupy (either face, half units counting as
half) out of its height, minus the units held only by devices whose device type is
excluded from utilisation (blanking panels, cable managers). An empty rack is **0 %**.

## Find racked assets

| Query | Finds |
|---|---|
| `rack = R12` | assets in rack R12 (by name or facility ID) |
| `rack.site:ams-1` | assets in a rack of site AMS-1 (name or slug) |
| `rack.role = network` | assets in racks with the Network role |
| `position >= 40` | assets whose lowest unit is U40 or higher |
| `face = rear` | assets mounted on a rear face |
| `exists(rack)` | every racked asset |

The asset list's CSV export carries **Site, Location, Rack, U and Face** columns.

## API

`/api/v2/inventory-service/dcim/rack-roles`, `/dcim/rack-types`, `/dcim/racks` and
`/dcim/rack-reservations` (list, create, read, edit, delete); `GET /dcim/racks/{id}/elevation`
returns the rack's per-unit occupancy of both faces, its reservations and its utilisation;
`GET`, `PUT` and `DELETE /dcim/assets/{id}/placement` read, set and clear an asset's
placement. A refused placement answers `409` with `placement_conflict` and the blocking
asset or reservation. Reads need `dcim.read`, writes `dcim.manage`.
