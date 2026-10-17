# Business Units

A **Business Unit** is the party an asset belongs to or is billed to: a department, a
customer, a cost centre. Units nest (Corporate, then Finance beneath it, and so on) up to
four levels deep. A NetBox *tenant* maps onto a Business Unit.

## Manage them

**Settings -> Organization -> Business Units** shows the tree with the number of assets in
each unit. Tenant admins can:

- **Create** a unit: a name, an optional slug (derived from the name when left empty), an
  optional parent and a description.
- **Edit** a unit, including moving it under another parent. A unit cannot go under itself
  or one of its own descendants, or deeper than four levels.
- **Delete** a unit. While assets or prefixes are assigned to it you choose another
  unit to move them to; units beneath the deleted one move up a level.

Anyone who can see the inventory can see the list; changing it needs the
`business_units.manage` permission, which only tenant admins hold.

## Assign assets

- **One asset:** the *Business unit* control on the asset form lists your units, *None*, and
  *Create new...* (type a name and the unit is created when you save).
- **Many assets:** Inventory -> select assets -> *Edit* -> *Business unit*.
- **Imports:** a *Business unit* column holding a name is matched to an existing unit
  (ignoring case) or creates one. A NetBox import assigns each device the unit its NetBox
  tenant maps to.

## Filter by unit

The *Business unit* facet in the Inventory filter rail shows unit names and counts. In the
query box:

| Query | Finds |
|---|---|
| `business_unit = "Finance"` | assets in the unit named (or with the slug) Finance |
| `business_unit.id = "<id>"` | assets in the unit with that id |
| `business_unit.parent = Corporate` | assets in Corporate **and every unit beneath it** |
| `not exists(business_unit)` | assets with no unit |

