# Power

Vista Platform records how power reaches your equipment, in NetBox's shape:

- A **power panel** is an electrical panel at a site, optionally in one of the site's locations.
- A **power feed** is one circuit from a panel, optionally serving a rack. It has a status (*Active*, *Planned*, *Offline*, *Failed*), a type (*primary* or *redundant*), a supply (*AC* or *DC*), a phase (*single-phase* or *three-phase*), a voltage, an amperage and a **maximum utilisation** (the percentage of its capacity that may be drawn).
- A **power port** is a socket that draws power: a server's power supply, a PDU's inlet. It can declare a **maximum draw** and an **allocated draw** in watts.
- A **power outlet** is a socket that supplies power: an outlet on a PDU. It names the **power port** it draws from (the PDU's own inlet) and, on a three-phase PDU, its **feed leg** (A, B or C).

A **power cable** runs from a power port to a power outlet, or from a power port to a power feed. With those cables in place, a server's power supply traces through its PDU to the feed and the panel that power it.

Each feed's **available power** is worked out as NetBox does: |voltage| × amperage × maximum utilisation, multiplied by 1.732 for a three-phase feed. A 120 V, 20 A, single-phase feed at 80 % has 1,920 VA available; a 208 V, 30 A, three-phase feed at 80 % has 8,646 VA.

## Where to find it

| You want | Go to |
|---|---|
| A site's power panels and their feeds | **Inventory → Sites → open the site → Power panels** |
| The feeds serving a rack | **Inventory → Racks → open the rack → Power feeds** |
| A rack's power budget | **Inventory → Racks → open the rack → Power**, the **Power overlay** on its elevation, and the **Power** column of the Racks list |
| Racks drawing more than their feeds supply | **Dashboard → Facilities → Racks over power budget**, and the **Over power** column of its site table |
| What a PDU measured on each socket | **Inventory → open the asset → Ports tab → Power ports** or **Power outlets → Measured** |
| A device's power supplies or a PDU's outlets | **Inventory → open the asset → Ports tab → Power ports** or **Power outlets** |
| Power port and outlet templates of a device type | **Settings → Device Types → open the type → Power ports** or **Power outlets** |

You need the **DCIM read** permission (`dcim.read`) to see any of this and **DCIM manage** (`dcim.manage`) to add, change or delete panels, feeds, ports, outlets and power cables.

## Power panels and feeds

On the site page, the **Power panels** card lists each panel with its location and its feeds. Each feed shows its status, type, rack, rating and available power, and which device it **powers**: the power port at the far end of its cable (usually a PDU's inlet), or *not cabled*.

- **Add panel** asks for a **Name**, an optional **Location** inside the site and a **Description**. Two panels at one site cannot share a name.
- The **+** button on a panel opens **Add a feed**: **Name**, **Rack** (optional; it must be at the same site as the panel), **Status**, **Type**, **Supply**, **Phase**, **Voltage**, **Amperage** and **Maximum utilisation**. The form previews the available power. A DC supply cannot be three-phase; the voltage cannot be zero (a negative voltage records a DC plant such as -48 V); the amperage is at least 1 and the utilisation between 1 and 100 %. Two feeds on one panel cannot share a name.
- Deleting a panel deletes its feeds; deleting a feed detaches its cable. The change log keeps what they were.

A panel cannot move to another site while one of its feeds serves a rack at the current site; clear those feeds' racks first.

On the rack page, the **Power feeds** card lists the feeds declared as serving the rack, grouped by panel, with the total available power of the active ones. The **Power** card above it is the rack's power budget (see [Rack power budget](#rack-power-budget)).

## Power ports and outlets on an asset

On the **Ports** tab, the **Power ports** and **Power outlets** sections list the asset's power sockets, and the faceplate draws them in their own rows.

- A power port shows its **Type**, **Maximum draw** and **Allocated draw**. A draw nobody declared reads *not recorded*, never 0 W, and is sent as empty when you save. The allocated draw cannot exceed the maximum.
- A power outlet shows its **Type**, the **Power port** of the same asset it draws from, and its **Feed leg**.
- The **Power** summary above both sections totals the declared draws (and says on how many ports they were declared), lists the feeds the asset reaches with their available power, and for each power port says where its cable path ends. On a PDU, each inlet also shows how many of its outlets feed something and what those devices declare they draw.

**Apply templates** creates the power ports and outlets of the asset's device type along with every other component, including each outlet's power port and feed leg.

## Connect power

Use **Connect** on a power port or outlet, as for any port (see [Connect a port](./cabling.md#connect-a-port)):

- A **power outlet** cables to a **power port**.
- A **power port** cables to a **power outlet** or a **power feed**.
- Nothing else can be cabled to a power socket, and a power socket cannot be cabled to anything else. The Connect dialog labels the other kinds *(not compatible)*.

For a feed, choose *Power feed* as the far end, pick the **Site** (and optionally the **Rack**) and then the **Power feed**, shown as `panel:feed`. A feed already cabled is marked *(in use)*. The cable type defaults to *Power*. A PDU's outlets and a server's power supplies can also be cabled from **Edit cables as table**; a feed cannot, because it is not on an asset.

## Trace power

**Trace** on a power port, outlet or feed shows where the power comes from or goes to. A server's power supply traces to the PDU outlet it plugs into and, when the PDU's inlet is cabled, on through the PDU (*outlet → inlet*) to the feed, shown as `panel:feed`. When the PDU's inlet is not cabled, or the outlet names no power port, the path ends at the outlet. A feed traces to the power port it powers. A loop (a PDU's inlet cabled back to one of its own outlets) stops after 64 cables, incomplete.

## Rack power budget

A rack's power budget compares what its devices are allocated to draw with what the feeds serving it can supply, the way NetBox does:

- The feeds counted are every feed declared as serving the rack, whatever its status.
- Each feed's draw is that of the power port at the far end of its cable, usually a PDU's inlet. When that port declares an **allocated draw**, that figure is used. When it declares no draw, the figure is the sum of the allocated draws of the devices plugged into its outlets.
- The rack's utilisation is the allocated draw on all its feeds, divided by their available power, to one decimal.

On the rack page, the **Power** card shows a bar for each feed (*allocated W / available VA · %*) and one for the rack. On a three-phase feed it also shows each leg, using the outlets' feed legs, against a third of the feed's available power. A bar turns amber over 80 % and red over 95 %, the same thresholds the Facilities dashboard uses for rack space. A feed whose devices declare no draw reads *No draw declared*, and a feed with nothing cabled to it reads *Nothing cabled to it*. Neither is shown as 0 W. A rack that no feed serves has no budget at all. That does not mean it draws nothing.

Turn on **Power overlay** above the elevation to tint each device by its own declared draw as a share of the rack's available power. The tint gets stronger as the share grows, in the same amber and red. A device whose power ports declare no draw is drawn dashed and labelled *Draw not recorded*. The crypto overlay is turned off while the power overlay is on.

The Racks list's **Power** column shows each rack's utilisation, or *no feed*. The Facilities dashboard counts the **racks over power budget**: racks whose allocated draw is more than their feeds' available power. Its site table shows the count per site, or a dash for a site where no rack has a feed declared.

Measured draws (see below) are shown beside the budget. They are never part of it: the budget is about what devices are allocated, and a reading is what they drew when the PDU was last read.

## PDU collection

When a rack PDU is interrogated over SNMP (see [Device interrogation](../features/device-interrogation.md)), Vista Platform reads what the PDU measures:

| PDU | MIB | What is read |
|---|---|---|
| APC rack PDUs | PowerNet-MIB (rPDU2) | the PDU's total load, each phase's current and load, each outlet's name, on / off state, current and power |
| Raritan PDUs | PDU2-MIB | each inlet's current and power, per pole (feed leg), each outlet's name, on / off state, current and power |
| Eaton ePDUs | EATON-EPDU-MIB | each input's total power and per-phase current and power, each outlet's name, on / off state, current and power |
| Any other device | ENTITY-SENSOR-MIB | a power supply's watts and amperes sensors (a server's or switch's power supply, as a power port) |

Each reading is matched to the PDU's power ports and outlets. A socket is first matched by name. If no name matches, it is matched by number: the PDU's outlet 3 is the one power outlet whose name ends in 3, such as *Power Outlet 3* from the device type. When two sockets could match, neither is used. A matched socket keeps everything a person or a sync recorded; only its **measured** draw, current, on / off state and reading time are written, and an outlet's power port and feed leg are filled only when nothing was recorded. A socket the PDU lists that the asset does not have is added as discovered. It is *pending* until its asset is approved, and then it becomes active.

The **Ports** tab shows the reading in a **Measured** column (for example *On · 40 W · 0.2 A*), with the time it was taken on hover. A socket nothing has measured reads *not measured*.

What is not collected: anything else a PDU reports, such as its user accounts, contact or location, and the SNMP community used to read it. Only the first unit of a daisy-chained set is read. A reading is not written to an object's change log, but adding a socket is.

## Search by power

The inventory search reads the feeds an asset's power ports reach:

| Field | Example |
|---|---|
| `power_feed.status` | `power_feed.status = failed` — assets drawing from a failed feed |
| `power_feed.type`, `power_feed.supply`, `power_feed.phase` | `power_feed.phase = three-phase` |
| `power_feed.voltage`, `power_feed.amperage`, `power_feed.available_power` | `power_feed.available_power < 2000` |
| `power_feed.panel`, `power_feed.rack`, `power_feed.site` | `power_feed.panel = "Panel 1"` |

An asset that reaches no feed (an uncabled supply, a PDU whose inlet is not cabled) matches none of them, and satisfies `!=`.

## API

Under `/api/v2/inventory-service/dcim`:

- `GET/POST /power-panels`, `GET/PATCH/DELETE /power-panels/{id}` — filters `site_id`, `location_id`, `name`.
- `GET/POST /power-feeds`, `GET/PATCH/DELETE /power-feeds/{id}` — filters `power_panel_id`, `rack_id`, `site_id`, `location_id`, `operational_status`, `type`, `supply`, `phase`, `business_unit_id`. `available_power` is read-only.
- `GET /power-ports/{id}/trace`, `GET /power-outlets/{id}/trace`, `GET /power-feeds/{id}/trace` — the cable path.
- `GET /assets/{id}/power` — the asset's power summary.
- `GET /racks/{id}/power` — the rack's power budget: each feed with its allocated draw, available power, utilisation, legs and measured load, and each device's own declared draw and share. The rack list (`GET /racks`) carries `power_utilization`, or `null` for a rack no feed serves.
- Power ports and outlets carry the read-only `measured_draw`, `measured_current`, `measured_at` (and `measured_legs` on a port, `measured_state` on an outlet).

Power ports and outlets keep their routes (`/power-ports`, `/power-outlets`, `/assets/{id}/power-ports`, `/assets/{id}/power-outlets`).
