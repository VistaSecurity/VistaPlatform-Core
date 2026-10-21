# Device types

A **device type** is a hardware model: a Cisco Catalyst 9300-48P, a Dell PowerEdge R650, an APC AP7900B rack PDU. It records the manufacturer, the part number, the height in rack units, whether it is full depth, its airflow, and the interfaces and ports every unit of that model has (its **templates**). Assigning a device type to an asset tells the inventory what the box is and lets it create the box's interfaces in one step.

The catalogue follows the NetBox device-type model, so a type imported from NetBox's community library means the same thing here.

## What ships with the product

Every installation carries a catalogue of common models, taken from the NetBox community device-type library (public domain, CC0-1.0): Cisco Catalyst 9200/9300/9500 and Nexus 9300 switches, Arista 7050 and 7280, Juniper EX4300, EX4400, QFX5120 and SRX, FortiGate 60F to 600F, Palo Alto PA-220 to PA-3400, F5 BIG-IP i-series, Ubiquiti UniFi switches, gateways and access points, Dell PowerEdge, HPE ProLiant DL360/DL380, Supermicro 1U/2U servers and APC rack PDUs — 154 models in all. The manufacturers list also includes the vendors the platform recognises from MAC addresses.

Built-in types, manufacturers and device roles are marked **Built in**. Everyone can use them; nobody can change or delete them. To change one, import or create your own copy.

## Where to find them

**Settings → Infrastructure → Device Types.** Filter by manufacturer, show built-in types or your own, and search by model or part number. Click a type to see its templates by kind: interfaces, console ports, console server ports, front and rear ports, module bays, device bays, power ports and power outlets.

Next to it: **Manufacturers**, **Device Roles** (what a device does — one role ships for each hardware and virtual asset class: Switch, Router, Firewall, Server, Access point, …) and **Platforms (OS)** (the operating system or firmware family: IOS-XE, Junos, FortiOS, Ubuntu). These are simple lists; add your own entries there.

You need the **DCIM read** permission to see these pages and **DCIM manage** to add, edit, delete or import.

## Importing a type from the library

When a model you own is not in the catalogue, find its file in the [device-type library](https://github.com/netbox-community/devicetype-library) (under `device-types/<Manufacturer>/`), then click **Import from library** and paste the file's contents or upload the file. Several files can go in one paste, separated by a line containing only `---`.

Each file becomes your organization's own device type with all its templates; a manufacturer you do not have yet is created. A model already in the catalogue (built in or yours) is reported as **Already in the catalogue** and left as it is. A value the platform cannot store — an interface type it does not know yet, a port with an over-long name — is dropped or set to *Other*, and the result lists what was adjusted. An import is all or nothing: if one file is not a valid device-type file, nothing is imported.

Elevation images are not imported yet; the type records where the library keeps them.

## Assigning a type to an asset

Open the asset, click **Edit**, and use the **Hardware** fields: **Device type** (type to search; each choice shows its height), **Device role**, **Platform (OS)**, **Serial** and **Asset tag**. A device type can only be given to a hardware asset (a switch, server, firewall, PDU, …), not to a virtual machine or a cloud resource. An asset tag must be unique among your assets.

The asset page's **Hardware** card shows the manufacturer, model, part number, height, serial, asset tag, role and platform.

## Apply templates

On the Hardware card, **Apply templates** creates the device type's interfaces on the asset. It merges with what discovery already found rather than adding a second copy:

- An interface the type declares and the asset does not have yet is created.
- An interface the asset already has under the same name — `GigabitEthernet1/0/1` reported by SNMP as `Gi1/0/1` counts as the same name — is kept. Its measured MAC address, speed, duplex, MTU and up/down state are never overwritten, nor its enabled flag or description. If it had no specific type (*Other*), it takes the template's type; a missing label or PoE setting is filled in.
- Applying the same type again changes nothing.
- Changing the asset to a different device type and applying again adds the new type's interfaces. An interface the old type created is removed only if the new type does not have it, no collector has ever reported it, and nothing is attached to it (no MAC address, IP address or cable). Everything discovered stays.

For example: SNMP has reported 12 ports of a switch. Assigning the Catalyst 9300-48P and applying templates gives the switch its 48 typed GigabitEthernet ports (plus its stack and management ports), the 12 measured ones keeping their MAC addresses and state.

Console, front and rear ports, power ports and outlets, and module and device bays are stored on the type but not created on the asset yet; the card says how many are waiting.

## End of sale, support and life

A device type and a platform (OS) each carry three lifecycle dates: **End of sale**, **End of support** and **End of life**. Set them in the type's or platform's form (**Settings → Infrastructure → Device Types** or **Platforms (OS)**, **Edit**), or in a device-type or platform import file (`end_of_sale`, `end_of_support`, `end_of_life`, as `YYYY-MM-DD`).

The same form can link the type or platform to an entry in the **end-of-life catalogue**, the platform-curated list of product support dates (a device type links to a *hardware* entry, a platform to an *operating system* entry). A date you leave blank falls back to the linked entry: end of support takes the entry's end-of-support date, end of life its extended-support date. The catalogue has no end-of-sale date. A date you set always wins over the catalogue.

You do not have to link every entry yourself. When you create or import a device type or platform, and once a day for those already there, the inventory looks for the one catalogue entry that fits and links it. A device type matches a hardware entry whose vendor is its manufacturer and whose product is its model or part number (ignoring case and extra spaces), or, failing that, a product that opens the model at a whole word or dash (product `C9300` for model `C9300-48P`). A platform matches an operating-system entry by its name, or by its "name release" (`Ubuntu 22.04`). If two or more entries fit, which happens whenever a product has several releases and the name does not say which, nothing is linked. A link you chose is never replaced, and a type or platform you unlinked stays unlinked. The edit form says whether the link was made automatically or by you; choose another entry, or None, to override an automatic one. Built-in device types and platforms are not matched.

Built-in device types and platforms cannot be edited, so their dates cannot be set; use your own copy of the type if you need them.

## Commercial lifecycle

The asset page's **Hardware** tab has a **Lifecycle** card with what the asset cost and who sold it, its warranty and support contract, and when it was installed and decommissioned:

| Field | Notes |
|---|---|
| Purchase date, Purchase cost, Currency, Purchase order | The cost is an amount with at most two decimals; the currency is an ISO 4217 code such as USD or EUR. |
| Vendor (seller) | Who sold it — a reseller or distributor. The maker is the device type's manufacturer. |
| Warranty start, Warranty end | The end cannot be before the start. |
| Support contract, Support contract ends | |
| Installed, Decommissioned | Decommissioned cannot be before installed. |

People with the **DCIM manage** permission click **Edit** on the card; each save is recorded in the asset's **Changes** tab. The asset import file has the same eleven columns (`purchase_date`, `warranty_start`, `warranty_end`, `purchase_cost`, `purchase_currency`, `purchase_order`, `vendor`, `support_contract`, `support_contract_end`, `installed_at`, `decommissioned_at`), and the import's preview shows each one that would change.

The card also shows two states:

- **Warranty** — *Under warranty*, *Warranty ends within 90 days*, or *Warranty expired*, from the warranty end date.
- **End of support** — *Supported*, *End of support within 12 months*, or *Past end of support*. The date used is the earlier of the device type's and the platform's end of support (each the date set on it, or else its end-of-life catalogue entry's), and the card says which one it is and where it came from. An asset whose hardware is supported until 2030 on an operating system that lost support last year is past end of support.

When nothing is recorded, the card says **Warranty not recorded** and **End of support not recorded**. That is not the same as covered or supported: it means nobody has told the platform.

The asset list has optional **Warranty end**, **End of support**, **Purchased** and **Vendor (seller)** columns, and the list's CSV export includes them, blank when not recorded.

## Spare parts

Parts that are not in an asset — a spare power supply, a box of optics, a unit out for return — are inventory items with a stock location instead of an asset. Installing a spare into a module bay creates a module of the module type its part number names. See [Spares and RMA](./spares-and-rma.md).

## Searching

The inventory search understands `device_type` (model, slug or part number: `device_type = "C9300-48P"`), `device_type.manufacturer` (`device_type.manufacturer:cisco`), `device_role`, `platform`, `serial` and `asset_tag`.

For the commercial lifecycle: `warranty_end`, `purchase_date`, `support_contract_end`, `installed_at` and `decommissioned_at` compare as dates (`warranty_end < now+90d` finds warranties ending in the next 90 days; `not decommissioned_at:*` finds assets still in service), `vendor` matches the seller (`vendor = "Acme Resale"`), and `end_of_support` is the effective end-of-support date described above (`end_of_support < now` finds assets past end of support). An asset with no date recorded never matches a date comparison.
