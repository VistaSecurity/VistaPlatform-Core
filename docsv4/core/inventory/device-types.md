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

## Searching

The inventory search understands `device_type` (model, slug or part number: `device_type = "C9300-48P"`), `device_type.manufacturer` (`device_type.manufacturer:cisco`), `device_role`, `platform`, `serial` and `asset_tag`.
