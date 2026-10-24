# Wireless LANs and links

A **wireless LAN** (WLAN) is an SSID that access points broadcast, together with how it authenticates. A **wireless LAN group** collects related WLANs (a campus, a controller site, a brand) so the same SSID on two sites can be told apart. A **wireless link** is a point-to-point wireless connection between two interfaces, such as a mesh uplink or a bridge pair. This is inventory only: there is no RF planning and no controller management.

The point of recording them is posture. Each WLAN's authentication type and cipher are looked up in the platform's algorithm catalogue, so an open network, WEP or TKIP stands out from WPA2 with AES.

## Where to find it

| You want to | Go to |
|---|---|
| See, add and edit WLANs, groups and links | **Settings → Infrastructure → Wireless** |
| See the SSIDs one access point serves, or the SSID a Wi-Fi client joined | **Inventory →** the asset **→ Interfaces** tab, under the interface table: **Wireless LANs** |

Reading needs the `wireless.read` permission and every change needs `wireless.manage`. Tenant Administrators and Security Administrators have both; Viewers can read. Without `wireless.manage` the **Add**, edit and delete buttons are not shown.

## Settings → Infrastructure → Wireless

The page has three tables.

### Wireless LANs

Each row shows the **SSID**, **Group**, **Authentication** (for example *WPA Personal (shared key) · AES (CCMP)*), **Key** and **Cipher risk**. A row waiting for approval carries a *Pending* tag and, for a user with `wireless.manage`, an **Approve** button (see [Approval](#approval)). **Add wireless LAN** asks for:

- **SSID** (required) — case-sensitive, up to 32 bytes.
- **Group** — optional.
- **Authentication** — *Open (no encryption)*, *WEP*, *WPA Personal (shared key)* or *WPA Enterprise (802.1X)*, or *Not reported*.
- **Cipher** — *Negotiated (AES or TKIP)*, *TKIP* or *AES (CCMP)*, or *Not reported*. It is not used by an open or WEP network.
- **A pre-shared key is configured** — a checkbox that records only that a key exists.
- **Status** — *Active*, *Reserved*, *Disabled* or *Deprecated*.
- **Description**.

### Wireless LAN groups

**Add group** asks for a name, an optional slug (made from the name if left blank), an optional parent group and a description.

### Wireless links

The table shows each link's **From** and **To** interfaces, **SSID**, **Authentication** and **Cipher risk**. There is no **Add** button: links are created by discovery or the API, because they join two interfaces by id. You can edit a link's status (*Connected*, *Planned* or *Decommissioning*), distance and unit (km, m, mi, ft) and description, and delete it. A discovered link waits for approval and has the same **Approve** button as a WLAN.

### Approval

A WLAN you add is active straight away. A WLAN discovery reports takes its status from the access point that broadcasts it, the same way that access point's interfaces do:

- From an **approved** access point it is **active**.
- From an access point still waiting for approval it is **pending**. It becomes active the next time the access point is interrogated after you approve the access point.
- **Approve** on the row makes it active now, whichever access point reported it.

The VLAN a discovered WLAN puts its clients on follows the same rule. A WLAN you archived or rejected stays as you left it, and so does one you added yourself. A pending WLAN is still checked for weak authentication.

## How the catalogue scores a WLAN

The cipher risk is read from the algorithm catalogue, not from a list in the product. The catalogue has a row each for AES-CCMP, TKIP, WEP and open Wi-Fi, and a WLAN's authentication and cipher point at one of them. The **Cipher risk** chip shows the band of that row's risk score (Critical, High, Medium, Low, Informational); hover for the score and the catalogue's strength rating. A WLAN with no catalogue row, such as a negotiated cipher or no authentication recorded, shows a grey **Not assessed** chip, not a clean one. The catalogue is maintained by the platform and tenants view it; see [Algorithm Reference](../features/algorithm-reference.md).

A weak WLAN raises a finding against the access point that broadcasts it (the `weak_wireless_auth` finding), with its severity taken from the catalogue. Clients that joined the WLAN are not named in the finding. See [Findings](../features/findings.md).

## Pre-shared keys are never collected

The platform records that a shared key is set (*Key set* in the table, *No key* for an open network) and nothing more. The key is never entered, read from a controller, stored or shown.

## The Wireless LANs panel on an asset

On an asset that has at least one wireless interface, the **Interfaces** tab ends with a **Wireless LANs** panel: **SSID**, **Authentication**, **Key**, **Cipher risk** and **Status**. On an access point it lists the SSIDs its radios serve; on a Wi-Fi client, the SSID it joined. It needs `wireless.read`; without it the panel says so. A switch with no wireless interface shows no panel.

"No wireless LANs reported" means no controller has reported an SSID on this asset and none is declared. It says nothing about what the access point actually broadcasts. A WLAN waiting for approval shows *Pending approval*.

The panel is on the asset page only. There is no wireless panel on the site page yet.

## How discovery fills these in

Interrogating a **UniFi** controller records each access point's radios as wireless interfaces, and its WLAN configuration as WLANs with their authentication type, cipher and whether a key is set. The passphrase itself is dropped. See [Device interrogation](../features/device-interrogation.md) and [Interfaces](./interfaces.md). Controllers other than UniFi are not read yet, and UniFi does not report wireless links, so links come from the API.

The controller's client list also says which SSID each Wi-Fi client joined. The client's interface (the one holding its MAC address) becomes a wireless **station** on that WLAN, typed by the 802.11 generation it connected with, for example *IEEE 802.11ax*. A client is joined only to a WLAN an access point has reported, and is never used to create one. If two WLANs in different groups share the SSID, the client is not joined to either. A client using a randomised (private) MAC address is not joined, because that address is not a stable way to find its interface. A client that moves to another SSID keeps the earlier one too. The client's **Relationships** tab separately shows which access point it is connected to.


## Finding assets by WLAN

The inventory query language reaches WLANs with `wireless_lan.ssid` and `wireless_lan.auth_type`. They match both the access points that serve a WLAN and the clients that joined it, so `wireless_lan.ssid:Guest` lists everything on the Guest network; see [Query](../features/query.md).

## API

`/api/v2/inventory-service/wireless/wireless-lan-groups`, `/wireless-lans` and `/wireless-links` list, create, read, change (JSON merge-patch) and delete. `GET /wireless-lans` accepts an `asset_id` filter, which is what the access point's panel uses. Reads need `wireless.read`, writes `wireless.manage`.
