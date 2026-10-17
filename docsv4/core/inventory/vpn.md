# VPN tunnels

A **tunnel** is an encrypted link between two gateways: an IPsec site-to-site tunnel between two firewalls, a GRE tunnel, a WireGuard or OpenVPN link. Each tunnel is built from **IKE** (phase 1) and **IPsec** (phase 2) settings, and every algorithm in those settings is looked up in the platform's algorithm catalogue, so you can see which tunnels still offer a weak Diffie-Hellman group or 3DES and which will need post-quantum migration.

## The objects

| Object | What it is |
|---|---|
| **Tunnel group** | A named collection of tunnels (for example one per customer or per region). |
| **Tunnel** | One link, with its encapsulation, status and IPsec profile. |
| **Tunnel termination** | One end of a tunnel: a role (*peer*, *hub* or *spoke*) on an interface of an asset, optionally with the outside IP address. An interface terminates at most one tunnel. |
| **IKE proposal** | One phase-1 transform: authentication method, encryption, integrity, Diffie-Hellman group and lifetime. |
| **IKE policy** | An IKE version (1 or 2) and mode, with the list of IKE proposals it offers. |
| **IPsec proposal** | One phase-2 transform: encryption, integrity and lifetimes. |
| **IPsec policy** | The IPsec proposals offered, and the perfect-forward-secrecy (PFS) group. |
| **IPsec profile** | An IKE policy plus an IPsec policy (mode *ESP* or *AH*). A tunnel names a profile. |

## Where to find it

| You want to | Go to |
|---|---|
| See every tunnel with its posture | **Inventory → Tunnels** (in the *Cryptography* group of lenses) |
| Maintain proposals, policies and profiles | **Settings → Infrastructure → VPN Policies** |
| See how many tunnels need migration | The **Tunnels needing migration** tile on the PQC dashboard, which opens the Tunnels lens |

Reading needs the `vpn.read` permission and every change needs `vpn.manage`. Tenant Administrators and Security Administrators have both; Viewers can read. Without `vpn.manage` the **Add**, edit and delete buttons are not shown.

## The Tunnels lens

Each row shows the tunnel's **Name**, **Encapsulation** (IPsec transport or tunnel, IP-in-IP, GRE, WireGuard, L2TP, PPTP or OpenVPN), **Status**, **Ends**, **IKE** version, **Weakest component** and **PQC** class. Filter by encapsulation with the *All encapsulations* menu.

- **Ends** lists the devices and interfaces the tunnel terminates on, and any remote gateway address a collector measured whose far end is not (yet) an interface in your inventory.
- **Weakest component** is the single worst catalogue risk across both phases, shown as a risk band (Critical, High, Medium, Low, Informational) with the algorithm's code, for example `3DES`. Hover for the phase and role it came from. A tunnel where no algorithm could be matched to the catalogue says **Not assessed**; that is not the same as safe.
- **PQC** is the tunnel's post-quantum readiness class: *Needs PQC migration* (the tunnel's Diffie-Hellman groups are classical key agreement, which a quantum computer can break), *PQC ready*, *Symmetric only* or *Not classified*.

Click a row to open the tunnel's side panel. Its **Proposals** tab lists the IKE (phase 1) proposals, with the IKE version, mode and PFS group, and the IPsec (phase 2) proposals. Next to each algorithm a chip gives the catalogue's strength rating; hover for the algorithm code, its deprecation status and its risk score. An algorithm the catalogue does not know is marked *unassessed*. The **Changes** tab shows who changed the tunnel and when.

**Add tunnel** asks for a name, an encapsulation, a status (*Active*, *Planned* or *Disabled*), an IPsec profile and a description. The pencil and bin buttons on a row edit and delete a tunnel.

## Policies, proposals and profiles

**Settings → Infrastructure → VPN Policies** has five tables: IPsec profiles, IKE policies, IKE proposals, IPsec policies and IPsec proposals. Each has an **Add** button and an edit and delete button per row. Discovered rows arrive from interrogated devices; you can also add your own.

- **IKE proposal** — authentication (pre-shared keys, certificates, RSA signatures or DSA signatures), encryption (`aes-128-cbc` … `aes-256-gcm`, `3des-cbc`, `des-cbc`), integrity (`hmac-sha1` … `hmac-sha512`, `hmac-md5`, or *None (AEAD)*), the Diffie-Hellman group number and the SA lifetime. The table shows each algorithm with its catalogue strength.
- **IKE policy** — version (IKEv2 or IKEv1), mode (main or aggressive, for IKEv1) and the proposals it offers.
- **IPsec proposal** — encryption, integrity and lifetimes (seconds and KB).
- **IPsec policy** — the PFS group (empty for none) and the proposals offered.
- **IPsec profile** — mode (ESP or AH), an IKE policy and an IPsec policy.

## How the catalogue scores a tunnel

Scoring is not done in the VPN pages. A tunnel's IKE and IPsec settings are recorded as crypto configurations, and every algorithm in them (encryption, integrity, Diffie-Hellman group, PFS group) is matched to a row of the algorithm catalogue. The tunnel's risk is the highest `risk_score` among those rows, banded with the platform's one severity ladder. The catalogue is maintained by the platform and tenants view it, they do not edit it; see [Algorithm Reference](../features/algorithm-reference.md). When a rating changes, tunnels move with it; nothing on the tunnel itself has to be edited.

The same rule means a Diffie-Hellman group or a cipher that is not in the catalogue is shown as unassessed rather than given an invented score.

## Pre-shared keys are never collected

The platform records that an IKE policy uses a pre-shared key, and shows *Configured* in the **Pre-shared key** column, but it never reads, stores, shows or syncs the key itself. Collectors project a firewall's VPN configuration onto the fields above and drop everything else; no field in these pages accepts a key. The same goes for the `vpn.manage` permission: it cannot reveal a key because none is held.

## How discovery fills these in

Interrogating a **Fortinet**, **Palo Alto** or **Cisco** device, or a **UniFi** gateway, records its tunnels, their terminations on the device's own interfaces, and their IKE and IPsec proposals, each scored against the catalogue. See [Device interrogation](../features/device-interrogation.md). Cloud VPN gateways are not read yet. An empty lens means nothing has reported a tunnel and nobody declared one, not that there are none.


## Finding tunnels

The inventory query language reaches tunnels with `tunnel`, `tunnel.encapsulation`, `tunnel.ike_version` and `tunnel.pfs_group`; see [Query](../features/query.md).

## API

`/api/v2/inventory-service/vpn/` has `tunnel-groups`, `tunnels`, `tunnel-terminations`, `ike-proposals`, `ike-policies`, `ipsec-proposals`, `ipsec-policies`, `ipsec-profiles`, `l2vpns` and `l2vpn-terminations`, each with list, create, read, change (JSON merge-patch) and delete. Reads need `vpn.read`, writes `vpn.manage`. Tunnel groups, tunnel terminations and L2VPNs are created through the API or by discovery; the pages above have no button to add them.
