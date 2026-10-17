# Vocabulary

Vista Platform uses one set of nouns for the objects it inventories, in the
user interface, the API and these docs. Where an industry data model already
has a name for a thing, Vista uses it. This page lists the terms.

The NetBox column shows the object each term corresponds to when you exchange
data with a NetBox instance. A dash means there is no counterpart.

<!-- BEGIN GENERATED: vocabulary — from standards/vocabulary.yaml (make generate) -->
| Term | Plural | Meaning | NetBox counterpart |
|---|---|---|---|
| Asset | Assets | The configuration item. A NetBox Device or Virtual Machine is an asset. | `dcim/device, virtualization/virtual-machine` |
| Endpoint | Endpoints | A listening (address, port, transport, protocol) on an asset. | `ipam/service` |
| Business Unit | Business Units | A Business Unit. | `tenancy/tenant` |
| Contact | Contacts | A Contact. | `tenancy/contact` |
| Contact Role | Contact Roles | A Contact Role. | `tenancy/contact-role` |
| Contact Assignment | Contact Assignments | A Contact Assignment. | `tenancy/contact-assignment` |
| Region | Regions | A Region. | `dcim/region` |
| Site Group | Site Groups | A Site Group. | `dcim/site-group` |
| Site | Sites | A Site. | `dcim/site` |
| Location | Locations | A Location. | `dcim/location` |
| Rack Role | Rack Roles | A Rack Role. | `dcim/rack-role` |
| Rack Type | Rack Types | A Rack Type. | `dcim/rack-type` |
| Rack | Racks | A Rack. | `dcim/rack` |
| Rack Reservation | Rack Reservations | A Rack Reservation. | `dcim/rack-reservation` |
| Manufacturer | Manufacturers | A Manufacturer. | `dcim/manufacturer` |
| Device Type | Device Types | A Device Type. | `dcim/device-type` |
| Module Type | Module Types | A Module Type. | `dcim/module-type` |
| Module Bay | Module Bays | A Module Bay. | `dcim/module-bay` |
| Module | Modules | A Module. | `dcim/module` |
| Device Role | Device Roles | A Device Role. | `dcim/device-role` |
| Platform (OS) | Platforms | A Platform. | `dcim/platform` |
| Inventory Item | Inventory Items | An Inventory Item. | `dcim/inventory-item` |
| Inventory Item Role | Inventory Item Roles | An Inventory Item Role. | `dcim/inventory-item-role` |
| Virtual Chassis | Virtual Chassis | A Virtual Chassis. | `dcim/virtual-chassis` |
| Device Bay | Device Bays | A Device Bay. | `dcim/device-bay` |
| Interface Template | Interface Templates | An Interface Template. | `dcim/interface-template` |
| Console Port Template | Console Port Templates | A Console Port Template. | `dcim/console-port-template` |
| Console Server Port Template | Console Server Port Templates | A Console Server Port Template. | `dcim/console-server-port-template` |
| Front Port Template | Front Port Templates | A Front Port Template. | `dcim/front-port-template` |
| Rear Port Template | Rear Port Templates | A Rear Port Template. | `dcim/rear-port-template` |
| Module Bay Template | Module Bay Templates | A Module Bay Template. | `dcim/module-bay-template` |
| Device Bay Template | Device Bay Templates | A Device Bay Template. | `dcim/device-bay-template` |
| Power Port Template | Power Port Templates | A Power Port Template. | `dcim/power-port-template` |
| Power Outlet Template | Power Outlet Templates | A Power Outlet Template. | `dcim/power-outlet-template` |
| Interface | Interfaces | An Interface. | `dcim/interface, virtualization/vm-interface` |
| MAC Address | MAC Addresses | A MAC Address. | `dcim/mac-address` |
| Console Port | Console Ports | A Console Port. | `dcim/console-port` |
| Console Server Port | Console Server Ports | A Console Server Port. | `dcim/console-server-port` |
| Front Port | Front Ports | A Front Port. | `dcim/front-port` |
| Rear Port | Rear Ports | A Rear Port. | `dcim/rear-port` |
| Power Port | Power Ports | A Power Port. | `dcim/power-port` |
| Power Outlet | Power Outlets | A Power Outlet. | `dcim/power-outlet` |
| Power Feed | Power Feeds | A Power Feed. | `dcim/power-feed` |
| Power Panel | Power Panels | A Power Panel. | `dcim/power-panel` |
| Cable | Cables | A Cable. | `dcim/cable` |
| Cable Termination | Cable Terminations | A Cable Termination. | `dcim/cable-termination` |
| Cable Path | Cable Paths | A Cable Path. | `dcim/cable-path` |
| Unresolved Termination | Unresolved Terminations | An Unresolved Termination. | — |
| RIR | RIRs | An RIR. | `ipam/rir` |
| Aggregate | Aggregates | An Aggregate. | `ipam/aggregate` |
| VRF | VRFs | A VRF. | `ipam/vrf` |
| Route Target | Route Targets | A Route Target. | `ipam/route-target` |
| Prefix Role | Prefix Roles | A Prefix Role. | `ipam/role` |
| Prefix | Prefixes | A Prefix. | `ipam/prefix` |
| IP Range | IP Ranges | An IP Range. | `ipam/ip-range` |
| IP Address | IP Addresses | An IP Address. | `ipam/ip-address` |
| VLAN Group | VLAN Groups | A VLAN Group. | `ipam/vlan-group` |
| VLAN | VLANs | A VLAN. | `ipam/vlan` |
| FHRP Group | FHRP Groups | An FHRP Group. | `ipam/fhrp-group` |
| FHRP Group Assignment | FHRP Group Assignments | An FHRP Group Assignment. | `ipam/fhrp-group-assignment` |
| ASN | ASNs | An ASN. | `ipam/asn` |
| Circuit Provider | Providers | A Provider. | `circuits/provider` |
| Provider Account | Provider Accounts | A Provider Account. | `circuits/provider-account` |
| Provider Network | Provider Networks | A Provider Network. | `circuits/provider-network` |
| Circuit Type | Circuit Types | A Circuit Type. | `circuits/circuit-type` |
| Circuit | Circuits | A Circuit. | `circuits/circuit` |
| Circuit Termination | Circuit Terminations | A Circuit Termination. | `circuits/circuit-termination` |
| Circuit Group | Circuit Groups | A Circuit Group. | `circuits/circuit-group` |
| Circuit Group Assignment | Circuit Group Assignments | A Circuit Group Assignment. | `circuits/circuit-group-assignment` |
| Cluster Type | Cluster Types | A Cluster Type. | `virtualization/cluster-type` |
| Cluster Group | Cluster Groups | A Cluster Group. | `virtualization/cluster-group` |
| Cluster | Clusters | A Cluster. | `virtualization/cluster` |
| Virtual Disk | Virtual Disks | A Virtual Disk. | `virtualization/virtual-disk` |
| Tunnel Group | Tunnel Groups | A Tunnel Group. | `vpn/tunnel-group` |
| Tunnel | Tunnels | A Tunnel. | `vpn/tunnel` |
| Tunnel Termination | Tunnel Terminations | A Tunnel Termination. | `vpn/tunnel-termination` |
| IKE Proposal | IKE Proposals | An IKE Proposal. | `vpn/ike-proposal` |
| IKE Policy | IKE Policies | An IKE Policy. | `vpn/ike-policy` |
| IPsec Proposal | IPsec Proposals | An IPsec Proposal. | `vpn/ipsec-proposal` |
| IPsec Policy | IPsec Policies | An IPsec Policy. | `vpn/ipsec-policy` |
| IPsec Profile | IPsec Profiles | An IPsec Profile. | `vpn/ipsec-profile` |
| L2VPN | L2VPNs | An L2VPN. | `vpn/l2vpn` |
| L2VPN Termination | L2VPN Terminations | An L2VPN Termination. | `vpn/l2vpn-termination` |
| Wireless LAN Group | Wireless LAN Groups | A Wireless LAN Group. | `wireless/wireless-lan-group` |
| Wireless LAN | Wireless LANs | A Wireless LAN. | `wireless/wireless-lan` |
| Wireless Link | Wireless Links | A Wireless Link. | `wireless/wireless-link` |
| Tag | Tags | A Tag. | `extras/tag` |
| Custom Field | Custom Fields | A Custom Field. | `extras/custom-field` |
| Custom Field Choice Set | Custom Field Choice Sets | A Custom Field Choice Set. | `extras/custom-field-choice-set` |
| Journal Entry | Journal Entries | A Journal Entry. | `extras/journal-entry` |
| Change | Changes | A Change. | `core/object-change` |
| Config Context | Config Contexts | A Config Context. | `extras/config-context` |
| Export Template | Export Templates | An Export Template. | `extras/export-template` |
| Saved Filter | Saved Filters | A Saved Filter. | `extras/saved-filter` |
| Image Attachment | Image Attachments | An Image Attachment. | `extras/image-attachment` |
<!-- END GENERATED: vocabulary -->
