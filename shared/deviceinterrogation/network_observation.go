package deviceinterrogation

// The network posture of an interrogated device, as the collector measured it
// (DCIM row 1.5, ADR-0010 D3): its interfaces, the addresses on them, the
// VLANs it knows and the ARP cache it holds.
//
// This is the wire form of identity.ObservedInterface / ObservedAddress /
// ObservedVLAN (shared/identity/observed_network.go). It is spelled here, with
// the same JSON names, for the reason PeerRef is: this package is vendored into
// the standalone device agent and must not import shared/identity and the
// platform-runtime dependencies that package carries.
// network_observation_test.go pins the two spellings together field by field.
//
// A collector fills it; it never writes. device-interrogation-service turns it
// into the interfaces, ip_addresses, vlans and prefixes rows by posting a
// sighting to inventory-service's identity engine, the one path every source
// files interfaces by. Posture only: every field is a typed projection of the
// vendor response, so a field the collector does not name is discarded
// structurally.

// NetworkObservation is the network posture one interrogation measured about
// the interrogated device ITSELF. A neighbour's interfaces are never in it.
type NetworkObservation struct {
	// ManagementAddress is the address the platform reached the device on, when
	// that was an IP literal. The engine makes it the primary IP of its family.
	ManagementAddress string `json:"management_address,omitempty"`
	// Vendor is the vendor family (shared/dcim/ifnames) the interface names
	// were canonicalised with, "" when unknown.
	Vendor string `json:"vendor,omitempty"`
	// Producer names the collector in anything parked on its behalf
	// (`unresolved_terminations.producer`); "" is the SNMP collector, which
	// predates the field.
	Producer   string              `json:"producer,omitempty"`
	Interfaces []ObservedInterface `json:"interfaces,omitempty"`
	VLANs      []ObservedVLAN      `json:"vlans,omitempty"`
	Prefixes   []ObservedPrefix    `json:"prefixes,omitempty"`
	ARP        []ObservedARPEntry  `json:"arp,omitempty"`
	// Tunnels are the device's VPN tunnels with their IKE / IPsec proposals
	// (DCIM row 4.3), filed by inventory-service beside the interfaces.
	Tunnels []ObservedTunnel `json:"tunnels,omitempty"`
	// Neighbors are the device's LLDP / CDP neighbour table (DCIM row 3.3):
	// the platform turns them into proposed cables, parked terminations and
	// cable drift findings.
	Neighbors []ObservedNeighbor `json:"neighbors,omitempty"`
	// InventoryItems, Modules and VirtualChassis are the device's hardware
	// parts, the modules in its bays and the stack it manages (DCIM row 2.4,
	// hardware_observation.go), filed by inventory-service beside the
	// interfaces.
	InventoryItems []ObservedInventoryItem `json:"inventory_items,omitempty"`
	Modules        []ObservedModule        `json:"modules,omitempty"`
	VirtualChassis *ObservedVirtualChassis `json:"virtual_chassis,omitempty"`
	// VirtualDeviceContexts are the logical devices the device is partitioned
	// into (DCIM gap 1): a Fortinet VDOM, a Palo Alto vsys, an F5 route
	// domain, a Cisco Nexus VDC. Each interface names its own in
	// ObservedInterface.VirtualDeviceContext.
	VirtualDeviceContexts []ObservedVirtualDeviceContext `json:"virtual_device_contexts,omitempty"`
	// PowerPorts and PowerOutlets are what a PDU collector measured of the
	// device's power sockets (DCIM row 6.2, power_observation.go), filed by
	// inventory-service beside the hardware.
	PowerPorts   []ObservedPowerPort   `json:"power_ports,omitempty"`
	PowerOutlets []ObservedPowerOutlet `json:"power_outlets,omitempty"`
}

// HasPower reports whether the observation carries any power socket.
func (n *NetworkObservation) HasPower() bool {
	return n != nil && (len(n.PowerPorts) > 0 || len(n.PowerOutlets) > 0)
}

// ObservedVirtualDeviceContext mirrors identity.ObservedVirtualDeviceContext:
// a context's name and, where the platform numbers its contexts (a vsys, a
// route domain, a VDC; a VDOM has none), its identifier. Nothing else of the
// vendor's context object is carried.
type ObservedVirtualDeviceContext struct {
	Name       string `json:"name"`
	Identifier *int   `json:"identifier,omitempty"`
	// Description is the operator's display name for the context, where the
	// platform has one (a Palo Alto vsys's display-name); nothing else of the
	// vendor's context object is carried.
	Description string `json:"description,omitempty"`
}

// Empty reports whether there is nothing to record.
func (n *NetworkObservation) Empty() bool {
	return n == nil || (len(n.Interfaces) == 0 && len(n.VLANs) == 0 && len(n.Prefixes) == 0 && len(n.ARP) == 0 && len(n.Tunnels) == 0 &&
		len(n.Neighbors) == 0 && len(n.VirtualDeviceContexts) == 0 && !n.HasHardware() && !n.HasPower())
}

// HasHardware reports whether the observation carries any hardware.
func (n *NetworkObservation) HasHardware() bool {
	return n != nil && (len(n.InventoryItems) > 0 || len(n.Modules) > 0 || n.VirtualChassis != nil)
}

// ObservedNeighbor mirrors identity.ObservedNeighbor: one row of the device's
// LLDP or CDP neighbour table, the far end as it ADVERTISED itself and the
// local port it was heard on. No system description banner: what classifies a
// peer travels on its PeerRef.
type ObservedNeighbor struct {
	LocalInterface    string `json:"local_interface"`
	RemoteChassisID   string `json:"remote_chassis_id,omitempty"`
	RemotePortID      string `json:"remote_port_id,omitempty"`
	RemotePortDescr   string `json:"remote_port_descr,omitempty"`
	RemoteSystemName  string `json:"remote_system_name,omitempty"`
	RemoteMgmtAddress string `json:"remote_mgmt_address,omitempty"`
	// Protocol is lldp or cdp.
	Protocol string `json:"protocol"`
}

// ObservedInterface mirrors identity.ObservedInterface.
type ObservedInterface struct {
	Name         string            `json:"name"`
	Type         string            `json:"type,omitempty"`
	MAC          string            `json:"mac,omitempty"`
	SpeedKbps    *int64            `json:"speed_kbps,omitempty"`
	MTU          *int              `json:"mtu,omitempty"`
	Enabled      *bool             `json:"enabled,omitempty"`
	OperStatus   string            `json:"oper_status,omitempty"`
	Mode         string            `json:"mode,omitempty"`
	UntaggedVLAN int               `json:"untagged_vlan,omitempty"`
	TaggedVLANs  []int             `json:"tagged_vlans,omitempty"`
	Parent       string            `json:"parent,omitempty"`
	LAG          string            `json:"lag,omitempty"`
	Addresses    []ObservedAddress `json:"addresses,omitempty"`
	// RFRole and SSIDs are an access point's radio and the wireless LANs it
	// serves (DCIM row 4.4). UniFi carries them on its own net.interfaces
	// items; the vendor-CLI collectors that produce this type set neither.
	RFRole string   `json:"rf_role,omitempty"`
	SSIDs  []string `json:"ssids,omitempty"`
	// VirtualDeviceContext names the context that owns the interface (DCIM
	// gap 1), one of NetworkObservation.VirtualDeviceContexts; "" for none or
	// not said.
	VirtualDeviceContext string `json:"virtual_device_context,omitempty"`
}

// ObservedAddress mirrors identity.ObservedAddress. Assignment is the string
// form of identity.AddressAssignment ("static", "dynamic", "").
type ObservedAddress struct {
	Address    string `json:"address"`
	PrefixLen  int    `json:"prefix_len,omitempty"`
	VRF        string `json:"vrf,omitempty"`
	Source     string `json:"source,omitempty"`
	Assignment string `json:"assignment,omitempty"`
}

// ObservedPrefix mirrors identity.ObservedPrefix.
type ObservedPrefix struct {
	Prefix          string `json:"prefix"`
	VRF             string `json:"vrf,omitempty"`
	VLAN            int    `json:"vlan,omitempty"`
	DHCPManaged     *bool  `json:"dhcp_managed,omitempty"`
	NetworkType     string `json:"network_type,omitempty"`
	CloudNetworkRef string `json:"cloud_network_ref,omitempty"`
	// ScopeKind / ScopeID mirror identity.ObservedPrefix's placement (DCIM
	// row 2.1). No device collector states one today.
	ScopeKind string `json:"scope_kind,omitempty"`
	ScopeID   string `json:"scope_id,omitempty"`
}

// ObservedVLAN mirrors identity.ObservedVLAN.
type ObservedVLAN struct {
	VID  int    `json:"vid"`
	Name string `json:"name,omitempty"`
}

// ObservedARPEntry is one complete entry of the device's ARP cache: the
// address, the MAC it resolved to and the device interface that learned it.
// It is SUPPORTING evidence about some other device's address — never an
// identifier, never enough to create an asset (see the sink's ARP rule).
type ObservedARPEntry struct {
	Address   string `json:"address"`
	MAC       string `json:"mac"`
	Interface string `json:"interface,omitempty"`
}

// ObservedIKEProposal mirrors identity.ObservedIKEProposal.
type ObservedIKEProposal struct {
	Encryption      string `json:"encryption"`
	Integrity       string `json:"integrity,omitempty"`
	Group           int    `json:"group,omitempty"`
	LifetimeSeconds int    `json:"lifetime_seconds,omitempty"`
}

// ObservedIPsecProposal mirrors identity.ObservedIPsecProposal.
type ObservedIPsecProposal struct {
	Encryption      string `json:"encryption"`
	Integrity       string `json:"integrity,omitempty"`
	LifetimeSeconds int    `json:"lifetime_seconds,omitempty"`
	LifetimeKB      int    `json:"lifetime_kb,omitempty"`
}

// ObservedTunnel mirrors identity.ObservedTunnel: one VPN tunnel as the
// device configures it. Posture only — there is no field a pre-shared key
// could travel in; PresharedKeyPresent records that one is configured.
type ObservedTunnel struct {
	Name                 string                  `json:"name"`
	Encapsulation        string                  `json:"encapsulation"`
	Status               string                  `json:"status,omitempty"`
	LocalInterface       string                  `json:"local_interface,omitempty"`
	LocalIP              string                  `json:"local_ip,omitempty"`
	PeerIP               string                  `json:"peer_ip,omitempty"`
	IKEVersion           int                     `json:"ike_version,omitempty"`
	IKEMode              string                  `json:"ike_mode,omitempty"`
	AuthenticationMethod string                  `json:"authentication_method,omitempty"`
	PresharedKeyPresent  bool                    `json:"preshared_key_present,omitempty"`
	IKEProposals         []ObservedIKEProposal   `json:"ike_proposals,omitempty"`
	IPsecProposals       []ObservedIPsecProposal `json:"ipsec_proposals,omitempty"`
	PFSGroup             int                     `json:"pfs_group,omitempty"`
	IPsecMode            string                  `json:"ipsec_mode,omitempty"`
}
