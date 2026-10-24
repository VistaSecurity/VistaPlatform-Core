package services

// The UniFi intake adapter of DCIM row 1.5b (ADR-0010 D3): what a UniFi
// controller reported about the interfaces, prefixes and VLANs of the devices
// it manages and the clients it sees becomes the observed network of each
// one's sighting, and the identity engine writes `interfaces`,
// `ip_addresses`, `prefixes` and `vlans` from it. Nothing here calls the
// interface or IPAM services; the sighting is the only way in.
//
// The controller sends this as facts bound to a SUBJECT — the device or
// client they describe, not the controller (shared/deviceinterrogation
// unifi_ops.go): a `net.interfaces` list per managed device and per client,
// and the site's networks as a `net.vlans` list on the site's gateway. Only
// the UniFi collector emits subject-bound `net.interfaces` or `net.vlans`
// facts, and that shape on the wire is what an agent build and the platform
// agree on; the platform no longer STORES either (`net.interfaces` is
// `retired` in standards/fact-keys.yaml). The facts still resolve their
// subject, which is how a client the controller lists with no edge reaches
// the inventory at all.
//
// A run that carries its networks on a subject has measured them as
// prefixes, so the controller's own `net.vlans` copy is not stored as a fact.
// It still does two jobs: the gateway-address claims (
// gateway_claims.go), and the measured prefixes written BEFORE any peer is
// resolved (ensureVLANPrefixes; DCIM row 1.6 moved them off the retired
// segments). Those pre-peer prefixes are what lets a peer's address resolve
// into a known network on a tenant's first run — the engine records the
// sighting's own prefixes only once the device carrying them is admitted, and
// under enforced identity admission no device is admitted whose address
// resolves into no network (TestIntegration_UniFiCollector_DrawsEdgesThroughTheEngine,
// "admission enforced", goes red without them).

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// controllerInterfaceItem is one net.interfaces item a controller reported
// about a device it manages or a client it sees (unifiInterfaces,
// unifiClientInterface). Typed, so a field nobody reviewed is discarded
// structurally rather than carried along.
type controllerInterfaceItem struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses"`
	// StaticAddresses is the subset of Addresses the device configured
	// itself (a gateway's own address on each network it serves).
	StaticAddresses []string `json:"static_addresses"`
	State           string   `json:"state"`
	AdminState      string   `json:"admin_state"`
	SpeedMbps       int64    `json:"speed"`
	VLAN            int      `json:"vlan"`
	Mode            string   `json:"mode"`
	TaggedVLANs     []int    `json:"tagged_vlans"`
	LAG             string   `json:"lag"`
	Parent          string   `json:"parent"`
	MTU             int      `json:"mtu"`
	// RFRole, SSIDs and Wireless describe an access point's radio interface
	// (row 4.4). Wireless is posture only: psk_present is a boolean, and there
	// is no field to carry a passphrase.
	RFRole   string                 `json:"rf_role"`
	SSIDs    []string               `json:"ssids"`
	Wireless *controllerWirelessLAN `json:"wireless"`
}

// controllerWirelessLAN is the posture of the SSID a radio serves.
type controllerWirelessLAN struct {
	SSID       string `json:"ssid"`
	AuthType   string `json:"auth_type"`
	AuthCipher string `json:"auth_cipher"`
	VLAN       int    `json:"vlan"`
	PSKPresent bool   `json:"psk_present"`
}

// controllerNetworkItem is one net.vlans item: a network the site serves.
type controllerNetworkItem struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Subnet      string `json:"subnet"`
	DHCPEnabled *bool  `json:"dhcp_enabled"`
	Purpose     string `json:"purpose"`
}

// subjectNetwork is the observed network of one subject of a run: what its
// sighting carries beside its identifiers.
type subjectNetwork struct {
	Interfaces []identity.ObservedInterface
	// Identifiers are the MACs and addresses of interface items with no name
	// (a client's): the controller does not know which interface carried
	// them, so they are identifiers with no interface and the engine files
	// them on a synthetic `observed-<n>` interface (row 1.4).
	Identifiers []identity.SightedIdentifier
	Prefixes    []identity.ObservedPrefix
	VLANs       []identity.ObservedVLAN
	// WirelessLANs are the SSIDs the subject's radios serve (row 4.4).
	WirelessLANs []identity.ObservedWirelessLAN
	// WirelessStations are a wireless client's radio and the SSID it joined,
	// from a nameless station item (the controller's client list).
	WirelessStations []identity.ObservedWirelessStation
	// Neighbors are the subject's LLDP neighbours and wired uplink (row 3.3):
	// cable ends, never stored as a net.neighbors fact.
	Neighbors []identity.ObservedNeighbor
}

func (n subjectNetwork) empty() bool {
	return len(n.Interfaces) == 0 && len(n.Identifiers) == 0 && len(n.Prefixes) == 0 && len(n.VLANs) == 0 &&
		len(n.WirelessLANs) == 0 && len(n.WirelessStations) == 0 && len(n.Neighbors) == 0
}

// isSubjectNetworkFact reports whether f is a controller's account of a
// subject's interfaces or networks: carried on that subject's sighting, never
// stored as a fact.
func isSubjectNetworkFact(f di.FactObservation) bool {
	return !f.Subject.IsZero() && (f.Key == facts.KeyNetInterfaces || f.Key == facts.KeyNetVlans || f.Key == facts.KeyNetNeighbors)
}

// networksMeasuredAsPrefixes reports whether the run carried its networks on
// a subject (a UniFi site's gateway): then the networks are recorded as
// prefixes, and the interrogated device's own net.vlans copy is not stored as
// a fact (it still feeds the gateway claims and the pre-peer prefixes).
func networksMeasuredAsPrefixes(fs []di.FactObservation) bool {
	for _, f := range fs {
		if f.Key == facts.KeyNetVlans && !f.Subject.IsZero() {
			return true
		}
	}
	return false
}

// subjectNetworks projects every subject-bound net.interfaces and net.vlans
// fact of a run onto the observed network of its subject, keyed as the pass
// keys peers (retainedPeerKey), so the sighting built for that peer — first
// pass or replay envelope — carries it.
func subjectNetworks(fs []di.FactObservation) map[string]subjectNetwork {
	out := map[string]subjectNetwork{}
	for _, f := range fs {
		if !isSubjectNetworkFact(f) {
			continue
		}
		key := retainedPeerKey(f.Subject)
		n := out[key]
		switch f.Key {
		case facts.KeyNetInterfaces:
			ifaces, ids := controllerInterfaces(f.Value)
			n.Interfaces = append(n.Interfaces, ifaces...)
			n.Identifiers = append(n.Identifiers, ids...)
			n.WirelessLANs = append(n.WirelessLANs, controllerWirelessLANs(f.Value)...)
			n.WirelessStations = append(n.WirelessStations, controllerWirelessStations(f.Value)...)
		case facts.KeyNetVlans:
			prefixes, vlans := controllerNetworks(f.Value)
			n.Prefixes = append(n.Prefixes, prefixes...)
			n.VLANs = append(n.VLANs, vlans...)
		case facts.KeyNetNeighbors:
			n.Neighbors = append(n.Neighbors, controllerNeighbors(f.Value)...)
		}
		if !n.empty() {
			out[key] = n
		}
	}
	return out
}

// controllerInterfaces projects a controller's net.interfaces list onto
// observed interfaces, and its nameless items (a client's) onto identifiers.
//
// Names arrive canonical: the collector names every interface through
// shared/dcim/ifnames with vendor unifi (unifiInterfaces), and Intake folds
// whatever it is sent once more. A speed is in Mbit/s on the wire and kbit/s
// in the model; MTU and speed of 0 are "not reported". Addresses keep the
// length the device configured and, where it said, that it configured them
// statically; their source is left to the engine (the sighting's).
func controllerInterfaces(value any) ([]identity.ObservedInterface, []identity.SightedIdentifier) {
	blob, err := json.Marshal(value)
	if err != nil {
		return nil, nil
	}
	var items []controllerInterfaceItem
	if err := json.Unmarshal(blob, &items); err != nil {
		return nil, nil
	}
	var (
		out []identity.ObservedInterface
		ids []identity.SightedIdentifier
	)
	for _, it := range items {
		name := strings.TrimSpace(it.Name)
		if name == "" {
			if m := normaliseHostMAC(it.MAC); m != "" {
				ids = append(ids, identity.SightedIdentifier{Kind: identity.KindMACAddress, Value: m})
			}
			for _, raw := range it.Addresses {
				if a, _, ok := controllerAddress(raw); ok {
					ids = append(ids, identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: a})
				}
			}
			continue
		}
		o := identity.ObservedInterface{
			Name:         name,
			Type:         strings.TrimSpace(it.Type),
			MAC:          strings.TrimSpace(it.MAC),
			Mode:         it.Mode,
			UntaggedVLAN: it.VLAN,
			TaggedVLANs:  it.TaggedVLANs,
			LAG:          strings.TrimSpace(it.LAG),
			Parent:       strings.TrimSpace(it.Parent),
			RFRole:       strings.TrimSpace(it.RFRole),
			SSIDs:        it.SSIDs,
		}
		switch it.State {
		case "up", "down", "unknown":
			o.OperStatus = it.State
		}
		switch it.AdminState {
		case "up":
			enabled := true
			o.Enabled = &enabled
		case "down":
			enabled := false
			o.Enabled = &enabled
		}
		if it.SpeedMbps > 0 {
			kbps := it.SpeedMbps * 1000
			o.SpeedKbps = &kbps
		}
		if it.MTU > 0 {
			mtu := it.MTU
			o.MTU = &mtu
		}
		static := map[string]bool{}
		for _, raw := range it.StaticAddresses {
			static[strings.TrimSpace(raw)] = true
		}
		for _, raw := range it.Addresses {
			if a, bits, ok := controllerAddress(raw); ok {
				oa := identity.ObservedAddress{Address: a, PrefixLen: bits}
				if static[strings.TrimSpace(raw)] {
					oa.Assignment = identity.AssignmentStatic
				}
				o.Addresses = append(o.Addresses, oa)
			}
		}
		out = append(out, o)
	}
	return out, ids
}

// controllerWirelessLANs lifts the SSID posture off a controller's
// net.interfaces list: one wireless LAN per radio interface that reported one.
// The same SSID on several radios and access points is one LAN; the intake
// folds the duplicates.
func controllerWirelessLANs(value any) []identity.ObservedWirelessLAN {
	blob, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var items []controllerInterfaceItem
	if err := json.Unmarshal(blob, &items); err != nil {
		return nil
	}
	var out []identity.ObservedWirelessLAN
	for _, it := range items {
		if it.Wireless == nil || strings.TrimSpace(it.Wireless.SSID) == "" {
			continue
		}
		out = append(out, identity.ObservedWirelessLAN{
			SSID:       it.Wireless.SSID,
			AuthType:   it.Wireless.AuthType,
			AuthCipher: it.Wireless.AuthCipher,
			VLAN:       it.Wireless.VLAN,
			PSKPresent: it.Wireless.PSKPresent,
		})
	}
	return out
}

// controllerWirelessStations lifts a wireless client's association off its
// nameless net.interfaces item: the radio's MAC, the SSID it joined and the
// 802.11 type it joined with. A named item is an interface of the device and
// says what it serves (SSIDs), not what it joined.
func controllerWirelessStations(value any) []identity.ObservedWirelessStation {
	blob, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var items []controllerInterfaceItem
	if err := json.Unmarshal(blob, &items); err != nil {
		return nil
	}
	var out []identity.ObservedWirelessStation
	for _, it := range items {
		if strings.TrimSpace(it.Name) != "" || it.RFRole != "station" || len(it.SSIDs) == 0 {
			continue
		}
		mac := normaliseHostMAC(it.MAC)
		if mac == "" {
			continue
		}
		out = append(out, identity.ObservedWirelessStation{MAC: mac, SSID: it.SSIDs[0], Type: strings.TrimSpace(it.Type)})
	}
	return out
}

// controllerAddress parses one reported address, bare or in CIDR form.
func controllerAddress(raw string) (string, int, bool) {
	raw = strings.TrimSpace(raw)
	if p, err := netip.ParsePrefix(raw); err == nil {
		return p.Addr().Unmap().String(), p.Bits(), true
	}
	if a, err := netip.ParseAddr(raw); err == nil {
		return a.Unmap().String(), 0, true
	}
	return "", 0, false
}

// controllerNetworks projects a site's net.vlans list onto observed prefixes
// and VLANs: each tagged network is a VLAN (with its name), each network with
// a subnet a prefix (on that VLAN, with the DHCP posture the controller
// stated — nil where it said nothing — and its purpose as the network type).
// UniFi's subnet is already masked by the collector; a network with no subnet
// (vlan-only) is a VLAN and no prefix.
func controllerNetworks(value any) ([]identity.ObservedPrefix, []identity.ObservedVLAN) {
	blob, err := json.Marshal(value)
	if err != nil {
		return nil, nil
	}
	var items []controllerNetworkItem
	if err := json.Unmarshal(blob, &items); err != nil {
		return nil, nil
	}
	var (
		prefixes []identity.ObservedPrefix
		vlans    []identity.ObservedVLAN
	)
	for _, it := range items {
		if it.ID >= 1 && it.ID <= 4094 {
			vlans = append(vlans, identity.ObservedVLAN{VID: it.ID, Name: strings.TrimSpace(it.Name)})
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(it.Subnet))
		if err != nil {
			continue
		}
		op := identity.ObservedPrefix{Prefix: p.Masked().String(), VLAN: it.ID, NetworkType: controllerNetworkType(it.Purpose)}
		if it.DHCPEnabled != nil {
			dhcp := *it.DHCPEnabled
			op.DHCPManaged = &dhcp
		}
		prefixes = append(prefixes, op)
	}
	return prefixes, vlans
}

// controllerNetworkType maps a UniFi network purpose onto the prefix's
// network type: `corporate` and `guest` are the values both vocabularies
// share; anything else is left unsaid.
func controllerNetworkType(purpose string) string {
	switch strings.ToLower(strings.TrimSpace(purpose)) {
	case "corporate":
		return "corporate"
	case "guest":
		return "guest"
	}
	return ""
}

// controllerNeighborItem is one net.neighbors item a controller reported
// about a device it manages (unifiLLDPNeighbors, unifiUplinkNeighbor). Typed:
// a field nobody reviewed is discarded structurally.
type controllerNeighborItem struct {
	Protocol      string `json:"protocol"`
	LocalPort     string `json:"local_port"`
	RemoteMAC     string `json:"remote_mac"`
	RemoteName    string `json:"remote_name"`
	RemotePort    string `json:"remote_port"`
	RemoteAddress string `json:"remote_address"`
}

// controllerNeighbors projects a controller's net.neighbors list onto
// observed neighbours (DCIM row 3.3). The local port is named the way the
// controller names the subject's interfaces (ifnames, vendor unifi), so the
// platform finds the local interface by its own row; ARP items are not
// neighbours and are dropped.
func controllerNeighbors(value any) []identity.ObservedNeighbor {
	blob, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var items []controllerNeighborItem
	if err := json.Unmarshal(blob, &items); err != nil {
		return nil
	}
	var out []identity.ObservedNeighbor
	for _, it := range items {
		if it.Protocol != identity.NeighborProtocolLLDP && it.Protocol != identity.NeighborProtocolCDP {
			continue
		}
		local, _ := ifnames.Canonical(ifnames.VendorUniFi, strings.TrimSpace(it.LocalPort))
		if strings.TrimSpace(local) == "" {
			continue
		}
		out = append(out, identity.ObservedNeighbor{
			Protocol: it.Protocol, LocalInterface: local,
			RemoteChassisID: it.RemoteMAC, RemotePortID: it.RemotePort,
			RemoteSystemName: it.RemoteName, RemoteMgmtAddress: it.RemoteAddress,
		})
	}
	return out
}

// subjectNetworksKey carries a run's subject networks to peerSighting.
type subjectNetworksKey struct{}

func withSubjectNetworks(ctx context.Context, networks map[string]subjectNetwork) context.Context {
	if len(networks) == 0 {
		return ctx
	}
	return context.WithValue(ctx, subjectNetworksKey{}, networks)
}

func subjectNetworkFor(ctx context.Context, peer di.PeerRef) (subjectNetwork, bool) {
	networks, _ := ctx.Value(subjectNetworksKey{}).(map[string]subjectNetwork)
	n, ok := networks[retainedPeerKey(peer)]
	return n, ok
}

// applyTo puts the subject's observed network on its sighting.
//
// A device the controller lists in its inventory is managed at the address
// the controller lists it at — its first address identifier — which the
// engine makes its primary IP. A client is not managed at anything.
func (n subjectNetwork) applyTo(s *identity.Sighting, peer di.PeerRef) {
	s.Interfaces = append(s.Interfaces, n.Interfaces...)
	s.Prefixes = append(s.Prefixes, n.Prefixes...)
	s.WirelessLANs = append(s.WirelessLANs, n.WirelessLANs...)
	s.WirelessStations = append(s.WirelessStations, n.WirelessStations...)
	s.VLANs = append(s.VLANs, n.VLANs...)
	s.Neighbors = append(s.Neighbors, n.Neighbors...)
	for _, id := range n.Identifiers {
		if !sightingHolds(*s, id) {
			s.Identifiers = append(s.Identifiers, id)
		}
	}
	if peer.IdentityEvidence.ControllerInventory && len(n.Interfaces) > 0 && s.ManagementAddress == "" {
		s.ManagementAddress = peer.Identifier(di.IdentifierIPAddress)
	}
}

// sightingHolds reports whether the sighting already lists id's value.
func sightingHolds(s identity.Sighting, id identity.SightedIdentifier) bool {
	want, err := identity.Normalize(id.Kind, id.Value)
	if err != nil {
		return true // not a value Intake would take; never add it
	}
	for _, have := range s.Identifiers {
		if have.Kind != id.Kind {
			continue
		}
		if v, err := identity.Normalize(have.Kind, have.Value); err == nil && v == want {
			return true
		}
	}
	return false
}
