package identity

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
	"github.com/vistasecurity/vistaplatform/shared/dcim/wireless"
)

// The intake seam of DCIM row 1.5 (ADR-0010 D3): what a collector saw of a
// device's interfaces, their addresses, the prefixes and the VLANs, carried on
// the sighting beside its identifiers so that EVERY adapter writes interfaces
// and IP addresses through one path — this engine — and none calls the
// interface or IPAM services itself.
//
// Two halves, deliberately:
//
//   - Identity. An interface's MAC and its global-VRF addresses are identity
//     concepts (row 1.4). [Intake] turns them into `mac_address` /
//     `ip_address` identifiers carrying the interface's name, so they are
//     scoped, hygiene-checked, admitted and filed by 1.4's one rule
//     ([PlanInterfaces] + [ResolveInterfaces]) exactly like any other
//     identifier. An identifier the sighting already lists for the same value
//     only gains the interface name; nothing is reported twice.
//   - Posture. Everything else — type, MTU, speed, operational and admin
//     status, mode, VLANs, parent and LAG, the prefix length of an address,
//     addresses in a named VRF, the prefixes and VLANs themselves — is not
//     identity, and the engine hands it to an [ObservedNetworkRepository]
//     after the observation resolved to an asset, inside the same transaction.
//
// Posture only: nothing here can carry a credential. Adapters project a vendor
// response onto these typed fields and nothing else (CLAUDE.md "collect
// posture, never key material"); identitytest.RunAdapterParity plants a
// secret in every recorded fixture and fails if it reaches any table.

// ObservedAddress is one address a collector saw on an interface.
type ObservedAddress struct {
	// Address is the host address, without a length ("198.51.100.24"). A
	// CIDR spelling is accepted and split into Address and PrefixLen.
	Address string `json:"address"`
	// PrefixLen is the length the device configured the address with (24 for
	// 198.51.100.24/24), 0 when the source does not say. It is the length
	// NetBox records on an interface address; it never creates a prefix.
	PrefixLen int `json:"prefix_len,omitempty"`
	// VRF names the VRF the address is in — the VRF's name, or its route
	// distinguisher — empty for the global table. Identity is global-VRF only
	// (row 1.4): an address in a named VRF is recorded on the interface but is
	// never an `ip_address` identifier, and an address naming a VRF the tenant
	// does not have is skipped and reported, not filed in the global table.
	VRF string `json:"vrf,omitempty"`
	// Source is how the collector learned it, in `ip_addresses.last_seen_source`'s
	// vocabulary: agent, arp, dhcp, passive, probe, cloud. Empty lets the
	// engine derive it from the sighting's source.
	Source string `json:"source,omitempty"`
	// Assignment is how the address is configured, where the device says:
	// static or dynamic. Empty is unknown — never a guess (see
	// [SightedIdentifier.Assignment]).
	Assignment AddressAssignment `json:"assignment,omitempty"`
}

// ObservedInterface is one interface as a collector measured it.
type ObservedInterface struct {
	// Name as the source spelled it; [Intake] canonicalises it
	// (shared/dcim/ifnames). An interface with no usable name is dropped and
	// reported: 1.4's synthetic `observed-<n>` interfaces are for values whose
	// source did not say which interface carried them, not for interfaces.
	Name string `json:"name"`
	// Type is a key of the interface-type registry (`1000base-t`, `virtual`,
	// `lag`, `ieee802.11ax`, …). Empty, or a value the registry does not hold,
	// lets the name's kind choose (a LAG, a bridge, a VLAN sub-interface are
	// `lag` / `bridge` / `virtual`) or leaves `other`.
	Type string `json:"type,omitempty"`
	// MAC is the interface's own (primary) MAC.
	MAC string `json:"mac,omitempty"`
	// SpeedKbps is the negotiated speed in kbit/s (NetBox's unit); nil when
	// the source does not say. A zero speed from a down port is "unknown", so
	// adapters send nil rather than 0.
	SpeedKbps *int64 `json:"speed_kbps,omitempty"`
	// MTU in bytes; nil when the source does not say.
	MTU *int `json:"mtu,omitempty"`
	// Enabled is the device's ADMINISTRATIVE state (a shut port is false). It
	// is recorded as the measured `admin_status`; the declared `enabled` column
	// is seeded from it only on an interface this observation creates and is
	// never written afterwards (interface_service.UpsertObserved's rule).
	Enabled *bool `json:"enabled,omitempty"`
	// OperStatus is the operational state: up, down, testing, unknown.
	OperStatus string `json:"oper_status,omitempty"`
	// Mode is the 802.1Q mode: access, tagged, tagged-all, q-in-q.
	Mode string `json:"mode,omitempty"`
	// UntaggedVLAN is the access / native VLAN id (1–4094), 0 for none.
	// TaggedVLANs are the trunked VLAN ids.
	UntaggedVLAN int   `json:"untagged_vlan,omitempty"`
	TaggedVLANs  []int `json:"tagged_vlans,omitempty"`
	// Parent names the interface this one is a sub-interface of (a VLAN
	// sub-interface `eth0.100` has parent `eth0`), LAG the aggregate it is a
	// member of (`bond0`). Both name interfaces of the SAME observation.
	Parent string `json:"parent,omitempty"`
	LAG    string `json:"lag,omitempty"`
	// Addresses are the addresses configured on it, as the device reported.
	Addresses []ObservedAddress `json:"addresses,omitempty"`
	// RFRole is `ap` for an access point's radio interface, `station` for a
	// client radio; empty for a wired interface (row 4.4).
	RFRole string `json:"rf_role,omitempty"`
	// SSIDs are the wireless LANs this interface serves, by SSID. Each names a
	// LAN of the same observation's [ObservedNetwork.WirelessLANs]; the engine
	// adds the LAN to the interface's wireless_lan_ids and never removes one.
	SSIDs []string `json:"ssids,omitempty"`
	// VirtualDeviceContext names the virtual device context the interface
	// belongs to on the device (DCIM gap 1): a Fortinet VDOM, a Palo Alto
	// vsys, a Cisco Nexus VDC, an F5 route domain. Empty is none, or not
	// said. The Fortinet, Palo Alto, F5 and Cisco NX-OS collectors fill it;
	// the engine records the context (one of the same observation's
	// [ObservedNetwork.VirtualDeviceContexts], or a new name) and adds the
	// interface to it.
	VirtualDeviceContext string `json:"virtual_device_context,omitempty"`
}

// ObservedVirtualDeviceContext is a virtual device context a collector read
// off the device (DCIM gap 1): its name and, where the platform numbers its
// contexts, its identifier (a vsys number, a route-domain id, a VDC id; a
// Fortinet VDOM has none) and, where the operator gave it one, the display
// name they chose (a Palo Alto vsys's). Nothing else of a context is measured.
type ObservedVirtualDeviceContext struct {
	// Name as the device spells it, 1–64 characters.
	Name string `json:"name"`
	// Identifier is the device's number for the context, 0–32767; nil when
	// the platform has none or did not say.
	Identifier *int `json:"identifier,omitempty"`
	// Description is the operator's display name for the context, written to
	// the context's description on a measured row only; empty when the
	// platform has none or did not say (empty never clears a stored one).
	Description string `json:"description,omitempty"`
}

// ObservedWirelessLAN is a wireless LAN a collector measured on an access
// point (DCIM row 4.4). It carries posture only: the authentication scheme and
// cipher, and whether a pre-shared key EXISTS. The key itself must never be
// copied here -- adapters read it only to set PSKPresent.
type ObservedWirelessLAN struct {
	// SSID as broadcast; case-sensitive, at most 32 bytes.
	SSID string `json:"ssid"`
	// AuthType is open, wep, wpa-personal or wpa-enterprise; empty when the
	// source did not say. AuthCipher is auto, tkip or aes; empty likewise.
	AuthType   string `json:"auth_type,omitempty"`
	AuthCipher string `json:"auth_cipher,omitempty"`
	// VLAN is the VLAN id the LAN's clients are on, 0 for none or unknown.
	VLAN int `json:"vlan,omitempty"`
	// Group names the wireless LAN group (a controller site, an SSID family),
	// empty for none.
	Group string `json:"group,omitempty"`
	// PSKPresent records that a pre-shared key is configured.
	PSKPresent bool `json:"psk_present,omitempty"`
}

// ObservedWirelessLink is a point-to-point wireless link a collector
// measured: a mesh uplink, a bridge pair (DCIM row 4.4).
type ObservedWirelessLink struct {
	// InterfaceA names an interface of the observed asset (canonicalised like
	// any interface name). InterfaceB is the far end's MAC address; the link is
	// recorded only when the tenant already holds exactly one interface with
	// that MAC, and reported as skipped otherwise.
	InterfaceA string `json:"interface_a"`
	InterfaceB string `json:"interface_b"`
	SSID       string `json:"ssid,omitempty"`
	// Status is connected, planned or decommissioning; empty means connected.
	Status string `json:"status,omitempty"`
}

// ObservedPrefix is a prefix a collector measured: a controller's network, a
// cloud subnet, a router's connected route. A host's own view of the subnet
// its address sits in is NOT a prefix measurement (the device-agent's host
// inventory sends none): a prefix the engine learns changes how every address
// inside it is scoped (row 1.4), which is a claim about the network only a
// network source can make.
type ObservedPrefix struct {
	// Prefix in CIDR form; normalised to its network address.
	Prefix string `json:"prefix"`
	// VRF names the VRF (name or RD), empty for the global table.
	VRF string `json:"vrf,omitempty"`
	// VLAN is the VLAN id the prefix is on, 0 for none. The VLAN must be in
	// the same observation's VLANs (or already known) to be linked.
	VLAN int `json:"vlan,omitempty"`
	// DHCPManaged is the source's statement that the prefix hands addresses
	// out by DHCP; nil when it did not say (three-valued — see
	// `prefixes.dhcp_managed`). Written only where nobody has said.
	DHCPManaged     *bool  `json:"dhcp_managed,omitempty"`
	NetworkType     string `json:"network_type,omitempty"`
	CloudNetworkRef string `json:"cloud_network_ref,omitempty"`
	// ScopeKind / ScopeID place the prefix (NetBox Prefix.scope): a region,
	// site group, site or location id, both or neither (DCIM row 2.1). The
	// cloud enumeration scopes a subnet to its region's location under the
	// account's site. Written on create and only where nobody has said.
	ScopeKind string `json:"scope_kind,omitempty"`
	ScopeID   string `json:"scope_id,omitempty"`
}

// ObservedVLAN is a VLAN a collector measured.
type ObservedVLAN struct {
	// VID is the 802.1Q id, 1–4094.
	VID int `json:"vid"`
	// Name as the source spelled it; empty becomes "VLAN <vid>" on a new row
	// and never overwrites a name already recorded.
	Name string `json:"name,omitempty"`
}

// ObservedNetwork is the posture half of an observation, as
// [ObservedNetworkRepository.RecordObservedNetwork] receives it.
type ObservedNetwork struct {
	Interfaces []ObservedInterface
	Prefixes   []ObservedPrefix
	VLANs      []ObservedVLAN
	// WirelessLANs and WirelessLinks are an access point's SSIDs and its
	// point-to-point links (row 4.4).
	WirelessLANs  []ObservedWirelessLAN
	WirelessLinks []ObservedWirelessLink
	// VirtualDeviceContexts are the device's contexts (DCIM gap 1); the
	// interfaces name theirs.
	VirtualDeviceContexts []ObservedVirtualDeviceContext
	// Source is the observation's provenance; ObservedAt its time.
	Source     Source
	ObservedAt time.Time
}

// Empty reports whether there is nothing to record.
func (n ObservedNetwork) Empty() bool {
	return len(n.Interfaces) == 0 && len(n.Prefixes) == 0 && len(n.VLANs) == 0 &&
		len(n.WirelessLANs) == 0 && len(n.WirelessLinks) == 0 && len(n.VirtualDeviceContexts) == 0
}

// ObservedNetworkResult is what one recording did, for logs and tests.
type ObservedNetworkResult struct {
	InterfacesCreated, InterfacesUpdated       int
	AddressesRecorded                          int
	PrefixesCreated, PrefixesUpdated           int
	VLANsCreated, VLANsUpdated                 int
	WirelessLANsCreated, WirelessLANsUpdated   int
	WirelessLinksCreated, WirelessLinksUpdated int
	// Virtual device contexts (DCIM gap 1): rows created, rows matched and
	// refreshed, and measured rows marked stale.
	ContextsCreated, ContextsUpdated, ContextsMarkedStale int
	// Skipped names what could not be stored, with the reason.
	Skipped []string
}

// ObservedNetworkRepository is implemented by a store that records the
// posture half of an observation. The engine calls it after an observation
// resolved to an asset it may write to, on the engine's own transaction; a
// store that does not implement it records only the identity half.
type ObservedNetworkRepository interface {
	RecordObservedNetwork(ctx context.Context, asset AssetRef, n ObservedNetwork) (ObservedNetworkResult, error)
}

// ObservedPrefixEnsurer is implemented by a store that can record a
// sighting's prefixes BEFORE the sighting is scoped (DCIM row 1.6).
//
// A device's own addresses are scoped by the prefixes it reports in the SAME
// sighting: a switch, firewall or controller is the first thing that tells the
// platform a network exists. Without this, a sighting whose address is in no
// prefix yet resolves to the tenant default scope, enforced admission retains
// it as network_scope_unresolved, and its prefixes — which are written only
// once a sighting resolves to an asset — are never recorded: the device can
// never admit itself. EnsureObservedPrefixes breaks that cycle by creating the
// prefixes the sighting names that do not exist yet, as `measured` `pending`
// rows with no observation counted (the observation is counted, and the VLAN
// linked, when the sighting resolves and RecordObservedNetwork runs). It
// returns how many rows it created; an existing prefix is never touched.
type ObservedPrefixEnsurer interface {
	EnsureObservedPrefixes(ctx context.Context, tenantID string, prefixes []ObservedPrefix, src Source) (int, error)
}

// missingPrefixes are the sighting's global- or VRF-named prefixes the
// snapshot does not already hold for the same cloud network.
func missingPrefixes(snap SegmentSnapshot, prefixes []ObservedPrefix) []ObservedPrefix {
	have := map[string]bool{}
	for _, p := range snap.Prefixes {
		have[p.Value+"|"+p.CloudNetworkRef] = true
	}
	var out []ObservedPrefix
	for _, p := range prefixes {
		if p.VRF == "" && have[p.Prefix+"|"+p.CloudNetworkRef] {
			continue
		}
		out = append(out, p)
	}
	return out
}

// recordsObservedNetwork reports whether a resolution names an asset the
// observation's posture may be written to: one it matched, created or created
// provisionally, or the pending asset a conflict created for it. Supporting
// evidence never writes (it is held, platform ADR-0003 D2), and an outcome
// with no asset has nowhere to write.
func recordsObservedNetwork(res Resolution) bool {
	if res.Asset.Zero() || res.EvidenceHeld {
		return false
	}
	switch res.Outcome {
	case OutcomeMatched, OutcomeCreated, OutcomeProvisional, OutcomeConflict:
		return true
	}
	return false
}

// recordObservedNetwork hands the posture half of obs to the repository.
func (e *Engine) recordObservedNetwork(ctx context.Context, obs Observation, res Resolution) error {
	n := ObservedNetwork{Interfaces: obs.Interfaces, Prefixes: obs.Prefixes, VLANs: obs.VLANs,
		WirelessLANs: obs.WirelessLANs, WirelessLinks: obs.WirelessLinks, VirtualDeviceContexts: obs.VirtualDeviceContexts,
		Source: obs.Source, ObservedAt: obs.ObservedAt}
	if n.Empty() || !recordsObservedNetwork(res) {
		return nil
	}
	w, ok := e.repo.(ObservedNetworkRepository)
	if !ok {
		return nil
	}
	if n.ObservedAt.IsZero() {
		n.ObservedAt = e.now().UTC()
	}
	if _, err := w.RecordObservedNetwork(ctx, res.Asset, n); err != nil {
		return fmt.Errorf("identity: recording interfaces of %s: %w", res.Asset.ID, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Normalisation (Intake)
// ---------------------------------------------------------------------------

// NormalizeObservedNetwork canonicalises a sighting's interfaces, prefixes and
// VLANs: names through shared/dcim/ifnames, types and enumerations onto the
// registry's, numbers into the schema's ranges, addresses split and
// zone-stripped. A value the schema could not hold is dropped (and, for a
// whole interface or prefix, reported) rather than failing the sighting over
// one field. Duplicate names, prefixes and VIDs keep their first occurrence.
func NormalizeObservedNetwork(ifaces []ObservedInterface, prefixes []ObservedPrefix, vlans []ObservedVLAN) ([]ObservedInterface, []ObservedPrefix, []ObservedVLAN, []string) {
	var (
		outI    []ObservedInterface
		outP    []ObservedPrefix
		outV    []ObservedVLAN
		dropped []string
	)
	seenI := map[string]bool{}
	for _, raw := range ifaces {
		name, kind := ifnames.Canonical("", strings.TrimSpace(raw.Name))
		name = strings.TrimSpace(name)
		if name == "" || len(name) > maxInterfaceName {
			dropped = append(dropped, fmt.Sprintf("interface %q: no name the interfaces table can hold", raw.Name))
			continue
		}
		if seenI[name] {
			continue
		}
		seenI[name] = true
		o := raw
		o.Name = name
		if _, ok := dcim.ParseInterfaceType(o.Type); !ok || o.Type == "" {
			o.Type = interfaceTypeForKind(kind)
		}
		o.MAC = normalizedMAC(o.MAC)
		if o.MTU != nil && (*o.MTU < 1 || *o.MTU > 65536) {
			o.MTU = nil
		}
		if o.SpeedKbps != nil && *o.SpeedKbps <= 0 {
			o.SpeedKbps = nil
		}
		switch o.OperStatus {
		case "up", "down", "testing", "unknown":
		default:
			o.OperStatus = ""
		}
		switch o.Mode {
		case "access", "tagged", "tagged-all", "q-in-q":
		default:
			o.Mode = ""
		}
		if !validVID(o.UntaggedVLAN) {
			o.UntaggedVLAN = 0
		}
		o.TaggedVLANs = normalizeVIDs(o.TaggedVLANs)
		o.Parent = CanonicalInterfaceName(o.Parent)
		o.LAG = CanonicalInterfaceName(o.LAG)
		if o.Parent == name {
			o.Parent = ""
		}
		if o.LAG == name {
			o.LAG = ""
		}
		o.Addresses = normalizeObservedAddresses(o.Addresses)
		switch o.RFRole {
		case "ap", "station":
		default:
			o.RFRole = ""
		}
		var ssids []string
		for _, ssid := range o.SSIDs {
			if ssid != "" && len(ssid) <= 32 && !slices.Contains(ssids, ssid) {
				ssids = append(ssids, ssid)
			}
		}
		o.SSIDs = ssids
		outI = append(outI, o)
	}
	seenP := map[string]bool{}
	for _, raw := range prefixes {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw.Prefix))
		if err != nil {
			dropped = append(dropped, fmt.Sprintf("prefix %q: not a CIDR prefix", raw.Prefix))
			continue
		}
		p = netip.PrefixFrom(p.Addr().Unmap().WithZone(""), p.Bits()).Masked()
		if !p.IsValid() {
			dropped = append(dropped, fmt.Sprintf("prefix %q: not a CIDR prefix", raw.Prefix))
			continue
		}
		o := raw
		o.Prefix = p.String()
		o.VRF = strings.TrimSpace(o.VRF)
		key := o.VRF + "|" + o.Prefix
		if seenP[key] {
			continue
		}
		seenP[key] = true
		if !validVID(o.VLAN) {
			o.VLAN = 0
		}
		o.NetworkType = strings.TrimSpace(o.NetworkType)
		o.CloudNetworkRef = strings.TrimSpace(o.CloudNetworkRef)
		outP = append(outP, o)
	}
	seenV := map[int]bool{}
	for _, raw := range vlans {
		if !validVID(raw.VID) {
			dropped = append(dropped, fmt.Sprintf("vlan %d: not a VLAN id (1-4094)", raw.VID))
			continue
		}
		if seenV[raw.VID] {
			continue
		}
		seenV[raw.VID] = true
		o := raw
		o.Name = strings.TrimSpace(o.Name)
		if len(o.Name) > 64 {
			o.Name = o.Name[:64]
		}
		outV = append(outV, o)
	}
	return outI, outP, outV, dropped
}

// interfaceTypeForKind is the type a name's kind implies when the source gave
// none — interface_service's rule, so the two writers agree.
func interfaceTypeForKind(kind string) string {
	switch ifnames.Kind(kind) {
	case ifnames.KindLAG:
		return string(dcim.InterfaceTypeLag)
	case ifnames.KindBridge:
		return string(dcim.InterfaceTypeBridge)
	case ifnames.KindVirtual, ifnames.KindLoopback, ifnames.KindVLAN, ifnames.KindTunnel:
		return string(dcim.InterfaceTypeVirtual)
	}
	return SyntheticInterfaceType
}

func validVID(v int) bool { return v >= 1 && v <= 4094 }

func normalizeVIDs(in []int) []int {
	var out []int
	for _, v := range in {
		if validVID(v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

// normalizedMAC is the identifier spelling of a MAC, or "" when it is not one
// (or is a placeholder no identity may be minted from).
func normalizedMAC(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	n, err := Normalize(KindMACAddress, v)
	if err != nil {
		return ""
	}
	return n
}

func normalizeObservedAddresses(in []ObservedAddress) []ObservedAddress {
	var out []ObservedAddress
	seen := map[string]bool{}
	for _, a := range in {
		raw := strings.TrimSpace(a.Address)
		bits := a.PrefixLen
		if p, err := netip.ParsePrefix(raw); err == nil {
			raw, bits = p.Addr().String(), p.Bits()
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		addr = addr.Unmap().WithZone("")
		if addr.IsUnspecified() {
			continue
		}
		if bits < 0 || bits > addr.BitLen() {
			bits = 0
		}
		o := a
		o.Address, o.PrefixLen = addr.String(), bits
		o.VRF = strings.TrimSpace(o.VRF)
		switch o.Source {
		case "agent", "arp", "dhcp", "passive", "probe", "cloud":
		default:
			o.Source = ""
		}
		switch o.Assignment {
		case AssignmentStatic, AssignmentDynamic:
		default:
			o.Assignment = ""
		}
		key := o.VRF + "|" + o.Address
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, o)
	}
	return out
}

// interfaceIdentifiers folds a sighting's interfaces into its identifiers: the
// interface's MAC and each global-VRF address become identifiers carrying the
// interface's name. A value the sighting already lists keeps its own entry and
// gains the name when it had none, so a collector that reports both ways
// (identifiers for admission, interfaces for posture) files each value once.
func interfaceIdentifiers(ids []SightedIdentifier, ifaces []ObservedInterface) []SightedIdentifier {
	out := append([]SightedIdentifier(nil), ids...)
	index := func(kind Kind, value string) int {
		for i, id := range out {
			if id.Kind != kind {
				continue
			}
			if v, err := Normalize(kind, id.Value); err == nil && v == value {
				return i
			}
		}
		return -1
	}
	for _, ifc := range ifaces {
		if ifc.MAC != "" {
			if i := index(KindMACAddress, ifc.MAC); i >= 0 {
				if out[i].Interface == "" {
					out[i].Interface = ifc.Name
				}
			} else {
				out = append(out, SightedIdentifier{Kind: KindMACAddress, Value: ifc.MAC, Interface: ifc.Name})
			}
		}
		for _, a := range ifc.Addresses {
			if a.VRF != "" {
				continue // identity is global-VRF only (row 1.4)
			}
			v, err := Normalize(KindIPAddress, a.Address)
			if err != nil {
				continue
			}
			if i := index(KindIPAddress, v); i >= 0 {
				if out[i].Interface == "" {
					out[i].Interface = ifc.Name
				}
				if out[i].Assignment == "" {
					out[i].Assignment = a.Assignment
				}
			} else {
				out = append(out, SightedIdentifier{Kind: KindIPAddress, Value: a.Address, Interface: ifc.Name, Assignment: a.Assignment})
			}
		}
	}
	return out
}

// NormalizeObservedWireless canonicalises a sighting's wireless LANs and
// links: enumerations onto the schema's, SSIDs bounded, duplicate SSIDs (per
// group) kept once. What the schema could not hold is dropped and reported.
func NormalizeObservedWireless(lans []ObservedWirelessLAN, links []ObservedWirelessLink) ([]ObservedWirelessLAN, []ObservedWirelessLink, []string) {
	var (
		outL    []ObservedWirelessLAN
		outK    []ObservedWirelessLink
		dropped []string
	)
	seen := map[string]bool{}
	for _, raw := range lans {
		if raw.SSID == "" || len(raw.SSID) > 32 {
			dropped = append(dropped, fmt.Sprintf("wireless LAN %q: an SSID is 1-32 bytes", raw.SSID))
			continue
		}
		o := raw
		o.AuthType = strings.ToLower(strings.TrimSpace(o.AuthType))
		o.AuthCipher = strings.ToLower(strings.TrimSpace(o.AuthCipher))
		o.Group = strings.TrimSpace(o.Group)
		if !wireless.ValidAuthType(o.AuthType) {
			o.AuthType = ""
		}
		if !wireless.ValidAuthCipher(o.AuthCipher) || o.AuthType == "" || o.AuthType == "open" {
			o.AuthCipher = ""
		}
		if !validVID(o.VLAN) {
			o.VLAN = 0
		}
		key := o.Group + "\x00" + o.SSID
		if seen[key] {
			continue
		}
		seen[key] = true
		outL = append(outL, o)
	}
	for _, raw := range links {
		o := raw
		o.InterfaceA = CanonicalInterfaceName(o.InterfaceA)
		o.InterfaceB = normalizedMAC(o.InterfaceB)
		if o.InterfaceA == "" || o.InterfaceB == "" {
			dropped = append(dropped, fmt.Sprintf("wireless link %q-%q: both ends are required (a name and a MAC)", raw.InterfaceA, raw.InterfaceB))
			continue
		}
		if len(o.SSID) > 32 {
			o.SSID = ""
		}
		switch o.Status {
		case "connected", "planned", "decommissioning":
		default:
			o.Status = "connected"
		}
		outK = append(outK, o)
	}
	return outL, outK, dropped
}

// maxContextName and maxContextIdentifier are the virtual_device_contexts
// columns' bounds (name 1–64, identifier a smallint the service holds to
// 0–32767).
const (
	maxContextName        = 64
	maxContextIdentifier  = 32767
	maxContextDescription = 200
)

// boundContextDescription trims a display name and cuts it to the bound the
// description column is held to, on a character boundary.
func boundContextDescription(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxContextDescription {
		s = strings.TrimSpace(string(r[:maxContextDescription]))
	}
	return s
}

// NormalizeObservedVirtualDeviceContexts canonicalises a sighting's virtual
// device contexts (DCIM gap 1) against its (already normalised) interfaces:
// names trimmed and bounded, an identifier outside 0–32767 dropped (the
// context is kept without it), duplicate names keeping the first occurrence
// (and the first identifier stated for it), and every name an interface gives
// that the list lacks added without an identifier, so the engine records the
// context each interface names. An interface naming a context the table cannot
// hold loses the name and is reported.
func NormalizeObservedVirtualDeviceContexts(contexts []ObservedVirtualDeviceContext, ifaces []ObservedInterface) ([]ObservedVirtualDeviceContext, []ObservedInterface, []string) {
	var (
		out     []ObservedVirtualDeviceContext
		dropped []string
	)
	at := map[string]int{}
	add := func(name string, id *int, description string) {
		if i, ok := at[name]; ok {
			if out[i].Identifier == nil && id != nil {
				out[i].Identifier = id
			}
			if out[i].Description == "" {
				out[i].Description = description
			}
			return
		}
		at[name] = len(out)
		out = append(out, ObservedVirtualDeviceContext{Name: name, Identifier: id, Description: description})
	}
	for _, c := range contexts {
		name := strings.TrimSpace(c.Name)
		if name == "" || len(name) > maxContextName {
			dropped = append(dropped, fmt.Sprintf("virtual device context %q: no name the table can hold", c.Name))
			continue
		}
		var id *int
		if c.Identifier != nil && *c.Identifier >= 0 && *c.Identifier <= maxContextIdentifier {
			v := *c.Identifier
			id = &v
		}
		add(name, id, boundContextDescription(c.Description))
	}
	var outI []ObservedInterface
	for i, ifc := range ifaces {
		name := strings.TrimSpace(ifc.VirtualDeviceContext)
		if len(name) > maxContextName {
			dropped = append(dropped, fmt.Sprintf("interface %q: virtual device context %q: no name the table can hold", ifc.Name, ifc.VirtualDeviceContext))
			name = ""
		}
		if name != ifc.VirtualDeviceContext {
			if outI == nil {
				outI = slices.Clone(ifaces)
			}
			outI[i].VirtualDeviceContext = name
		}
		if name != "" {
			add(name, nil, "")
		}
	}
	if outI == nil {
		outI = ifaces
	}
	return out, outI, dropped
}
