package deviceinterrogation

import (
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// The Cisco, Palo Alto, Fortinet and F5 collectors' side of the row 1.5
// intake seam (DCIM row 1.5c, ADR-0010 D3).
//
// These four used to describe a device's interfaces and VLANs as the
// `net.interfaces` / `net.vlans` FACTS. They now hand the platform the same
// NetworkObservation the SNMP collector does (network_observation.go): the
// device's interfaces, the addresses on them, its connected prefixes, its
// VLANs and its ARP cache, which device-interrogation-service files through
// the identity engine and the ARP rule — never written by a collector.
//
// Each vendor projection builds a vendorNetwork first (cisco_network.go,
// paloalto_network.go, fortinet_network.go, f5_network.go): plain values,
// names as the vendor spells them, every field typed posture — there is no
// field a vendor's `psksecret` or `private-key` could land in. setNetwork then
// canonicalises the names with the vendor family (shared/dcim/ifnames),
// bounds every table and converts to the wire form.

// vendorNetwork is what a vendor projection measured on the device itself.
type vendorNetwork struct {
	// NameFamily is the shared/dcim/ifnames vendor family the interface names
	// are spelled in ("cisco", "fortinet"; "" lets the names speak for
	// themselves).
	NameFamily string
	// Producer names the collector for anything parked on its behalf
	// (`unresolved_terminations.producer`, `^[a-z0-9_]+$`).
	Producer string

	Interfaces []netIface
	Prefixes   []netPrefix
	VLANs      []netVLAN
	// ARP is the device's ARP table: evidence about OTHER hosts.
	ARP []netARP
}

// Empty reports whether nothing was observed.
func (n *vendorNetwork) Empty() bool {
	return n == nil || (len(n.Interfaces) == 0 && len(n.Prefixes) == 0 && len(n.VLANs) == 0 && len(n.ARP) == 0)
}

// netIface is one of the device's interfaces.
type netIface struct {
	Name string
	// Type is an interface-type registry key (shared/dcim, `1000base-t`,
	// `lag`, `virtual`), or "" when the device did not say enough to know.
	Type string
	MAC  string
	// SpeedKbps is the negotiated speed in kbit/s, 0 when unknown.
	SpeedKbps int64
	// MTU in bytes, 0 when unknown.
	MTU int
	// Enabled is the administrative state; nil when the device did not say.
	Enabled *bool
	// OperStatus is up, down or unknown; "" when the device did not say.
	OperStatus string
	// Mode is access, tagged or tagged-all; "" for a routed port or unknown.
	Mode         string
	UntaggedVLAN int
	TaggedVLANs  []int
	// Parent names the interface a sub-interface hangs off; LAG the aggregate
	// this one is a member of. Both name interfaces of the same observation.
	Parent    string
	LAG       string
	Addresses []netAddr
}

// netAddr is one address configured on an interface: "198.51.100.2/24"
// (or a bare host when the device gave no length), in a named VRF / VDOM /
// route domain or "" for the global table.
type netAddr struct {
	Address string
	VRF     string
}

// netPrefix is a prefix the device is directly connected to (a connected
// route: an interface address's network), with the VLAN it is on.
type netPrefix struct {
	Prefix string
	VRF    string
	VLAN   int
}

// netVLAN is a VLAN the device carries.
type netVLAN struct {
	VID  int
	Name string
}

// netARP is one resolved ARP entry: a neighbour at Address answered with MAC
// on the device's Interface. Incomplete entries are never recorded.
type netARP struct {
	Address   string
	MAC       string
	Interface string
	VRF       string
}

// Bounds. A device decides how much it sends; these decide how much we keep,
// matching the table bounds the collectors already apply.
const (
	maxNetInterfaces = 2000
	maxNetPrefixes   = 2000
	maxNetVLANs      = 4094
	// maxARPEntries bounds the ARP table taken from one device. A core
	// router's table is unbounded by anything we control.
	maxARPEntries = 4096
	// maxNetNameLen bounds every device-chosen name (interface, VLAN, VRF).
	maxNetNameLen = 64
)

// boolRef returns a pointer to b.
func boolRef(b bool) *bool { return &b }

// kbpsFromMbps converts a speed in Mbit/s to kbit/s, 0 for unknown.
func kbpsFromMbps(mbps int64) int64 {
	if mbps <= 0 {
		return 0
	}
	return mbps * 1000
}

// netAddressFromCIDR returns the address in "host/len" or bare "host" form, or
// "" when v is not an address. Unspecified and loopback addresses are not
// addresses of an interface anybody can reach.
func netAddressFromCIDR(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return ""
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		a := p.Addr().Unmap().WithZone("")
		if a.IsUnspecified() || a.IsLoopback() {
			return ""
		}
		return netip.PrefixFrom(a, p.Bits()).String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap().WithZone("")
		if a.IsUnspecified() || a.IsLoopback() {
			return ""
		}
		return a.String()
	}
	return ""
}

// connectedPrefix is the network a "host/len" interface address sits on, or
// "" when the address has no length or is a host route (/32, /128): a host
// route is not a network anybody else is on.
func connectedPrefix(addr string) string {
	p, err := netip.ParsePrefix(strings.TrimSpace(addr))
	if err != nil || p.Bits() >= p.Addr().BitLen() {
		return ""
	}
	if a := p.Addr(); a.IsLinkLocalUnicast() || a.IsLoopback() {
		return ""
	}
	return p.Masked().String()
}

// connectedPrefixes derives the device's connected prefixes from its
// interface addresses: the network of each address with a length, on the
// VLAN of the interface carrying it (an SVI's or a sub-interface's untagged
// VLAN). The first interface naming a prefix decides its VLAN.
func connectedPrefixes(ifaces []netIface) []netPrefix {
	var out []netPrefix
	seen := map[string]bool{}
	for _, ifc := range ifaces {
		// An SVI names its VLAN; a sub-interface or a VLAN interface carries
		// it as its untagged VLAN. A trunk's addresses (rare) sit on no one
		// VLAN.
		vlan := vlanDeclaredByName(ifc.Name)
		if vlan == 0 && (ifc.Mode == "access" || ifc.Mode == "") {
			vlan = ifc.UntaggedVLAN
		}
		for _, a := range ifc.Addresses {
			p := connectedPrefix(a.Address)
			if p == "" {
				continue
			}
			key := a.VRF + "|" + p
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, netPrefix{Prefix: p, VRF: a.VRF, VLAN: vlan})
		}
	}
	return out
}

// vlanDeclaredByName is the VLAN id an interface name declares by itself:
// Cisco's SVI `Vlan10`. 0 for any other name.
func vlanDeclaredByName(name string) int {
	n := strings.TrimSpace(name)
	if len(n) < 5 || !strings.EqualFold(n[:4], "vlan") {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(n[4:]))
	if err != nil || v < 1 || v > 4094 {
		return 0
	}
	return v
}

// expandVLANList reads a VLAN list as the devices print it ("1,10-12,30"),
// bounded to valid ids. all is true when the list covers every VLAN (1-4094),
// which NetBox models as `tagged-all` rather than 4094 rows.
func expandVLANList(list string) (vids []int, all bool) {
	s := strings.TrimSpace(list)
	if s == "" || strings.EqualFold(s, "none") {
		return nil, false
	}
	set := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := part, part
		if i := strings.Index(part, "-"); i > 0 {
			lo, hi = part[:i], part[i+1:]
		}
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		b, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil || a > b {
			continue
		}
		if a <= 1 && b >= 4094 {
			return nil, true
		}
		for v := max(a, 1); v <= min(b, 4094); v++ {
			set[v] = true
		}
	}
	for v := range set {
		vids = append(vids, v)
	}
	sort.Ints(vids)
	return vids, false
}

// mediaInterfaceType maps a vendor's media description (IOS `media type is
// 10/100/1000BaseTX`, `show interfaces status` Type column, F5 `mediaActive`
// `10000SR-FD`) and the negotiated speed onto an interface-type registry key.
// "" when the media does not say which: a speed alone does not tell copper
// from fibre, and `other` is a better answer than a guess.
func mediaInterfaceType(media string, speedMbps int64) string {
	m := strings.ToLower(strings.TrimSpace(media))
	if m == "" || m == "none" || m == "auto" || strings.Contains(m, "not present") || strings.Contains(m, "unknown") {
		return ""
	}
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(m, s) {
				return true
			}
		}
		return false
	}
	// The media's own rate, where it names one, beats the negotiated speed.
	rate := speedMbps
	switch {
	case has("100g", "100000"):
		rate = 100000
	case has("40g", "40000"):
		rate = 40000
	case has("25g", "25000"):
		rate = 25000
	case has("10g", "10000", "sfp+", "sfp-10"):
		rate = 10000
	case has("5g", "5000"):
		rate = 5000
	case has("2.5g", "2500"):
		rate = 2500
	}
	switch {
	case has("qsfp28"), has("qsfp") && rate >= 100000:
		return "100gbase-x-qsfp28"
	case has("qsfp"), rate == 40000 && has("sr4", "lr4", "fiber", "fibre"):
		return "40gbase-x-qsfpp"
	case has("sfp28"):
		return "25gbase-x-sfp28"
	case has("sfp+", "sfpp", "sfp-10"), rate == 10000 && has("sr", "lr", "er", "zr", "fiber", "fibre", "cu"):
		return "10gbase-x-sfpp"
	case has("1000basesx", "1000sx", "-sx"):
		return "1000base-sx"
	case has("1000baselx", "1000lx", "-lx"):
		return "1000base-lx"
	case has("sfp"):
		return "1000base-x-sfp"
	case has("basetx", "base-tx", "baset", "base-t", "rj45", "10/100/1000", "1000t", "100tx", "10000t"):
		switch {
		case rate >= 10000:
			return "10gbase-t"
		case rate == 5000:
			return "5gbase-t"
		case rate == 2500:
			return "2.5gbase-t"
		case rate == 100 || (rate == 0 && !has("1000") && has("100")):
			return "100base-tx"
		default:
			return "1000base-t"
		}
	}
	return ""
}

// boundName trims a device-chosen name to the bound every name column holds.
func boundName(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxNetNameLen {
		s = s[:maxNetNameLen]
	}
	return s
}

// setNetwork converts n to the wire form and stores it on the result,
// bounded, recording a truncation warning for each table cut. endpoint names
// the command or call the table came from.
//
// Names are canonicalised with the vendor family here, once, so every name a
// table cross-references (a parent, a LAG) is spelled the way the interface it
// names is. An ARP entry in a named VRF is dropped: the platform matches ARP
// evidence against the global table only, and an address in a VRF is not that
// address.
func (r *InterrogateResult) setNetwork(n *vendorNetwork, endpoint string) {
	if n.Empty() {
		return
	}
	if len(n.Interfaces) > maxNetInterfaces {
		r.warnTruncated(endpoint, "Interface table", maxNetInterfaces)
		n.Interfaces = n.Interfaces[:maxNetInterfaces]
	}
	if len(n.Prefixes) > maxNetPrefixes {
		r.warnTruncated(endpoint, "Connected prefixes", maxNetPrefixes)
		n.Prefixes = n.Prefixes[:maxNetPrefixes]
	}
	if len(n.VLANs) > maxNetVLANs {
		r.warnTruncated(endpoint, "VLAN table", maxNetVLANs)
		n.VLANs = n.VLANs[:maxNetVLANs]
	}
	if len(n.ARP) > maxARPEntries {
		r.warnTruncated(endpoint, "ARP table", maxARPEntries)
		n.ARP = n.ARP[:maxARPEntries]
	}
	canon := func(name string) string {
		if strings.TrimSpace(name) == "" {
			return ""
		}
		c, _ := ifnames.Canonical(n.NameFamily, name)
		return c
	}
	out := &NetworkObservation{Vendor: ifnames.NormalizeVendor(n.NameFamily), Producer: n.Producer}
	for _, ifc := range n.Interfaces {
		o := ObservedInterface{
			Name: canon(ifc.Name), Type: ifc.Type, MAC: ifc.MAC, Enabled: ifc.Enabled, OperStatus: ifc.OperStatus,
			Mode: ifc.Mode, UntaggedVLAN: ifc.UntaggedVLAN, TaggedVLANs: append([]int(nil), ifc.TaggedVLANs...),
			Parent: canon(ifc.Parent), LAG: canon(ifc.LAG),
		}
		if ifc.SpeedKbps > 0 {
			kbps := ifc.SpeedKbps
			o.SpeedKbps = &kbps
		}
		if ifc.MTU > 0 {
			mtu := ifc.MTU
			o.MTU = &mtu
		}
		for _, a := range ifc.Addresses {
			o.Addresses = append(o.Addresses, ObservedAddress{Address: a.Address, VRF: a.VRF})
		}
		out.Interfaces = append(out.Interfaces, o)
	}
	for _, p := range n.Prefixes {
		out.Prefixes = append(out.Prefixes, ObservedPrefix{Prefix: p.Prefix, VRF: p.VRF, VLAN: p.VLAN})
	}
	for _, v := range n.VLANs {
		out.VLANs = append(out.VLANs, ObservedVLAN(v))
	}
	for _, e := range n.ARP {
		if e.VRF != "" {
			continue
		}
		out.ARP = append(out.ARP, ObservedARPEntry{Address: e.Address, MAC: e.MAC, Interface: canon(e.Interface)})
	}
	// Tunnels, neighbours and hardware may have been added before the
	// interface table was projected; they are kept.
	if r.Network != nil {
		out.Tunnels, out.Neighbors = r.Network.Tunnels, r.Network.Neighbors
		out.InventoryItems, out.Modules, out.VirtualChassis = r.Network.InventoryItems, r.Network.Modules, r.Network.VirtualChassis
		if out.ManagementAddress == "" {
			out.ManagementAddress = r.Network.ManagementAddress
		}
	}
	r.Network = out
}

// networkManagementAddress is the address the platform reached the device on,
// when that was an IP literal: the device record's address, or the host of
// its management URL. The engine makes it the asset's primary IP.
func networkManagementAddress(device DeviceInfo) string {
	for _, h := range []string{device.IPAddress, managementURLHost(device.ManagementURL)} {
		// A loopback or link-local address is how a test or a tunnel reached
		// the device, never the address the device is managed by.
		if a, err := netip.ParseAddr(strings.TrimSpace(h)); err == nil && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsUnspecified() {
			return a.Unmap().WithZone("").String()
		}
	}
	return ""
}

// setNetworkManagementAddress records on the network observation the address
// the device was reached at, when the collector produced one.
func (r *InterrogateResult) setNetworkManagementAddress(device DeviceInfo) {
	if r == nil || r.Network == nil || r.Network.ManagementAddress != "" {
		return
	}
	r.Network.ManagementAddress = networkManagementAddress(device)
}

// managementURLHost is the host of a management URL, "" when it has none.
func managementURLHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// sanitizeNetwork is [Sanitize]'s pass over the network observation. Every
// field is typed posture, so name-based redaction has nothing to find; the
// free-text ones (names a device's operator chose) still get the value-shaped
// rule and the length bound, for the same reason a peer's display name does
// (sanitizePeer).
func sanitizeNetwork(n *NetworkObservation) {
	if n == nil {
		return
	}
	text := func(s string) string { return boundName(redact.TextPEM(redact.Text(s))) }
	for i := range n.Interfaces {
		ifc := &n.Interfaces[i]
		ifc.Name, ifc.Parent, ifc.LAG = text(ifc.Name), text(ifc.Parent), text(ifc.LAG)
		for j := range ifc.Addresses {
			ifc.Addresses[j].VRF = text(ifc.Addresses[j].VRF)
		}
	}
	for i := range n.Prefixes {
		n.Prefixes[i].VRF = text(n.Prefixes[i].VRF)
	}
	for i := range n.VLANs {
		n.VLANs[i].Name = text(n.VLANs[i].Name)
	}
	for i := range n.ARP {
		n.ARP[i].Interface = text(n.ARP[i].Interface)
	}
	for i := range n.Tunnels {
		n.Tunnels[i].Name, n.Tunnels[i].LocalInterface = text(n.Tunnels[i].Name), text(n.Tunnels[i].LocalInterface)
	}
	for i := range n.InventoryItems {
		it := &n.InventoryItems[i]
		it.Name, it.Parent, it.Description, it.Interface = text(it.Name), text(it.Parent), text(it.Description), text(it.Interface)
	}
	for i := range n.Modules {
		n.Modules[i].Bay = text(n.Modules[i].Bay)
	}
	if n.VirtualChassis != nil {
		n.VirtualChassis.Name = text(n.VirtualChassis.Name)
	}
	for i := range n.Neighbors {
		nb := &n.Neighbors[i]
		nb.LocalInterface, nb.RemoteChassisID, nb.RemotePortID = text(nb.LocalInterface), text(nb.RemoteChassisID), text(nb.RemotePortID)
		nb.RemotePortDescr, nb.RemoteSystemName = text(nb.RemotePortDescr), text(nb.RemoteSystemName)
	}
}

// maxNetNeighbors bounds the neighbour rows one interrogation reports.
const maxNetNeighbors = 1024

// addNeighbors appends LLDP / CDP neighbours (DCIM row 3.3) to the network
// observation, creating it when the collector reported nothing else. family
// canonicalises the local port names the way the interface table spells them,
// so the platform finds the local interface by its own name. A row with no
// local port names no cable end and is dropped here.
func (r *InterrogateResult) addNeighbors(neighbors []ObservedNeighbor, family, endpoint string) {
	if r == nil || len(neighbors) == 0 {
		return
	}
	if r.Network == nil {
		r.Network = &NetworkObservation{Vendor: ifnames.NormalizeVendor(family), Producer: r.collector}
	}
	for _, nb := range neighbors {
		if strings.TrimSpace(nb.LocalInterface) == "" {
			continue
		}
		if len(r.Network.Neighbors) >= maxNetNeighbors {
			r.warnTruncated(endpoint, "Neighbour table", maxNetNeighbors)
			return
		}
		nb.LocalInterface, _ = ifnames.Canonical(family, nb.LocalInterface)
		r.Network.Neighbors = append(r.Network.Neighbors, nb)
	}
}

// maxNetTunnels bounds the tunnels one interrogation reports, and
// maxTunnelProposalList the proposals of one tunnel.
const (
	maxNetTunnels         = 1024
	maxTunnelProposalList = 32
)

// addTunnels appends the device's VPN tunnels (DCIM row 4.3) to the network
// observation, creating it when the collector reported no interfaces, bounded
// and with a truncation warning per table cut. family canonicalises the local
// interface names the way the interface table spells them.
func (r *InterrogateResult) addTunnels(tunnels []ObservedTunnel, family, endpoint string) {
	if len(tunnels) == 0 {
		return
	}
	if r.Network == nil {
		r.Network = &NetworkObservation{Vendor: ifnames.NormalizeVendor(family), Producer: r.collector}
	}
	room := maxNetTunnels - len(r.Network.Tunnels)
	if room <= 0 {
		r.warnTruncated(endpoint, "Tunnel table", maxNetTunnels)
		return
	}
	if len(tunnels) > room {
		r.warnTruncated(endpoint, "Tunnel table", maxNetTunnels)
		tunnels = tunnels[:room]
	}
	for _, t := range tunnels {
		if strings.TrimSpace(t.LocalInterface) != "" {
			t.LocalInterface, _ = ifnames.Canonical(family, t.LocalInterface)
		}
		if len(t.IKEProposals) > maxTunnelProposalList {
			t.IKEProposals = t.IKEProposals[:maxTunnelProposalList]
		}
		if len(t.IPsecProposals) > maxTunnelProposalList {
			t.IPsecProposals = t.IPsecProposals[:maxTunnelProposalList]
		}
		r.Network.Tunnels = append(r.Network.Tunnels, t)
	}
}

// neighborItemsAsNeighbors splits a collector's neighbour items (the
// net.neighbors item shape every collector already builds) into the LLDP / CDP
// rows, as ObservedNeighbors for the network observation (DCIM row 3.3), and
// the rest (ARP), which stay a fact. An LLDP or CDP neighbour is a cable end
// now, not a fact: the platform proposes the cable, parks the far identity or
// raises the drift finding from it.
//
// Item keys read: protocol, local_port, remote_mac, remote_chassis_id (a
// chassis id that is not a MAC), remote_port, remote_port_description,
// remote_name, remote_address.
func neighborItemsAsNeighbors(items []map[string]interface{}) ([]ObservedNeighbor, []map[string]interface{}) {
	var (
		out  []ObservedNeighbor
		rest []map[string]interface{}
	)
	str := func(m map[string]interface{}, k string) string {
		s, _ := m[k].(string)
		return strings.TrimSpace(s)
	}
	for _, it := range items {
		proto := str(it, "protocol")
		if proto != "lldp" && proto != "cdp" {
			rest = append(rest, it)
			continue
		}
		nb := ObservedNeighbor{
			Protocol:          proto,
			LocalInterface:    str(it, "local_port"),
			RemoteChassisID:   str(it, "remote_mac"),
			RemotePortID:      str(it, "remote_port"),
			RemotePortDescr:   str(it, "remote_port_description"),
			RemoteSystemName:  str(it, "remote_name"),
			RemoteMgmtAddress: str(it, "remote_address"),
		}
		if nb.RemoteChassisID == "" {
			nb.RemoteChassisID = str(it, "remote_chassis_id")
		}
		out = append(out, nb)
	}
	return out, rest
}
