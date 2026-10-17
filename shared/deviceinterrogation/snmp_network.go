package deviceinterrogation

import (
	"context"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// The network posture of an SNMP device (DCIM row 1.5d, ADR-0004 D1 item 3):
// interfaces, the addresses on them, VLANs and their port membership, and the
// ARP cache — projected onto [NetworkObservation], which
// device-interrogation-service files through the identity engine. Nothing in
// this file writes a fact: `net.interfaces` is retired for this collector
// (standards/fact-keys.yaml), and the table it summarised now has a model.
//
// Standard MIBs only:
//
//	IF-MIB       ifTable / ifXTable   name, type, MTU, speed, MAC, admin and oper state
//	IP-MIB       ipAddressTable       addresses per ifIndex (v4 and v6), origin, prefix length
//	RFC 1213     ipAddrTable          the fallback for agents with no ipAddressTable (v4 + netmask)
//	IF-MIB       ifStackTable         a VLAN sub-interface's lower interface, an aggregate's members
//	IEEE8023-LAG dot3adAggPortAttachedAggID  the LAG a port belongs to
//	Q-BRIDGE     dot1qVlanStaticTable / dot1qPvid / dot1dBasePortIfIndex  VLANs, native VLAN, trunk membership
//	RFC 1213     ipNetToMediaTable    the ARP cache (supporting evidence only)
//
// ifAlias is deliberately NOT walked. It is the operator's free-text port
// description ("uplink to HR — vpn psk: ..."), which the interface model has no
// field for and which has no business in a posture inventory; the community
// string and every other secret a device might echo into a banner stay out of
// the projection for the same reason: only the typed fields below are carried.

const (
	snmpOIDIfType = "1.3.6.1.2.1.2.2.1.3"
	snmpOIDIfMtu  = "1.3.6.1.2.1.2.2.1.4"

	snmpOIDIfStackStatus = "1.3.6.1.2.1.31.1.2.1.3"

	// IEEE8023-LAG-MIB dot3adAggPortAttachedAggID: indexed by the PORT's
	// ifIndex, the value is the aggregator's ifIndex (0 when unattached).
	snmpOIDLagAttachedAgg = "1.2.840.10006.300.43.1.2.1.1.13"

	snmpOIDIPAddressIfIndex = "1.3.6.1.2.1.4.34.1.3"
	snmpOIDIPAddressType    = "1.3.6.1.2.1.4.34.1.4"
	snmpOIDIPAddressPrefix  = "1.3.6.1.2.1.4.34.1.5"
	snmpOIDIPAddressOrigin  = "1.3.6.1.2.1.4.34.1.6"

	snmpOIDIPAdEntAddr    = "1.3.6.1.2.1.4.20.1.1"
	snmpOIDIPAdEntIfIndex = "1.3.6.1.2.1.4.20.1.2"
	snmpOIDIPAdEntNetMask = "1.3.6.1.2.1.4.20.1.3"

	snmpOIDDot1qVlanStaticName     = "1.3.6.1.2.1.17.7.1.4.3.1.1"
	snmpOIDDot1qVlanStaticEgress   = "1.3.6.1.2.1.17.7.1.4.3.1.2"
	snmpOIDDot1qVlanStaticUntagged = "1.3.6.1.2.1.17.7.1.4.3.1.4"
	snmpOIDDot1qPvid               = "1.3.6.1.2.1.17.7.1.4.5.1.1"
	snmpOIDDot1dBasePortIfIndex    = "1.3.6.1.2.1.17.1.4.1.2"

	snmpOIDIPNetToMediaType = "1.3.6.1.2.1.4.22.1.4"
)

// snmpNetworkBudget bounds the network phase. The walks are one GETNEXT per
// row, and a 48-port switch is a few hundred rows per phase; a distant device
// gets a minute, after which the tables read so far are used and the cut walks
// are warned about (snmpWalkColumn).
const snmpNetworkBudget = 60 * time.Second

// ipAddressOrigin values (IP-MIB IpAddressOriginTC) that say how an address is
// configured.
const (
	snmpOriginManual    = 2
	snmpOriginDHCP      = 4
	snmpOriginLinkLayer = 5
	snmpOriginRandom    = 6
)

// snmpVLANSuffix matches a sub-interface name that carries its VLAN id
// (`eth0.100`, `GigabitEthernet1/0/1.100`).
var snmpVLANSuffix = regexp.MustCompile(`^(.+)\.(\d{1,4})$`)

// snmpVendorFamily is the ifnames vendor family a sysObjectID implies, "" when
// it names none. The enterprise number is an IANA registry, not a guess; the
// agent-only arcs (Net-SNMP, Microsoft) name the OS family the interface names
// follow.
func snmpVendorFamily(sysObjectID string) string {
	if v := ifnames.NormalizeVendor(snmpObjectIDHint(sysObjectID).Vendor); v != ifnames.VendorAuto {
		return v
	}
	switch {
	case strings.HasPrefix(sysObjectID, "1.3.6.1.4.1.8072."): // Net-SNMP
		return ifnames.VendorLinux
	case strings.HasPrefix(sysObjectID, "1.3.6.1.4.1.311."): // Microsoft
		return ifnames.VendorWindows
	}
	return ifnames.VendorAuto
}

// snmpCollectNetwork walks the interface, address, VLAN and ARP tables and
// returns the device's network posture, nil when the agent answered none of
// them. Every step is best-effort, like snmpCollectOps.
func snmpCollectNetwork(ctx context.Context, result *InterrogateResult, conn net.Conn, community string, timeout time.Duration, sysObjectID, mgmtHost string) *NetworkObservation {
	deadline := time.Now().Add(snmpNetworkBudget)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	walk := func(column string) map[string]snmpVarBind {
		m, _ := snmpWalkColumn(ctx, result, conn, community, column, timeout, deadline)
		return m
	}

	vendor := snmpVendorFamily(sysObjectID)
	ifaces := snmpInterfaceTable(walk, vendor)

	n := &NetworkObservation{Vendor: vendor}
	if ip, err := netip.ParseAddr(strings.TrimSpace(mgmtHost)); err == nil {
		n.ManagementAddress = ip.Unmap().String()
	}

	byIndex := map[string]*snmpIface{}
	for _, i := range ifaces {
		byIndex[i.index] = i
	}
	snmpApplyStack(ifaces, byIndex, walk)
	snmpApplyLAG(ifaces, byIndex, walk)
	snmpApplyAddresses(byIndex, walk)
	n.VLANs = snmpApplyVLANs(ifaces, byIndex, walk)
	snmpApplyVLANSuffixes(ifaces, &n.VLANs)

	for _, i := range ifaces {
		n.Interfaces = append(n.Interfaces, i.obs)
	}
	n.ARP = snmpARPEvidence(ifaces, byIndex, walk)
	n.Neighbors = snmpNeighbors(byIndex, vendor, walk)
	// The hardware (DCIM row 2.4): entPhysicalTable's parts, modules and
	// stack members, a part tied to the interface its port is.
	ifName := map[string]string{}
	for _, i := range ifaces {
		ifName[i.index] = i.obs.Name
	}
	n.InventoryItems, n.Modules, n.VirtualChassis = snmpHardware(walk, ifName, snmpObjectIDHint(sysObjectID).Vendor)
	if n.Empty() {
		return nil
	}
	return n
}

// snmpIface is an interface under construction: its ifIndex and the type the
// agent reported, beside the observation being built.
type snmpIface struct {
	index  string
	ifType int64
	obs    ObservedInterface
	// container is a Linux container/virtualisation bridge or veth: its
	// addresses (docker0's 172.17.0.1 is on every Docker host) and generated MAC
	// are not the host's and never identify it.
	container bool
}

// snmpContainerInterface matches the interfaces a container runtime or
// hypervisor creates on a Linux host. Deliberately narrow: `br0` and `br-lan`
// are real bridges (a router's LAN), `br-<12 hex>` is Docker's.
var snmpContainerInterface = regexp.MustCompile(`^(docker\d+|veth.*|cni\d*|flannel.*|cali.*|vxlan\.calico|virbr\d+.*|lxcbr\d+|lxdbr\d+|kube-ipvs\d+|br-[0-9a-f]{12})$`)

// snmpInterfaceTable builds one observation per ifIndex from ifTable and
// ifXTable. The name is ifName, else ifDescr, canonicalised for the device's
// vendor family (ifnames) so the short spelling a CLI shows and the long one
// ifDescr carries are one interface.
func snmpInterfaceTable(walk func(string) map[string]snmpVarBind, vendor string) []*snmpIface {
	descrs := walk(snmpOIDIfDescr)
	names := walk(snmpOIDIfName)
	if len(descrs) == 0 && len(names) == 0 {
		return nil
	}
	types := walk(snmpOIDIfType)
	mtus := walk(snmpOIDIfMtu)
	macs := walk(snmpOIDIfPhysAddress)
	admin := walk(snmpOIDIfAdminStatus)
	oper := walk(snmpOIDIfOperStatus)
	highSpeed := walk(snmpOIDIfHighSpeed)
	speed := walk(snmpOIDIfSpeed)

	indexes := make([]string, 0, len(descrs)+len(names))
	seen := map[string]bool{}
	for _, source := range []map[string]snmpVarBind{names, descrs} {
		for index := range source {
			if !seen[index] {
				seen[index] = true
				indexes = append(indexes, index)
			}
		}
	}
	sort.Slice(indexes, func(i, j int) bool { return snmpIndexLess(indexes[i], indexes[j]) })

	var out []*snmpIface
	for _, index := range indexes {
		raw := strings.TrimSpace(names[index].Text())
		if raw == "" {
			raw = strings.TrimSpace(descrs[index].Text())
		}
		if raw == "" {
			continue
		}
		name, kind := ifnames.Canonical(vendor, raw)
		i := &snmpIface{index: index, obs: ObservedInterface{Name: name}}
		i.container = vendor == ifnames.VendorLinux && snmpContainerInterface.MatchString(name)
		if t, ok := types[index].Int(); ok {
			i.ifType = t
		}

		if mbits, ok := highSpeed[index].Int(); ok && mbits > 0 {
			kbps := mbits * 1000
			i.obs.SpeedKbps = &kbps
		} else if bits, ok := speed[index].Int(); ok && bits > 0 && bits < snmpIfSpeedSaturated {
			kbps := bits / 1000
			i.obs.SpeedKbps = &kbps
		}
		var kbps int64
		if i.obs.SpeedKbps != nil {
			kbps = *i.obs.SpeedKbps
		}
		i.obs.Type = snmpInterfaceType(i.ifType, kbps, ifnames.Kind(kind))

		if mtu, ok := mtus[index].Int(); ok && mtu > 0 && mtu <= 65536 {
			v := int(mtu)
			i.obs.MTU = &v
		}
		if mac, ok := macs[index].MAC(); ok && !i.container && snmpGloballyAdministered(mac) {
			i.obs.MAC = mac
		}
		if state, ok := oper[index].Int(); ok {
			i.obs.OperStatus = snmpOperStatus(state)
		}
		if state, ok := admin[index].Int(); ok {
			switch state {
			case 1:
				on := true
				i.obs.Enabled = &on
			case 2:
				off := false
				i.obs.Enabled = &off
			}
		}
		out = append(out, i)
	}
	return out
}

// snmpIfSpeedSaturated is what ifSpeed (a Gauge32) reports for anything faster
// than 4.29 Gb/s: a ceiling, not a speed.
const snmpIfSpeedSaturated = 4294967295

// snmpInterfaceType is the registry type for an interface, "" when the type is
// better left to the interface's name (Intake's rule) or is `other` anyway.
//
// An ethernetCsmacd that the name says is a bond, bridge, VLAN, tunnel or
// loopback is not a media type: net-snmp reports every Linux interface,
// including bond0 and eth0.100, as ifType 6.
func snmpInterfaceType(ifType, speedKbps int64, kind ifnames.Kind) string {
	t := dcim.InterfaceTypeFromIfType(ifType, speedKbps)
	switch ifType {
	case dcim.IfTypeEthernetCsmacd, dcim.IfTypeGigabitEthernet, dcim.IfTypeFastEther, dcim.IfTypeFastEtherFX:
		switch kind {
		case ifnames.KindLAG, ifnames.KindBridge, ifnames.KindVLAN, ifnames.KindVirtual, ifnames.KindLoopback, ifnames.KindTunnel:
			return ""
		}
	}
	if t == dcim.InterfaceTypeOther {
		return ""
	}
	return string(t)
}

// snmpGloballyAdministered reports whether a canonical MAC is one the vendor
// assigned: a locally administered bit marks a software-generated address (a
// bond, a veth, a VLAN sub-interface) that never identifies a device — the
// rule the host-inventory adapter applies — and a group bit marks a multicast.
func snmpGloballyAdministered(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) > 0 && hw[0]&0x03 == 0
}

// snmpApplyStack reads ifStackTable for a VLAN sub-interface's lower interface
// (ifType l2vlan) and an aggregate's members (ifType ieee8023adLag). Only
// interfaces that need it cause the walk.
func snmpApplyStack(ifaces []*snmpIface, byIndex map[string]*snmpIface, walk func(string) map[string]snmpVarBind) {
	need := false
	for _, i := range ifaces {
		if i.ifType == dcim.IfTypeL2Vlan || i.ifType == dcim.IfTypeIEEE8023adLag {
			need = true
			break
		}
	}
	if !need {
		return
	}
	rows := walk(snmpOIDIfStackStatus)
	keys := make([]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool { return snmpIndexLess(keys[a], keys[b]) })
	for _, k := range keys {
		if status, ok := rows[k].Int(); !ok || status != 1 { // active
			continue
		}
		parts := strings.Split(k, ".")
		if len(parts) != 2 || parts[0] == "0" || parts[1] == "0" {
			continue
		}
		higher, lower := byIndex[parts[0]], byIndex[parts[1]]
		if higher == nil || lower == nil || higher == lower {
			continue
		}
		switch higher.ifType {
		case dcim.IfTypeL2Vlan:
			if higher.obs.Parent == "" {
				higher.obs.Parent = lower.obs.Name
			}
		case dcim.IfTypeIEEE8023adLag:
			if lower.obs.LAG == "" {
				lower.obs.LAG = higher.obs.Name
			}
		}
	}
}

// snmpApplyLAG reads the LACP attachment of each port.
func snmpApplyLAG(ifaces []*snmpIface, byIndex map[string]*snmpIface, walk func(string) map[string]snmpVarBind) {
	rows := walk(snmpOIDLagAttachedAgg)
	for port, bind := range rows {
		agg, ok := bind.Int()
		if !ok || agg <= 0 {
			continue
		}
		member, aggregator := byIndex[port], byIndex[strconv.FormatInt(agg, 10)]
		if member == nil || aggregator == nil || member == aggregator {
			continue
		}
		member.obs.LAG = aggregator.obs.Name
	}
}

// snmpApplyAddresses attaches each unicast address to its interface, from
// ipAddressTable, else from ipAddrTable.
func snmpApplyAddresses(byIndex map[string]*snmpIface, walk func(string) map[string]snmpVarBind) {
	ifIndexes := walk(snmpOIDIPAddressIfIndex)
	if len(ifIndexes) == 0 {
		snmpApplyLegacyAddresses(byIndex, walk)
		return
	}
	types := walk(snmpOIDIPAddressType)
	prefixes := walk(snmpOIDIPAddressPrefix)
	origins := walk(snmpOIDIPAddressOrigin)

	// The prefix length also lives in ipAddrTable's netmask for v4; read it
	// only when the prefix column does not carry one.
	var legacy map[netip.Addr]int
	keys := make([]string, 0, len(ifIndexes))
	for k := range ifIndexes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool { return snmpIndexLess(keys[a], keys[b]) })
	for _, k := range keys {
		addr, ok := snmpAddressFromIPAddressIndex(k)
		if !ok {
			continue
		}
		if t, ok := types[k].Int(); ok && t != 1 { // not unicast
			continue
		}
		origin, _ := origins[k].Int()
		if origin == snmpOriginLinkLayer || origin == snmpOriginRandom {
			continue
		}
		if !snmpUsableAddress(addr) {
			continue
		}
		idx, _ := ifIndexes[k].Int()
		iface := byIndex[strconv.FormatInt(idx, 10)]
		if iface == nil || iface.container {
			continue
		}
		oa := ObservedAddress{Address: addr.String()}
		switch origin {
		case snmpOriginManual:
			oa.Assignment = "static"
		case snmpOriginDHCP:
			oa.Assignment = "dynamic"
		}
		oa.PrefixLen = snmpPrefixLenFromOID(prefixes[k].Text(), addr)
		if oa.PrefixLen == 0 && addr.Is4() {
			if legacy == nil {
				legacy = snmpLegacyPrefixLens(walk)
			}
			oa.PrefixLen = legacy[addr]
		}
		iface.obs.Addresses = append(iface.obs.Addresses, oa)
	}
}

// snmpApplyLegacyAddresses is the ipAddrTable fallback (IPv4 only).
func snmpApplyLegacyAddresses(byIndex map[string]*snmpIface, walk func(string) map[string]snmpVarBind) {
	ifIndexes := walk(snmpOIDIPAdEntIfIndex)
	if len(ifIndexes) == 0 {
		return
	}
	masks := walk(snmpOIDIPAdEntNetMask)
	keys := make([]string, 0, len(ifIndexes))
	for k := range ifIndexes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool { return snmpIndexLess(keys[a], keys[b]) })
	for _, k := range keys {
		addr, err := netip.ParseAddr(k) // the index IS the address
		if err != nil || !snmpUsableAddress(addr) {
			continue
		}
		idx, _ := ifIndexes[k].Int()
		iface := byIndex[strconv.FormatInt(idx, 10)]
		if iface == nil || iface.container {
			continue
		}
		iface.obs.Addresses = append(iface.obs.Addresses, ObservedAddress{
			Address: addr.String(), PrefixLen: snmpMaskLen(masks[k]),
		})
	}
}

func snmpLegacyPrefixLens(walk func(string) map[string]snmpVarBind) map[netip.Addr]int {
	out := map[netip.Addr]int{}
	for k, bind := range walk(snmpOIDIPAdEntNetMask) {
		if addr, err := netip.ParseAddr(k); err == nil {
			out[addr] = snmpMaskLen(bind)
		}
	}
	return out
}

// snmpMaskLen is the length of an IpAddress-typed netmask, 0 when it is not a
// contiguous mask.
func snmpMaskLen(b snmpVarBind) int {
	if b.Tag != snmpTagIPAddress || len(b.Raw) != 4 {
		return 0
	}
	ones, bits := net.IPMask(b.Raw).Size()
	if bits != 32 {
		return 0
	}
	return ones
}

// snmpAddressFromIPAddressIndex decodes an ipAddressTable index:
// (addrType, length-prefixed address octets) — `1.4.a.b.c.d` for IPv4,
// `2.16.<16 octets>` for IPv6.
func snmpAddressFromIPAddressIndex(index string) (netip.Addr, bool) {
	parts := strings.Split(index, ".")
	if len(parts) < 3 {
		return netip.Addr{}, false
	}
	typ, err1 := strconv.Atoi(parts[0])
	n, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || n != len(parts)-2 {
		return netip.Addr{}, false
	}
	octets := make([]byte, n)
	for i, p := range parts[2:] {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return netip.Addr{}, false
		}
		octets[i] = byte(v)
	}
	switch {
	case typ == 1 && n == 4, typ == 2 && n == 16:
		addr, ok := netip.AddrFromSlice(octets)
		return addr.Unmap(), ok
	}
	return netip.Addr{}, false
}

// snmpPrefixLenFromOID reads the prefix length off an ipAddressPrefix value —
// a pointer into ipAddressPrefixTable whose last sub-identifier is the length.
// Agents that keep no prefix table answer zeroDotZero (`0.0`), which says
// nothing.
func snmpPrefixLenFromOID(oid string, addr netip.Addr) int {
	if !strings.HasPrefix(oid, "1.3.6.1.2.1.4.32.1.5.") {
		return 0
	}
	last := oid[strings.LastIndexByte(oid, '.')+1:]
	n, err := strconv.Atoi(last)
	if err != nil || n < 0 || n > addr.BitLen() {
		return 0
	}
	return n
}

// snmpUsableAddress keeps the addresses an interface can be identified by:
// not loopback, link-local, multicast or unspecified.
func snmpUsableAddress(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsMulticast() && !a.IsUnspecified()
}

// snmpApplyVLANs reads the Q-BRIDGE static VLAN table: the VLANs the device
// knows (with names), each port's native VLAN (dot1qPvid) and trunk
// membership (egress ports that are not untagged). Absent on a router or a
// host, in which case it adds nothing.
func snmpApplyVLANs(ifaces []*snmpIface, byIndex map[string]*snmpIface, walk func(string) map[string]snmpVarBind) []ObservedVLAN {
	names := walk(snmpOIDDot1qVlanStaticName)
	if len(names) == 0 {
		return nil
	}
	egress := walk(snmpOIDDot1qVlanStaticEgress)
	untagged := walk(snmpOIDDot1qVlanStaticUntagged)
	pvids := walk(snmpOIDDot1qPvid)
	basePorts := walk(snmpOIDDot1dBasePortIfIndex)

	ifaceOfPort := func(port int) *snmpIface {
		idx, ok := basePorts[strconv.Itoa(port)].Int()
		if !ok {
			return nil
		}
		return byIndex[strconv.FormatInt(idx, 10)]
	}

	vids := make([]string, 0, len(names))
	for k := range names {
		vids = append(vids, k)
	}
	sort.Slice(vids, func(a, b int) bool { return snmpIndexLess(vids[a], vids[b]) })

	var vlans []ObservedVLAN
	tagged := map[*snmpIface][]int{}
	for _, k := range vids {
		vid, err := strconv.Atoi(k)
		if err != nil || vid < 1 || vid > 4094 {
			continue
		}
		vlans = append(vlans, ObservedVLAN{VID: vid, Name: strings.TrimSpace(names[k].Text())})
		for _, port := range snmpPortListMembers(egress[k].Raw) {
			if snmpPortListHas(untagged[k].Raw, port) {
				continue
			}
			if i := ifaceOfPort(port); i != nil {
				tagged[i] = append(tagged[i], vid)
			}
		}
	}
	for port, bind := range pvids {
		p, err := strconv.Atoi(port)
		pvid, ok := bind.Int()
		if err != nil || !ok || pvid < 1 || pvid > 4094 {
			continue
		}
		if i := ifaceOfPort(p); i != nil {
			i.obs.UntaggedVLAN = int(pvid)
		}
	}
	for i, v := range tagged {
		i.obs.TaggedVLANs = v
	}
	for _, i := range ifaces {
		switch {
		case len(i.obs.TaggedVLANs) > 0:
			i.obs.Mode = "tagged"
		case i.obs.UntaggedVLAN > 0:
			i.obs.Mode = "access"
		}
	}
	return vlans
}

// snmpPortListMembers returns the bridge port numbers set in a PortList
// bitmap: the first octet's most significant bit is port 1.
func snmpPortListMembers(list []byte) []int {
	var out []int
	for i, b := range list {
		for bit := 0; bit < 8; bit++ {
			if b&(0x80>>bit) != 0 {
				out = append(out, i*8+bit+1)
			}
		}
	}
	return out
}

func snmpPortListHas(list []byte, port int) bool {
	i, bit := (port-1)/8, (port-1)%8
	return port >= 1 && i < len(list) && list[i]&(0x80>>bit) != 0
}

// snmpApplyVLANSuffixes reads a VLAN sub-interface's VLAN off its name when the
// device did not say through Q-BRIDGE (a host has no Q-BRIDGE; a router's
// `Gi0/1.100` has no port membership): `eth0.100` is `eth0` in VLAN 100,
// access mode — the shape the host-inventory adapter files. A name whose base
// is not another interface of the device is left alone.
func snmpApplyVLANSuffixes(ifaces []*snmpIface, vlans *[]ObservedVLAN) {
	names := map[string]bool{}
	for _, i := range ifaces {
		names[i.obs.Name] = true
	}
	known := map[int]bool{}
	for _, v := range *vlans {
		known[v.VID] = true
	}
	for _, i := range ifaces {
		if i.ifType != dcim.IfTypeL2Vlan && i.ifType != dcim.IfTypeEthernetCsmacd {
			continue
		}
		m := snmpVLANSuffix.FindStringSubmatch(i.obs.Name)
		if m == nil {
			continue
		}
		vid, _ := strconv.Atoi(m[2])
		if vid < 1 || vid > 4094 || !names[m[1]] {
			continue
		}
		if i.obs.Parent == "" {
			i.obs.Parent = m[1]
		}
		i.obs.Type = string(dcim.InterfaceTypeVirtual)
		if i.obs.UntaggedVLAN == 0 {
			i.obs.UntaggedVLAN, i.obs.Mode = vid, "access"
		}
		if !known[vid] {
			known[vid] = true
			*vlans = append(*vlans, ObservedVLAN{VID: vid})
		}
	}
}

// snmpARPEvidence projects ipNetToMediaTable onto ARP evidence: complete
// entries only (a MAC that is a real address, a type that is not `invalid`),
// not the device's own addresses, each with the interface that learned it.
// This is supporting evidence about OTHER devices' addresses; it never carries
// an identifier and the sink never creates an asset from it.
func snmpARPEvidence(ifaces []*snmpIface, byIndex map[string]*snmpIface, walk func(string) map[string]snmpVarBind) []ObservedARPEntry {
	physAddrs := walk(snmpOIDIPNetToMediaPhysAddress)
	if len(physAddrs) == 0 {
		return nil
	}
	netAddrs := walk(snmpOIDIPNetToMediaNetAddress)
	types := walk(snmpOIDIPNetToMediaType)

	own := map[netip.Addr]bool{}
	for _, i := range ifaces {
		for _, a := range i.obs.Addresses {
			if addr, err := netip.ParseAddr(a.Address); err == nil {
				own[addr] = true
			}
		}
	}
	indexes := make([]string, 0, len(physAddrs))
	for index := range physAddrs {
		indexes = append(indexes, index)
	}
	sort.Slice(indexes, func(i, j int) bool { return snmpIndexLess(indexes[i], indexes[j]) })

	var out []ObservedARPEntry
	for _, index := range indexes {
		if t, ok := types[index].Int(); ok && t == 2 { // invalid
			continue
		}
		mac, ok := physAddrs[index].MAC()
		if !ok {
			continue
		}
		raw := strings.TrimSpace(netAddrs[index].Text())
		if raw == "" {
			raw = snmpAddressFromIndex(index)
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil || !snmpUsableAddress(addr) || own[addr.Unmap()] {
			continue
		}
		entry := ObservedARPEntry{Address: addr.Unmap().String(), MAC: mac}
		if i := byIndex[strings.SplitN(index, ".", 2)[0]]; i != nil {
			entry.Interface = i.obs.Name
		}
		out = append(out, entry)
	}
	return out
}
