package deviceinterrogation

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// Cisco interfaces, addresses, VLANs and ARP as objects (DCIM row 1.5c).
//
// Five commands, each read-only and each asked narrowly (CLAUDE.md "don't
// retrieve it"):
//
//   - `show interfaces` — states, MAC, address with its length, MTU, the
//     negotiated speed and media type, a port-channel's members, a
//     sub-interface's 802.1Q tag. Its `Description:` line is free text an
//     operator wrote and is never read.
//   - `show ip interface brief` — the layer-3 interfaces on platforms whose
//     `show interfaces` this parser cannot read (NX-OS).
//   - `show interfaces status` — each switch port's access VLAN or `trunk`, and
//     its media Type column. Read by COLUMN POSITION from the header, so the
//     `Name` column (the port description, free text) is never read at all.
//   - `show interfaces trunk` — each trunk's native VLAN and allowed list.
//   - `show vlan brief` — the VLAN table, and the access ports of each VLAN on
//     a switch that does not answer `show interfaces status`.
//
// And `show ip arp` (`show arp` on IOS-XR and ASA) for the ARP evidence. Every
// command was already guarded by the closed list in cisco_commands_test.go;
// the two new ones are added there.
//
// On NX-OS only, `show vdc membership` (DCIM gap 1): each virtual device
// context's id and name and the interfaces allocated to it. Read are the
// `vdc_id: N vdc_name: X interfaces:` headers and the interface names under
// them; VDC 0 is the pool of unallocated ports, not a context. Asked of NX-OS
// alone: no other Cisco OS has VDCs, and IOS would answer with an error.

// ciscoIfDetail is what `show interfaces` says about one interface beyond the
// states, MAC and address the existing parser reads.
type ciscoIfDetail struct {
	mtu        int
	speedMbps  int64 // negotiated ("1000Mb/s", "10Gb/s"); 0 when not stated
	bwKbps     int64 // the BW line
	media      string
	members    []string
	dot1qVLAN  int
	addrCIDR   string
	hasAddress bool
}

var (
	ciscoMTURE       = regexp.MustCompile(`(?i)\bMTU (\d+) bytes`)
	ciscoSpeedRE     = regexp.MustCompile(`(?i)(?:^|[\s,])(\d+)\s*(Mb|Gb)/s`)
	ciscoMediaRE     = regexp.MustCompile(`(?i)media type is (.+)$`)
	ciscoMembersRE   = regexp.MustCompile(`(?i)^Members in this channel:\s*(.+)$`)
	ciscoDot1QRE     = regexp.MustCompile(`(?i)^Encapsulation 802\.1Q Virtual LAN, Vlan ID\s+(\d+)`)
	ciscoBWKbpsRE    = regexp.MustCompile(`(?i)\bBW (\d+) Kbit`)
	ciscoStatusHdrRE = regexp.MustCompile(`^Port\s+Name\s+Status\s+Vlan\s+Duplex\s+Speed\s+Type`)
	ciscoVDCHeaderRE = regexp.MustCompile(`^\s*vdc_id:\s*(\d+)\s+vdc_name:\s*(\S+)\s+interfaces:\s*(.*)$`)
	ciscoVDCPortRE   = regexp.MustCompile(`^[A-Za-z][A-Za-z-]*\d+(?:/\d+)*(?:\.\d+)?$`)
)

// ciscoVDC is one virtual device context of `show vdc membership`.
type ciscoVDC struct {
	id    int
	name  string
	ports []string // canonical names
}

// ciscoParseVDCMembership reads `show vdc membership`: each context's header
// and the interface names listed under it (a breakout port's `(b)` flag
// dropped). VDC 0 (the unallocated ports) is skipped; a token that is not an
// interface name ends nothing and is ignored.
func ciscoParseVDCMembership(output string) []ciscoVDC {
	var (
		out []ciscoVDC
		cur *ciscoVDC
	)
	ports := func(text string) {
		if cur == nil {
			return
		}
		for _, f := range strings.Fields(text) {
			f = strings.TrimSuffix(f, "(b)")
			if !ciscoVDCPortRE.MatchString(f) {
				continue
			}
			cur.ports = append(cur.ports, ciscoCanonical(f))
		}
	}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		if m := ciscoVDCHeaderRE.FindStringSubmatch(line); m != nil {
			id, err := strconv.Atoi(m[1])
			if err != nil || id < 1 || id > maxContextIdentifier {
				cur = nil
				continue
			}
			out = append(out, ciscoVDC{id: id, name: m[2]})
			cur = &out[len(out)-1]
			ports(m[3])
			continue
		}
		if strings.TrimSpace(line) == "" || (line[0] != ' ' && line[0] != '\t') {
			if strings.TrimSpace(line) != "" {
				cur = nil
			}
			continue
		}
		ports(line)
	}
	return out
}

// ciscoParseInterfaceDetails reads the posture half of `show interfaces`,
// keyed by canonical interface name. Only lines whose prefix is one of the
// patterns above are read.
func ciscoParseInterfaceDetails(output string) map[string]*ciscoIfDetail {
	out := map[string]*ciscoIfDetail{}
	var cur *ciscoIfDetail
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := ciscoInterfaceHeaderRE.FindStringSubmatch(line); m != nil {
			cur = &ciscoIfDetail{}
			out[ciscoCanonical(m[1])] = cur
			continue
		}
		if cur == nil {
			continue
		}
		t := strings.TrimSpace(line)
		if m := ciscoMTURE.FindStringSubmatch(t); m != nil && cur.mtu == 0 {
			cur.mtu, _ = strconv.Atoi(m[1])
		}
		if m := ciscoBWKbpsRE.FindStringSubmatch(t); m != nil && cur.bwKbps == 0 {
			cur.bwKbps, _ = strconv.ParseInt(m[1], 10, 64)
		}
		if strings.Contains(strings.ToLower(t), "duplex") {
			if m := ciscoSpeedRE.FindStringSubmatch(t); m != nil {
				n, _ := strconv.ParseInt(m[1], 10, 64)
				if strings.EqualFold(m[2], "gb") {
					n *= 1000
				}
				cur.speedMbps = n
			}
		}
		if m := ciscoMediaRE.FindStringSubmatch(t); m != nil {
			cur.media = strings.TrimSpace(m[1])
		}
		if m := ciscoMembersRE.FindStringSubmatch(t); m != nil {
			for _, f := range strings.Fields(m[1]) {
				cur.members = append(cur.members, ciscoCanonical(f))
			}
		}
		if m := ciscoDot1QRE.FindStringSubmatch(t); m != nil {
			cur.dot1qVLAN, _ = strconv.Atoi(m[1])
		}
		if m := ciscoInterfaceAddrRE.FindStringSubmatch(t); m != nil {
			if a := netAddressFromCIDR(m[1]); a != "" {
				cur.addrCIDR, cur.hasAddress = a, true
			}
		}
	}
	return out
}

// ciscoPortStatus is one row of `show interfaces status`.
type ciscoPortStatus struct {
	vlan  string // a VLAN id, "trunk", "routed", "unassigned"
	media string // the Type column
}

// ciscoParseInterfacesStatus reads `show interfaces status` by the header's
// column positions. The Name column — the port description — lies between Port
// and Status and is never sliced out.
func ciscoParseInterfacesStatus(output string) map[string]ciscoPortStatus {
	out := map[string]ciscoPortStatus{}
	var vlanAt, duplexAt, typeAt int
	header := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if ciscoStatusHdrRE.MatchString(line) {
			vlanAt = strings.Index(line, "Vlan")
			duplexAt = strings.Index(line, "Duplex")
			typeAt = strings.Index(line, "Type")
			header = true
			continue
		}
		if !header || strings.TrimSpace(line) == "" || line[0] == ' ' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || len(line) <= vlanAt {
			continue
		}
		port := ciscoCanonical(fields[0])
		col := func(from, to int) string {
			if from >= len(line) {
				return ""
			}
			if to > len(line) || to <= 0 {
				to = len(line)
			}
			return strings.TrimSpace(line[from:to])
		}
		st := ciscoPortStatus{vlan: col(vlanAt, duplexAt)}
		if typeAt > 0 {
			st.media = col(typeAt, 0)
		}
		// The VLAN column is a single token; anything else means the row was
		// not laid out under this header.
		if strings.Contains(st.vlan, " ") {
			continue
		}
		out[port] = st
	}
	return out
}

// ciscoTrunk is one port of `show interfaces trunk`.
type ciscoTrunk struct {
	native  int
	allowed []int
	all     bool
}

// ciscoParseInterfacesTrunk reads the native VLAN (first section) and the
// allowed list (the "Vlans allowed on trunk" section) of each trunk port. The
// later "allowed and active" and "spanning tree forwarding" sections are not
// configuration and are not read. A list that wraps continues on lines that
// start with whitespace.
func ciscoParseInterfacesTrunk(output string) map[string]*ciscoTrunk {
	out := map[string]*ciscoTrunk{}
	section := ""
	lastPort := ""
	lists := map[string]string{}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "Port") {
			switch {
			case strings.Contains(t, "Native vlan"):
				section = "native"
			case strings.Contains(t, "Vlans allowed on trunk"):
				section = "allowed"
			default:
				section = "other"
			}
			lastPort = ""
			continue
		}
		fields := strings.Fields(t)
		if section == "allowed" && (line[0] == ' ' || line[0] == '\t') && lastPort != "" {
			lists[lastPort] += t
			continue
		}
		if len(fields) < 2 {
			continue
		}
		port := ciscoCanonical(fields[0])
		switch section {
		case "native":
			n, err := strconv.Atoi(fields[len(fields)-1])
			if err != nil {
				continue
			}
			tr := out[port]
			if tr == nil {
				tr = &ciscoTrunk{}
				out[port] = tr
			}
			tr.native = n
		case "allowed":
			lists[port] = fields[1]
			lastPort = port
		}
	}
	for port, list := range lists {
		tr := out[port]
		if tr == nil {
			tr = &ciscoTrunk{}
			out[port] = tr
		}
		tr.allowed, tr.all = expandVLANList(list)
	}
	return out
}

// ciscoVLANPorts reads the Ports column of `show vlan brief` (with its
// continuation lines): which VLAN each access port is in.
func ciscoVLANPorts(output string) map[string]int {
	out := map[string]int{}
	current := 0
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		portsText := ""
		if m := ciscoVlanRowRE.FindStringSubmatch(t); m != nil && line[0] != ' ' {
			id, err := strconv.Atoi(m[1])
			if err != nil || id < 1 || id > 4094 || (id >= 1002 && id <= 1005) {
				current = 0
				continue
			}
			current = id
			// Everything after the Status column.
			parts := strings.Fields(t)
			if len(parts) > 3 {
				portsText = strings.Join(parts[3:], " ")
			}
		} else if line[0] == ' ' && current != 0 {
			portsText = t
		} else {
			current = 0
			continue
		}
		for _, p := range strings.Split(portsText, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out[ciscoCanonical(p)] = current
			}
		}
	}
	return out
}

// ciscoCanonical is a Cisco interface name in its canonical (long) form.
func ciscoCanonical(name string) string {
	n, _ := ifnames.Canonical(ifnames.VendorCisco, strings.TrimSpace(name))
	return n
}

// ciscoNetworkInputs is every command output the projection reads; "" for a
// command that did not answer.
type ciscoNetworkInputs struct {
	interfaces       string
	merged           []map[string]interface{}
	interfacesStatus string
	interfacesTrunk  string
	vlanBrief        string
	arp              []map[string]interface{}
	// osName picks the per-platform commands; vdcMembership is
	// `show vdc membership` (NX-OS only).
	osName        string
	vdcMembership string
}

// ciscoNetwork builds the network observation from the parsed command outputs.
func ciscoNetwork(in ciscoNetworkInputs) *vendorNetwork {
	details := ciscoParseInterfaceDetails(in.interfaces)
	status := ciscoParseInterfacesStatus(in.interfacesStatus)
	trunks := ciscoParseInterfacesTrunk(in.interfacesTrunk)
	accessPorts := ciscoVLANPorts(in.vlanBrief)

	n := &vendorNetwork{NameFamily: ifnames.VendorCisco, Producer: ciscoCollector}
	lagOf := map[string]string{}
	for name, d := range details {
		for _, m := range d.members {
			lagOf[m] = name
		}
	}
	ownMACs, ownAddrs := map[string]bool{}, map[string]bool{}
	for _, entry := range in.merged {
		raw, _ := entry["name"].(string)
		name := ciscoCanonical(raw)
		if name == "" {
			continue
		}
		_, kind := ifnames.Canonical(ifnames.VendorCisco, name)
		ifc := netIface{Name: name}
		if mac, _ := entry["mac"].(string); mac != "" {
			ifc.MAC = mac
			ownMACs[mac] = true
		}
		switch entry["admin_state"] {
		case "up":
			ifc.Enabled = boolRef(true)
		case "down":
			ifc.Enabled = boolRef(false)
		}
		if s, _ := entry["state"].(string); s == "up" || s == "down" || s == "unknown" {
			ifc.OperStatus = s
		}
		d := details[name]
		physical := kind == string(ifnames.KindPhysical) || kind == string(ifnames.KindLAG)
		if d != nil {
			ifc.MTU = d.mtu
			if physical && ifc.OperStatus == "up" {
				switch {
				case kind == string(ifnames.KindLAG) && d.bwKbps > 0:
					// An aggregate's duplex line names one member's speed;
					// its BW is the bundle's.
					ifc.SpeedKbps = d.bwKbps
				case d.speedMbps > 0:
					ifc.SpeedKbps = kbpsFromMbps(d.speedMbps)
				case d.bwKbps > 0:
					ifc.SpeedKbps = d.bwKbps
				}
			}
		}
		st, hasStatus := status[name]
		if kind == string(ifnames.KindPhysical) {
			media := st.media
			if media == "" && d != nil {
				media = d.media
			}
			ifc.Type = mediaInterfaceType(media, ifc.SpeedKbps/1000)
		}
		ifc.LAG = lagOf[name]
		// 802.1Q: a trunk, an access port, or a sub-interface.
		switch tr := trunks[name]; {
		case tr != nil:
			ifc.UntaggedVLAN = tr.native
			if tr.all {
				ifc.Mode = "tagged-all"
			} else {
				ifc.Mode = "tagged"
				for _, v := range tr.allowed {
					if v != tr.native {
						ifc.TaggedVLANs = append(ifc.TaggedVLANs, v)
					}
				}
			}
		case hasStatus && st.vlan != "":
			if v, err := strconv.Atoi(st.vlan); err == nil && v >= 1 && v <= 4094 {
				ifc.Mode, ifc.UntaggedVLAN = "access", v
			}
		case accessPorts[name] != 0:
			ifc.Mode, ifc.UntaggedVLAN = "access", accessPorts[name]
		case d != nil && d.dot1qVLAN > 0:
			if i := strings.LastIndex(name, "."); i > 0 {
				ifc.Parent = name[:i]
			}
			ifc.Mode, ifc.UntaggedVLAN = "access", d.dot1qVLAN
		}
		// Addresses: the detailed view's carries its length; the brief view's
		// is the bare address.
		if d != nil && d.hasAddress {
			ifc.Addresses = append(ifc.Addresses, netAddr{Address: d.addrCIDR})
		} else if addrs, ok := entry["addresses"].([]interface{}); ok {
			for _, a := range addrs {
				if s, _ := a.(string); netAddressFromCIDR(s) != "" {
					ifc.Addresses = append(ifc.Addresses, netAddr{Address: netAddressFromCIDR(s)})
				}
			}
		}
		for _, a := range ifc.Addresses {
			ownAddrs[hostOf(a.Address)] = true
		}
		n.Interfaces = append(n.Interfaces, ifc)
	}

	for _, v := range ciscoParseVlanBrief(in.vlanBrief) {
		id, _ := v["id"].(int)
		name, _ := v["name"].(string)
		n.VLANs = append(n.VLANs, netVLAN{VID: id, Name: name})
	}
	n.Prefixes = connectedPrefixes(n.Interfaces)
	n.ARP = arpFromNeighbors(in.arp, ownMACs, ownAddrs, "")
	vdcOf := map[string]string{}
	for _, v := range ciscoParseVDCMembership(in.vdcMembership) {
		n.addContext(v.name, v.id, true)
		for _, p := range v.ports {
			if _, taken := vdcOf[p]; !taken {
				vdcOf[p] = v.name
			}
		}
	}
	for i := range n.Interfaces {
		n.Interfaces[i].Context = vdcOf[n.Interfaces[i].Name]
	}
	return n
}

// hostOf is the host part of "host/len" or "host".
func hostOf(addr string) string {
	if i := strings.Index(addr, "/"); i >= 0 {
		return addr[:i]
	}
	return addr
}

// arpFromNeighbors turns `protocol: arp` neighbour maps (the parsers'
// existing output) into ARP entries, dropping the device's own addresses and
// MACs — IOS lists its own interfaces in its ARP table with age `-`, and an
// entry about the device itself is not evidence about another host.
func arpFromNeighbors(neighbors []map[string]interface{}, ownMACs, ownAddrs map[string]bool, vrf string) []netARP {
	var out []netARP
	seen := map[string]bool{}
	for _, nb := range neighbors {
		if p, _ := nb["protocol"].(string); p != "arp" {
			continue
		}
		mac, _ := nb["remote_mac"].(string)
		addr, _ := nb["remote_address"].(string)
		if mac == "" || addr == "" || ownMACs[mac] || ownAddrs[addr] {
			continue
		}
		key := vrf + "|" + addr + "|" + mac
		if seen[key] {
			continue
		}
		seen[key] = true
		port, _ := nb["local_port"].(string)
		out = append(out, netARP{Address: addr, MAC: mac, Interface: port, VRF: vrf})
	}
	return out
}

// ciscoCollectNetwork runs the two switch-port commands the network projection
// adds and stores the observation. interfaces/merged/vlanBrief/arp are what
// ciscoCollectOps already read.
func ciscoCollectNetwork(ctx context.Context, result *InterrogateResult, run ciscoRunner, in ciscoNetworkInputs) {
	if out, ok := ciscoRun(ctx, result, run, "show interfaces status", "Switch-port access VLANs and media types not collected"); ok {
		in.interfacesStatus = out
	}
	if out, ok := ciscoRun(ctx, result, run, "show interfaces trunk", "Trunk native and allowed VLANs not collected"); ok {
		in.interfacesTrunk = out
	}
	if in.osName == "NX-OS" {
		if out, ok := ciscoRun(ctx, result, run, "show vdc membership", "Virtual device contexts not collected"); ok {
			in.vdcMembership = out
		}
	}
	result.setNetwork(ciscoNetwork(in), "show interfaces")
}
