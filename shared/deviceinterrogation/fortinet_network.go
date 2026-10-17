package deviceinterrogation

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// FortiOS interfaces, addresses, VLANs and ARP as objects (DCIM row 1.5c).
//
// `cmdb/system/interface` (configured), `monitor/system/interface` (running)
// and `monitor/network/arp`. Each item is decoded into a TYPED struct with json
// tags — a re-encode of the vendor map into the struct — so `password`,
// `ppp-*`, `auth-cert`, `ike-*` and every field a FortiOS release adds later
// have nowhere to land. `projectFortinet` remains the allowlist for the maps
// the collector still keeps elsewhere; this path never holds a map.
//
//   - VDOM → VRF: an interface's `vdom` names its virtual domain. `root` is the
//     default VDOM every FortiGate has and is the global table; any other VDOM
//     is the VRF its addresses are in.
//   - A `vlan` interface is a sub-interface: its `interface` is the parent and
//     its `vlanid` the untagged VLAN (a FortiGate has no VLAN database, so the
//     VLAN is named after the interface that declares it).
//   - An `aggregate` is a LAG; its `member` list names the member ports.

// fortinetCmdbInterface is the configured view of one interface.
type fortinetCmdbInterface struct {
	Name      string   `json:"name"`
	IP        string   `json:"ip"`
	MACAddr   string   `json:"macaddr"`
	Status    string   `json:"status"`
	VLANID    fortiInt `json:"vlanid"`
	Type      string   `json:"type"`
	Interface string   `json:"interface"`
	VDOM      string   `json:"vdom"`
	MTU       fortiInt `json:"mtu"`
	// MTUOverride is "enable" when MTU is the configured value; otherwise the
	// interface runs at its type's default and MTU is not a statement.
	MTUOverride string `json:"mtu-override"`
	Member      []struct {
		InterfaceName string `json:"interface-name"`
	} `json:"member"`
}

// fortinetMonitorInterface is the running view of one interface.
type fortinetMonitorInterface struct {
	Name  string   `json:"name"`
	Link  *bool    `json:"link"`
	Speed fortiInt `json:"speed"`
	MAC   string   `json:"mac"`
	IP    string   `json:"ip"`
	Mask  string   `json:"mask"`
}

// fortiInt is a FortiOS integer: a JSON number, or a numeric string on a few
// older releases (fortinetInt's rule). Anything else reads as 0, unknown.
type fortiInt int64

func (f *fortiInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		*f = fortiInt(n)
	} else {
		*f = 0
	}
	return nil
}

// fortinetARP is one entry of `monitor/network/arp`.
type fortinetARP struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Interface string `json:"interface"`
}

// fortinetDecode re-encodes one vendor item into T: the projection by
// structure. An item that does not decode is skipped.
func fortinetDecode[T any](raw map[string]interface{}) (T, bool) {
	var out T
	b, err := json.Marshal(raw)
	if err != nil {
		return out, false
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, false
	}
	return out, true
}

// fortinetVRF is the VRF a VDOM's addresses are in: "" for root.
func fortinetVRF(vdom string) string {
	v := strings.TrimSpace(vdom)
	if v == "" || strings.EqualFold(v, "root") {
		return ""
	}
	return v
}

// fortinetInterfaceType maps the FortiOS interface type onto the registry.
// A physical port says nothing of its media, so it is left to the name.
func fortinetInterfaceType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "aggregate", "redundant":
		return "lag"
	case "vlan", "loopback", "tunnel", "vap-switch", "ssl", "wl-mesh", "emac-vlan", "vxlan", "geneve":
		return "virtual"
	case "hard-switch", "switch":
		return "bridge"
	}
	return ""
}

// fortinetNetwork merges the configured and running views into the network
// observation, and turns the ARP table into evidence.
func fortinetNetwork(configured, running, arp []map[string]interface{}) *vendorNetwork {
	n := &vendorNetwork{NameFamily: ifnames.VendorFortinet, Producer: fortinetCollector}
	byName := map[string]int{}
	vrfOf := map[string]string{}
	lagOf := map[string]string{}
	vlanName := map[int]string{}

	for _, raw := range configured {
		c, ok := fortinetDecode[fortinetCmdbInterface](raw)
		name := strings.TrimSpace(c.Name)
		if !ok || name == "" {
			continue
		}
		ifc := netIface{Name: name, Type: fortinetInterfaceType(c.Type)}
		if mac, err := canonicalMAC(c.MACAddr); err == nil {
			ifc.MAC = mac
		}
		switch fortinetUpDown(c.Status) {
		case "up":
			ifc.Enabled = boolRef(true)
		case "down":
			ifc.Enabled = boolRef(false)
		}
		if strings.EqualFold(c.MTUOverride, "enable") && c.MTU > 0 {
			ifc.MTU = int(c.MTU)
		}
		vrf := fortinetVRF(c.VDOM)
		vrfOf[strings.ToLower(name)] = vrf
		if a := netAddressFromCIDR(fortinetAddress(c.IP)); a != "" {
			ifc.Addresses = append(ifc.Addresses, netAddr{Address: a, VRF: vrf})
		}
		if vid := int(c.VLANID); vid >= 1 && vid <= 4094 {
			ifc.Mode, ifc.UntaggedVLAN = "access", vid
			ifc.Parent = strings.TrimSpace(c.Interface)
			if _, seen := vlanName[vid]; !seen {
				vlanName[vid] = name
			}
		}
		for _, m := range c.Member {
			if m := strings.TrimSpace(m.InterfaceName); m != "" {
				lagOf[strings.ToLower(m)] = name
			}
		}
		byName[strings.ToLower(name)] = len(n.Interfaces)
		n.Interfaces = append(n.Interfaces, ifc)
	}

	for _, raw := range running {
		r, ok := fortinetDecode[fortinetMonitorInterface](raw)
		name := strings.TrimSpace(r.Name)
		if !ok || name == "" {
			continue
		}
		i, known := byName[strings.ToLower(name)]
		if !known {
			byName[strings.ToLower(name)] = len(n.Interfaces)
			n.Interfaces = append(n.Interfaces, netIface{Name: name})
			i = len(n.Interfaces) - 1
		}
		ifc := &n.Interfaces[i]
		if r.Link != nil {
			ifc.OperStatus = fortinetUpDown(*r.Link)
		}
		if r.Speed > 0 && ifc.OperStatus == "up" {
			ifc.SpeedKbps = kbpsFromMbps(int64(r.Speed))
		}
		if ifc.MAC == "" {
			if mac, err := canonicalMAC(r.MAC); err == nil {
				ifc.MAC = mac
			}
		}
		if len(ifc.Addresses) == 0 {
			if a := netAddressFromCIDR(cidrFromAddressAndMask(r.IP, r.Mask)); a != "" {
				ifc.Addresses = append(ifc.Addresses, netAddr{Address: a, VRF: vrfOf[strings.ToLower(name)]})
			}
		}
	}
	for i := range n.Interfaces {
		if lag, ok := lagOf[strings.ToLower(n.Interfaces[i].Name)]; ok {
			n.Interfaces[i].LAG = lag
		}
	}
	for vid := 1; vid <= 4094 && len(vlanName) > 0; vid++ {
		if name, ok := vlanName[vid]; ok {
			n.VLANs = append(n.VLANs, netVLAN{VID: vid, Name: name})
			delete(vlanName, vid)
		}
	}
	n.Prefixes = connectedPrefixes(n.Interfaces)

	ownMACs, ownAddrs := map[string]bool{}, map[string]bool{}
	for _, ifc := range n.Interfaces {
		if ifc.MAC != "" {
			ownMACs[ifc.MAC] = true
		}
		for _, a := range ifc.Addresses {
			ownAddrs[hostOf(a.Address)] = true
		}
	}
	seen := map[string]bool{}
	for _, raw := range arp {
		e, ok := fortinetDecode[fortinetARP](raw)
		if !ok {
			continue
		}
		mac, err := canonicalMAC(e.MAC)
		if err != nil || ownMACs[mac] {
			continue
		}
		addr, err := canonicalIP(strings.TrimSpace(e.IP))
		if err != nil || ownAddrs[addr] {
			continue
		}
		port := strings.TrimSpace(e.Interface)
		vrf := vrfOf[strings.ToLower(port)]
		key := vrf + "|" + addr + "|" + mac
		if seen[key] {
			continue
		}
		seen[key] = true
		n.ARP = append(n.ARP, netARP{Address: addr, MAC: mac, Interface: port, VRF: vrf})
	}
	return n
}
