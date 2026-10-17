package deviceinterrogation

import (
	"strconv"
	"strings"
)

// PAN-OS interfaces, addresses, VLANs and ARP as objects (DCIM row 1.5c).
//
// From the two op commands the collector already runs — `show interface all`
// and `show arp all` — plus the management interface `show system info`
// reports. Typed XML structs, as every PAN-OS response here: an element the
// struct does not name is discarded by the decoder.
//
//   - <ifnet> gives each layer-3 interface's address with its length, its
//     802.1Q tag and its forwarding instance (`vr:<virtual router>`, or
//     `lr:<logical router>` under Advanced Routing). The default instance is
//     the global table; any other is the address's VRF.
//   - <hw> gives the MAC, link state and negotiated speed, and for an
//     aggregate (`ae1`) its members.
//   - A sub-interface (`ethernet1/2.100`, tag 100) is its parent plus its
//     untagged VLAN, exactly as row 1.5a models a host's VLAN sub-interface.

// panNetIfnet is the <ifnet> entry the network projection reads.
type panNetIfnet struct {
	Name string `xml:"name"`
	IP   string `xml:"ip"`
	Tag  string `xml:"tag"`
	Fwd  string `xml:"fwd"`
}

type panNetIfnetBlock struct {
	Entries []panNetIfnet `xml:"entry"`
}

// panNetHW is the <hw> entry the network projection reads.
type panNetHW struct {
	Name      string   `xml:"name"`
	MAC       string   `xml:"mac"`
	State     string   `xml:"state"`
	Speed     string   `xml:"speed"`
	AEMembers []string `xml:"ae_member>member"`
}

type panNetHWBlock struct {
	Entries []panNetHW `xml:"entry"`
}

// panVRF maps a forwarding instance (`vr:default`, `lr:corp`) onto a VRF name,
// "" for the default instance (the global table) or none.
func panVRF(fwd string) string {
	f := strings.TrimSpace(fwd)
	for _, p := range []string{"vr:", "lr:"} {
		if strings.HasPrefix(f, p) {
			f = strings.TrimPrefix(f, p)
			if f == "default" {
				return ""
			}
			return f
		}
	}
	return ""
}

// panNetwork builds the network observation from `show interface all`
// (body), the management interface in system info, and `show arp all`
// (arpBody; "" when it did not answer).
func panNetwork(body string, info panSystemInfo, arpBody string) (*vendorNetwork, error) {
	n := &vendorNetwork{Producer: panCollector}
	byName := map[string]int{}
	upsert := func(name string) *netIface {
		key := strings.ToLower(name)
		if i, ok := byName[key]; ok {
			return &n.Interfaces[i]
		}
		byName[key] = len(n.Interfaces)
		n.Interfaces = append(n.Interfaces, netIface{Name: name})
		return &n.Interfaces[len(n.Interfaces)-1]
	}
	vrfOf := map[string]string{}
	vlans := map[int]bool{}

	if body != "" {
		ifnets, err := panFindElements[panNetIfnetBlock](body, "ifnet")
		if err != nil {
			return nil, err
		}
		for _, block := range ifnets {
			for _, e := range block.Entries {
				name := strings.TrimSpace(e.Name)
				if name == "" {
					continue
				}
				ifc := upsert(name)
				vrf := panVRF(e.Fwd)
				vrfOf[strings.ToLower(name)] = vrf
				if a := netAddressFromCIDR(panNormalizeCIDR(e.IP)); a != "" {
					ifc.Addresses = append(ifc.Addresses, netAddr{Address: a, VRF: vrf})
				}
				// Tag 0 is an untagged interface, not VLAN 0.
				if tag, err := strconv.Atoi(strings.TrimSpace(e.Tag)); err == nil && tag >= 1 && tag <= 4094 {
					ifc.Mode, ifc.UntaggedVLAN = "access", tag
					if i := strings.LastIndex(name, "."); i > 0 {
						ifc.Parent = name[:i]
					}
					vlans[tag] = true
				}
			}
		}

		hw, err := panFindElements[panNetHWBlock](body, "hw")
		if err != nil {
			return nil, err
		}
		lagOf := map[string]string{}
		for _, block := range hw {
			for _, e := range block.Entries {
				name := strings.TrimSpace(e.Name)
				if name == "" {
					continue
				}
				ifc := upsert(name)
				if mac, err := canonicalMAC(e.MAC); err == nil {
					ifc.MAC = mac
				}
				ifc.OperStatus = panLinkState(e.State)
				if speed, err := strconv.ParseInt(strings.TrimSpace(e.Speed), 10, 64); err == nil && speed > 0 && ifc.OperStatus == "up" {
					ifc.SpeedKbps = kbpsFromMbps(speed)
				}
				for _, m := range e.AEMembers {
					if m = strings.TrimSpace(m); m != "" {
						lagOf[strings.ToLower(m)] = name
					}
				}
				if len(e.AEMembers) > 0 {
					ifc.Type = "lag"
				}
			}
		}
		for i := range n.Interfaces {
			if lag, ok := lagOf[strings.ToLower(n.Interfaces[i].Name)]; ok {
				n.Interfaces[i].LAG = lag
			}
		}
	}

	if info.IPAddress != "" || info.MACAddress != "" {
		ifc := upsert("management")
		if a := netAddressFromCIDR(panManagementCIDR(info)); a != "" && len(ifc.Addresses) == 0 {
			ifc.Addresses = append(ifc.Addresses, netAddr{Address: a})
		}
		if mac, err := canonicalMAC(info.MACAddress); err == nil && ifc.MAC == "" {
			ifc.MAC = mac
		}
	}

	for vid := 1; vid <= 4094 && len(vlans) > 0; vid++ {
		if vlans[vid] {
			n.VLANs = append(n.VLANs, netVLAN{VID: vid})
			delete(vlans, vid)
		}
	}
	n.Prefixes = connectedPrefixes(n.Interfaces)

	if arpBody != "" {
		neighbors, err := panARPNeighbors(arpBody)
		if err != nil {
			return nil, err
		}
		ownMACs, ownAddrs := map[string]bool{}, map[string]bool{}
		for _, ifc := range n.Interfaces {
			if ifc.MAC != "" {
				ownMACs[ifc.MAC] = true
			}
			for _, a := range ifc.Addresses {
				ownAddrs[hostOf(a.Address)] = true
			}
		}
		for _, e := range arpFromNeighbors(neighbors, ownMACs, ownAddrs, "") {
			e.VRF = vrfOf[strings.ToLower(e.Interface)]
			n.ARP = append(n.ARP, e)
		}
	}
	return n, nil
}
