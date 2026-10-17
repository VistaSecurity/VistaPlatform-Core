package deviceinterrogation

import (
	"context"
	"strconv"
	"strings"
)

// BIG-IP interfaces, trunks, VLANs, self IPs, route domains and ARP as objects
// (DCIM row 1.5c).
//
// Every response is a typed struct (the F5 rule, f5_ops.go): nothing the
// struct does not name survives the decoder.
//
//   - `net/interface` — the physical ports: MAC, admin state, MTU, and
//     `mediaActive`, which is both the link state and the media ("1000T-FD").
//   - `net/trunk` — the aggregates; each is a LAG and names its member ports.
//   - `net/vlan?expandSubcollections=true` — each VLAN's tag, MTU and its
//     member interfaces or trunks, each tagged or untagged. A BIG-IP VLAN is
//     also a layer-3 interface (the self IPs live on it), so each VLAN becomes
//     a virtual interface named after it, untagged in its own VLAN.
//   - `net/self` — the device's addresses, each on a VLAN. `%N` names the
//     route domain; route domain 0 is the global table, any other is the VRF
//     named by `net/route-domain`.
//   - `net/arp` — the ARP table, as evidence about other hosts.

// f5NetTrunk is the `net/trunk` projection.
type f5NetTrunk struct {
	Name       string   `json:"name"`
	Interfaces []string `json:"interfaces"`
	MACAddress string   `json:"macAddress"`
}

// f5NetVLANMember is one interface or trunk of a VLAN.
type f5NetVLANMember struct {
	Name     string `json:"name"`
	Tagged   bool   `json:"tagged"`
	Untagged bool   `json:"untagged"`
}

// f5NetVLANExpanded is the `net/vlan?expandSubcollections=true` projection.
type f5NetVLANExpanded struct {
	Name                string `json:"name"`
	FullPath            string `json:"fullPath"`
	Tag                 int    `json:"tag"`
	MTU                 int    `json:"mtu"`
	InterfacesReference struct {
		Items []f5NetVLANMember `json:"items"`
	} `json:"interfacesReference"`
}

// f5RouteDomain is the `net/route-domain` projection.
type f5RouteDomain struct {
	Name string `json:"name"`
	ID   int    `json:"id"`
}

// f5ARP is the `net/arp` projection.
type f5ARP struct {
	IPAddress  string `json:"ipAddress"`
	MACAddress string `json:"macAddress"`
	VLAN       string `json:"vlan"`
	Status     string `json:"status"`
}

// f5SplitRouteDomain splits "10.1.20.5%2/24" into "10.1.20.5/24" and route
// domain 2. An address with no `%` is in route domain 0.
func f5SplitRouteDomain(addr string) (string, int) {
	s := strings.TrimSpace(addr)
	i := strings.IndexByte(s, '%')
	if i < 0 {
		return s, 0
	}
	rest := s[i+1:]
	length := ""
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest, length = rest[:j], rest[j:]
	}
	rd, err := strconv.Atoi(rest)
	if err != nil || rd < 0 {
		rd = 0
	}
	return s[:i] + length, rd
}

// f5VRF names a route domain's VRF: "" for route domain 0 (the global table),
// the route domain's name where `net/route-domain` gave one, else `rd<N>`.
func f5VRF(rd int, names map[int]string) string {
	if rd == 0 {
		return ""
	}
	if name := strings.TrimSpace(names[rd]); name != "" {
		return name
	}
	return "rd" + strconv.Itoa(rd)
}

// f5Network builds the network observation.
func f5Network(ifaces []f5NetInterface, trunks []f5NetTrunk, vlans []f5NetVLANExpanded,
	selfIPs []f5SelfIP, domains []f5RouteDomain, arp []f5ARP) *vendorNetwork {
	n := &vendorNetwork{Producer: f5Collector}
	rdNames := map[int]string{}
	for _, d := range domains {
		rdNames[d.ID] = f5ObjectName(d.Name)
	}
	byName := map[string]int{}
	add := func(ifc netIface) *netIface {
		if i, ok := byName[ifc.Name]; ok {
			return &n.Interfaces[i]
		}
		byName[ifc.Name] = len(n.Interfaces)
		n.Interfaces = append(n.Interfaces, ifc)
		return &n.Interfaces[len(n.Interfaces)-1]
	}

	lagOf := map[string]string{}
	for _, t := range trunks {
		for _, m := range t.Interfaces {
			lagOf[strings.TrimSpace(m)] = strings.TrimSpace(t.Name)
		}
	}
	for _, iface := range ifaces {
		name := strings.TrimSpace(iface.Name)
		if name == "" {
			continue
		}
		ifc := netIface{Name: name, MTU: iface.MTU, LAG: lagOf[name]}
		if mac, err := canonicalMAC(iface.MACAddress); err == nil {
			ifc.MAC = mac
		}
		switch {
		case iface.Disabled:
			ifc.Enabled = boolRef(false)
		case iface.Enabled:
			ifc.Enabled = boolRef(true)
		}
		switch media := strings.ToLower(strings.TrimSpace(iface.MediaActive)); media {
		case "":
		case "none":
			ifc.OperStatus = "down"
		default:
			ifc.OperStatus = "up"
			ifc.SpeedKbps = kbpsFromMbps(int64(f5MediaSpeed(iface.MediaActive)))
			ifc.Type = mediaInterfaceType(iface.MediaActive, int64(f5MediaSpeed(iface.MediaActive)))
		}
		add(ifc)
	}
	for _, t := range trunks {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			continue
		}
		ifc := netIface{Name: name, Type: "lag"}
		if mac, err := canonicalMAC(t.MACAddress); err == nil {
			ifc.MAC = mac
		}
		add(ifc)
	}

	vlanIfc := map[string]string{} // VLAN name → its interface name
	for _, v := range vlans {
		name := strings.TrimSpace(v.Name)
		if name == "" {
			name = f5ObjectName(v.FullPath)
		}
		if name == "" {
			continue
		}
		tag := 0
		if v.Tag >= 1 && v.Tag <= 4094 {
			tag = v.Tag
			n.VLANs = append(n.VLANs, netVLAN{VID: tag, Name: name})
		}
		// The VLAN's own layer-3 interface.
		ifc := netIface{Name: name, Type: "virtual", MTU: v.MTU}
		if tag > 0 {
			ifc.Mode, ifc.UntaggedVLAN = "access", tag
		}
		add(ifc)
		vlanIfc[name] = name
		if tag == 0 {
			continue
		}
		// Its members: untagged is the port's access / native VLAN, tagged
		// adds to its trunked list.
		for _, m := range v.InterfacesReference.Items {
			member := strings.TrimSpace(m.Name)
			i, ok := byName[member]
			if !ok {
				continue
			}
			p := &n.Interfaces[i]
			switch {
			case m.Tagged:
				p.TaggedVLANs = append(p.TaggedVLANs, tag)
				p.Mode = "tagged"
			case m.Untagged:
				p.UntaggedVLAN = tag
				if p.Mode == "" {
					p.Mode = "access"
				}
			}
		}
	}

	for _, self := range selfIPs {
		addr, rd := f5SplitRouteDomain(self.Address)
		a := netAddressFromCIDR(addr)
		vlan := f5ObjectName(self.VLAN)
		name, ok := vlanIfc[vlan]
		if a == "" || !ok {
			continue
		}
		p := &n.Interfaces[byName[name]]
		p.Addresses = append(p.Addresses, netAddr{Address: a, VRF: f5VRF(rd, rdNames)})
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
	for _, e := range arp {
		if s := strings.ToLower(strings.TrimSpace(e.Status)); s != "" && s != "resolved" && s != "permanent" {
			continue
		}
		mac, err := canonicalMAC(e.MACAddress)
		if err != nil || ownMACs[mac] {
			continue
		}
		raw, rd := f5SplitRouteDomain(e.IPAddress)
		addr, err := canonicalIP(raw)
		if err != nil || ownAddrs[addr] {
			continue
		}
		vrf := f5VRF(rd, rdNames)
		key := vrf + "|" + addr + "|" + mac
		if seen[key] {
			continue
		}
		seen[key] = true
		n.ARP = append(n.ARP, netARP{Address: addr, MAC: mac, Interface: f5ObjectName(e.VLAN), VRF: vrf})
	}
	return n
}

// f5CollectNetwork reads the network collections and stores the observation.
// interfaces and selfIPs are what f5CollectOps already read.
func (c *f5Client) f5CollectNetwork(ctx context.Context, result *InterrogateResult, interfaces []f5NetInterface, selfIPs []f5SelfIP) {
	trunks, err := f5GetCollection[f5NetTrunk](ctx, c, "/mgmt/tm/net/trunk")
	if err != nil {
		result.warn("/mgmt/tm/net/trunk", err, "Trunks (link aggregates) not collected")
	}
	vlans, err := f5GetCollection[f5NetVLANExpanded](ctx, c, "/mgmt/tm/net/vlan?expandSubcollections=true")
	if err != nil {
		result.warn("/mgmt/tm/net/vlan", err, "VLANs not collected")
	}
	domains, err := f5GetCollection[f5RouteDomain](ctx, c, "/mgmt/tm/net/route-domain")
	if err != nil {
		result.warn("/mgmt/tm/net/route-domain", err, "Route-domain names not collected; addresses outside route domain 0 are named rd<N>")
	}
	arp, err := f5GetCollection[f5ARP](ctx, c, "/mgmt/tm/net/arp")
	if err != nil {
		result.warn("/mgmt/tm/net/arp", err, "ARP neighbours not collected")
	}
	result.setNetwork(f5Network(interfaces, trunks, vlans, selfIPs, domains, arp), "/mgmt/tm/net/interface")
}
