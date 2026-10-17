package deviceinterrogation

// The SNMP collector's neighbour tables (DCIM row 3.3, ADR-0010 D6): LLDP-MIB
// lldpRemTable and CISCO-CDP-MIB cdpCacheTable, projected onto the network
// observation's Neighbors — each a cable end the platform proposes, parks or
// checks against a declared cable. The local port is named the way the
// interface table names it (ifName / ifDescr through ifnames), so the platform
// finds the local interface by its own row.

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

const (
	// lldpLocPortDesc (lldpLocPortTable column 4), beside lldpLocPortId.
	snmpOIDLLDPLocPortDesc = "1.0.8802.1.1.2.1.3.7.1.4"
	// lldpRemManAddrIfSubtype: any column of lldpRemManAddrTable; the address
	// is in the index (timeMark.localPortNum.remIndex.subtype.len.octets).
	snmpOIDLLDPRemManAddrIfSubtype = "1.0.8802.1.1.2.1.4.2.1.3"

	// CISCO-CDP-MIB cdpCacheTable, indexed ifIndex.deviceIndex.
	snmpOIDCDPCacheAddress    = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
	snmpOIDCDPCacheDeviceID   = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
	snmpOIDCDPCacheDevicePort = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
)

// snmpNeighbors walks the LLDP and CDP neighbour tables. A row whose local
// port cannot be named, or whose far end advertised nothing it could be found
// by, is dropped.
func snmpNeighbors(byIndex map[string]*snmpIface, vendor string, walk func(string) map[string]snmpVarBind) []ObservedNeighbor {
	names := map[string]string{} // canonical-folded name → interface name
	for _, i := range byIndex {
		names[strings.ToLower(i.obs.Name)] = i.obs.Name
	}
	// localName resolves an LLDP local port: its lldpLocPortId (or
	// description) when that is an interface's name, else the port number as
	// an ifIndex (the common implementation choice; not guaranteed by the MIB).
	localName := func(portNum, portID, portDesc string) string {
		for _, raw := range []string{portID, portDesc} {
			if strings.TrimSpace(raw) == "" {
				continue
			}
			c, _ := ifnames.Canonical(vendor, strings.TrimSpace(raw))
			if n, ok := names[strings.ToLower(c)]; ok {
				return n
			}
		}
		if i := byIndex[portNum]; i != nil {
			return i.obs.Name
		}
		return ""
	}

	var out []ObservedNeighbor

	// --- LLDP --------------------------------------------------------------
	chassis := walk(snmpOIDLLDPRemChassisID)
	if len(chassis) > 0 {
		portIDs := walk(snmpOIDLLDPRemPortID)
		portDescs := walk(snmpOIDLLDPRemPortDesc)
		sysNames := walk(snmpOIDLLDPRemSysName)
		locIDs := walk(snmpOIDLLDPLocPortID)
		locDescs := walk(snmpOIDLLDPLocPortDesc)
		mgmt := snmpLLDPManagementAddresses(walk(snmpOIDLLDPRemManAddrIfSubtype))

		indexes := make([]string, 0, len(chassis))
		for index := range chassis {
			indexes = append(indexes, index)
		}
		sort.Slice(indexes, func(i, j int) bool { return snmpIndexLess(indexes[i], indexes[j]) })
		for _, index := range indexes {
			parts := strings.Split(index, ".")
			if len(parts) < 3 {
				continue
			}
			portNum := parts[1]
			local := localName(portNum, locIDs[portNum].Text(), locDescs[portNum].Text())
			if local == "" {
				continue
			}
			nb := ObservedNeighbor{
				Protocol:          "lldp",
				LocalInterface:    local,
				RemotePortID:      strings.TrimSpace(portIDs[index].Text()),
				RemotePortDescr:   strings.TrimSpace(portDescs[index].Text()),
				RemoteSystemName:  strings.TrimSpace(sysNames[index].Text()),
				RemoteMgmtAddress: mgmt[strings.Join(parts[:3], ".")],
			}
			if mac, ok := chassis[index].MAC(); ok {
				nb.RemoteChassisID = mac
			} else {
				nb.RemoteChassisID = strings.TrimSpace(chassis[index].Text())
			}
			if mac, ok := portIDs[index].MAC(); ok {
				nb.RemotePortID = mac
			}
			if nb.RemoteChassisID == "" && nb.RemoteSystemName == "" {
				continue
			}
			out = append(out, nb)
		}
	}

	// --- CDP ---------------------------------------------------------------
	devices := walk(snmpOIDCDPCacheDeviceID)
	if len(devices) > 0 {
		ports := walk(snmpOIDCDPCacheDevicePort)
		addrs := walk(snmpOIDCDPCacheAddress)
		indexes := make([]string, 0, len(devices))
		for index := range devices {
			indexes = append(indexes, index)
		}
		sort.Slice(indexes, func(i, j int) bool { return snmpIndexLess(indexes[i], indexes[j]) })
		for _, index := range indexes {
			ifIndex := strings.SplitN(index, ".", 2)[0]
			i := byIndex[ifIndex]
			if i == nil {
				continue
			}
			nb := ObservedNeighbor{
				Protocol:       "cdp",
				LocalInterface: i.obs.Name,
				RemotePortID:   strings.TrimSpace(ports[index].Text()),
			}
			id := strings.TrimSpace(devices[index].Text())
			if mac, err := canonicalMAC(id); err == nil {
				nb.RemoteChassisID = mac
			} else {
				// NX-OS appends the serial: "N9K-1(FDO123)".
				if k := strings.IndexByte(id, '('); k > 0 && strings.HasSuffix(id, ")") {
					id = strings.TrimSpace(id[:k])
				}
				nb.RemoteSystemName = id
			}
			if raw := addrs[index].Raw; len(raw) == 4 {
				nb.RemoteMgmtAddress = netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]}).String()
			}
			if nb.RemoteChassisID == "" && nb.RemoteSystemName == "" {
				continue
			}
			out = append(out, nb)
		}
	}
	return out
}

// snmpLLDPManagementAddresses reads the IPv4 / IPv6 management addresses out
// of lldpRemManAddrTable's index, keyed by the remote row
// (timeMark.localPortNum.remIndex). The first address of a row wins.
func snmpLLDPManagementAddresses(rows map[string]snmpVarBind) map[string]string {
	out := map[string]string{}
	indexes := make([]string, 0, len(rows))
	for index := range rows {
		indexes = append(indexes, index)
	}
	sort.Slice(indexes, func(i, j int) bool { return snmpIndexLess(indexes[i], indexes[j]) })
	for _, index := range indexes {
		parts := strings.Split(index, ".")
		if len(parts) < 5 {
			continue
		}
		key := strings.Join(parts[:3], ".")
		if _, ok := out[key]; ok {
			continue
		}
		var octets []byte
		for _, p := range parts[5:] {
			var b int
			for _, c := range p {
				if c < '0' || c > '9' {
					b = -1
					break
				}
				b = b*10 + int(c-'0')
			}
			if b < 0 || b > 255 {
				octets = nil
				break
			}
			octets = append(octets, byte(b))
		}
		var addr netip.Addr
		switch {
		case parts[3] == "1" && len(octets) == 4:
			addr = netip.AddrFrom4([4]byte(octets))
		case parts[3] == "2" && len(octets) == 16:
			addr = netip.AddrFrom16([16]byte(octets))
		default:
			continue
		}
		if snmpUsableAddress(addr) {
			out[key] = addr.Unmap().String()
		}
	}
	return out
}
