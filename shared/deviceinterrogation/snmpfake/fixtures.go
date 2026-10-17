package snmpfake

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Synthesised walks. Neither is a capture of a real device (the addresses are
// documentation ranges and the MACs are made up); each is shaped the way the
// real agent answers the tables the collector walks, including the quirks the
// projection has to handle: ifSpeed saturating, an all-zero ifPhysAddress,
// net-snmp reporting every Linux interface as ethernetCsmacd, an agent that
// answers zeroDotZero for ipAddressPrefix.
//
// Each plants secrets in fields the projection has no business carrying — the
// community string (in sysDescr, as agents that echo their configuration do),
// the operator's port descriptions (ifAlias) and sysContact/sysLocation — so a
// parity test can prove none of them reaches a table.

type mibBuilder struct{ v []Value }

func (m *mibBuilder) add(v ...Value) { m.v = append(m.v, v...) }

const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysContact  = "1.3.6.1.2.1.1.4.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"

	oidIfDescr  = "1.3.6.1.2.1.2.2.1.2"
	oidIfType   = "1.3.6.1.2.1.2.2.1.3"
	oidIfMtu    = "1.3.6.1.2.1.2.2.1.4"
	oidIfSpeed  = "1.3.6.1.2.1.2.2.1.5"
	oidIfPhys   = "1.3.6.1.2.1.2.2.1.6"
	oidIfAdmin  = "1.3.6.1.2.1.2.2.1.7"
	oidIfOper   = "1.3.6.1.2.1.2.2.1.8"
	oidIfName   = "1.3.6.1.2.1.31.1.1.1.1"
	oidIfHigh   = "1.3.6.1.2.1.31.1.1.1.15"
	oidIfAlias  = "1.3.6.1.2.1.31.1.1.1.18"
	oidIfStack  = "1.3.6.1.2.1.31.1.2.1.3"
	oidLagAgg   = "1.2.840.10006.300.43.1.2.1.1.13"
	oidIPAddrIf = "1.3.6.1.2.1.4.34.1.3"
	oidIPAddrTy = "1.3.6.1.2.1.4.34.1.4"
	oidIPAddrPf = "1.3.6.1.2.1.4.34.1.5"
	oidIPAddrOr = "1.3.6.1.2.1.4.34.1.6"
	oidIPAdEnt  = "1.3.6.1.2.1.4.20.1"
	oidArpPhys  = "1.3.6.1.2.1.4.22.1.2"
	oidArpNet   = "1.3.6.1.2.1.4.22.1.3"
	oidArpType  = "1.3.6.1.2.1.4.22.1.4"
	oidVlanName = "1.3.6.1.2.1.17.7.1.4.3.1.1"
	oidVlanEgr  = "1.3.6.1.2.1.17.7.1.4.3.1.2"
	oidVlanUnt  = "1.3.6.1.2.1.17.7.1.4.3.1.4"
	oidPvid     = "1.3.6.1.2.1.17.7.1.4.5.1.1"
	oidBasePort = "1.3.6.1.2.1.17.1.4.1.2"
)

// ifEntry is one ifTable/ifXTable row.
type ifEntry struct {
	idx         int
	name, descr string
	ifType      int64
	mtu         int64
	speedBps    int64 // ifSpeed (bits/s), 0 for none
	highMbps    int64 // ifHighSpeed, -1 for the column absent
	mac         string
	admin, oper int64
	alias       string
}

func (m *mibBuilder) iface(e ifEntry) {
	i := "." + strconv.Itoa(e.idx)
	m.add(Str(oidIfDescr+i, e.descr), Int(oidIfType+i, e.ifType), Int(oidIfMtu+i, e.mtu),
		Gauge(oidIfSpeed+i, e.speedBps), Int(oidIfAdmin+i, e.admin), Int(oidIfOper+i, e.oper))
	if e.name != "" {
		m.add(Str(oidIfName+i, e.name))
	}
	if e.highMbps >= 0 {
		m.add(Gauge(oidIfHigh+i, e.highMbps))
	}
	if e.alias != "" {
		m.add(Str(oidIfAlias+i, e.alias))
	}
	if e.mac != "" {
		m.add(MAC(oidIfPhys+i, e.mac))
	} else {
		m.add(Bytes(oidIfPhys+i, nil))
	}
}

func octets(a netip.Addr) string {
	b := a.AsSlice()
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = strconv.Itoa(int(c))
	}
	return strings.Join(parts, ".")
}

// address adds an ipAddressTable row (and, for IPv4, the ipAddrTable row).
// prefixed false answers zeroDotZero for ipAddressPrefix.
func (m *mibBuilder) address(ifIndex int, cidr string, origin int64, prefixed bool) {
	p := netip.MustParsePrefix(cidr)
	a := p.Addr()
	typ := 1
	if a.Is6() {
		typ = 2
	}
	idx := fmt.Sprintf(".%d.%d.%s", typ, a.BitLen()/8, octets(a))
	m.add(Int(oidIPAddrIf+idx, int64(ifIndex)), Int(oidIPAddrTy+idx, 1), Int(oidIPAddrOr+idx, origin))
	if prefixed {
		m.add(OIDValue(oidIPAddrPf+idx, fmt.Sprintf("1.3.6.1.2.1.4.32.1.5.%d.%d.%d.%s.%d", ifIndex, typ, a.BitLen()/8, octets(p.Masked().Addr()), p.Bits())))
	} else {
		m.add(OIDValue(oidIPAddrPf+idx, "0.0"))
	}
	if a.Is4() {
		m.legacy(ifIndex, cidr)
	}
}

// legacy adds an ipAddrTable (RFC 1213) row.
func (m *mibBuilder) legacy(ifIndex int, cidr string) {
	p := netip.MustParsePrefix(cidr)
	mask := make([]byte, 4)
	for i := 0; i < p.Bits(); i++ {
		mask[i/8] |= 0x80 >> (i % 8)
	}
	k := "." + p.Addr().String()
	m.add(IP(oidIPAdEnt+".1"+k, p.Addr().String()), Int(oidIPAdEnt+".2"+k, int64(ifIndex)),
		Value{OID: oidIPAdEnt + ".3" + k, tag: tagIPAddress, raw: mask})
}

func (m *mibBuilder) arp(ifIndex int, addr, mac string, kind int64) {
	k := fmt.Sprintf(".%d.%s", ifIndex, addr)
	if mac == "" {
		m.add(Bytes(oidArpPhys+k, nil))
	} else {
		m.add(MAC(oidArpPhys+k, mac))
	}
	m.add(IP(oidArpNet+k, addr), Int(oidArpType+k, kind))
}

// portList builds a Q-BRIDGE PortList bitmap of the 1-based ports.
func portList(size int, ports ...int) []byte {
	b := make([]byte, (size+7)/8)
	for _, p := range ports {
		b[(p-1)/8] |= 0x80 >> ((p - 1) % 8)
	}
	return b
}

func rangeInts(from, to int) []int {
	var out []int
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

// Planted secrets in the synthesised walks. A parity fixture lists them as
// the values that must reach no table.
const (
	SwitchCommunity = "PlantedCommunity-r7Kx92"
	SwitchSecret    = "PlantedSnmpSecret-Zq4418"
	LinuxCommunity  = "PlantedLinuxCommunity-m3Tt07"
	LinuxSecret     = "PlantedLinuxSecret-Vb2260"
)

// L3Switch48 is a stacked 48-port layer-3 switch (Cisco-shaped, enterprise 9):
//
//   - Gi1/0/1..48 (ifIndex 1..48), ethernetCsmacd, MAC per port, 1 Gb/s
//     (highSpeed 1000) on the first 24 ports, down and speed-less beyond;
//     Gi1/0/47 is shut; Gi1/0/46 is a routed port with a DHCP address;
//   - Po1 (ifIndex 49, ifType 161) with Gi1/0/47 and Gi1/0/48 attached over
//     LACP (dot3adAggPortAttachedAggID);
//   - SVIs Vlan10 / Vlan20 / Vlan99 (ifIndex 50..52, propVirtual) with
//     addresses, Vlan99 the management address; Loopback0 (53) whose
//     ipAddressPrefix is zeroDotZero, so the length comes from ipAddrTable;
//     a routed sub-interface Gi1/0/2.200 (54, l2vlan) over Gi1/0/2 by ifStack;
//   - Q-BRIDGE: VLANs 1/10/20/99; ports 1-12 access VLAN 10, 13-23 access 20,
//     25-45 access 99, port 24 and Po1 trunks (native 1; tagged 10, 20, 99);
//   - ARP: three complete entries on the SVIs, the switch's own address, an
//     `invalid` entry and an all-zero (incomplete) one.
func L3Switch48() Recording {
	var m mibBuilder
	m.add(
		Str(oidSysDescr, "Cisco IOS Software, C9300 Software, Version 17.09.04a\nsnmp-server community "+SwitchCommunity+" RO\nline vty: password "+SwitchSecret),
		OIDValue(oidSysObjectID, "1.3.6.1.4.1.9.1.2494"),
		Ticks(oidSysUpTime, 123456789),
		Str(oidSysContact, "netops@example.net "+SwitchSecret),
		Str(oidSysName, "core-sw-1.example.net"),
		Str(oidSysLocation, "HQ Rack 4 / "+SwitchSecret),
		// entPhysicalTable: the chassis.
		Int("1.3.6.1.2.1.47.1.1.1.1.5.1", 3),
		Str("1.3.6.1.2.1.47.1.1.1.1.11.1", "FOC2432L0AB"),
		Str("1.3.6.1.2.1.47.1.1.1.1.12.1", "Cisco Systems"),
		Str("1.3.6.1.2.1.47.1.1.1.1.13.1", "C9300-48P"),
		Str("1.3.6.1.2.1.47.1.1.1.1.9.1", "17.09.04a"),
	)
	for p := 1; p <= 48; p++ {
		e := ifEntry{idx: p, name: fmt.Sprintf("Gi1/0/%d", p), descr: fmt.Sprintf("GigabitEthernet1/0/%d", p),
			ifType: 6, mtu: 1500, mac: fmt.Sprintf("00:1b:17:aa:00:%02x", p), admin: 1, oper: 1,
			speedBps: 1_000_000_000, highMbps: 1000, alias: "uplink to HR vpn psk " + SwitchSecret}
		if p > 24 {
			e.oper, e.speedBps, e.highMbps = 2, 0, 0
		}
		if p == 47 {
			e.admin = 2
		}
		m.iface(e)
	}
	m.iface(ifEntry{idx: 49, name: "Po1", descr: "Port-channel1", ifType: 161, mtu: 1500, mac: "00:1b:17:aa:00:31", admin: 1, oper: 1,
		speedBps: 2_000_000_000, highMbps: 2000})
	m.iface(ifEntry{idx: 50, name: "Vl10", descr: "Vlan10", ifType: 53, mtu: 1500, mac: "00:1b:17:aa:01:0a", admin: 1, oper: 1, speedBps: 1_000_000_000, highMbps: 1000})
	m.iface(ifEntry{idx: 51, name: "Vl20", descr: "Vlan20", ifType: 53, mtu: 1500, mac: "00:1b:17:aa:01:14", admin: 1, oper: 1, speedBps: 1_000_000_000, highMbps: 1000})
	m.iface(ifEntry{idx: 52, name: "Vl99", descr: "Vlan99", ifType: 53, mtu: 1500, mac: "00:1b:17:aa:01:63", admin: 1, oper: 1, speedBps: 1_000_000_000, highMbps: 1000})
	m.iface(ifEntry{idx: 53, name: "Lo0", descr: "Loopback0", ifType: 24, mtu: 1514, admin: 1, oper: 1, highMbps: -1, speedBps: 4294967295})
	m.iface(ifEntry{idx: 54, name: "Gi1/0/2.200", descr: "GigabitEthernet1/0/2.200", ifType: 135, mtu: 1500, mac: "00:1b:17:aa:00:02", admin: 1, oper: 1, speedBps: 1_000_000_000, highMbps: 1000})
	m.add(Int(oidIfStack+".54.2", 1), Int(oidIfStack+".0.54", 1))

	m.add(Int(oidLagAgg+".47", 49), Int(oidLagAgg+".48", 49), Int(oidLagAgg+".1", 0))

	m.address(50, "10.0.10.1/24", 2, true)
	m.address(50, "2001:db8:10::1/64", 2, true)
	m.address(50, "fe80::21b:17ff:feaa:10a/64", 5, true)
	m.address(51, "10.0.20.1/24", 2, true)
	m.address(52, "10.0.99.2/24", 2, true)
	m.address(53, "10.255.0.2/32", 2, false)
	m.address(54, "192.0.2.1/30", 2, true)
	m.address(46, "172.16.46.9/24", 4, true)

	// Q-BRIDGE.
	const nPorts = 49
	for p := 1; p <= 45; p++ {
		m.add(Int(fmt.Sprintf("%s.%d", oidBasePort, p), int64(p)))
	}
	m.add(Int(oidBasePort+".49", 49))
	trunks := []int{24, 49}
	access10, access20, access99 := rangeInts(1, 12), rangeInts(13, 23), rangeInts(25, 45)
	for _, p := range access10 {
		m.add(Gauge(fmt.Sprintf("%s.%d", oidPvid, p), 10))
	}
	for _, p := range access20 {
		m.add(Gauge(fmt.Sprintf("%s.%d", oidPvid, p), 20))
	}
	for _, p := range access99 {
		m.add(Gauge(fmt.Sprintf("%s.%d", oidPvid, p), 99))
	}
	for _, p := range trunks {
		m.add(Gauge(fmt.Sprintf("%s.%d", oidPvid, p), 1))
	}
	vlan := func(vid int, name string, untagged []int) {
		egress := append(append([]int{}, untagged...), trunks...)
		k := "." + strconv.Itoa(vid)
		m.add(Str(oidVlanName+k, name), Bytes(oidVlanEgr+k, portList(nPorts, egress...)), Bytes(oidVlanUnt+k, portList(nPorts, untagged...)))
	}
	vlan(1, "default", trunks)
	vlan(10, "users", access10)
	vlan(20, "voice", access20)
	vlan(99, "infra", access99)

	// ARP.
	m.arp(50, "10.0.10.11", "00:00:5e:00:53:11", 3)
	m.arp(50, "10.0.10.12", "00:00:5e:00:53:12", 4)
	m.arp(51, "10.0.20.21", "00:00:5e:00:53:21", 3)
	m.arp(50, "10.0.10.1", "00:1b:17:aa:01:0a", 4)  // the switch's own address
	m.arp(50, "10.0.10.13", "00:00:5e:00:53:13", 2) // invalid
	m.arp(50, "10.0.10.14", "", 3)                  // incomplete
	return Recording{Community: SwitchCommunity, MIB: m.v}
}

// LinuxNetSNMP is a Linux host answering through net-snmp (enterprise 8072):
// every interface is ethernetCsmacd, there is no Q-BRIDGE or LACP table, the
// VLAN sub-interface carries its id only in its name, ipAddressPrefix is
// zeroDotZero (so the length is ipAddrTable's netmask), and the container
// bridge and veth have locally administered MACs.
func LinuxNetSNMP() Recording {
	var m mibBuilder
	m.add(
		Str(oidSysDescr, "Linux web-01 6.8.0-45-generic #45-Ubuntu SMP x86_64 community="+LinuxCommunity),
		OIDValue(oidSysObjectID, "1.3.6.1.4.1.8072.3.2.10"),
		Ticks(oidSysUpTime, 987654321),
		Str(oidSysContact, "root <root@localhost> "+LinuxSecret),
		Str(oidSysName, "web-01.example.net"),
		Str(oidSysLocation, "Server room "+LinuxSecret),
	)
	m.iface(ifEntry{idx: 1, name: "lo", descr: "lo", ifType: 24, mtu: 65536, admin: 1, oper: 1, speedBps: 10_000_000, highMbps: 10})
	m.iface(ifEntry{idx: 2, name: "eth0", descr: "eth0", ifType: 6, mtu: 9000, mac: "3c:ec:ef:11:22:33", admin: 1, oper: 1,
		speedBps: 1_000_000_000, highMbps: 1000, alias: "mgmt " + LinuxSecret})
	m.iface(ifEntry{idx: 3, name: "eth0.100", descr: "eth0.100", ifType: 6, mtu: 9000, mac: "3c:ec:ef:11:22:33", admin: 1, oper: 1,
		speedBps: 1_000_000_000, highMbps: 1000})
	m.iface(ifEntry{idx: 4, name: "docker0", descr: "docker0", ifType: 6, mtu: 1500, mac: "02:42:ac:11:00:00", admin: 1, oper: 2, speedBps: 0, highMbps: 0})
	m.iface(ifEntry{idx: 5, name: "veth3a9c1d2", descr: "veth3a9c1d2", ifType: 6, mtu: 1500, mac: "9a:5c:11:fe:00:07", admin: 1, oper: 1, speedBps: 10_000_000_000, highMbps: 10000})
	m.address(1, "127.0.0.1/8", 2, false)
	m.address(2, "198.51.100.24/24", 4, false)
	m.address(2, "2001:db8:aa::24/64", 2, false)
	m.address(2, "fe80::3eec:efff:fe11:2233/64", 5, false)
	m.address(3, "10.100.0.24/24", 2, false)
	m.address(4, "172.17.0.1/16", 2, false)
	m.arp(2, "198.51.100.1", "00:00:5e:00:53:01", 3)
	m.arp(2, "198.51.100.30", "00:00:5e:00:53:1e", 3)
	return Recording{Community: LinuxCommunity, MIB: m.v}
}
