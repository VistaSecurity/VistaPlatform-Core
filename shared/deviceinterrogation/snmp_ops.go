package deviceinterrogation

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SNMP ops facts and observed topology (asset-inventory ADR-0004 D1 item 3).
//
// "This one call set turns SNMP from a crypto probe into a generic
// network-device collector for every vendor without a native interrogator."
// That is the whole argument for doing SNMP before Cisco, Fortinet and F5: a
// customer's network has one Palo Alto and forty switches from four vendors,
// and MIB-II answers the same questions on all forty.
//
// The OIDs below are all standard MIBs — MIB-II (RFC 1213), IF-MIB (RFC 2863),
// ENTITY-MIB (RFC 6933), LLDP-MIB (IEEE 802.1AB) and IP-MIB — so nothing here
// is vendor-specific except the sysObjectID enterprise number, which is an IANA
// registry (classhint.go).
//
// Not collected, deliberately:
//   - The routing table (ipRouteTable / ipCidrRouteTable). Unbounded, and a
//     full routing table is a map of the network for anyone who reaches our
//     database. ADR-0004 D1 asks for routes "summarised as next-hop count"; the
//     summary is not designed yet and a placeholder would ship the raw table.
//   - The bridge forwarding table (dot1dTpFdbTable). It is the MAC address of
//     every host on the segment, which is endpoint discovery wearing a switch's
//     clothing — the same decision as UniFi's client list, deferred with it.
//   - snmpEngine and USM tables. The v3 user table names the device's SNMP
//     users; the interrogation has no use for it.

// Scalar OIDs (MIB-II system group). sysObjectID was declared in the original
// constant block and never queried — it is the single most useful scalar SNMP
// has, because it identifies the vendor and the product line.
const (
	snmpOIDSysUpTime = "1.3.6.1.2.1.1.3.0"
)

// ENTITY-MIB entPhysicalTable columns. The chassis row (entPhysicalClass = 3)
// carries the model, serial and firmware of the device itself; the other rows
// are its fans, power supplies and modules.
const (
	snmpOIDEntPhysicalClass       = "1.3.6.1.2.1.47.1.1.1.1.5"
	snmpOIDEntPhysicalFirmwareRev = "1.3.6.1.2.1.47.1.1.1.1.9"
	snmpOIDEntPhysicalSerialNum   = "1.3.6.1.2.1.47.1.1.1.1.11"
	snmpOIDEntPhysicalMfgName     = "1.3.6.1.2.1.47.1.1.1.1.12"
	snmpOIDEntPhysicalModelName   = "1.3.6.1.2.1.47.1.1.1.1.13"
)

// entPhysicalClass value for the chassis.
const snmpEntPhysicalClassChassis = 3

// IF-MIB columns: ifTable for the legacy view, ifXTable for the name and the
// high-speed counter a gigabit interface needs (ifSpeed saturates at 4.29 Gb/s
// and reports 4294967295 for anything faster, which is not a speed).
const (
	snmpOIDIfDescr       = "1.3.6.1.2.1.2.2.1.2"
	snmpOIDIfSpeed       = "1.3.6.1.2.1.2.2.1.5"
	snmpOIDIfPhysAddress = "1.3.6.1.2.1.2.2.1.6"
	snmpOIDIfAdminStatus = "1.3.6.1.2.1.2.2.1.7"
	snmpOIDIfOperStatus  = "1.3.6.1.2.1.2.2.1.8"
	snmpOIDIfName        = "1.3.6.1.2.1.31.1.1.1.1"
	snmpOIDIfHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15"
)

// LLDP-MIB columns. lldpRemTable is indexed
// (lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex); the local port number
// is the middle component, and lldpLocPortId names it.
const (
	snmpOIDLLDPRemChassisID = "1.0.8802.1.1.2.1.4.1.1.5"
	snmpOIDLLDPRemPortID    = "1.0.8802.1.1.2.1.4.1.1.7"
	snmpOIDLLDPRemPortDesc  = "1.0.8802.1.1.2.1.4.1.1.8"
	snmpOIDLLDPRemSysName   = "1.0.8802.1.1.2.1.4.1.1.9"
	snmpOIDLLDPLocPortID    = "1.0.8802.1.1.2.1.3.7.1.3"
)

// IP-MIB ipNetToMediaTable: the ARP cache, indexed (ifIndex, IPv4 address).
const (
	snmpOIDIPNetToMediaPhysAddress = "1.3.6.1.2.1.4.22.1.2"
	snmpOIDIPNetToMediaNetAddress  = "1.3.6.1.2.1.4.22.1.3"
)

// snmpOpsBudget bounds the whole ops phase — every walk below shares one
// deadline. Ten column walks each allowed their own timeout would let a slow
// device hold a job open for minutes; one budget makes the worst case a
// property of the interrogation rather than of the device.
const snmpOpsBudget = 30 * time.Second

// snmpManagementProtocol is what mgmt.protocol records for a successful v2c
// exchange, and mgmt.plaintext is true because it is one: v2c authenticates
// with a community string sent in the clear, which the plaintext_management
// finding names explicitly ("Telnet, HTTP, FTP, SNMP v1/v2c").
const snmpManagementProtocol = "snmpv2c"

// snmpChassis is the identity read from the chassis row of entPhysicalTable.
type snmpChassis struct {
	Vendor   string
	Model    string
	Serial   string
	Firmware string
}

// snmpCollectOps walks the ops MIBs and emits the facts and edges they
// describe. Every step is best-effort: a device that answers MIB-II but not
// ENTITY-MIB is normal, and losing the whole interrogation over it would be
// worse than losing one fact.
func snmpCollectOps(ctx context.Context, conn net.Conn, community string, result *InterrogateResult, timeout time.Duration) snmpChassis {
	deadline := time.Now().Add(snmpOpsBudget)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	// --- uptime -----------------------------------------------------------
	if bind, err := snmpGetVar(conn, community, snmpOIDSysUpTime, timeout); err == nil {
		if ticks, ok := bind.Int(); ok && ticks >= 0 {
			// sysUpTime is in hundredths of a second.
			result.addFact(factNetUptimeSeconds, int(ticks/100), ConfidenceReported)
		}
	}

	// --- hardware identity ------------------------------------------------
	chassis := snmpReadChassis(ctx, result, conn, community, timeout, deadline)
	if chassis.Vendor != "" {
		result.addFact(factHWVendor, chassis.Vendor, ConfidenceReported)
	}
	if chassis.Model != "" {
		result.addFact(factHWModel, chassis.Model, ConfidenceReported)
	}
	if chassis.Serial != "" {
		result.addFact(factHWSerial, chassis.Serial, ConfidenceReported)
	}
	if chassis.Firmware != "" {
		result.addFact(factHWFirmwareVersion, chassis.Firmware, ConfidenceReported)
	}

	// --- interfaces -------------------------------------------------------
	if interfaces := snmpInterfaces(ctx, result, conn, community, timeout, deadline); len(interfaces) > 0 {
		result.addFact(factNetInterfaces, interfaces, ConfidenceReported)
	}

	// --- neighbours and edges --------------------------------------------
	neighbors, edges := snmpLLDPObservations(ctx, result, conn, community, timeout, deadline)
	neighbors = append(neighbors, snmpARPNeighbors(ctx, result, conn, community, timeout, deadline)...)
	if len(neighbors) > 0 {
		result.addFact(factNetNeighbors, neighbors, ConfidenceReported)
	}
	for _, edge := range edges {
		result.addRelationship(edge)
	}

	// --- management plane -------------------------------------------------
	result.addFact(factMgmtProtocol, snmpManagementProtocol, ConfidenceReported)
	result.addFact(factMgmtPlaintext, true, ConfidenceReported)

	return chassis
}

// snmpReadChassis reads the chassis row of entPhysicalTable.
//
// A stack reports several chassis rows. The lowest entPhysicalIndex is taken —
// the stack master by convention — and the rest are left alone rather than
// merged: a stack is several pieces of hardware with several serials, and
// flattening them into one asset's identity would invent a device that does not
// exist. Modelling stack members properly is a class question, not a projection
// one.
func snmpReadChassis(ctx context.Context, result *InterrogateResult, conn net.Conn, community string, timeout time.Duration, deadline time.Time) snmpChassis {
	classes, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDEntPhysicalClass, timeout, deadline)
	if len(classes) == 0 {
		return snmpChassis{}
	}

	var chassisIndexes []string
	for index, bind := range classes {
		if class, ok := bind.Int(); ok && class == snmpEntPhysicalClassChassis {
			chassisIndexes = append(chassisIndexes, index)
		}
	}
	if len(chassisIndexes) == 0 {
		return snmpChassis{}
	}
	sort.Slice(chassisIndexes, func(i, j int) bool {
		return snmpIndexLess(chassisIndexes[i], chassisIndexes[j])
	})
	index := chassisIndexes[0]

	vendors, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDEntPhysicalMfgName, timeout, deadline)
	models, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDEntPhysicalModelName, timeout, deadline)
	serials, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDEntPhysicalSerialNum, timeout, deadline)
	firmware, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDEntPhysicalFirmwareRev, timeout, deadline)

	return snmpChassis{
		Vendor:   strings.TrimSpace(vendors[index].Text()),
		Model:    strings.TrimSpace(models[index].Text()),
		Serial:   strings.TrimSpace(serials[index].Text()),
		Firmware: strings.TrimSpace(firmware[index].Text()),
	}
}

// snmpInterfaces builds the net.interfaces value from ifTable and ifXTable.
func snmpInterfaces(ctx context.Context, result *InterrogateResult, conn net.Conn, community string, timeout time.Duration, deadline time.Time) []map[string]interface{} {
	descrs, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDIfDescr, timeout, deadline)
	names, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDIfName, timeout, deadline)
	if len(descrs) == 0 && len(names) == 0 {
		return nil
	}
	macs, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDIfPhysAddress, timeout, deadline)
	admin, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDIfAdminStatus, timeout, deadline)
	oper, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDIfOperStatus, timeout, deadline)
	highSpeed, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDIfHighSpeed, timeout, deadline)
	speed, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDIfSpeed, timeout, deadline)

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

	out := make([]map[string]interface{}, 0, len(indexes))
	for _, index := range indexes {
		// ifName is the short form an operator uses ("Gi1/0/1"); ifDescr is the
		// long one. Prefer the short one and fall back.
		name := strings.TrimSpace(names[index].Text())
		if name == "" {
			name = strings.TrimSpace(descrs[index].Text())
		}
		if name == "" {
			continue
		}
		entry := map[string]interface{}{"name": name}
		if mac, ok := macs[index].MAC(); ok {
			entry["mac"] = mac
		}
		if state, ok := oper[index].Int(); ok {
			entry["state"] = snmpOperStatus(state)
		}
		if state, ok := admin[index].Int(); ok {
			entry["admin_state"] = snmpAdminStatus(state)
		}
		if mbits, ok := highSpeed[index].Int(); ok && mbits > 0 {
			entry["speed"] = int(mbits)
		} else if bits, ok := speed[index].Int(); ok && bits > 0 {
			entry["speed"] = int(bits / 1_000_000)
		}
		out = append(out, entry)
	}
	return out
}

// snmpOperStatus maps IF-MIB ifOperStatus onto the fact vocabulary. dormant,
// testing and unknown become "unknown" rather than "down": an interface waiting
// for a call is not an interface that is off, and the difference is what an
// operator acts on.
func snmpOperStatus(v int64) string {
	switch v {
	case 1:
		return "up"
	case 2, 6, 7: // down, notPresent, lowerLayerDown
		return "down"
	default:
		return "unknown"
	}
}

// snmpAdminStatus maps IF-MIB ifAdminStatus. testing is a real administrative
// state and the fact schema carries it.
func snmpAdminStatus(v int64) string {
	switch v {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	default:
		return "unknown"
	}
}

// snmpLLDPObservations walks lldpRemTable and returns the neighbour facts and
// the connects_to edges built from them.
func snmpLLDPObservations(ctx context.Context, result *InterrogateResult, conn net.Conn, community string, timeout time.Duration, deadline time.Time) ([]map[string]interface{}, []RelationshipObservation) {
	chassisIDs, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDLLDPRemChassisID, timeout, deadline)
	if len(chassisIDs) == 0 {
		return nil, nil
	}
	portIDs, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDLLDPRemPortID, timeout, deadline)
	portDescs, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDLLDPRemPortDesc, timeout, deadline)
	sysNames, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDLLDPRemSysName, timeout, deadline)
	localPorts, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDLLDPLocPortID, timeout, deadline)

	indexes := make([]string, 0, len(chassisIDs))
	for index := range chassisIDs {
		indexes = append(indexes, index)
	}
	sort.Slice(indexes, func(i, j int) bool { return snmpIndexLess(indexes[i], indexes[j]) })

	var neighbors []map[string]interface{}
	var edges []RelationshipObservation
	for _, index := range indexes {
		// A chassis id is a MAC when its subtype says so; in practice it is
		// either six binary bytes or an ASCII name. MAC() answers the first
		// case and Text() the second, and neither invents the other.
		chassisBind := chassisIDs[index]
		mac, isMAC := chassisBind.MAC()
		chassisText := strings.TrimSpace(chassisBind.Text())
		sysName := strings.TrimSpace(sysNames[index].Text())
		localPort := snmpLLDPLocalPort(index, localPorts)
		remotePort := strings.TrimSpace(portIDs[index].Text())

		entry := map[string]interface{}{"protocol": "lldp"}
		if isMAC {
			entry["remote_mac"] = mac
		}
		if sysName != "" {
			entry["remote_name"] = sysName
		} else if !isMAC && chassisText != "" {
			entry["remote_name"] = chassisText
		}
		if remotePort != "" {
			entry["remote_port"] = remotePort
		}
		if localPort != "" {
			entry["local_port"] = localPort
		}
		if entry["remote_mac"] == nil && entry["remote_name"] == nil {
			continue
		}
		neighbors = append(neighbors, entry)

		peer := peerRef(sysName, "")
		if isMAC {
			peer.AddIdentifier(IdentifierMACAddress, mac)
		}
		// An advertised system name that is an address is an address, not a
		// name: digits and dots are legal in a DNS name, so "198.51.100.20"
		// normalises as one, and a neighbour that reaches us as an IP literal
		// would carry a hostname it does not have. Offered under its own kind
		// first so the edge keeps an identity rather than losing one.
		peer.AddIdentifier(IdentifierIPAddress, sysName)
		addHostIdentifiers(&peer, sysName)
		if len(peer.Identifiers) == 0 {
			continue
		}
		attributes := map[string]interface{}{"discovery_protocol": "lldp"}
		if localPort != "" {
			attributes["local_port"] = localPort
		}
		if remotePort != "" {
			attributes["remote_port"] = remotePort
		}
		if desc := strings.TrimSpace(portDescs[index].Text()); desc != "" {
			attributes["remote_port_description"] = desc
		}
		edges = append(edges, RelationshipObservation{
			Type:       relTypeConnectsTo,
			Direction:  SubjectToPeer,
			Peer:       peer,
			Attributes: attributes,
		})
	}
	return neighbors, edges
}

// snmpLLDPLocalPort resolves the local port a neighbour was seen on.
//
// lldpRemTable's index is (timeMark, localPortNum, remIndex), so the local port
// number is its middle component, and lldpLocPortTable is indexed by that
// number alone. Falling back to the bare number is better than nothing: it is
// what the device calls the port even when lldpLocPortId is unreadable.
func snmpLLDPLocalPort(remIndex string, localPorts map[string]snmpVarBind) string {
	parts := strings.Split(remIndex, ".")
	if len(parts) < 2 {
		return ""
	}
	portNum := parts[1]
	if bind, ok := localPorts[portNum]; ok {
		if name := strings.TrimSpace(bind.Text()); name != "" {
			return name
		}
	}
	return portNum
}

// snmpARPNeighbors walks ipNetToMediaTable and projects it onto net.neighbors
// items with protocol "arp".
func snmpARPNeighbors(ctx context.Context, result *InterrogateResult, conn net.Conn, community string, timeout time.Duration, deadline time.Time) []map[string]interface{} {
	physAddrs, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDIPNetToMediaPhysAddress, timeout, deadline)
	if len(physAddrs) == 0 {
		return nil
	}
	netAddrs, _ := snmpWalkColumn(ctx, result, conn, community, snmpOIDIPNetToMediaNetAddress, timeout, deadline)

	indexes := make([]string, 0, len(physAddrs))
	for index := range physAddrs {
		indexes = append(indexes, index)
	}
	sort.Slice(indexes, func(i, j int) bool { return snmpIndexLess(indexes[i], indexes[j]) })

	out := make([]map[string]interface{}, 0, len(indexes))
	for _, index := range indexes {
		mac, ok := physAddrs[index].MAC()
		if !ok {
			// An incomplete ARP entry has no physical address yet.
			continue
		}
		entry := map[string]interface{}{"protocol": "arp", "remote_mac": mac}
		// The address is the tail of the index (ifIndex.a.b.c.d), and also the
		// value of ipNetToMediaNetAddress. The column is preferred; the index
		// is the fallback for an agent that does not return it.
		address := strings.TrimSpace(netAddrs[index].Text())
		if address == "" {
			address = snmpAddressFromIndex(index)
		}
		if addr, err := canonicalIP(address); err == nil {
			entry["remote_address"] = addr
		}
		if ifIndex := strings.SplitN(index, ".", 2)[0]; ifIndex != "" {
			entry["local_port"] = "ifIndex " + ifIndex
		}
		out = append(out, entry)
	}
	return out
}

// snmpAddressFromIndex extracts the IPv4 address from an ipNetToMedia index
// (ifIndex.a.b.c.d).
func snmpAddressFromIndex(index string) string {
	parts := strings.Split(index, ".")
	if len(parts) != 5 {
		return ""
	}
	return strings.Join(parts[1:], ".")
}

// snmpIndexLess orders table indexes numerically component by component, so
// ifIndex 2 sorts before ifIndex 10. A lexical sort would order a 48-port
// switch's ports 1, 10, 11, 2 — which is what an operator reads as a bug.
func snmpIndexLess(a, b string) bool {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		ai, aErr := strconv.Atoi(aParts[i])
		bi, bErr := strconv.Atoi(bParts[i])
		if aErr != nil || bErr != nil {
			if aParts[i] != bParts[i] {
				return aParts[i] < bParts[i]
			}
			continue
		}
		if ai != bi {
			return ai < bi
		}
	}
	return len(aParts) < len(bParts)
}

// snmpIdentity builds the structured device identity from the chassis row and
// the sysObjectID hint.
//
// The chassis row is preferred wherever it answered — a vendor that names
// itself is better than one we inferred from an enterprise number — and the
// hint fills the gaps. Where neither answers, the field stays empty: the
// sysDescr banner is NOT parsed into a model, because every vendor writes it
// differently and a regex over it produces a plausible wrong answer.
func snmpIdentity(chassis snmpChassis, sysObjectID, sysDescr string) *DeviceIdentity {
	hint := snmpObjectIDHint(sysObjectID)

	identity := &DeviceIdentity{
		Vendor:          chassis.Vendor,
		Model:           chassis.Model,
		SerialNumber:    chassis.Serial,
		FirmwareVersion: chassis.Firmware,
		OSVersion:       sysDescr,
		ClassHint:       hint.Class,
	}
	if identity.Vendor == "" {
		identity.Vendor = hint.Vendor
	}
	return identity
}

// snmpEmitVendorHint emits hw.vendor from the sysObjectID enterprise number
// when the chassis row did not name a manufacturer.
//
// Derived, not reported: the enterprise number says who registered the OID
// arc, which is the manufacturer in every case we have listed but is still an
// inference we maintain rather than an answer the device gave.
func snmpEmitVendorHint(result *InterrogateResult, chassis snmpChassis, sysObjectID string) {
	if chassis.Vendor != "" {
		return
	}
	if hint := snmpObjectIDHint(sysObjectID); hint.Vendor != "" {
		result.addFact(factHWVendor, hint.Vendor, ConfidenceDerived)
	}
}
