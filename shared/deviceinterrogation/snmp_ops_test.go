package deviceinterrogation

import (
	"context"
	"encoding/asn1"
	"encoding/json"
	"net"
	"sort"
	"strings"
	"testing"
	"time"
)

// A fake SNMP v2c agent.
//
// The alternative — unit-testing the projections against hand-built varbind
// slices — would not have exercised the GETNEXT loop, the request-id matching,
// or the ASN.1 encoding, which are the three places this collector can go
// wrong in ways that look like a device problem. The agent answers real
// datagrams from a table of OIDs, so the walk is driven end to end.

type snmpTestValue struct {
	oid string
	tag byte
	raw []byte
}

func snmpTestOctet(oid, value string) snmpTestValue {
	return snmpTestValue{oid: oid, tag: snmpTagOctetString, raw: []byte(value)}
}

func snmpTestInt(oid string, tag byte, value int64) snmpTestValue {
	var raw []byte
	if value == 0 {
		raw = []byte{0}
	} else {
		for shift := 56; shift >= 0; shift -= 8 {
			b := byte(value >> shift)
			if len(raw) == 0 && b == 0 {
				continue
			}
			raw = append(raw, b)
		}
		if raw[0]&0x80 != 0 {
			raw = append([]byte{0}, raw...)
		}
	}
	return snmpTestValue{oid: oid, tag: tag, raw: raw}
}

func snmpTestMAC(oid string, mac ...byte) snmpTestValue {
	return snmpTestValue{oid: oid, tag: snmpTagOctetString, raw: mac}
}

func snmpTestOID(oid, value string) snmpTestValue {
	encoded, err := snmpOIDToASN1(value)
	if err != nil {
		panic(err)
	}
	tlv, err := asn1.Marshal(encoded)
	if err != nil {
		panic(err)
	}
	_, content, _, err := snmpReadTLV(tlv)
	if err != nil {
		panic(err)
	}
	return snmpTestValue{oid: oid, tag: snmpTagOID, raw: content}
}

func snmpTestIPAddress(oid, addr string) snmpTestValue {
	ip := net.ParseIP(addr).To4()
	return snmpTestValue{oid: oid, tag: snmpTagIPAddress, raw: []byte(ip)}
}

// snmpTestMIB is the device the fake agent presents: a stacked Cisco switch
// with three interfaces, one LLDP neighbour and one ARP entry.
//
// The sysDescr banner carries a PEM private key with the poison inside it. That
// is not a contrived shape: a banner is free text a device operator controls,
// and it is the one place a key can arrive under a field name nothing would
// suspect.
//
// It also carries a CERTIFICATE block, for the inverse polarity: a scrubber
// that eats public material has destroyed the inventory we exist to produce,
// and would do it just as silently.
func snmpTestMIB() []snmpTestValue {
	return []snmpTestValue{
		snmpTestOctet(snmpOIDSysDescr, "Cisco IOS Software, C9300 Software, Version 17.09.04a\n"+
			"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA"+poison+"\n-----END RSA PRIVATE KEY-----\n"+
			"-----BEGIN CERTIFICATE-----\nMIIBpublicCertBodyKeepMe\n-----END CERTIFICATE-----"),
		snmpTestOID(snmpOIDSysObjectID, "1.3.6.1.4.1.9.1.2494"),
		snmpTestInt(snmpOIDSysUpTime, snmpTagTimeTicks, 123456789),
		snmpTestOctet(snmpOIDSysContact, "netops@example.net"),
		snmpTestOctet(snmpOIDSysName, "core-sw-1.example.net"),
		snmpTestOctet(snmpOIDSysLocation, "HQ Rack 4"),

		// entPhysicalTable: the chassis (class 3) plus a module (class 9),
		// each with its own serial. Taking the module's would be wrong.
		snmpTestInt(snmpOIDEntPhysicalClass+".1", snmpTagInteger, 3),
		snmpTestInt(snmpOIDEntPhysicalClass+".2", snmpTagInteger, 9),
		snmpTestOctet(snmpOIDEntPhysicalFirmwareRev+".1", "17.09.04a"),
		snmpTestOctet(snmpOIDEntPhysicalSerialNum+".1", "FOC2432L0AB"),
		snmpTestOctet(snmpOIDEntPhysicalSerialNum+".2", "MODULE-SERIAL-NOT-THE-CHASSIS"),
		snmpTestOctet(snmpOIDEntPhysicalMfgName+".1", "Cisco Systems"),
		snmpTestOctet(snmpOIDEntPhysicalModelName+".1", "C9300-48P"),
		snmpTestOctet(snmpOIDEntPhysicalModelName+".2", "C9300-NM-8X"),

		// ifTable / ifXTable.
		snmpTestOctet(snmpOIDIfDescr+".1", "GigabitEthernet1/0/1"),
		snmpTestOctet(snmpOIDIfDescr+".2", "GigabitEthernet1/0/2"),
		snmpTestOctet(snmpOIDIfDescr+".10", "Vlan1"),
		snmpTestInt(snmpOIDIfSpeed+".2", snmpTagGauge32, 100_000_000),
		snmpTestMAC(snmpOIDIfPhysAddress+".1", 0x00, 0x1b, 0x17, 0x00, 0x00, 0x01),
		snmpTestMAC(snmpOIDIfPhysAddress+".2", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
		snmpTestInt(snmpOIDIfAdminStatus+".1", snmpTagInteger, 1),
		snmpTestInt(snmpOIDIfAdminStatus+".2", snmpTagInteger, 2),
		snmpTestInt(snmpOIDIfAdminStatus+".10", snmpTagInteger, 1),
		snmpTestInt(snmpOIDIfOperStatus+".1", snmpTagInteger, 1),
		snmpTestInt(snmpOIDIfOperStatus+".2", snmpTagInteger, 2),
		snmpTestInt(snmpOIDIfOperStatus+".10", snmpTagInteger, 1),
		snmpTestOctet(snmpOIDIfName+".1", "Gi1/0/1"),
		snmpTestOctet(snmpOIDIfName+".2", "Gi1/0/2"),
		snmpTestOctet(snmpOIDIfName+".10", "Vl1"),
		snmpTestInt(snmpOIDIfHighSpeed+".1", snmpTagGauge32, 1000),
		snmpTestInt(snmpOIDIfHighSpeed+".2", snmpTagGauge32, 0),

		// LLDP: one neighbour on local port 1.
		snmpTestOctet(snmpOIDLLDPLocPortID+".1", "Gi1/0/1"),
		snmpTestMAC(snmpOIDLLDPRemChassisID+".0.1.1", 0x00, 0x1b, 0x17, 0x00, 0x00, 0xaa),
		snmpTestOctet(snmpOIDLLDPRemPortID+".0.1.1", "Gi1/0/24"),
		snmpTestOctet(snmpOIDLLDPRemPortDesc+".0.1.1", "uplink to core-sw-1"),
		snmpTestOctet(snmpOIDLLDPRemSysName+".0.1.1", "dist-sw-1.example.net"),

		// ARP cache: one complete entry.
		snmpTestMAC(snmpOIDIPNetToMediaPhysAddress+".1.198.51.100.1", 0x00, 0x1b, 0x17, 0x00, 0x00, 0xbb),
		snmpTestIPAddress(snmpOIDIPNetToMediaNetAddress+".1.198.51.100.1", "198.51.100.1"),
	}
}

// startSNMPTestAgent serves the MIB over UDP on localhost and returns its
// address.
func startSNMPTestAgent(t *testing.T, mib []snmpTestValue) string {
	t.Helper()
	sorted := append([]snmpTestValue(nil), mib...)
	sort.Slice(sorted, func(i, j int) bool { return snmpIndexLess(sorted[i].oid, sorted[j].oid) })

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, snmpMaxResponseBytes)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return // closed
			}
			reply, err := snmpTestAnswer(buf[:n], sorted)
			if err != nil {
				continue
			}
			_, _ = conn.WriteTo(reply, addr)
		}
	}()

	return conn.LocalAddr().String()
}

// snmpTestAnswer parses a GET or GETNEXT request and builds the response.
func snmpTestAnswer(request []byte, mib []snmpTestValue) ([]byte, error) {
	tag, msg, _, err := snmpReadTLV(request)
	if err != nil || tag != snmpTagSequence {
		return nil, err
	}
	_, _, rest, err := snmpReadTLV(msg) // version
	if err != nil {
		return nil, err
	}
	_, community, rest, err := snmpReadTLV(rest)
	if err != nil {
		return nil, err
	}
	pduTag, pdu, _, err := snmpReadTLV(rest)
	if err != nil {
		return nil, err
	}
	idTag, idBytes, afterID, err := snmpReadTLV(pdu)
	if err != nil {
		return nil, err
	}
	requestID, _ := snmpVarBind{Tag: idTag, Raw: idBytes}.Int()

	_, _, afterStatus, err := snmpReadTLV(afterID)
	if err != nil {
		return nil, err
	}
	_, _, afterIndex, err := snmpReadTLV(afterStatus)
	if err != nil {
		return nil, err
	}
	_, list, _, err := snmpReadTLV(afterIndex)
	if err != nil {
		return nil, err
	}
	_, bind, _, err := snmpReadTLV(list)
	if err != nil {
		return nil, err
	}
	_, oidContent, _, err := snmpReadTLV(bind)
	if err != nil {
		return nil, err
	}
	requested, err := snmpDecodeOIDValue(oidContent)
	if err != nil {
		return nil, err
	}

	var answer snmpTestValue
	found := false
	switch pduTag {
	case snmpPDUGetRequest:
		for _, v := range mib {
			if v.oid == requested {
				answer, found = v, true
				break
			}
		}
	case snmpPDUGetNext:
		for _, v := range mib {
			if snmpIndexLess(requested, v.oid) {
				answer, found = v, true
				break
			}
		}
	}
	if !found {
		answer = snmpTestValue{oid: requested, tag: snmpTagNoSuchObject}
	}

	return snmpTestResponse(int(requestID), string(community), answer)
}

func snmpTestResponse(requestID int, community string, value snmpTestValue) ([]byte, error) {
	oid, err := snmpOIDToASN1(value.oid)
	if err != nil {
		return nil, err
	}
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	valueTLV := append([]byte{value.tag}, snmpEncodeLength(len(value.raw))...)
	valueTLV = append(valueTLV, value.raw...)

	varBindList := snmpMakeSequence(snmpMakeSequence(append(oidBytes, valueTLV...)))
	idBytes, err := asn1.Marshal(requestID)
	if err != nil {
		return nil, err
	}
	pduData := append(idBytes, snmpTagInteger, 0x01, 0x00, snmpTagInteger, 0x01, 0x00)
	pduData = append(pduData, varBindList...)
	pdu := snmpMakeTaggedSequence(snmpPDUGetResponse, pduData)

	msg := append([]byte{snmpTagInteger, 0x01, 0x01}, snmpMakeOctetString([]byte(community))...)
	msg = append(msg, pdu...)
	return snmpMakeSequence(msg), nil
}

func TestSNMPInterrogator_CollectsOpsFactsAndTopology(t *testing.T) {
	addr := startSNMPTestAgent(t, snmpTestMIB())
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	registry := NewRegistry()
	interrogator, err := registry.Get("generic_snmp")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	result, err := interrogator.Interrogate(
		context.Background(),
		DeviceInfo{DeviceType: "generic_snmp", IPAddress: host, Port: port},
		Credentials{Custom: map[string]interface{}{"community": "public"}},
	)
	if err != nil {
		t.Fatalf("Interrogate: %v", err)
	}

	assertObservationsValid(t, "snmp", result)

	// The PEM in the banner must not survive anywhere — including in
	// DeviceIdentity.OSVersion, which is a plain string field that name-based
	// redaction cannot see.
	assertNoPoison(t, "snmp", result)
	blob, _ := json.Marshal(result)
	if strings.Contains(string(blob), "BEGIN RSA PRIVATE KEY") {
		t.Errorf("a PEM private key from the sysDescr banner survived: %s", blob)
	}
	if !strings.Contains(result.DeviceIdentity.OSVersion, "Cisco IOS Software") {
		t.Errorf("the banner's useful half was destroyed: %q", result.DeviceIdentity.OSVersion)
	}
	// Inverse polarity: a certificate in the same banner is public material and
	// is exactly what this platform inventories. Masking it would be the same
	// bug pointed the other way.
	if !strings.Contains(result.DeviceIdentity.OSVersion, "MIIBpublicCertBodyKeepMe") {
		t.Errorf("a CERTIFICATE block in the banner was redacted as if it were key material: %q", result.DeviceIdentity.OSVersion)
	}

	// --- identity ---------------------------------------------------------
	for key, want := range map[string]any{
		factHWVendor:          "Cisco Systems",
		factHWModel:           "C9300-48P",
		factHWSerial:          "FOC2432L0AB",
		factHWFirmwareVersion: "17.09.04a",
		factNetUptimeSeconds:  1234567,
		factMgmtProtocol:      snmpManagementProtocol,
		factMgmtPlaintext:     true,
	} {
		if got := factValue(t, result, key); got != want {
			t.Errorf("%s = %v (%T), want %v", key, got, got, want)
		}
	}
	if strings.Contains(string(blob), "MODULE-SERIAL-NOT-THE-CHASSIS") {
		t.Errorf("a module's serial was reported as the device's: %s", blob)
	}
	if result.DeviceIdentity.ClassHint != "network_device" {
		t.Errorf("sysObjectID enterprise 9 did not produce a class hint: %+v", result.DeviceIdentity)
	}

	// --- interfaces -------------------------------------------------------
	interfaces := factValue(t, result, factNetInterfaces).([]map[string]interface{})
	if len(interfaces) != 3 {
		t.Fatalf("expected three interfaces, got %+v", interfaces)
	}
	// Numerically ordered: ifIndex 2 before ifIndex 10.
	if interfaces[0]["name"] != "Gi1/0/1" || interfaces[1]["name"] != "Gi1/0/2" || interfaces[2]["name"] != "Vl1" {
		t.Errorf("interfaces are not in ifIndex order: %+v", interfaces)
	}
	first := interfaces[0]
	if first["mac"] != "00:1b:17:00:00:01" || first["state"] != "up" || first["admin_state"] != "up" || first["speed"] != 1000 {
		t.Errorf("ifTable projection wrong: %+v", first)
	}
	second := interfaces[1]
	if second["state"] != "down" || second["admin_state"] != "down" {
		t.Errorf("a shut interface must record both states: %+v", second)
	}
	if _, hasMAC := second["mac"]; hasMAC {
		t.Errorf("the all-zero ifPhysAddress was stored as a MAC: %+v", second)
	}
	if second["speed"] != 100 {
		t.Errorf("ifSpeed fallback (bits/s → Mbit/s) wrong: %+v", second)
	}

	// --- neighbours and edges --------------------------------------------
	neighbors := factValue(t, result, factNetNeighbors).([]map[string]interface{})
	if len(neighbors) != 2 {
		t.Fatalf("expected one LLDP and one ARP neighbour, got %+v", neighbors)
	}
	var lldp, arp map[string]interface{}
	for _, n := range neighbors {
		switch n["protocol"] {
		case "lldp":
			lldp = n
		case "arp":
			arp = n
		}
	}
	if lldp["remote_name"] != "dist-sw-1.example.net" || lldp["remote_mac"] != "00:1b:17:00:00:aa" ||
		lldp["remote_port"] != "Gi1/0/24" || lldp["local_port"] != "Gi1/0/1" {
		t.Errorf("LLDP projection wrong: %+v", lldp)
	}
	if arp["remote_mac"] != "00:1b:17:00:00:bb" || arp["remote_address"] != "198.51.100.1" {
		t.Errorf("ARP projection wrong: %+v", arp)
	}

	edges := relationshipsOfType(result, relTypeConnectsTo)
	if len(edges) != 1 {
		t.Fatalf("expected one connects_to edge from LLDP, got %+v", edges)
	}
	edge := edges[0]
	if edge.Peer.Identifier(IdentifierFQDN) != "dist-sw-1.example.net" ||
		edge.Peer.Identifier(IdentifierMACAddress) != "00:1b:17:00:00:aa" {
		t.Errorf("edge peer identifiers wrong: %+v", edge.Peer)
	}
	if edge.Attributes["local_port"] != "Gi1/0/1" || edge.Attributes["remote_port"] != "Gi1/0/24" {
		t.Errorf("edge port attributes wrong: %+v", edge.Attributes)
	}
}

// An agent that answers nothing is a failed interrogation, not a device with
// nothing on it. UDP "connects" without an exchange, so the old code path
// reported success for a filtered port or a wrong community string.
func TestSNMPInterrogator_SilentAgentIsAFailure(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = conn.Close() }()
	host, portStr, _ := net.SplitHostPort(conn.LocalAddr().String())
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := (&SNMPInterrogator{Timeout: 200 * time.Millisecond}).Interrogate(
			context.Background(),
			DeviceInfo{DeviceType: "generic_snmp", IPAddress: host, Port: port},
			Credentials{Custom: map[string]interface{}{"community": "wrong"}},
		)
		if err == nil {
			t.Error("an agent that answered nothing produced a successful interrogation")
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the interrogation did not give up on a silent agent")
	}
}

func TestSNMPWalk_IsBoundedByTheDeadline(t *testing.T) {
	// An agent that always answers with the next OID of an unbounded synthetic
	// table: the shape that would hold a job open forever.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		buf := make([]byte, snmpMaxResponseBytes)
		next := 0
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			next++
			request := append([]byte(nil), buf[:n]...)
			reply, err := snmpTestAnswer(request, []snmpTestValue{
				snmpTestOctet(snmpOIDIfDescr+"."+itoa(next), "Gi1/0/"+itoa(next)),
			})
			if err != nil {
				continue
			}
			_, _ = conn.WriteTo(reply, addr)
		}
	}()

	client, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	start := time.Now()
	binds, truncated, err := snmpWalk(context.Background(), client, "public", snmpOIDIfDescr, time.Second, time.Now().Add(750*time.Millisecond))
	if err != nil {
		t.Fatalf("snmpWalk: %v", err)
	}
	if !truncated {
		t.Error("a walk stopped by its deadline did not report itself truncated")
	}
	if len(binds) > snmpMaxWalkRows {
		t.Errorf("the row cap was exceeded: %d rows", len(binds))
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the walk ran for %s past a 750ms deadline", elapsed)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestSNMPVarBind_DecodesTheTagsMIBIIReturns(t *testing.T) {
	// TimeTicks is the one that mattered: the old parser understood only OCTET
	// STRING and INTEGER, so sysUpTime could not be read at all.
	ticks := snmpTestInt("1.3.6.1.2.1.1.3.0", snmpTagTimeTicks, 123456789)
	if n, ok := (snmpVarBind{Tag: ticks.tag, Raw: ticks.raw}).Int(); !ok || n != 123456789 {
		t.Errorf("TimeTicks decoded as (%d, %v)", n, ok)
	}
	// A Counter32 with the high bit set is unsigned; sign-extending it reports
	// a negative uptime.
	big := snmpVarBind{Tag: snmpTagCounter32, Raw: []byte{0x80, 0x00, 0x00, 0x00}}
	if n, ok := big.Int(); !ok || n != 2147483648 {
		t.Errorf("Counter32 0x80000000 decoded as (%d, %v), want 2147483648", n, ok)
	}
	// A negative INTEGER still decodes as negative.
	if n, ok := (snmpVarBind{Tag: snmpTagInteger, Raw: []byte{0xff}}).Int(); !ok || n != -1 {
		t.Errorf("INTEGER -1 decoded as (%d, %v)", n, ok)
	}
	// Binary OCTET STRINGs render as hex, not mojibake.
	mac := snmpVarBind{Tag: snmpTagOctetString, Raw: []byte{0x00, 0x1b, 0x17, 0x00, 0x00, 0x01}}
	if got, ok := mac.MAC(); !ok || got != "00:1b:17:00:00:01" {
		t.Errorf("MAC decoded as (%q, %v)", got, ok)
	}
	// An exception is an answer, not an empty value.
	if !(snmpVarBind{Tag: snmpTagNoSuchObject}).IsException() {
		t.Error("noSuchObject was not recognised as an exception")
	}
	if (snmpVarBind{Tag: snmpTagNoSuchObject}).Text() != "" {
		t.Error("an exception rendered as a value")
	}
}

func TestSNMPObjectIDHint(t *testing.T) {
	cases := map[string]snmpVendorHint{
		"1.3.6.1.4.1.9.1.2494":       {Vendor: "Cisco Systems", Class: "network_device"},
		".1.3.6.1.4.1.9.1.2494":      {Vendor: "Cisco Systems", Class: "network_device"},
		"1.3.6.1.4.1.25461.2.3.31":   {Vendor: "Palo Alto Networks", Class: "firewall"},
		"1.3.6.1.4.1.674.10895.3000": {Vendor: "Dell"},
		// Net-SNMP identifies the agent, not the hardware.
		"1.3.6.1.4.1.8072.3.2.10": {},
		// Outside the private-enterprise arc, and an unlisted enterprise.
		"1.3.6.1.2.1.1.2.0":   {},
		"1.3.6.1.4.1.99999.1": {},
		"not an oid":          {},
		"":                    {},
	}
	for oid, want := range cases {
		if got := snmpObjectIDHint(oid); got != want {
			t.Errorf("snmpObjectIDHint(%q) = %+v, want %+v", oid, got, want)
		}
	}
}
