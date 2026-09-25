package pipelinetest

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// A fake SNMP v2c agent answering GET and GETNEXT from device/mib.json.
//
// It is written against encoding/asn1 rather than the collector's own BER
// helpers on purpose: a fake that shares the collector's codec would agree
// with it about any encoding bug they both have.

// mibFile is device/mib.json.
type mibFile struct {
	Values []mibValue `json:"values"`
}

// mibValue is one object. Type is one of octet, hex (colon- or space-separated
// bytes, for MACs), integer, gauge32, counter32, timeticks, oid, ipaddress.
type mibValue struct {
	OID   string `json:"oid"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type snmpEntry struct {
	oid asn1.ObjectIdentifier
	tlv []byte
}

type snmpMessage struct {
	Version   int
	Community []byte
	PDU       asn1.RawValue
}

type snmpPDU struct {
	RequestID   int64
	ErrorStatus int
	ErrorIndex  int
	VarBinds    []snmpBind
}

type snmpBind struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}

const (
	snmpGet         = 0
	snmpGetNext     = 1
	snmpGetResponse = 2
)

func serveSNMP(t *testing.T, deviceDir string) string {
	t.Helper()
	var mf mibFile
	ReadJSON(t, filepath.Join(deviceDir, "mib.json"), &mf)
	entries := make([]snmpEntry, 0, len(mf.Values))
	for _, v := range mf.Values {
		e, err := encodeMIBValue(v)
		if err != nil {
			t.Fatalf("mib.json %s: %v", v.OID, err)
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return oidLess(entries[i].oid, entries[j].oid) })

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { _ = conn.Close(); <-done })
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			reply, err := snmpAnswer(buf[:n], entries)
			if err != nil {
				continue
			}
			_, _ = conn.WriteTo(reply, addr)
		}
	}()
	return conn.LocalAddr().String()
}

func snmpAnswer(request []byte, entries []snmpEntry) ([]byte, error) {
	var msg snmpMessage
	if _, err := asn1.Unmarshal(request, &msg); err != nil {
		return nil, err
	}
	if msg.PDU.Class != asn1.ClassContextSpecific {
		return nil, fmt.Errorf("not a PDU")
	}
	var pdu snmpPDU
	if _, err := asn1.UnmarshalWithParams(msg.PDU.FullBytes, &pdu, fmt.Sprintf("tag:%d", msg.PDU.Tag)); err != nil {
		return nil, err
	}
	out := snmpPDU{RequestID: pdu.RequestID}
	for _, bind := range pdu.VarBinds {
		out.VarBinds = append(out.VarBinds, snmpLookup(msg.PDU.Tag, bind.Name, entries))
	}
	pduBytes, err := asn1.MarshalWithParams(out, fmt.Sprintf("tag:%d", snmpGetResponse))
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(snmpMessage{Version: msg.Version, Community: msg.Community, PDU: asn1.RawValue{FullBytes: pduBytes}})
}

// snmpLookup answers one varbind: the exact object for GET, the next one in
// lexicographic OID order for GETNEXT, and the v2c exceptions otherwise.
func snmpLookup(pduTag int, name asn1.ObjectIdentifier, entries []snmpEntry) snmpBind {
	switch pduTag {
	case snmpGet:
		for _, e := range entries {
			if e.oid.Equal(name) {
				return snmpBind{Name: e.oid, Value: asn1.RawValue{FullBytes: e.tlv}}
			}
		}
		return snmpBind{Name: name, Value: asn1.RawValue{FullBytes: []byte{0x80, 0x00}}} // noSuchObject
	case snmpGetNext:
		for _, e := range entries {
			if oidLess(name, e.oid) {
				return snmpBind{Name: e.oid, Value: asn1.RawValue{FullBytes: e.tlv}}
			}
		}
		return snmpBind{Name: name, Value: asn1.RawValue{FullBytes: []byte{0x82, 0x00}}} // endOfMibView
	}
	return snmpBind{Name: name, Value: asn1.RawValue{FullBytes: []byte{0x05, 0x00}}}
}

func oidLess(a, b asn1.ObjectIdentifier) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(strings.TrimPrefix(s, "."), ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("oid %q: %w", s, err)
		}
		oid[i] = n
	}
	return oid, nil
}

// encodeMIBValue renders one object's value as a complete BER TLV.
func encodeMIBValue(v mibValue) (snmpEntry, error) {
	oid, err := parseOID(v.OID)
	if err != nil {
		return snmpEntry{}, err
	}
	var tlv []byte
	switch v.Type {
	case "octet":
		tlv, err = asn1.Marshal([]byte(v.Value))
	case "hex":
		raw, decErr := hex.DecodeString(strings.NewReplacer(":", "", " ", "", "-", "").Replace(v.Value))
		if decErr != nil {
			return snmpEntry{}, decErr
		}
		tlv, err = asn1.Marshal(raw)
	case "integer", "gauge32", "counter32", "timeticks":
		n, convErr := strconv.ParseInt(v.Value, 10, 64)
		if convErr != nil {
			return snmpEntry{}, convErr
		}
		tlv, err = asn1.Marshal(n)
		if err == nil {
			tlv[0] = map[string]byte{"integer": 0x02, "counter32": 0x41, "gauge32": 0x42, "timeticks": 0x43}[v.Type]
		}
	case "oid":
		target, oidErr := parseOID(v.Value)
		if oidErr != nil {
			return snmpEntry{}, oidErr
		}
		tlv, err = asn1.Marshal(target)
	case "ipaddress":
		ip := net.ParseIP(v.Value).To4()
		if ip == nil {
			return snmpEntry{}, fmt.Errorf("ipaddress %q is not IPv4", v.Value)
		}
		tlv = append([]byte{0x40, 0x04}, ip...)
	default:
		return snmpEntry{}, fmt.Errorf("unknown type %q", v.Type)
	}
	if err != nil {
		return snmpEntry{}, err
	}
	return snmpEntry{oid: oid, tlv: tlv}, nil
}
