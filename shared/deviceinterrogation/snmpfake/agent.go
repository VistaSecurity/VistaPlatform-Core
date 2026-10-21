// Package snmpfake is a fake SNMP v2c agent for tests: it answers real UDP
// GET and GETNEXT datagrams from a table of OIDs, so a collector's GETNEXT
// loop, request-id matching and ASN.1 decoding are driven end to end instead of
// being unit-tested against hand-built varbinds.
//
// It is the recorded-response source of the SNMP intake parity tests (DCIM row
// 1.5d): [L3Switch48] and [LinuxNetSNMP] synthesise what a 48-port layer-3
// switch and a net-snmp Linux host answer to the walks the collector makes.
// It imports nothing from shared/deviceinterrogation, so that package's own
// tests can use it too.
package snmpfake

import (
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// BER tags the fake speaks.
const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagOID         = 0x06
	tagSequence    = 0x30
	tagIPAddress   = 0x40
	tagGauge32     = 0x42
	tagTimeTicks   = 0x43
	tagNoSuchObj   = 0x80

	pduGet     = 0xa0
	pduGetNext = 0xa1
	pduResp    = 0xa2
)

// Value is one (OID, typed value) pair of the agent's MIB.
type Value struct {
	OID string
	tag byte
	raw []byte
}

// Str is an OCTET STRING holding text.
func Str(oid, s string) Value { return Value{OID: oid, tag: tagOctetString, raw: []byte(s)} }

// Bytes is an OCTET STRING holding binary (a MAC, a PortList bitmap).
func Bytes(oid string, b []byte) Value { return Value{OID: oid, tag: tagOctetString, raw: b} }

// MAC is an OCTET STRING holding the six bytes of a colon-separated MAC.
func MAC(oid, mac string) Value {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	return Bytes(oid, hw)
}

// Int is an INTEGER.
func Int(oid string, n int64) Value { return Value{OID: oid, tag: tagInteger, raw: signed(n)} }

// Gauge is a Gauge32.
func Gauge(oid string, n int64) Value {
	return Value{OID: oid, tag: tagGauge32, raw: unsigned(uint64(n))}
}

// Ticks is TimeTicks.
func Ticks(oid string, n int64) Value {
	return Value{OID: oid, tag: tagTimeTicks, raw: unsigned(uint64(n))}
}

// IP is an IpAddress (IPv4).
func IP(oid, addr string) Value {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		panic("snmpfake: not an IPv4 address: " + addr)
	}
	return Value{OID: oid, tag: tagIPAddress, raw: []byte(ip)}
}

// OIDValue is an OBJECT IDENTIFIER value.
func OIDValue(oid, value string) Value {
	return Value{OID: oid, tag: tagOID, raw: encodeOID(value)}
}

func signed(n int64) []byte {
	var raw []byte
	for shift := 56; shift >= 0; shift -= 8 {
		b := byte(n >> shift)
		if len(raw) == 0 && ((b == 0 && n >= 0) || (b == 0xff && n < 0)) {
			continue
		}
		raw = append(raw, b)
	}
	if len(raw) == 0 {
		// 0, or -1 (every byte 0xff was skipped as sign extension).
		if n < 0 {
			return []byte{0xff}
		}
		return []byte{0}
	}
	// Keep the sign bit honest.
	if n >= 0 && raw[0]&0x80 != 0 {
		raw = append([]byte{0}, raw...)
	}
	if n < 0 && raw[0]&0x80 == 0 {
		raw = append([]byte{0xff}, raw...)
	}
	return raw
}

func unsigned(n uint64) []byte {
	var raw []byte
	for shift := 56; shift >= 0; shift -= 8 {
		b := byte(n >> shift)
		if len(raw) == 0 && b == 0 {
			continue
		}
		raw = append(raw, b)
	}
	if len(raw) == 0 {
		return []byte{0}
	}
	if raw[0]&0x80 != 0 {
		raw = append([]byte{0}, raw...)
	}
	return raw
}

func encodeOID(oid string) []byte {
	parts := strings.Split(strings.TrimPrefix(oid, "."), ".")
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			panic("snmpfake: bad OID " + oid)
		}
		nums[i] = n
	}
	if len(nums) < 2 {
		panic("snmpfake: OID too short: " + oid)
	}
	out := []byte{byte(nums[0]*40 + nums[1])}
	for _, n := range nums[2:] {
		var tmp []byte
		tmp = append(tmp, byte(n&0x7f))
		for n >>= 7; n > 0; n >>= 7 {
			tmp = append(tmp, byte(n&0x7f)|0x80)
		}
		for i := len(tmp) - 1; i >= 0; i-- {
			out = append(out, tmp[i])
		}
	}
	return out
}

func decodeOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := []string{strconv.Itoa(int(b[0]) / 40), strconv.Itoa(int(b[0]) % 40)}
	var n uint64
	for _, c := range b[1:] {
		n = n<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			parts = append(parts, strconv.FormatUint(n, 10))
			n = 0
		}
	}
	return strings.Join(parts, ".")
}

func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	switch n := len(content); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}

func readTLV(b []byte) (tag byte, content, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("short")
	}
	tag = b[0]
	n, off := int(b[1]), 2
	if b[1]&0x80 != 0 {
		l := int(b[1] & 0x7f)
		if l == 0 || l > 3 || len(b) < 2+l {
			return 0, nil, nil, errors.New("bad length")
		}
		n = 0
		for _, c := range b[2 : 2+l] {
			n = n<<8 | int(c)
		}
		off = 2 + l
	}
	if len(b) < off+n {
		return 0, nil, nil, errors.New("truncated")
	}
	return tag, b[off : off+n], b[off+n:], nil
}

// oidLess orders OIDs numerically component by component.
func oidLess(a, b string) bool {
	ap, bp := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(ap) && i < len(bp); i++ {
		ai, _ := strconv.Atoi(ap[i])
		bi, _ := strconv.Atoi(bp[i])
		if ai != bi {
			return ai < bi
		}
	}
	return len(ap) < len(bp)
}

// Serve starts an agent answering from mib on a loopback UDP port and returns
// its host and port. community, when not empty, is required: a request with
// another community is silently dropped, as a real agent does.
func Serve(t testing.TB, mib []Value, community string) (host string, port int) {
	t.Helper()
	sorted := append([]Value(nil), mib...)
	sort.Slice(sorted, func(i, j int) bool { return oidLess(sorted[i].OID, sorted[j].OID) })

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("snmpfake: listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 8192)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if reply, err := answer(buf[:n], sorted, community); err == nil {
				_, _ = conn.WriteTo(reply, addr)
			}
		}
	}()
	h, p, _ := net.SplitHostPort(conn.LocalAddr().String())
	port, _ = strconv.Atoi(p)
	return h, port
}

func answer(request []byte, mib []Value, community string) ([]byte, error) {
	_, msg, _, err := readTLV(request)
	if err != nil {
		return nil, err
	}
	_, _, rest, err := readTLV(msg) // version
	if err != nil {
		return nil, err
	}
	_, comm, rest, err := readTLV(rest)
	if err != nil {
		return nil, err
	}
	if community != "" && string(comm) != community {
		return nil, errors.New("wrong community")
	}
	pduTag, pdu, _, err := readTLV(rest)
	if err != nil {
		return nil, err
	}
	_, idBytes, rest, err := readTLV(pdu)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 2; i++ { // error-status, error-index
		if _, _, rest, err = readTLV(rest); err != nil {
			return nil, err
		}
	}
	_, list, _, err := readTLV(rest)
	if err != nil {
		return nil, err
	}
	_, bind, _, err := readTLV(list)
	if err != nil {
		return nil, err
	}
	_, oidContent, _, err := readTLV(bind)
	if err != nil {
		return nil, err
	}
	requested := decodeOID(oidContent)

	var (
		got   Value
		found bool
	)
	switch pduTag {
	case pduGet:
		for _, v := range mib {
			if v.OID == requested {
				got, found = v, true
				break
			}
		}
	case pduGetNext:
		for _, v := range mib {
			if oidLess(requested, v.OID) {
				got, found = v, true
				break
			}
		}
	}
	if !found {
		got = Value{OID: requested, tag: tagNoSuchObj}
	}

	vb := tlv(tagSequence, append(tlv(tagOID, encodeOID(got.OID)), tlv(got.tag, got.raw)...))
	body := append([]byte{}, tlv(tagInteger, idBytes)...)
	body = append(body, tlv(tagInteger, []byte{0})...)
	body = append(body, tlv(tagInteger, []byte{0})...)
	body = append(body, tlv(tagSequence, vb)...)
	out := append(tlv(tagInteger, []byte{1}), tlv(tagOctetString, comm)...)
	out = append(out, tlv(pduResp, body)...)
	return tlv(tagSequence, out), nil
}

// Wire returns the value's OID, BER tag and content bytes, for a test that
// drives its own agent.
func (v Value) Wire() (oid string, tag byte, raw []byte) { return v.OID, v.tag, v.raw }
