package deviceinterrogation

import (
	"context"
	"encoding/asn1"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// SNMP GETNEXT walking and typed varbind decoding.
//
// The interrogator's SNMP support was four GET requests for four scalar OIDs,
// and a response parser that understood two ASN.1 tags (OCTET STRING and
// INTEGER). Turning SNMP from a crypto probe into a generic network-device
// collector (ADR-0004 D1 item 3) needs tables, which needs GETNEXT, which needs
// the OID of each response varbind rather than only its value.
//
// The hand-rolled ASN.1 stays: this package is CGO-free and vendored into the
// standalone agent, and the four dependency-free functions below are cheaper
// than an SNMP library's transitive graph. What is added is deliberately small
// — one PDU type, the tags a MIB-II walk actually returns, and two bounds.
//
// The bounds are the point. A walk is a loop driven by a remote device's
// answers: the device decides how many rows there are, and a device with a
// large routing or ARP table (or one answering adversarially) would otherwise
// hold an interrogation job open indefinitely. Every walk is capped at
// snmpMaxWalkRows rows and stops at a deadline, and a truncated walk SAYS it
// was truncated rather than passing a partial table off as a complete one.

// ASN.1 / SNMP tags. The application tags (0x40-0x46) are what MIB-II actually
// returns for counters, gauges and timeticks; the previous parser rejected all
// of them, which is why sysUpTime could not be read.
const (
	snmpTagInteger        byte = 0x02
	snmpTagOctetString    byte = 0x04
	snmpTagNull           byte = 0x05
	snmpTagOID            byte = 0x06
	snmpTagSequence       byte = 0x30
	snmpTagIPAddress      byte = 0x40
	snmpTagCounter32      byte = 0x41
	snmpTagGauge32        byte = 0x42
	snmpTagTimeTicks      byte = 0x43
	snmpTagOpaque         byte = 0x44
	snmpTagCounter64      byte = 0x46
	snmpTagNoSuchObject   byte = 0x80
	snmpTagNoSuchInstance byte = 0x81
	snmpTagEndOfMibView   byte = 0x82

	snmpPDUGetRequest  byte = 0xa0
	snmpPDUGetNext     byte = 0xa1
	snmpPDUGetResponse byte = 0xa2
)

// snmpMaxWalkRows bounds a single walk. 500 rows covers a 48-port switch's
// interface table many times over and a busy ARP table once; beyond it, the
// answer is "this table is too large to inventory row by row", which is a
// different problem from a slow device.
const snmpMaxWalkRows = 500

// snmpMaxResponseBytes is the receive buffer. SNMP over UDP is bounded by the
// datagram anyway; this is the ceiling on what one varbind can be.
const snmpMaxResponseBytes = 8192

// snmpRequestID is a process-wide counter so two requests on the same
// connection never share an id. Responses whose id does not match the request
// are discarded: on a connected UDP socket a retransmitted answer to the
// PREVIOUS request arrives looking exactly like the answer to this one, and
// accepting it shifts every subsequent row of a walk by one.
var snmpRequestID atomic.Int32

func nextSNMPRequestID() int32 {
	id := snmpRequestID.Add(1)
	if id <= 0 {
		// Wrapped. Any positive value is fine; the id only has to be unlikely
		// to collide with one still in flight.
		snmpRequestID.Store(1)
		return 1
	}
	return id
}

// snmpVarBind is one (OID, value) pair from a response, with the value left as
// raw bytes so the caller decodes it as the MIB says rather than as the parser
// guessed. ifPhysAddress and sysDescr are both OCTET STRINGs; one is six binary
// bytes and the other is text.
type snmpVarBind struct {
	OID string
	Tag byte
	Raw []byte
}

// IsException reports whether the agent answered "there is nothing here" —
// noSuchObject, noSuchInstance or endOfMibView. These are ANSWERS, not values:
// an unsupported MIB is a fact about the device, and treating one as an empty
// string is how "not supported" comes to read as "empty".
func (v snmpVarBind) IsException() bool {
	return v.Tag == snmpTagNoSuchObject || v.Tag == snmpTagNoSuchInstance || v.Tag == snmpTagEndOfMibView
}

// Text renders the value as a human-readable string: text for a printable
// OCTET STRING, a hex string for a binary one, decimal for the integer family,
// dotted for an OID or an IpAddress.
func (v snmpVarBind) Text() string {
	if v.IsException() {
		return ""
	}
	switch v.Tag {
	case snmpTagOctetString, snmpTagOpaque:
		if isPrintableASCII(v.Raw) {
			return strings.TrimRight(string(v.Raw), "\x00")
		}
		return snmpHexString(v.Raw)
	case snmpTagInteger, snmpTagCounter32, snmpTagGauge32, snmpTagTimeTicks, snmpTagCounter64:
		n, _ := v.Int()
		return strconv.FormatInt(n, 10)
	case snmpTagOID:
		oid, err := snmpDecodeOIDValue(v.Raw)
		if err != nil {
			return ""
		}
		return oid
	case snmpTagIPAddress:
		if len(v.Raw) == 4 {
			return net.IP(v.Raw).String()
		}
		return ""
	default:
		return ""
	}
}

// Int decodes the integer family. The second result is false for a value that
// is not an integer at all, which is not the same as the value zero.
func (v snmpVarBind) Int() (int64, bool) {
	switch v.Tag {
	case snmpTagInteger, snmpTagCounter32, snmpTagGauge32, snmpTagTimeTicks, snmpTagCounter64:
	default:
		return 0, false
	}
	if len(v.Raw) == 0 || len(v.Raw) > 8 {
		return 0, false
	}
	var n int64
	// INTEGER is signed two's complement; the counter/gauge/timeticks family is
	// unsigned. Sign-extending a Counter32 of 0x80000000 would report a
	// negative uptime, which is where a "rebooted in the future" reading comes
	// from.
	if v.Tag == snmpTagInteger && v.Raw[0]&0x80 != 0 {
		n = -1
	}
	for _, b := range v.Raw {
		n = n<<8 | int64(b)
	}
	return n, true
}

// MAC decodes a six-byte OCTET STRING as a MAC address in canonical form. The
// all-zero and broadcast addresses are rejected by canonicalMAC: an interface
// with no layer-2 address reports six zero bytes, and that is an absence.
func (v snmpVarBind) MAC() (string, bool) {
	if v.Tag != snmpTagOctetString || len(v.Raw) != 6 {
		return "", false
	}
	mac, err := canonicalMAC(snmpHexString(v.Raw))
	if err != nil {
		return "", false
	}
	return mac, true
}

func snmpHexString(b []byte) string {
	const hexDigits = "0123456789abcdef"
	var sb strings.Builder
	sb.Grow(len(b) * 3)
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteByte(hexDigits[c>>4])
		sb.WriteByte(hexDigits[c&0x0f])
	}
	return sb.String()
}

func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c == 0 || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// snmpBuildRequest builds a v2c GET or GETNEXT PDU for one OID.
func snmpBuildRequest(pduTag byte, community string, requestID int32, oidStr string) ([]byte, error) {
	oid, err := snmpOIDToASN1(oidStr)
	if err != nil {
		return nil, err
	}
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}

	varBind := snmpMakeSequence(append(oidBytes, snmpTagNull, 0x00))
	varBindList := snmpMakeSequence(varBind)

	idBytes, err := asn1.Marshal(int(requestID))
	if err != nil {
		return nil, err
	}
	errorStatus := []byte{snmpTagInteger, 0x01, 0x00}
	errorIndex := []byte{snmpTagInteger, 0x01, 0x00}

	pduData := make([]byte, 0, len(idBytes)+len(errorStatus)+len(errorIndex)+len(varBindList))
	pduData = append(pduData, idBytes...)
	pduData = append(pduData, errorStatus...)
	pduData = append(pduData, errorIndex...)
	pduData = append(pduData, varBindList...)
	pdu := snmpMakeTaggedSequence(pduTag, pduData)

	version := []byte{snmpTagInteger, 0x01, 0x01} // 1 = SNMPv2c
	msg := make([]byte, 0, len(version)+len(community)+len(pdu)+8)
	msg = append(msg, version...)
	msg = append(msg, snmpMakeOctetString([]byte(community))...)
	msg = append(msg, pdu...)
	return snmpMakeSequence(msg), nil
}

// snmpReadTLV splits one TLV off the front of data, returning its tag, its
// content, and whatever follows it.
func snmpReadTLV(data []byte) (tag byte, content, rest []byte, err error) {
	if len(data) < 2 {
		return 0, nil, nil, fmt.Errorf("TLV too short")
	}
	length, n := snmpDecodeLength(data[1:])
	if n <= 0 || 1+n+length > len(data) {
		return 0, nil, nil, fmt.Errorf("invalid TLV length")
	}
	return data[0], data[1+n : 1+n+length], data[1+n+length:], nil
}

// snmpParseMessage decodes a v2c GetResponse into its request id, its error
// status and its varbinds.
func snmpParseMessage(data []byte) (requestID int32, errorStatus int64, binds []snmpVarBind, err error) {
	tag, msg, _, err := snmpReadTLV(data)
	if err != nil {
		return 0, 0, nil, err
	}
	if tag != snmpTagSequence {
		return 0, 0, nil, fmt.Errorf("SNMP message is not a SEQUENCE (tag 0x%02x)", tag)
	}

	// version, community, PDU
	_, _, rest, err := snmpReadTLV(msg) // version
	if err != nil {
		return 0, 0, nil, err
	}
	_, _, rest, err = snmpReadTLV(rest) // community
	if err != nil {
		return 0, 0, nil, err
	}
	pduTag, pdu, _, err := snmpReadTLV(rest)
	if err != nil {
		return 0, 0, nil, err
	}
	if pduTag != snmpPDUGetResponse {
		return 0, 0, nil, fmt.Errorf("unexpected PDU type 0x%02x, want a GetResponse", pduTag)
	}

	idTag, idBytes, rest, err := snmpReadTLV(pdu)
	if err != nil {
		return 0, 0, nil, err
	}
	id, ok := snmpVarBind{Tag: idTag, Raw: idBytes}.Int()
	if !ok {
		return 0, 0, nil, fmt.Errorf("request id is not an INTEGER")
	}
	statusTag, statusBytes, rest, err := snmpReadTLV(rest)
	if err != nil {
		return 0, 0, nil, err
	}
	status, _ := snmpVarBind{Tag: statusTag, Raw: statusBytes}.Int()
	_, _, rest, err = snmpReadTLV(rest) // error index
	if err != nil {
		return 0, 0, nil, err
	}

	listTag, list, _, err := snmpReadTLV(rest)
	if err != nil {
		return 0, 0, nil, err
	}
	if listTag != snmpTagSequence {
		return 0, 0, nil, fmt.Errorf("varbind list is not a SEQUENCE")
	}

	for len(list) > 0 {
		var bindContent []byte
		var bindTag byte
		bindTag, bindContent, list, err = snmpReadTLV(list)
		if err != nil {
			return 0, 0, nil, err
		}
		if bindTag != snmpTagSequence {
			return 0, 0, nil, fmt.Errorf("varbind is not a SEQUENCE")
		}
		oidTag, oidContent, afterOID, err := snmpReadTLV(bindContent)
		if err != nil {
			return 0, 0, nil, err
		}
		if oidTag != snmpTagOID {
			return 0, 0, nil, fmt.Errorf("varbind does not start with an OID")
		}
		oid, err := snmpDecodeOIDValue(oidContent)
		if err != nil {
			return 0, 0, nil, err
		}
		valueTag, valueContent, _, err := snmpReadTLV(afterOID)
		if err != nil {
			return 0, 0, nil, err
		}
		binds = append(binds, snmpVarBind{OID: oid, Tag: valueTag, Raw: valueContent})
	}

	return int32(id), status, binds, nil
}

// snmpDecodeOIDValue renders an encoded OID's CONTENT bytes as a dotted string.
func snmpDecodeOIDValue(content []byte) (string, error) {
	if len(content) == 0 {
		return "", fmt.Errorf("empty OID")
	}
	// asn1.Unmarshal wants the full TLV, so put the header back on.
	tlv := append([]byte{snmpTagOID}, snmpEncodeLength(len(content))...)
	tlv = append(tlv, content...)
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(tlv, &oid); err != nil {
		return "", fmt.Errorf("failed to decode OID: %w", err)
	}
	return oid.String(), nil
}

// snmpExchange sends one request and returns the matching response's varbinds.
// Responses carrying a different request id are discarded and the read
// retried until the deadline.
func snmpExchange(conn net.Conn, community string, pduTag byte, oid string, timeout time.Duration) ([]snmpVarBind, error) {
	requestID := nextSNMPRequestID()
	request, err := snmpBuildRequest(pduTag, community, requestID, oid)
	if err != nil {
		return nil, fmt.Errorf("failed to build SNMP request: %w", err)
	}
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set SNMP deadline: %w", err)
	}
	if _, err := conn.Write(request); err != nil {
		return nil, fmt.Errorf("failed to send SNMP request: %w", err)
	}

	buf := make([]byte, snmpMaxResponseBytes)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to read SNMP response: %w", err)
		}
		gotID, status, binds, err := snmpParseMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		if gotID != requestID {
			// A late answer to an earlier request. Keep reading while there is
			// time left rather than accepting it.
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("no SNMP response with request id %d before the deadline", requestID)
			}
			continue
		}
		if status != 0 {
			return nil, fmt.Errorf("SNMP agent returned error-status %d", status)
		}
		return binds, nil
	}
}

// snmpGetVar performs a GET for one OID and returns its varbind.
func snmpGetVar(conn net.Conn, community, oid string, timeout time.Duration) (snmpVarBind, error) {
	binds, err := snmpExchange(conn, community, snmpPDUGetRequest, oid, timeout)
	if err != nil {
		return snmpVarBind{}, err
	}
	if len(binds) == 0 {
		return snmpVarBind{}, fmt.Errorf("no varbind in SNMP response")
	}
	if binds[0].IsException() {
		return snmpVarBind{}, fmt.Errorf("OID %s is not supported by this agent", oid)
	}
	return binds[0], nil
}

// snmpWalk walks the sub-tree under root with GETNEXT, returning its varbinds.
//
// It stops at the first OID outside the sub-tree, at an end-of-MIB exception,
// at snmpMaxWalkRows rows, at the deadline, or when the context is cancelled —
// whichever comes first. A walk cut short by a bound returns the rows it did
// read together with a truncated flag, because a partial table presented as a
// whole one is exactly the sort of quiet half-answer this codebase keeps paying
// for.
func snmpWalk(ctx context.Context, conn net.Conn, community, root string, timeout time.Duration, deadline time.Time) (binds []snmpVarBind, truncated bool, err error) {
	prefix := root + "."
	current := root
	for len(binds) < snmpMaxWalkRows {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return binds, true, ctxErr
		}
		if !time.Now().Before(deadline) {
			return binds, true, nil
		}

		// Never let one exchange outlive the walk's own budget.
		step := timeout
		if remaining := time.Until(deadline); remaining < step {
			step = remaining
		}
		got, err := snmpExchange(conn, community, snmpPDUGetNext, current, step)
		if err != nil {
			// A walk that fails mid-table has still learned something true
			// about the rows it read.
			return binds, true, err
		}
		if len(got) == 0 {
			return binds, false, nil
		}
		bind := got[0]
		if bind.IsException() || !strings.HasPrefix(bind.OID, prefix) {
			return binds, false, nil
		}
		if bind.OID == current {
			// A non-advancing agent would spin here forever.
			return binds, true, fmt.Errorf("SNMP agent repeated OID %s on GETNEXT", current)
		}
		binds = append(binds, bind)
		current = bind.OID
	}
	return binds, true, nil
}

// snmpIndex returns the row index of a column OID — everything after the
// column's own OID and the dot that follows it.
func snmpIndex(column, oid string) string {
	return strings.TrimPrefix(oid, column+".")
}

// snmpWalkColumn walks one table column and returns its rows keyed by index,
// together with whether the walk was cut short.
//
// A truncated walk is SAID out loud here. The bounds above exist so a device
// cannot hold a job open; the cost of them firing is that the table the caller
// builds is partial, and a partial interface list presented as a complete one
// is the quiet half-answer this file's header warns about. Callers that do not
// use the flag at least leave a trace.
func snmpWalkColumn(ctx context.Context, conn net.Conn, community, column string, timeout time.Duration, deadline time.Time) (map[string]snmpVarBind, bool) {
	binds, truncated, err := snmpWalk(ctx, conn, community, column, timeout, deadline)
	switch {
	case err != nil:
		fmt.Printf("Warning: SNMP walk of %s stopped early after %d row(s): %v\n", column, len(binds), err)
	case truncated:
		fmt.Printf("Warning: SNMP walk of %s was cut short at %d row(s) by the row cap (%d) or the collection deadline; the table built from it is partial\n",
			column, len(binds), snmpMaxWalkRows)
	}
	out := make(map[string]snmpVarBind, len(binds))
	for _, bind := range binds {
		out[snmpIndex(column, bind.OID)] = bind
	}
	return out, truncated
}

// snmpDecodeLength returns (length, bytesConsumed) for a BER length, handling
// the short and long forms.
func snmpDecodeLength(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}
	b := data[0]
	if b < 0x80 {
		return int(b), 1
	}
	numBytes := int(b & 0x7f)
	// BER allows up to 127 length-of-length bytes; reject anything > 4 to prevent
	// integer overflow when accumulating the length value into a Go int.
	if numBytes > 4 || len(data) < 1+numBytes {
		return 0, 0
	}
	length := 0
	for i := 1; i < 1+numBytes; i++ {
		length = length<<8 | int(data[i])
	}
	return length, 1 + numBytes
}
