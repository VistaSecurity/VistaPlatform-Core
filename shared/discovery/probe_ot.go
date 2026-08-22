package discovery

// OT/ICS active probes for the shared discovery package.
//
// Ported from the standalone Sensor's sensor/internal/discovery/ot_probers.go.
// Each prober here is registered into the central tcp/udpProberRegistry at
// init time. The framework calls them by uppercased canonical protocol name
// (see CanonicalProtocolName); the prober owns its request/response on the
// wire and returns a neutral *ProbeResult with protocol-specific Metadata.
//
// Safety stance: every probe here uses the protocol's own well-known
// discovery method (Modbus Function 43/14, OPC UA Hello, EtherNet/IP List
// Identity, BACnet Who-Is). These are the methods OT vendors document for
// asset enumeration; they do not write or change device state. Per CLAUDE.md
// and the OT design doc, we explicitly do NOT add active probes for
// protocols that lack a safe well-known probe (DNP3, MMS, ICCP, S7).
//
// Active probing of OT devices is gated externally:
//   - subscription tier feature flag `ot_active_probing` (auth-service)
//   - per-discovery-job opt-in (discovery_jobs.ot_probe_protocols)
//
// This file just reacts to "go probe X for protocol Modbus" and returns
// whatever the wire said.

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"
)

func init() {
	tcpProberRegistry["MODBUS"] = probeModbus
	tcpProberRegistry["OPCUA"] = probeOPCUA
	udpProberRegistry["ETHERNETIP"] = probeEtherNetIP
	udpProberRegistry["BACNET"] = probeBACnet
}

// =============================================================================
// Modbus/TCP — Function 43 sub-function 14 (Read Device Identification)
// =============================================================================
//
// Wire (request):
//   MBAP header (7 bytes):
//     TxID(2)=0x0001  ProtoID(2)=0x0000  Length(2)=0x0005  UnitID(1)=0x01
//   PDU (4 bytes):
//     FunctionCode(1)=0x2B  MEIType(1)=0x0E
//     ReadDeviceIDCode(1)=0x01 (Basic)  ObjectID(1)=0x00
//
// Successful response carries vendor name / product code / revision strings;
// we return them in Metadata so the OT-lens "Inventory" tab can populate
// the device class column with real vendor/model data.

const (
	modbusUnitIDProbe        = 0x01
	modbusFnReadDeviceID     = 0x2B
	modbusFnReadDeviceIDExc  = 0xAB // exception form (function | 0x80)
	modbusMEIType            = 0x0E
	modbusReadDeviceIDBasic  = 0x01
	modbusObjVendorName      = 0x00
	modbusObjProductCode     = 0x01
	modbusObjMajorMinorRev   = 0x02
	modbusProbeReadBufferLen = 4096
)

func probeModbus(p *Prober, conn net.Conn, _ string, port int) (*ProbeResult, error) {
	// Build the 11-byte request.
	req := make([]byte, 11)
	binary.BigEndian.PutUint16(req[0:2], 0x0001) // TxID
	binary.BigEndian.PutUint16(req[2:4], 0x0000) // ProtoID — must be 0 for Modbus
	binary.BigEndian.PutUint16(req[4:6], 0x0005) // Length: UnitID + 4-byte PDU
	req[6] = modbusUnitIDProbe                   // UnitID
	req[7] = modbusFnReadDeviceID                // Function code 43
	req[8] = modbusMEIType                       // MEI type 14
	req[9] = modbusReadDeviceIDBasic             // Read Device ID code: Basic
	req[10] = modbusObjVendorName                // Object ID: start at vendor name

	if err := otWriteWithDeadline(conn, req, p.timeout); err != nil {
		return nil, fmt.Errorf("modbus write: %w", err)
	}

	resp, err := otReadWithDeadline(conn, modbusProbeReadBufferLen, p.timeout)
	if err != nil {
		return nil, fmt.Errorf("modbus read: %w", err)
	}
	if len(resp) < 8 {
		return nil, fmt.Errorf("modbus response too short: %d bytes", len(resp))
	}
	// Validate MBAP header.
	if binary.BigEndian.Uint16(resp[2:4]) != 0x0000 {
		return nil, fmt.Errorf("modbus response has wrong protocol id")
	}
	pduLen := int(binary.BigEndian.Uint16(resp[4:6]))
	if pduLen < 2 || pduLen > len(resp)-6 {
		return nil, fmt.Errorf("modbus response length field invalid: %d", pduLen)
	}
	pdu := resp[6 : 6+pduLen]

	result := &ProbeResult{
		Protocol:   "Modbus",
		Port:       port,
		Confidence: 0.95,
		Metadata: map[string]interface{}{
			"unit_id":          int(pdu[0]),
			"probe":            "function43_read_device_identification",
			"modbus_variant":   "ModbusTCP",
			"security":         "none",
			"discovery_method": "active",
		},
	}

	// Exception response: still confirms it's a Modbus device, just one that
	// doesn't support function 43. Return a minimal result rather than
	// erroring — operator still wants to know "Modbus speaks here".
	if pdu[1] == modbusFnReadDeviceIDExc {
		result.Metadata["function_43_supported"] = false
		if len(pdu) >= 3 {
			result.Metadata["modbus_exception_code"] = int(pdu[2])
		}
		return result, nil
	}
	if pdu[1] != modbusFnReadDeviceID {
		return nil, fmt.Errorf("modbus response unexpected function code 0x%02x", pdu[1])
	}
	result.Metadata["function_43_supported"] = true

	// Parse the device-ID objects.
	// PDU layout after function code:
	//   MEIType(1) | ReadDeviceIDCode(1) | ConformityLevel(1) | MoreFollows(1) |
	//   NextObjectID(1) | NumberOfObjects(1) | { ObjectID(1) Length(1) Value(N) }*
	if len(pdu) < 8 {
		return result, nil
	}
	numObjects := int(pdu[7])
	off := 8
	objects := map[string]string{}
	for i := 0; i < numObjects && off+2 <= len(pdu); i++ {
		objID := pdu[off]
		objLen := int(pdu[off+1])
		off += 2
		if off+objLen > len(pdu) {
			break
		}
		val := string(pdu[off : off+objLen])
		off += objLen
		switch objID {
		case modbusObjVendorName:
			objects["vendor_name"] = val
		case modbusObjProductCode:
			objects["product_code"] = val
		case modbusObjMajorMinorRev:
			objects["revision"] = val
		default:
			objects[fmt.Sprintf("object_0x%02x", objID)] = val
		}
	}
	for k, v := range objects {
		result.Metadata[k] = v
	}
	return result, nil
}

// =============================================================================
// OPC UA — HEL (Hello) message → ACK (Acknowledge) handshake
// =============================================================================
//
// The full GetEndpoints exchange requires opening a SecureChannel and sending
// a CreateSession request — non-trivial. The HEL/ACK message exchange is the
// first thing every OPC UA Binary client does, and an ACK confirms the
// service is OPC UA. We surface the protocol-version bytes so the operator
// can see which OPC UA version the server speaks.
//
// Wire reference: OPC 10000-6 §7.1.

const (
	opcuaProbeReadBufferLen = 4096
	opcuaHelloHeaderLen     = 8 // "HELF" + length(uint32 LE)
)

func probeOPCUA(p *Prober, conn net.Conn, hostname string, port int) (*ProbeResult, error) {
	endpoint := fmt.Sprintf("opc.tcp://%s:%d", hostname, port)
	endpointBytes := []byte(endpoint)

	// HEL message body: 24 fixed bytes + endpoint URL.
	bodyLen := 24 + len(endpointBytes)
	totalLen := opcuaHelloHeaderLen + bodyLen
	msg := make([]byte, totalLen)
	copy(msg[0:4], []byte("HELF"))
	binary.LittleEndian.PutUint32(msg[4:8], uint32(totalLen))
	binary.LittleEndian.PutUint32(msg[8:12], 0)      // Protocol version (0 = current)
	binary.LittleEndian.PutUint32(msg[12:16], 65535) // ReceiveBufferSize
	binary.LittleEndian.PutUint32(msg[16:20], 65535) // SendBufferSize
	binary.LittleEndian.PutUint32(msg[20:24], 0)     // MaxMessageSize (0 = no cap)
	binary.LittleEndian.PutUint32(msg[24:28], 0)     // MaxChunkCount (0 = no cap)
	binary.LittleEndian.PutUint32(msg[28:32], uint32(len(endpointBytes)))
	copy(msg[32:], endpointBytes)

	if err := otWriteWithDeadline(conn, msg, p.timeout); err != nil {
		return nil, fmt.Errorf("opc ua write: %w", err)
	}

	resp, err := otReadWithDeadline(conn, opcuaProbeReadBufferLen, p.timeout)
	if err != nil {
		return nil, fmt.Errorf("opc ua read: %w", err)
	}
	if len(resp) < 28 {
		return nil, fmt.Errorf("opc ua response too short: %d bytes", len(resp))
	}
	msgType := string(resp[0:3])

	result := &ProbeResult{
		Protocol:   "OPC_UA",
		Port:       port,
		Confidence: 0.9,
		Metadata: map[string]interface{}{
			"probe":              "hello",
			"opcua_message_type": msgType,
			"discovery_method":   "active",
		},
	}

	// "ACKF" is the success path; "ERRF" is a structured rejection that
	// still confirms the listener is OPC UA.
	switch msgType {
	case "ACK":
		result.Metadata["opcua_protocol_version"] = binary.LittleEndian.Uint32(resp[8:12])
		result.Metadata["opcua_receive_buffer_size"] = binary.LittleEndian.Uint32(resp[12:16])
		result.Metadata["opcua_send_buffer_size"] = binary.LittleEndian.Uint32(resp[16:20])
		result.Metadata["opcua_max_message_size"] = binary.LittleEndian.Uint32(resp[20:24])
		result.Metadata["opcua_max_chunk_count"] = binary.LittleEndian.Uint32(resp[24:28])
	case "ERR":
		// ERR: 4-byte status code + 4-byte reason length + reason string.
		result.Confidence = 0.85
		if len(resp) >= 12 {
			result.Metadata["opcua_error_status"] = fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(resp[8:12]))
		}
	default:
		return nil, fmt.Errorf("opc ua response unrecognized message type %q", msgType)
	}

	return result, nil
}

// =============================================================================
// EtherNet/IP CIP — List Identity (UDP 44818)
// =============================================================================
//
// Encapsulation header (24 bytes) with Command=0x0063 (List Identity) and
// no command-specific data. Response carries vendor ID, device type, product
// code, revision, status, serial number, and product name string — exactly
// the inventory data the OT-lens Inventory tab wants for vendor/model
// columns.
//
// Wire reference: ODVA "EtherNet/IP CIP" spec, encapsulation protocol §2.

const (
	enipCmdListIdentity = 0x0063
	enipReadBufferLen   = 4096
)

func probeEtherNetIP(p *Prober, _ string, ip string, port int) (*ProbeResult, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, p.timeout)
	if err != nil {
		return nil, fmt.Errorf("ethernet/ip dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	req := make([]byte, 24)
	binary.LittleEndian.PutUint16(req[0:2], enipCmdListIdentity)
	// remaining 22 bytes are zero (length, session, status, context, options)

	if err := otWriteWithDeadline(conn, req, p.timeout); err != nil {
		return nil, fmt.Errorf("ethernet/ip write: %w", err)
	}
	resp, err := otReadWithDeadline(conn, enipReadBufferLen, p.timeout)
	if err != nil {
		return nil, fmt.Errorf("ethernet/ip read: %w", err)
	}
	if len(resp) < 24 {
		return nil, fmt.Errorf("ethernet/ip response too short: %d bytes", len(resp))
	}
	if binary.LittleEndian.Uint16(resp[0:2]) != enipCmdListIdentity {
		return nil, fmt.Errorf("ethernet/ip response wrong command 0x%04x", binary.LittleEndian.Uint16(resp[0:2]))
	}

	result := &ProbeResult{
		Protocol:   "EtherNet_IP",
		Port:       port,
		Confidence: 0.95,
		Metadata: map[string]interface{}{
			"probe":            "list_identity",
			"discovery_method": "active",
			"security":         "none", // CIP without CIP Security is plaintext
		},
	}

	// CPF (Common Packet Format) starts after the 24-byte encapsulation
	// header. ItemCount(2) then per-item: TypeCode(2) Length(2) Data(N).
	body := resp[24:]
	if len(body) < 2 {
		return result, nil
	}
	itemCount := int(binary.LittleEndian.Uint16(body[0:2]))
	off := 2
	for i := 0; i < itemCount && off+4 <= len(body); i++ {
		typeCode := binary.LittleEndian.Uint16(body[off : off+2])
		itemLen := int(binary.LittleEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+itemLen > len(body) {
			break
		}
		item := body[off : off+itemLen]
		off += itemLen

		// Type 0x000C is the ListIdentityResponse item.
		if typeCode != 0x000C {
			continue
		}
		// Item layout (after the 4-byte CPF header):
		//   EncapProtoVer(2) | SocketFamily(2) | SocketPort(2 BE) | SocketIP(4) |
		//   SocketZero(8) | VendorID(2) | DeviceType(2) | ProductCode(2) |
		//   Revision(2: major/minor) | Status(2) | Serial(4) | ProductNameLen(1) |
		//   ProductName(N) | State(1)
		if len(item) < 33 {
			break
		}
		result.Metadata["enip_protocol_version"] = binary.LittleEndian.Uint16(item[0:2])
		result.Metadata["vendor_id"] = binary.LittleEndian.Uint16(item[18:20])
		result.Metadata["device_type"] = binary.LittleEndian.Uint16(item[20:22])
		result.Metadata["product_code"] = binary.LittleEndian.Uint16(item[22:24])
		result.Metadata["revision_major"] = item[24]
		result.Metadata["revision_minor"] = item[25]
		result.Metadata["status"] = binary.LittleEndian.Uint16(item[26:28])
		result.Metadata["serial_number"] = binary.LittleEndian.Uint32(item[28:32])
		nameLen := int(item[32])
		if 33+nameLen <= len(item) {
			result.Metadata["product_name"] = string(item[33 : 33+nameLen])
		}
		break // one identity item is all we need
	}
	return result, nil
}

// =============================================================================
// BACnet — Who-Is (UDP 47808)
// =============================================================================
//
// Wire (request, 8 bytes total):
//   BVLC: Type(1)=0x81 Function(1)=0x0B Length(2 BE)=0x0008
//   NPDU: Version(1)=0x01 Control(1)=0x20 (expecting reply)
//   APDU: PDUType(1)=0x10 (Unconfirmed Request) ServiceChoice(1)=0x08 (Who-Is)
//
// We send the Who-Is unicast to the target IP. BACnet routers honor unicast
// Who-Is and reply with I-Am. Broadcast Who-Is is the more common discovery
// pattern but is tenant-network-policy-sensitive — unicast keeps the blast
// radius to one device per probe.
//
// Wire reference: ASHRAE 135 BACnet/IP §B.4.

const (
	bacnetBVLCTypeBACnetIP  = 0x81
	bacnetBVLCFnUnicastNPDU = 0x0A
	bacnetReadBufferLen     = 4096
)

func probeBACnet(p *Prober, _ string, ip string, port int) (*ProbeResult, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, p.timeout)
	if err != nil {
		return nil, fmt.Errorf("bacnet dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	req := []byte{
		bacnetBVLCTypeBACnetIP,  // BVLC Type
		bacnetBVLCFnUnicastNPDU, // BVLC Function: Original-Unicast-NPDU
		0x00, 0x08,              // BVLC Length (8 bytes total)
		0x01, // NPDU Version
		0x20, // NPDU Control: expecting reply, no source/dest
		0x10, // APDU: Unconfirmed Request
		0x08, // Service Choice: Who-Is (no params = match all)
	}

	if err := otWriteWithDeadline(conn, req, p.timeout); err != nil {
		return nil, fmt.Errorf("bacnet write: %w", err)
	}
	resp, err := otReadWithDeadline(conn, bacnetReadBufferLen, p.timeout)
	if err != nil {
		return nil, fmt.Errorf("bacnet read: %w", err)
	}
	if len(resp) < 8 {
		return nil, fmt.Errorf("bacnet response too short: %d bytes", len(resp))
	}
	if resp[0] != bacnetBVLCTypeBACnetIP {
		return nil, fmt.Errorf("bacnet response wrong BVLC type 0x%02x", resp[0])
	}

	result := &ProbeResult{
		Protocol:   "BACnet",
		Port:       port,
		Confidence: 0.9,
		Metadata: map[string]interface{}{
			"probe":            "who_is",
			"discovery_method": "active",
			"security":         "none", // BACnet/SC is rare; classic BACnet/IP is plaintext
			"bvlc_function":    fmt.Sprintf("0x%02x", resp[1]),
		},
	}

	// Look for I-Am inside the APDU. After the 4-byte BVLC header and a
	// minimum 2-byte NPDU, scan for the I-Am marker bytes (PDU type 0x10,
	// service choice 0x00). NPDU length is variable depending on routing
	// info, so we don't blindly skip a fixed offset.
	for i := 4; i < len(resp)-1; i++ {
		if resp[i] == 0x10 && resp[i+1] == 0x00 {
			result.Metadata["bacnet_iam_detected"] = true
			// I-Am body immediately follows: object identifier (5 bytes,
			// tag 0xC4), then max APDU length, segmentation, vendor ID.
			// We extract the device instance number — bottom 22 bits of
			// the 4-byte object identifier.
			if i+6 < len(resp) && resp[i+2] == 0xC4 {
				objID := binary.BigEndian.Uint32(resp[i+3 : i+7])
				result.Metadata["bacnet_device_instance"] = int(objID & 0x3FFFFF)
				result.Metadata["bacnet_object_type"] = int((objID >> 22) & 0x3FF)
			}
			break
		}
	}
	return result, nil
}

// =============================================================================
// Helpers
// =============================================================================

// otWriteWithDeadline applies the per-probe timeout to a single conn.Write.
// Splitting the deadline is not necessary for our short request payloads —
// every OT probe in this file fits in a single packet.
func otWriteWithDeadline(conn net.Conn, payload []byte, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

// otReadWithDeadline reads up to maxBytes within the timeout window. Returns
// whatever was read; OT responses are typically a single packet so a single
// Read is enough.
func otReadWithDeadline(conn net.Conn, maxBytes int, timeout time.Duration) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	buf := make([]byte, maxBytes)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}
