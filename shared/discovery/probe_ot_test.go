package discovery

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// =============================================================================
// canonicalProtocolName
// =============================================================================

func TestCanonicalProtocolName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"TLS", "TLS"},
		{"tls", "TLS"},
		{"https", "HTTPS"},
		{"OPC UA", "OPCUA"},
		{"OPC-UA", "OPCUA"},
		{"OPC_UA", "OPCUA"},
		{"opc.ua", "OPCUA"},
		{"EtherNet/IP", "ETHERNETIP"},
		{"ethernet_ip", "ETHERNETIP"},
		{"BACnet", "BACNET"},
		{"Modbus", "MODBUS"},
	}
	for _, c := range cases {
		if got := CanonicalProtocolName(c.in); got != c.want {
			t.Errorf("CanonicalProtocolName(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

func TestProberRegistry_RegistersAllExpectedProtocols(t *testing.T) {
	t.Parallel()
	expectedTCP := []string{"TLS", "HTTPS", "SSH", "SMB", "MODBUS", "OPCUA"}
	for _, p := range expectedTCP {
		if _, ok := tcpProberRegistry[p]; !ok {
			t.Errorf("tcpProberRegistry missing %q", p)
		}
	}
	expectedUDP := []string{"ETHERNETIP", "BACNET"}
	for _, p := range expectedUDP {
		if _, ok := udpProberRegistry[p]; !ok {
			t.Errorf("udpProberRegistry missing %q", p)
		}
	}
}

// =============================================================================
// Modbus probe — runs against a TCP test server that speaks the expected
// MBAP request shape and returns a synthesized Read Device Identification
// response with vendor / product / revision strings.
// =============================================================================

func TestProbeModbus_ReadDeviceIdentificationOK(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Read the 11-byte request.
		req := make([]byte, 11)
		if _, err := conn.Read(req); err != nil {
			return
		}
		// Verify request shape.
		if binary.BigEndian.Uint16(req[2:4]) != 0x0000 {
			t.Errorf("request protocol id != 0")
		}
		if req[7] != modbusFnReadDeviceID || req[8] != modbusMEIType {
			t.Errorf("request function/MEI wrong: 0x%02x 0x%02x", req[7], req[8])
		}
		// Build a response with 3 objects (vendor, product, revision).
		vendor := []byte("ACME PLC")
		product := []byte("FX-3000")
		revision := []byte("1.4")
		// PDU layout:
		//   FC(1) MEI(1) ReadDevIDCode(1) ConformityLevel(1) MoreFollows(1)
		//   NextObjectID(1) NumberOfObjects(1) [ ObjID(1) Len(1) Val(N) ]*
		pdu := []byte{
			modbusFnReadDeviceID, // 0x2B
			modbusMEIType,        // 0x0E
			modbusReadDeviceIDBasic,
			0x00, // ConformityLevel: basic identification
			0x00, // MoreFollows: false
			0x00, // NextObjectID
			0x03, // NumberOfObjects
		}
		pdu = append(pdu, modbusObjVendorName, byte(len(vendor)))
		pdu = append(pdu, vendor...)
		pdu = append(pdu, modbusObjProductCode, byte(len(product)))
		pdu = append(pdu, product...)
		pdu = append(pdu, modbusObjMajorMinorRev, byte(len(revision)))
		pdu = append(pdu, revision...)

		mbap := make([]byte, 7)
		binary.BigEndian.PutUint16(mbap[0:2], 0x0001)
		binary.BigEndian.PutUint16(mbap[2:4], 0x0000)
		binary.BigEndian.PutUint16(mbap[4:6], uint16(1+len(pdu)))
		mbap[6] = modbusUnitIDProbe
		_, _ = conn.Write(append(mbap, pdu...))
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	prober := NewProber(2 * time.Second)
	finding, err := probeModbus(prober, conn, "", 502)
	if err != nil {
		t.Fatalf("probeModbus error: %v", err)
	}
	if finding.Protocol != "Modbus" {
		t.Errorf("Protocol=%q, want Modbus", finding.Protocol)
	}
	if finding.Metadata["vendor_name"] != "ACME PLC" {
		t.Errorf("vendor_name=%v, want ACME PLC", finding.Metadata["vendor_name"])
	}
	if finding.Metadata["product_code"] != "FX-3000" {
		t.Errorf("product_code=%v, want FX-3000", finding.Metadata["product_code"])
	}
	if finding.Metadata["revision"] != "1.4" {
		t.Errorf("revision=%v, want 1.4", finding.Metadata["revision"])
	}
	if finding.Metadata["security"] != "none" {
		t.Errorf("security=%v, want none", finding.Metadata["security"])
	}
	if finding.Metadata["function_43_supported"] != true {
		t.Errorf("function_43_supported=%v, want true", finding.Metadata["function_43_supported"])
	}
}

func TestProbeModbus_ExceptionResponseStillIdentifiesDevice(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		req := make([]byte, 11)
		_, _ = conn.Read(req)
		// Exception response: function code | 0x80, exception code 0x01 (illegal function).
		mbap := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, modbusUnitIDProbe}
		pdu := []byte{modbusFnReadDeviceIDExc, 0x01}
		_, _ = conn.Write(append(mbap, pdu...))
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	prober := NewProber(2 * time.Second)
	finding, err := probeModbus(prober, conn, "", 502)
	if err != nil {
		t.Fatalf("probeModbus error: %v", err)
	}
	if finding.Protocol != "Modbus" {
		t.Errorf("Protocol=%q, want Modbus", finding.Protocol)
	}
	if finding.Metadata["function_43_supported"] != false {
		t.Errorf("function_43_supported=%v, want false", finding.Metadata["function_43_supported"])
	}
	if finding.Metadata["modbus_exception_code"] != 1 {
		t.Errorf("modbus_exception_code=%v, want 1", finding.Metadata["modbus_exception_code"])
	}
}

// =============================================================================
// OPC UA probe — simulate ACK response to HEL.
// =============================================================================

func TestProbeOPCUA_AckResponseParsesCorrectly(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Read enough to drain the HEL message.
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		// Build ACK response (28 bytes).
		resp := make([]byte, 28)
		copy(resp[0:4], []byte("ACKF"))
		binary.LittleEndian.PutUint32(resp[4:8], 28)       // size
		binary.LittleEndian.PutUint32(resp[8:12], 0)       // protocol version
		binary.LittleEndian.PutUint32(resp[12:16], 65535)  // receive buffer
		binary.LittleEndian.PutUint32(resp[16:20], 65535)  // send buffer
		binary.LittleEndian.PutUint32(resp[20:24], 100000) // max message
		binary.LittleEndian.PutUint32(resp[24:28], 5)      // max chunk count
		_, _ = conn.Write(resp)
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	prober := NewProber(2 * time.Second)
	finding, err := probeOPCUA(prober, conn, "device.local", 4840)
	if err != nil {
		t.Fatalf("probeOPCUA error: %v", err)
	}
	if finding.Protocol != "OPC_UA" {
		t.Errorf("Protocol=%q, want OPC_UA", finding.Protocol)
	}
	if finding.Metadata["opcua_message_type"] != "ACK" {
		t.Errorf("opcua_message_type=%v, want ACK", finding.Metadata["opcua_message_type"])
	}
	if finding.Metadata["opcua_max_chunk_count"] != uint32(5) {
		t.Errorf("opcua_max_chunk_count=%v, want 5", finding.Metadata["opcua_max_chunk_count"])
	}
}

// =============================================================================
// EtherNet/IP — UDP listener, List Identity request → response.
// =============================================================================

func TestProbeEtherNetIP_ListIdentityResponse(t *testing.T) {
	t.Parallel()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = pc.Close() }()
	udpAddr := pc.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 1024)
		_, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		// Build response: 24-byte enc header + CPF item.
		header := make([]byte, 24)
		binary.LittleEndian.PutUint16(header[0:2], enipCmdListIdentity)

		// CPF: ItemCount=1, then one item (type 0x000C).
		productName := []byte("Allen-Bradley CompactLogix")
		// item layout: 33 bytes fixed + name + state(1)
		itemLen := 33 + len(productName) + 1
		item := make([]byte, itemLen)
		binary.LittleEndian.PutUint16(item[0:2], 1) // protocol version
		// socket family/port/ip/zero — leave zero
		binary.LittleEndian.PutUint16(item[18:20], 0x0001)     // VendorID = 1 (Rockwell/Allen-Bradley)
		binary.LittleEndian.PutUint16(item[20:22], 14)         // DeviceType = Programmable Logic Controller
		binary.LittleEndian.PutUint16(item[22:24], 100)        // ProductCode
		item[24] = 33                                          // RevisionMajor
		item[25] = 1                                           // RevisionMinor
		binary.LittleEndian.PutUint16(item[26:28], 0)          // Status
		binary.LittleEndian.PutUint32(item[28:32], 0xDEADBEEF) // Serial
		item[32] = byte(len(productName))
		copy(item[33:], productName)
		// state byte at end is zero

		// Wrap into CPF.
		cpf := make([]byte, 0, 2+4+itemLen)
		cpfHeader := make([]byte, 6)
		binary.LittleEndian.PutUint16(cpfHeader[0:2], 1)      // ItemCount
		binary.LittleEndian.PutUint16(cpfHeader[2:4], 0x000C) // TypeCode
		binary.LittleEndian.PutUint16(cpfHeader[4:6], uint16(itemLen))
		cpf = append(cpf, cpfHeader...)
		cpf = append(cpf, item...)
		// Encapsulation length field = CPF length.
		binary.LittleEndian.PutUint16(header[2:4], uint16(len(cpf)))
		_, _ = pc.WriteTo(append(header, cpf...), addr)
	}()

	prober := NewProber(2 * time.Second)
	finding, err := probeEtherNetIP(prober, "", "127.0.0.1", udpAddr.Port)
	if err != nil {
		t.Fatalf("probeEtherNetIP error: %v", err)
	}
	if finding.Protocol != "EtherNet_IP" {
		t.Errorf("Protocol=%q, want EtherNet_IP", finding.Protocol)
	}
	if finding.Metadata["vendor_id"] != uint16(1) {
		t.Errorf("vendor_id=%v, want 1", finding.Metadata["vendor_id"])
	}
	if finding.Metadata["product_code"] != uint16(100) {
		t.Errorf("product_code=%v, want 100", finding.Metadata["product_code"])
	}
	if finding.Metadata["serial_number"] != uint32(0xDEADBEEF) {
		t.Errorf("serial_number=%v, want 0xDEADBEEF", finding.Metadata["serial_number"])
	}
	if finding.Metadata["product_name"] != "Allen-Bradley CompactLogix" {
		t.Errorf("product_name=%v", finding.Metadata["product_name"])
	}
}

// =============================================================================
// BACnet — UDP listener, Who-Is request → I-Am response.
// =============================================================================

func TestProbeBACnet_IAmResponseDecodesDeviceInstance(t *testing.T) {
	t.Parallel()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = pc.Close() }()
	udpAddr := pc.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 1024)
		_, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		// Build minimal I-Am response.
		// BVLC: 81 0A LL LL  | NPDU: 01 00 | APDU: 10 00 (Unconfirmed I-Am)
		// Object identifier (5 bytes): tag 0xC4, then 4-byte object ID
		// Object ID encoding: top 10 bits = object type (8 = device), bottom 22 bits = instance
		objType := uint32(8)
		instance := uint32(12345)
		objID := (objType << 22) | (instance & 0x3FFFFF)
		objIDBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(objIDBytes, objID)

		// Body: NPDU(2) + APDU(2 prefix) + 5 obj-id bytes + a few placeholder bytes
		body := []byte{
			0x01, 0x00, // NPDU version + control
			0x10, 0x00, // APDU: Unconfirmed Request, Service Choice I-Am
			0xC4, // tag for object identifier
			objIDBytes[0], objIDBytes[1], objIDBytes[2], objIDBytes[3],
			0x22, 0x01, 0xE0, // max APDU length placeholder
			0x91, 0x00, // segmentation supported
			0x21, 0x05, // vendor ID (5 = generic)
		}
		bvlc := []byte{0x81, 0x0A, 0x00, 0x00}
		binary.BigEndian.PutUint16(bvlc[2:4], uint16(4+len(body)))
		_, _ = pc.WriteTo(append(bvlc, body...), addr)
	}()

	prober := NewProber(2 * time.Second)
	finding, err := probeBACnet(prober, "", "127.0.0.1", udpAddr.Port)
	if err != nil {
		t.Fatalf("probeBACnet error: %v", err)
	}
	if finding.Protocol != "BACnet" {
		t.Errorf("Protocol=%q, want BACnet", finding.Protocol)
	}
	if finding.Metadata["bacnet_iam_detected"] != true {
		t.Errorf("bacnet_iam_detected=%v, want true", finding.Metadata["bacnet_iam_detected"])
	}
	if finding.Metadata["bacnet_device_instance"] != 12345 {
		t.Errorf("bacnet_device_instance=%v, want 12345", finding.Metadata["bacnet_device_instance"])
	}
	if finding.Metadata["bacnet_object_type"] != 8 {
		t.Errorf("bacnet_object_type=%v, want 8 (device)", finding.Metadata["bacnet_object_type"])
	}
}
