package discovery

// Honest per-service UDP discovery probes.
//
// A UDP port cannot be scanned the way a TCP port can: an empty datagram draws
// no reply from most services, and "no reply" is not "closed" (hole H18). So
// UDP discovery is per-service: each curated (protocol, port) pair gets ONE
// standard, unauthenticated discovery exchange whose reply identifies the
// service, and the outcome is reported in the honest vocabulary of ProbeUDP
// (answered / no-answer / refused / error) — never "no answer ⇒ closed".
//
// These probers are kept in their OWN registry (udpServiceProbers), separate
// from the OT-gated udpProberRegistry that ProbeUDP/PlanUDPProbes dispatch, so
// adding generic service discovery here changes none of that path's behaviour.
// OT UDP probers (BACnet, EtherNet/IP) stay where they are and run only under
// the explicit OT opt-in, exactly as before.
//
// Every payload here is a standard discovery request a monitoring tool sends:
// a DNS query for the root, one NTP client packet, an SNMPv3 engine-discovery
// message (NEVER a v1/v2c community guess — that would be credential probing),
// a minimal IKE_SA_INIT, an OpenVPN client reset, a DTLS/QUIC hello that forces
// an identifying reply, a unicast mDNS query and a unicast SSDP M-SEARCH. None
// is an amplification vector (each request is no larger than its reply) and
// none authenticates or changes device state.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// errUDPUnrecognised means a datagram came back but did not parse as the
// protocol we probed. It is deliberately not a timeout and not a refusal:
// something answered, we just cannot say it is the service — ProbeError, not
// ProbeNoAnswer (see classifyUDPProbeError).
var errUDPUnrecognised = errors.New("udp reply did not parse as the probed protocol")

// udpServiceProbe sends one discovery datagram on an already-connected UDP
// socket and parses the reply. It returns (result, nil) when the reply is the
// protocol, (nil, errUDPUnrecognised) when a datagram came back but was not,
// and the wire error otherwise (so a timeout becomes no-answer and an ICMP
// port-unreachable becomes refused). It writes exactly one datagram.
type udpServiceProbe func(conn net.Conn, timeout time.Duration) (*ProbeResult, error)

// udpServiceProbers is the generic (non-OT) UDP discovery registry, keyed by
// folded canonical protocol name.
var udpServiceProbers = map[string]udpServiceProbe{
	"DNS":     probeDNSUDP,
	"NTP":     probeNTP,
	"SNMP":    probeSNMPv3,
	"IKE":     probeIKE,
	"OPENVPN": probeOpenVPN,
	"DTLS":    probeDTLS,
	"QUIC":    probeQUIC,
	"MDNS":    probeMDNS,
	"SSDP":    probeSSDP,
}

// curatedUDPPortProtocols maps a curated UDP port to the protocol(s) probed on
// it. It is OUR list, justified per entry; it excludes the OT UDP ports, which
// live in otUDPPortProtocols and are gated.
//
//	53    DNS            123   NTP
//	161   SNMP           500   IKE (IKEv1/IKEv2, main)
//	1194  OpenVPN        1900  SSDP
//	4433  DTLS (common alt)    4500  IKE (NAT-T)
//	5353  mDNS           5684  DTLS (CoAP/DTLS)
//	443   QUIC + DTLS (HTTP/3 and WebRTC/DTLS share the port)
var curatedUDPPortProtocols = map[int][]string{
	53:   {"DNS"},
	123:  {"NTP"},
	161:  {"SNMP"},
	443:  {"QUIC", "DTLS"},
	500:  {"IKE"},
	1194: {"OpenVPN"},
	1900: {"SSDP"},
	4433: {"DTLS"},
	4500: {"IKE"},
	5353: {"mDNS"},
	5684: {"DTLS"},
}

// otUDPPortProtocols are the OT/ICS UDP ports. They are probed only under the
// OT opt-in (the existing BACnet/EtherNet-IP probers), never by a default UDP
// scan.
//
//	47808 BACnet/IP       44818 EtherNet/IP (CIP)
var otUDPPortProtocols = map[int][]string{
	47808: {"BACnet"},
	44818: {"EtherNet_IP"},
}

// CuratedUDPPorts returns the curated UDP ports a default UDP scan probes. It
// excludes the OT UDP ports (OTUDPPorts), which require the OT opt-in.
func CuratedUDPPorts() []int {
	out := make([]int, 0, len(curatedUDPPortProtocols))
	for p := range curatedUDPPortProtocols {
		out = append(out, p)
	}
	return out
}

// OTUDPPorts returns the OT/ICS UDP ports, probed only under the OT opt-in.
func OTUDPPorts() []int {
	out := make([]int, 0, len(otUDPPortProtocols))
	for p := range otUDPPortProtocols {
		out = append(out, p)
	}
	return out
}

// udpServiceProbersForPort returns the generic UDP probers registered for a
// curated port, in map order of their protocols.
func udpServiceProbersForPort(port int) []udpNamedProbe {
	var out []udpNamedProbe
	for _, proto := range curatedUDPPortProtocols[port] {
		if probe, ok := udpServiceProbers[CanonicalProtocolName(proto)]; ok {
			out = append(out, udpNamedProbe{protocol: proto, probe: probe})
		}
	}
	return out
}

type udpNamedProbe struct {
	protocol string
	probe    udpServiceProbe
}

// -----------------------------------------------------------------------------
// DNS (53) — a standard query for the root NS, recursion NOT desired, so this
// is neither a recursion-abuse nor an amplification request.
// -----------------------------------------------------------------------------

func probeDNSUDP(conn net.Conn, timeout time.Duration) (*ProbeResult, error) {
	var id [2]byte
	_, _ = rand.Read(id[:])
	msg := []byte{
		id[0], id[1], // transaction ID
		0x00, 0x00, // flags: QR=0, Opcode=0, RD=0
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR = 0
		0x00,       // QNAME = root (.)
		0x00, 0x02, // QTYPE = NS
		0x00, 0x01, // QCLASS = IN
	}
	reply, err := udpExchange(conn, msg, timeout, 4096)
	if err != nil {
		return nil, err
	}
	if len(reply) < 12 || reply[0] != id[0] || reply[1] != id[1] || reply[2]&0x80 == 0 {
		return nil, errUDPUnrecognised
	}
	return &ProbeResult{
		Protocol: "DNS",
		Metadata: map[string]interface{}{
			"transport":        "udp",
			"discovery_method": "active",
			"dns_rcode":        int(reply[3] & 0x0f),
		},
	}, nil
}

// -----------------------------------------------------------------------------
// NTP (123) — one mode-3 (client) packet; the reply is a mode-4 (server) packet.
// -----------------------------------------------------------------------------

func probeNTP(conn net.Conn, timeout time.Duration) (*ProbeResult, error) {
	msg := make([]byte, 48)
	msg[0] = 0x23 // LI=0, VN=4, Mode=3 (client)
	reply, err := udpExchange(conn, msg, timeout, 128)
	if err != nil {
		return nil, err
	}
	if len(reply) < 48 || reply[0]&0x07 != 4 { // mode 4 = server
		return nil, errUDPUnrecognised
	}
	return &ProbeResult{
		Protocol: "NTP",
		Metadata: map[string]interface{}{
			"transport":        "udp",
			"discovery_method": "active",
			"ntp_version":      int(reply[0]>>3) & 0x07,
			"ntp_stratum":      int(reply[1]),
		},
	}, nil
}

// -----------------------------------------------------------------------------
// SNMPv3 (161) — the unauthenticated engine-discovery message (RFC 3414 §4): a
// Get with an empty engineID and reportable flag set; the agent answers with a
// Report PDU carrying its engine ID. This reveals SNMPv3 support WITHOUT any
// community string — a v1/v2c community guess would be credential probing and
// is never sent.
// -----------------------------------------------------------------------------

func probeSNMPv3(conn net.Conn, timeout time.Duration) (*ProbeResult, error) {
	msg := buildSNMPv3Discovery()
	reply, err := udpExchange(conn, msg, timeout, 4096)
	if err != nil {
		return nil, err
	}
	// A v3 message is a SEQUENCE whose first element is INTEGER 3.
	if len(reply) < 5 || reply[0] != 0x30 {
		return nil, errUDPUnrecognised
	}
	body, ok := berSkipSeqHeader(reply)
	if !ok || len(body) < 3 || body[0] != 0x02 || body[1] != 0x01 || body[2] != 0x03 {
		return nil, errUDPUnrecognised
	}
	return &ProbeResult{
		Protocol: "SNMP",
		Metadata: map[string]interface{}{
			"transport":        "udp",
			"discovery_method": "active",
			"snmp_version":     3,
		},
	}, nil
}

// buildSNMPv3Discovery assembles the fixed engine-discovery message. All USM
// fields are empty; no credentials are present or guessed.
func buildSNMPv3Discovery() []byte {
	var msgID [2]byte
	_, _ = rand.Read(msgID[:])

	globalData := berSeq(bytes.Join([][]byte{
		berInt(int(binary.BigEndian.Uint16(msgID[:]))), // msgID
		berInt(65507),          // msgMaxSize
		berOctet([]byte{0x04}), // msgFlags: reportable, noAuthNoPriv
		berInt(3),              // msgSecurityModel = USM
	}, nil))

	usm := berSeq(bytes.Join([][]byte{
		berOctet(nil), // engineID
		berInt(0),     // engineBoots
		berInt(0),     // engineTime
		berOctet(nil), // userName
		berOctet(nil), // authParams
		berOctet(nil), // privParams
	}, nil))
	secParams := berOctet(usm)

	getPDU := berTLV(0xA0, bytes.Join([][]byte{
		berInt(0),   // request-id
		berInt(0),   // error-status
		berInt(0),   // error-index
		berSeq(nil), // empty variable-bindings
	}, nil))
	scopedPDU := berSeq(bytes.Join([][]byte{
		berOctet(nil), // contextEngineID
		berOctet(nil), // contextName
		getPDU,
	}, nil))

	return berSeq(bytes.Join([][]byte{
		berInt(3), // version
		globalData,
		secParams,
		scopedPDU,
	}, nil))
}

// -----------------------------------------------------------------------------
// IKE (500 / 4500) — a minimal IKEv2 IKE_SA_INIT. Any reply (a responder
// SA_INIT, or a NO_PROPOSAL_CHOSEN / INVALID_KE notify) identifies an IKE
// responder and its version; the exchange is the first, unauthenticated one and
// changes no state. On 4500 the packet carries the non-ESP marker.
// -----------------------------------------------------------------------------

func probeIKE(conn net.Conn, timeout time.Duration) (*ProbeResult, error) {
	var spi [8]byte
	_, _ = rand.Read(spi[:])
	pkt := buildIKEv2SAInit(spi)
	// 4500 (NAT-T) prefixes a 4-byte non-ESP marker; sending it on 500 too is
	// harmless only if the responder expects it, so key it off the port.
	if ra, ok := conn.RemoteAddr().(*net.UDPAddr); ok && ra.Port == 4500 {
		pkt = append([]byte{0x00, 0x00, 0x00, 0x00}, pkt...)
	}
	reply, err := udpExchange(conn, pkt, timeout, 4096)
	if err != nil {
		return nil, err
	}
	// Strip a non-ESP marker on the reply if present.
	if len(reply) >= 4 && bytes.Equal(reply[:4], []byte{0, 0, 0, 0}) {
		reply = reply[4:]
	}
	if len(reply) < 28 || !bytes.Equal(reply[0:8], spi[:]) {
		return nil, errUDPUnrecognised // must echo our initiator SPI
	}
	version := reply[17]
	if version != 0x20 && version != 0x10 {
		return nil, errUDPUnrecognised
	}
	ver := "IKEv2"
	if version == 0x10 {
		ver = "IKEv1"
	}
	return &ProbeResult{
		Protocol: "IKE",
		Metadata: map[string]interface{}{
			"transport":        "udp",
			"discovery_method": "active",
			"ike_version":      ver,
			"ike_exchange":     int(reply[18]),
		},
	}, nil
}

// buildIKEv2SAInit builds an IKE_SA_INIT with a single proposal (AES-CBC-128,
// HMAC-SHA256, PRF-SHA256, MODP-2048), a KE payload for group 14, and a nonce.
// The KE value need not be a real DH public value: an INVALID_KE_PAYLOAD or
// NO_PROPOSAL_CHOSEN reply still identifies the responder.
func buildIKEv2SAInit(spi [8]byte) []byte {
	// Transforms: ENCR(1)=AES_CBC(12) with 128-bit key attr, PRF(2)=HMAC_SHA2_256(5),
	// INTEG(3)=HMAC_SHA2_256_128(12), DH(4)=MODP2048(14).
	keyLenAttr := []byte{0x80, 0x0e, 0x00, 0x80}  // AF=1,type=14 keylen, value 128
	encr := ikeTransform(0x03, 1, 12, keyLenAttr) // more transforms follow
	prf := ikeTransform(0x03, 2, 5, nil)
	integ := ikeTransform(0x03, 3, 12, nil)
	dh := ikeTransform(0x00, 4, 14, nil) // last transform
	transforms := bytes.Join([][]byte{encr, prf, integ, dh}, nil)

	// Proposal: num=1, protocol=IKE(1), SPI size=0, #transforms=4.
	prop := []byte{0x00, 0x00, byte(len(transforms) + 8>>0), 0x00}
	_ = prop
	proposal := buildIKEProposal(transforms)
	saPayload := ikePayload(34 /*next=KE*/, proposal) // SA, next payload = KE

	keData := make([]byte, 256) // MODP-2048 public value length
	_, _ = rand.Read(keData)
	keBody := append([]byte{0x00, 0x0e, 0x00, 0x00}, keData...) // DH group 14, reserved
	kePayload := ikePayload(40 /*next=Nonce*/, keBody)

	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	noncePayload := ikePayload(0 /*next=none*/, nonce)

	payloads := bytes.Join([][]byte{saPayload, kePayload, noncePayload}, nil)

	hdr := make([]byte, 28)
	copy(hdr[0:8], spi[:]) // initiator SPI
	hdr[16] = 33           // first payload = SA
	hdr[17] = 0x20         // version IKEv2
	hdr[18] = 34           // exchange type = IKE_SA_INIT
	hdr[19] = 0x08         // flags: initiator
	binary.BigEndian.PutUint32(hdr[24:28], uint32(28+len(payloads)))
	return append(hdr, payloads...)
}

// ikeTransform builds one IKEv2 transform (type, id) with optional attributes;
// more=0x03 means another transform follows, 0x00 means last.
func ikeTransform(more byte, transformType byte, transformID uint16, attrs []byte) []byte {
	body := make([]byte, 4)
	body[0] = more
	body[1] = 0x00
	// length filled below
	t := []byte{transformType, 0x00}
	id := make([]byte, 2)
	binary.BigEndian.PutUint16(id, transformID)
	out := append(append(append(body[:0:0], body...), t...), id...)
	out = append(out, attrs...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}

func buildIKEProposal(transforms []byte) []byte {
	// Proposal substructure: last(0)/more(2), reserved, length, num, protoID,
	// SPIsize, #transforms.
	nTransforms := byte(4)
	body := []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, nTransforms}
	out := append(body, transforms...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}

// ikePayload wraps a payload body in the generic IKEv2 payload header
// (next payload, critical/reserved, length).
func ikePayload(next byte, body []byte) []byte {
	hdr := make([]byte, 4)
	hdr[0] = next
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(body)+4))
	return append(hdr, body...)
}

// -----------------------------------------------------------------------------
// OpenVPN (1194 UDP) — a P_CONTROL_HARD_RESET_CLIENT_V2; the server answers with
// P_CONTROL_HARD_RESET_SERVER_V2.
// -----------------------------------------------------------------------------

const (
	openvpnHardResetClientV2 = 7
	openvpnHardResetServerV2 = 8
)

func probeOpenVPN(conn net.Conn, timeout time.Duration) (*ProbeResult, error) {
	var session [8]byte
	_, _ = rand.Read(session[:])
	msg := make([]byte, 0, 14)
	msg = append(msg, byte(openvpnHardResetClientV2)<<3) // opcode<<3 | key_id(0)
	msg = append(msg, session[:]...)                     // session ID
	msg = append(msg, 0x00)                              // ACK array length = 0
	msg = append(msg, 0x00, 0x00, 0x00, 0x01)            // message packet-id
	reply, err := udpExchange(conn, msg, timeout, 512)
	if err != nil {
		return nil, err
	}
	if len(reply) < 1 || reply[0]>>3 != openvpnHardResetServerV2 {
		return nil, errUDPUnrecognised
	}
	return &ProbeResult{
		Protocol: "OpenVPN",
		Metadata: map[string]interface{}{"transport": "udp", "discovery_method": "active"},
	}, nil
}

// -----------------------------------------------------------------------------
// DTLS (443 / 4433 / 5684 / …) — a DTLS 1.2 ClientHello; the peer answers with a
// HelloVerifyRequest (or a ServerHello). A record with content type 22 and a
// DTLS version (0xFExx) identifies DTLS.
// -----------------------------------------------------------------------------

func probeDTLS(conn net.Conn, timeout time.Duration) (*ProbeResult, error) {
	msg := buildDTLSClientHello()
	reply, err := udpExchange(conn, msg, timeout, 4096)
	if err != nil {
		return nil, err
	}
	// DTLS record: ContentType(1) Version(2) Epoch(2) Seq(6) Length(2) ...
	if len(reply) < 13 || reply[0] != 22 || reply[1] != 0xFE {
		return nil, errUDPUnrecognised
	}
	return &ProbeResult{
		Protocol: "DTLS",
		Metadata: map[string]interface{}{
			"transport":        "udp",
			"discovery_method": "active",
			"dtls_record_type": int(reply[0]),
		},
	}, nil
}

// buildDTLSClientHello builds a minimal DTLS 1.2 ClientHello record with an
// empty cookie, one cipher suite and no extensions beyond what is needed to
// draw a HelloVerifyRequest.
func buildDTLSClientHello() []byte {
	var randBytes [32]byte
	_, _ = rand.Read(randBytes[:])
	// ClientHello body.
	body := new(bytes.Buffer)
	body.Write([]byte{0xFE, 0xFD}) // client_version DTLS 1.2
	body.Write(randBytes[:])       // random
	body.WriteByte(0x00)           // session id length
	body.WriteByte(0x00)           // cookie length
	body.Write([]byte{0x00, 0x02}) // cipher suites length
	body.Write([]byte{0x00, 0x2f}) // TLS_RSA_WITH_AES_128_CBC_SHA
	body.WriteByte(0x01)           // compression methods length
	body.WriteByte(0x00)           // null compression
	ch := body.Bytes()

	// Handshake header: type(1)=ClientHello, length(3), msg_seq(2), frag_off(3), frag_len(3).
	hs := new(bytes.Buffer)
	hs.WriteByte(0x01)
	hs.Write(uint24(len(ch)))
	hs.Write([]byte{0x00, 0x00}) // message_seq
	hs.Write(uint24(0))          // fragment_offset
	hs.Write(uint24(len(ch)))    // fragment_length
	hs.Write(ch)
	handshake := hs.Bytes()

	// Record header: type(1)=22, version(2)=DTLS1.2, epoch(2), seq(6), length(2).
	rec := new(bytes.Buffer)
	rec.WriteByte(22)
	rec.Write([]byte{0xFE, 0xFD})
	rec.Write([]byte{0x00, 0x00})                         // epoch
	rec.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // sequence number
	rec.Write([]byte{byte(len(handshake) >> 8), byte(len(handshake))})
	rec.Write(handshake)
	return rec.Bytes()
}

// -----------------------------------------------------------------------------
// QUIC (443 UDP) — an Initial long-header packet carrying a version the server
// cannot support, which forces a Version Negotiation reply (long header,
// version 0x00000000) that identifies QUIC without a crypto handshake.
// -----------------------------------------------------------------------------

func probeQUIC(conn net.Conn, timeout time.Duration) (*ProbeResult, error) {
	var dcid, scid [8]byte
	_, _ = rand.Read(dcid[:])
	_, _ = rand.Read(scid[:])
	pkt := new(bytes.Buffer)
	pkt.WriteByte(0xC0)                       // long header, fixed bit
	pkt.Write([]byte{0x0a, 0x1a, 0x2a, 0x3a}) // force-VN (reserved) version
	pkt.WriteByte(byte(len(dcid)))
	pkt.Write(dcid[:])
	pkt.WriteByte(byte(len(scid)))
	pkt.Write(scid[:])
	// Pad to the 1200-byte minimum so servers do not drop the Initial.
	for pkt.Len() < 1200 {
		pkt.WriteByte(0x00)
	}
	reply, err := udpExchange(conn, pkt.Bytes(), timeout, 4096)
	if err != nil {
		return nil, err
	}
	// Version Negotiation: long header (high bit set) with version 0x00000000.
	if len(reply) < 7 || reply[0]&0x80 == 0 || !bytes.Equal(reply[1:5], []byte{0, 0, 0, 0}) {
		return nil, errUDPUnrecognised
	}
	return &ProbeResult{
		Protocol: "QUIC",
		Metadata: map[string]interface{}{"transport": "udp", "discovery_method": "active"},
	}, nil
}

// -----------------------------------------------------------------------------
// mDNS (5353) — a unicast PTR query for _services._dns-sd._udp.local with the
// unicast-response (QU) bit set, so the reply comes back to us, not the
// multicast group.
// -----------------------------------------------------------------------------

func probeMDNS(conn net.Conn, timeout time.Duration) (*ProbeResult, error) {
	var id [2]byte
	_, _ = rand.Read(id[:])
	q := new(bytes.Buffer)
	q.Write(id[:])
	q.Write([]byte{0x00, 0x00}) // flags
	q.Write([]byte{0x00, 0x01}) // QDCOUNT
	q.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	for _, label := range []string{"_services", "_dns-sd", "_udp", "local"} {
		q.WriteByte(byte(len(label)))
		q.WriteString(label)
	}
	q.WriteByte(0x00)           // end of name
	q.Write([]byte{0x00, 0x0c}) // QTYPE = PTR
	q.Write([]byte{0x80, 0x01}) // QCLASS = IN with QU (unicast response) bit
	reply, err := udpExchange(conn, q.Bytes(), timeout, 4096)
	if err != nil {
		return nil, err
	}
	if len(reply) < 12 || reply[2]&0x80 == 0 { // QR set
		return nil, errUDPUnrecognised
	}
	return &ProbeResult{
		Protocol: "mDNS",
		Metadata: map[string]interface{}{"transport": "udp", "discovery_method": "active"},
	}, nil
}

// -----------------------------------------------------------------------------
// SSDP (1900) — a unicast M-SEARCH; a UPnP device answers with an HTTP/1.1 200.
// -----------------------------------------------------------------------------

func probeSSDP(conn net.Conn, timeout time.Duration) (*ProbeResult, error) {
	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n\r\n"
	reply, err := udpExchange(conn, []byte(msg), timeout, 4096)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(reply, []byte("HTTP/1.1")) && !bytes.HasPrefix(reply, []byte("HTTP/1.0")) {
		return nil, errUDPUnrecognised
	}
	return &ProbeResult{
		Protocol: "SSDP",
		Metadata: map[string]interface{}{"transport": "udp", "discovery_method": "active"},
	}, nil
}

// -----------------------------------------------------------------------------
// Wire helpers
// -----------------------------------------------------------------------------

// udpExchange writes msg to the connected socket and reads one reply within
// timeout. It returns the wire error unchanged so the caller can classify a
// timeout (no answer) apart from an ICMP port-unreachable (refused).
func udpExchange(conn net.Conn, msg []byte, timeout time.Duration, readLen int) ([]byte, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, readLen)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func uint24(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }

// --- minimal BER/DER encoding for the SNMPv3 discovery message ---

func berTLV(tag byte, val []byte) []byte {
	return append(append([]byte{tag}, berLen(len(val))...), val...)
}
func berSeq(val []byte) []byte   { return berTLV(0x30, val) }
func berOctet(val []byte) []byte { return berTLV(0x04, val) }
func berInt(n int) []byte {
	if n == 0 {
		return []byte{0x02, 0x01, 0x00}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	if b[0]&0x80 != 0 { // keep it positive
		b = append([]byte{0x00}, b...)
	}
	return berTLV(0x02, b)
}
func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

// berSkipSeqHeader returns the body of a BER SEQUENCE, skipping tag+length.
func berSkipSeqHeader(b []byte) ([]byte, bool) {
	if len(b) < 2 || b[0] != 0x30 {
		return nil, false
	}
	if b[1] < 0x80 {
		return b[2:], true
	}
	n := int(b[1] & 0x7f)
	if len(b) < 2+n {
		return nil, false
	}
	return b[2+n:], true
}
