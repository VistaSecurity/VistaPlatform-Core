// Package tlsparse implements TLS handshake parsing for the pcap-processor.
//
// It is deliberately pure Go — no gopacket, no libpcap/CGO — so the parsing
// logic that decides what a PCAP upload contributes to the crypto inventory can
// be unit-tested from synthetic handshake bytes without a capture toolchain.
//
// The behaviour mirrors the standalone sensor's passive capture path
// (sensor/internal/capture/tls_assembler.go): the negotiated protocol version
// comes from the ServerHello only — supported_versions (0x002b) when present,
// legacy server_version otherwise — cipher suites are reported by IANA name,
// and the Certificate message's DER bytes are parsed into the canonical
// "certificates" array via shared/certificates.
package tlsparse

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

// TLS record content types (RFC 5246 §6.2.1).
const (
	recordChangeCipherSpec byte = 0x14
	recordAlert            byte = 0x15
	recordHandshake        byte = 0x16
	recordApplicationData  byte = 0x17
)

// Handshake message types we care about.
const (
	handshakeClientHello byte = 0x01
	handshakeServerHello byte = 0x02
	handshakeCertificate byte = 0x0b
)

// Resource caps. A complete TLS handshake — including a full certificate chain
// — is a few kilobytes; 256 KiB per direction is generous while still bounding
// what a hostile or pathological capture can pin in memory. See
// docsv4/core/features/pcap-ingestion.md for the customer-facing statement of
// these limits.
const (
	// MaxFlowBytes caps the handshake bytes buffered per direction of a flow.
	MaxFlowBytes = 256 * 1024
	// MaxSessions caps the number of concurrently tracked TLS flows. Captures
	// with more unique TLS flows than this (scans, DDoS traces) have the
	// surplus dropped, counted in Tracker.Evicted.
	MaxSessions = 8192
	// maxHandshakeMessage rejects an implausible handshake length field before
	// it is used to size a wait-for-more-bytes decision.
	maxHandshakeMessage = 256 * 1024
	// maxHostnameLen is the DNS maximum; SNI longer than this is discarded.
	maxHostnameLen = 253
)

// VersionName maps a TLS wire version to a human-readable name. Unknown
// versions return "" so callers can distinguish "not a TLS version we know"
// from a real negotiated version.
//
// Format matches the sensor ("TLS 1.2", with a space) so PCAP-derived and
// sensor-derived inventory rows are indistinguishable downstream.
func VersionName(ver uint16) string {
	switch ver {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return ""
	}
}

// CipherName maps a cipher suite ID to its IANA name.
//
// crypto/tls.CipherSuiteName returns the IANA name for every suite the Go
// standard library knows and falls back to "0xXXXX" for the rest — exactly the
// behaviour wanted here: known suites resolve against the algorithms
// catalogue, unknown suites stay identifiable without pretending to be named.
// GREASE values (RFC 8701) return "" — they are deliberate nonsense and must
// never reach the inventory.
func CipherName(id uint16) string {
	if IsGREASE(id) {
		return ""
	}
	return tls.CipherSuiteName(id)
}

// IsGREASE reports whether a 16-bit code point is a GREASE value (RFC 8701):
// both bytes equal and of the form 0x?A.
func IsGREASE(v uint16) bool {
	hi := byte(v >> 8)
	lo := byte(v)
	return hi == lo && hi&0x0f == 0x0a
}

// SanitizeHostname bounds and screens an SNI value read from an untrusted
// capture before it is stored as a hostname. Returns "" when the value is not
// a plausible hostname.
func SanitizeHostname(s string) string {
	if s == "" || len(s) > maxHostnameLen {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '*':
		default:
			return ""
		}
	}
	// A bare dot-run or leading/trailing dot is not a usable hostname.
	if strings.Trim(s, ".") == "" {
		return ""
	}
	return s
}

// HandshakeMessage is one complete handshake message: its type byte and its
// body (the bytes after the 4-byte type+length header).
type HandshakeMessage struct {
	Type byte
	Body []byte
}

// record is one complete TLS record.
type record struct {
	contentType byte
	version     uint16
	fragment    []byte
}

// drainRecords pulls every complete TLS record out of buf. It returns the
// records, the unconsumed remainder, and ok=false when buf is not a TLS record
// stream (which means the flow has desynchronised and should be abandoned).
func drainRecords(buf []byte) (recs []record, rest []byte, ok bool) {
	for len(buf) >= 5 {
		ct := buf[0]
		switch ct {
		case recordChangeCipherSpec, recordAlert, recordHandshake, recordApplicationData:
		default:
			return recs, nil, false
		}
		if buf[1] != 0x03 {
			return recs, nil, false
		}
		ver := binary.BigEndian.Uint16(buf[1:3])
		length := int(binary.BigEndian.Uint16(buf[3:5]))
		if length > MaxFlowBytes {
			return recs, nil, false
		}
		if len(buf) < 5+length {
			break // incomplete record; wait for more bytes
		}
		recs = append(recs, record{contentType: ct, version: ver, fragment: buf[5 : 5+length]})
		buf = buf[5+length:]
	}
	return recs, buf, true
}

// drainHandshake pulls every complete handshake message out of the accumulated
// handshake bytes. ok=false means the length framing is implausible.
func drainHandshake(buf []byte) (msgs []HandshakeMessage, rest []byte, ok bool) {
	for len(buf) >= 4 {
		msgLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if msgLen > maxHandshakeMessage {
			return msgs, nil, false
		}
		if len(buf) < 4+msgLen {
			break // message spans further segments
		}
		msgs = append(msgs, HandshakeMessage{Type: buf[0], Body: buf[4 : 4+msgLen]})
		buf = buf[4+msgLen:]
	}
	return msgs, buf, true
}

// ClientHello holds what a ClientHello contributes.
//
// MaxOfferedVersion is the client's best OFFER, never the negotiated version.
// It is kept separate for exactly that reason: a TLS 1.3-capable client talking
// to a TLS 1.2-only server must not be inventoried as TLS 1.3.
type ClientHello struct {
	LegacyVersion     string
	MaxOfferedVersion string
	CipherSuites      []string
	SNI               string
}

// ParseClientHello parses a ClientHello body (handshake header already removed).
func ParseClientHello(body []byte) *ClientHello {
	// client_version(2) + random(32) = 34 minimum
	if len(body) < 34 {
		return nil
	}
	ch := &ClientHello{LegacyVersion: VersionName(binary.BigEndian.Uint16(body[0:2]))}

	offset := 34
	if offset >= len(body) {
		return ch
	}
	sidLen := int(body[offset])
	offset += 1 + sidLen

	if offset+2 > len(body) {
		return ch
	}
	csLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	csEnd := offset + csLen
	if csEnd > len(body) {
		return ch
	}
	for i := offset; i+2 <= csEnd; i += 2 {
		if name := CipherName(binary.BigEndian.Uint16(body[i : i+2])); name != "" {
			ch.CipherSuites = append(ch.CipherSuites, name)
		}
	}
	offset = csEnd

	if offset >= len(body) {
		return ch
	}
	compLen := int(body[offset])
	offset += 1 + compLen

	if offset+2 > len(body) {
		return ch
	}
	extTotal := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	extEnd := offset + extTotal
	if extEnd > len(body) {
		extEnd = len(body)
	}

	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > extEnd {
			break
		}
		extBody := body[offset : offset+extLen]
		switch extType {
		case 0x002b: // supported_versions
			if v := parseSupportedVersionsClient(extBody); v != "" {
				ch.MaxOfferedVersion = v
			}
		case 0x0000: // server_name
			if h := parseServerName(extBody); h != "" {
				ch.SNI = SanitizeHostname(h)
			}
		}
		offset += extLen
	}
	return ch
}

// ServerHello holds what a ServerHello contributes. Version is the NEGOTIATED
// version — supported_versions when the server sent it, legacy server_version
// otherwise.
type ServerHello struct {
	Version     string
	CipherSuite string
}

// ParseServerHello parses a ServerHello body (handshake header already removed).
func ParseServerHello(body []byte) *ServerHello {
	// server_version(2) + random(32) + sid_len(1) + cipher(2) + comp(1) = 38
	if len(body) < 38 {
		return nil
	}
	sh := &ServerHello{}

	// legacy_version IS the negotiated version for TLS <= 1.2 and SSL 3.0.
	// TLS 1.3 pins it to 0x0303 and carries the real version in
	// supported_versions, which overrides below.
	sh.Version = VersionName(binary.BigEndian.Uint16(body[0:2]))

	offset := 34
	sidLen := int(body[offset])
	offset += 1 + sidLen

	if offset+2 > len(body) {
		return sh
	}
	sh.CipherSuite = CipherName(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2

	// compression_method
	offset++

	if offset+2 > len(body) {
		return sh
	}
	extTotal := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	extEnd := offset + extTotal
	if extEnd > len(body) {
		extEnd = len(body)
	}

	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > extEnd {
			break
		}
		// In a ServerHello the supported_versions body is a single selected
		// 2-byte version, not a list.
		if extType == 0x002b && extLen == 2 {
			if v := VersionName(binary.BigEndian.Uint16(body[offset : offset+2])); v != "" {
				sh.Version = v
			}
		}
		offset += extLen
	}
	return sh
}

// parseSupportedVersionsClient parses the ClientHello form of the
// supported_versions extension: a 1-byte list length then 2-byte versions.
// Returns the highest version we recognise.
func parseSupportedVersionsClient(body []byte) string {
	if len(body) < 3 {
		return ""
	}
	listLen := int(body[0])
	if listLen == 0 || listLen%2 != 0 || 1+listLen > len(body) {
		return ""
	}
	var best uint16
	for i := 1; i+2 <= 1+listLen; i += 2 {
		ver := binary.BigEndian.Uint16(body[i : i+2])
		if VersionName(ver) != "" && ver > best {
			best = ver
		}
	}
	return VersionName(best)
}

// parseServerName returns the first host_name entry of an RFC 6066 server_name
// extension body.
func parseServerName(body []byte) string {
	if len(body) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(body[0:2]))
	if listLen < 3 || 2+listLen > len(body) {
		return ""
	}
	end := 2 + listLen
	p := 2
	for p+3 <= end {
		nameType := body[p]
		nameLen := int(binary.BigEndian.Uint16(body[p+1 : p+3]))
		p += 3
		if nameLen <= 0 || p+nameLen > end {
			break
		}
		if nameType == 0 {
			return string(body[p : p+nameLen])
		}
		p += nameLen
	}
	return ""
}

// ParseCertificateMessage parses a TLS <= 1.2 Certificate message body into the
// canonical CertificateInfo shape via shared/certificates. Entries that fail
// DER parsing are skipped; the chain order of the ones that parse is preserved.
//
// The TLS 1.3 Certificate message is sent encrypted, so it never appears in a
// passive capture and the 1.3 framing (certificate_request_context, per-entry
// extensions) is deliberately not handled.
func ParseCertificateMessage(body []byte) []certificates.CertificateInfo {
	if len(body) < 3 {
		return nil
	}
	listLen := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	offset := 3
	end := offset + listLen
	if end > len(body) {
		end = len(body)
	}

	var parsed []*x509.Certificate
	for offset+3 <= end {
		certLen := int(body[offset])<<16 | int(body[offset+1])<<8 | int(body[offset+2])
		offset += 3
		if certLen <= 0 || offset+certLen > end {
			break
		}
		if cert, err := x509.ParseCertificate(body[offset : offset+certLen]); err == nil {
			parsed = append(parsed, cert)
		}
		offset += certLen
	}
	if len(parsed) == 0 {
		return nil
	}
	return certificates.ExtractCertificatesFromX509(parsed)
}

// FlowKey identifies one direction of a TCP flow.
type FlowKey struct {
	SrcIP   string
	SrcPort int
	DstIP   string
	DstPort int
}

// sessionKey identifies a flow irrespective of direction.
type sessionKey struct {
	aIP   string
	aPort int
	bIP   string
	bPort int
}

func (f FlowKey) session() sessionKey {
	if f.SrcIP < f.DstIP || (f.SrcIP == f.DstIP && f.SrcPort <= f.DstPort) {
		return sessionKey{f.SrcIP, f.SrcPort, f.DstIP, f.DstPort}
	}
	return sessionKey{f.DstIP, f.DstPort, f.SrcIP, f.SrcPort}
}

// Session is the accumulated view of one TLS handshake, assembled across both
// directions and across TCP segments.
type Session struct {
	ServerIP   string
	ServerPort int
	ClientIP   string
	ClientPort int

	// NegotiatedVersion is populated from the ServerHello only. It is empty
	// when the capture never contained the server's side of the handshake —
	// empty means "not observed", never "assume the client's offer".
	NegotiatedVersion string
	CipherSuite       string

	ClientLegacyVersion string
	ClientMaxOffered    string
	OfferedCipherSuites []string
	SNI                 string

	RecordVersion  string
	Certificates   []certificates.CertificateInfo
	HandshakeTypes []string
	Truncated      bool

	FirstSeen time.Time
	LastSeen  time.Time

	seenType map[byte]bool
}

// HasContent reports whether the session observed enough of a handshake to be
// worth emitting.
func (s *Session) HasContent() bool {
	return s.seenType[handshakeClientHello] || s.seenType[handshakeServerHello] || len(s.Certificates) > 0
}

// flowBuffers holds the per-direction reassembly state.
type flowBuffers struct {
	recordBuf []byte
	hsBuf     []byte
}

type sessionState struct {
	session *Session
	dirs    map[FlowKey]*flowBuffers
	done    bool
}

// Tracker reassembles TLS handshakes from per-packet TCP payloads.
//
// It is not a full TCP reassembler: segments are appended in arrival order per
// direction, which is what a capture of a healthy handshake looks like. A flow
// whose record framing desynchronises (loss, reordering, retransmission
// overlap) is abandoned rather than mis-parsed.
type Tracker struct {
	sessions map[sessionKey]*sessionState

	maxSessions  int
	maxFlowBytes int

	onComplete func(*Session)

	// Evicted counts flows dropped because MaxSessions was already reached.
	Evicted int
	// Truncated counts flows abandoned because a direction exceeded
	// MaxFlowBytes.
	Truncated int
	// Desynced counts flows abandoned because their record framing stopped
	// making sense.
	Desynced int
}

// NewTracker creates a Tracker. onComplete is invoked once per session, when
// the handshake finishes, when the flow is abandoned, or from Flush.
func NewTracker(onComplete func(*Session)) *Tracker {
	return &Tracker{
		sessions:     make(map[sessionKey]*sessionState),
		maxSessions:  MaxSessions,
		maxFlowBytes: MaxFlowBytes,
		onComplete:   onComplete,
	}
}

// Feed supplies one TCP payload for one direction of a flow.
func (t *Tracker) Feed(key FlowKey, payload []byte, ts time.Time) {
	if len(payload) == 0 {
		return
	}
	sk := key.session()
	st, ok := t.sessions[sk]
	if !ok {
		// Only start tracking on something that looks like the beginning of a
		// TLS handshake record. Without this a scan-heavy capture would
		// allocate a buffer for every stray TCP payload.
		if !looksLikeHandshakeRecord(payload) {
			return
		}
		if len(t.sessions) >= t.maxSessions {
			t.Evicted++
			return
		}
		st = &sessionState{
			session: &Session{
				FirstSeen: ts,
				seenType:  make(map[byte]bool),
			},
			dirs: make(map[FlowKey]*flowBuffers, 2),
		}
		// The side that sends the first handshake record is presumed the
		// client; a ServerHello later confirms (or corrects) the roles.
		st.session.ClientIP = key.SrcIP
		st.session.ClientPort = key.SrcPort
		st.session.ServerIP = key.DstIP
		st.session.ServerPort = key.DstPort
		t.sessions[sk] = st
	}
	if st.done {
		return
	}
	if ts.After(st.session.LastSeen) {
		st.session.LastSeen = ts
	}

	buf, ok := st.dirs[key]
	if !ok {
		buf = &flowBuffers{}
		st.dirs[key] = buf
	}

	if len(buf.recordBuf)+len(payload) > t.maxFlowBytes {
		st.session.Truncated = true
		t.Truncated++
		t.finish(sk, st)
		return
	}
	buf.recordBuf = append(buf.recordBuf, payload...)

	recs, rest, ok := drainRecords(buf.recordBuf)
	if !ok {
		t.Desynced++
		t.finish(sk, st)
		return
	}
	buf.recordBuf = rest

	handshakeOver := false
	for _, rec := range recs {
		if st.session.RecordVersion == "" {
			st.session.RecordVersion = VersionName(rec.version)
		}
		if rec.contentType != recordHandshake {
			// ChangeCipherSpec / Alert / ApplicationData: nothing further in
			// this handshake is readable.
			handshakeOver = true
			continue
		}
		if len(buf.hsBuf)+len(rec.fragment) > t.maxFlowBytes {
			st.session.Truncated = true
			t.Truncated++
			t.finish(sk, st)
			return
		}
		buf.hsBuf = append(buf.hsBuf, rec.fragment...)
	}

	msgs, hsRest, ok := drainHandshake(buf.hsBuf)
	if !ok {
		t.Desynced++
		t.finish(sk, st)
		return
	}
	buf.hsBuf = hsRest

	for _, msg := range msgs {
		t.apply(st.session, key, msg)
	}

	if handshakeOver {
		t.finish(sk, st)
	}
}

// apply folds one handshake message into the session.
func (t *Tracker) apply(s *Session, key FlowKey, msg HandshakeMessage) {
	switch msg.Type {
	case handshakeClientHello:
		ch := ParseClientHello(msg.Body)
		if ch == nil {
			return
		}
		s.noteType(handshakeClientHello, "ClientHello")
		// The ClientHello's destination is the server.
		s.ClientIP, s.ClientPort = key.SrcIP, key.SrcPort
		s.ServerIP, s.ServerPort = key.DstIP, key.DstPort
		s.ClientLegacyVersion = ch.LegacyVersion
		s.ClientMaxOffered = ch.MaxOfferedVersion
		if len(ch.CipherSuites) > 0 {
			s.OfferedCipherSuites = ch.CipherSuites
		}
		if ch.SNI != "" {
			s.SNI = ch.SNI
		}
	case handshakeServerHello:
		sh := ParseServerHello(msg.Body)
		if sh == nil {
			return
		}
		s.noteType(handshakeServerHello, "ServerHello")
		// The ServerHello's source is definitively the server.
		s.ServerIP, s.ServerPort = key.SrcIP, key.SrcPort
		s.ClientIP, s.ClientPort = key.DstIP, key.DstPort
		if sh.Version != "" {
			s.NegotiatedVersion = sh.Version
		}
		if sh.CipherSuite != "" {
			s.CipherSuite = sh.CipherSuite
		}
	case handshakeCertificate:
		s.noteType(handshakeCertificate, "Certificate")
		// Certificates in a server flight come from the server.
		s.ServerIP, s.ServerPort = key.SrcIP, key.SrcPort
		s.ClientIP, s.ClientPort = key.DstIP, key.DstPort
		if certs := ParseCertificateMessage(msg.Body); len(certs) > 0 {
			s.Certificates = certs
		}
	}
}

func (s *Session) noteType(t byte, name string) {
	if s.seenType == nil {
		s.seenType = make(map[byte]bool)
	}
	if !s.seenType[t] {
		s.seenType[t] = true
		s.HandshakeTypes = append(s.HandshakeTypes, name)
	}
}

func (t *Tracker) finish(sk sessionKey, st *sessionState) {
	if st.done {
		return
	}
	st.done = true
	st.dirs = nil
	delete(t.sessions, sk)
	if st.session.HasContent() && t.onComplete != nil {
		t.onComplete(st.session)
	}
}

// Flush emits every session still in flight. Call once at end of capture.
func (t *Tracker) Flush() {
	for sk, st := range t.sessions {
		t.finish(sk, st)
	}
}

// looksLikeHandshakeRecord reports whether a payload starts with a plausible
// TLS handshake record header.
func looksLikeHandshakeRecord(payload []byte) bool {
	return len(payload) >= 5 && payload[0] == recordHandshake && payload[1] == 0x03 && payload[2] <= 0x04
}

// LimitsDescription renders the configured caps for logging.
func (t *Tracker) LimitsDescription() string {
	return fmt.Sprintf("max_flows=%d max_bytes_per_direction=%d", t.maxSessions, t.maxFlowBytes)
}
