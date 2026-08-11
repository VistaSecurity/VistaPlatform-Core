package capture

import (
	"testing"
	"time"

	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/vistasecurity/vistaplatform/sensor/internal/cache"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// =============================================================================
// MAC algorithm lookup
// =============================================================================

func TestDNP3MACAlgorithm(t *testing.T) {
	t.Parallel()
	cases := []struct {
		id         uint8
		wantName   string
		wantVer    string
		wantStrong string
		wantOk     bool
	}{
		{1, "HMAC-SHA-1-4", "SAv2", "weak", true},
		{2, "HMAC-SHA-256-8", "SAv5", "present", true},
		{3, "HMAC-SHA-256-16", "SAv5", "present", true},
		{4, "HMAC-SHA-1-10", "SAv2", "weak", true},
		{5, "AES-128-GMAC-12", "SAv5", "present", true},
		{6, "HMAC-SHA-256-10", "SAv5", "present", true},
		{0, "", "", "", false},
		{99, "", "", "", false},
	}
	for _, c := range cases {
		got, ok := dnp3MACAlgorithm(c.id)
		if ok != c.wantOk {
			t.Errorf("dnp3MACAlgorithm(%d) ok=%v, want %v", c.id, ok, c.wantOk)
			continue
		}
		if !ok {
			continue
		}
		if got.Name != c.wantName {
			t.Errorf("dnp3MACAlgorithm(%d).Name=%q, want %q", c.id, got.Name, c.wantName)
		}
		if got.Version != c.wantVer {
			t.Errorf("dnp3MACAlgorithm(%d).Version=%q, want %q", c.id, got.Version, c.wantVer)
		}
		if got.Strength != c.wantStrong {
			t.Errorf("dnp3MACAlgorithm(%d).Strength=%q, want %q", c.id, got.Strength, c.wantStrong)
		}
	}
}

// =============================================================================
// Frame builders
// =============================================================================

// buildDNP3Frame constructs a minimal DNP3 frame with the given application
// payload. Uses dummy CRCs (zero bytes) since the parser doesn't validate.
func buildDNP3Frame(dst, src uint16, app []byte) []byte {
	// userBytes = source(2) + dest(2) + app payload
	// linkLen = userBytes - 5? No — per IEEE 1815, length covers from
	// length field through end of source-address field, then DATA blocks
	// follow. For our parser the convention used in handleFrame is:
	//   userBytes = linkLen - 5
	// so we set linkLen = 5 + len(app).
	linkLen := 5 + len(app)
	if linkLen > 255 {
		linkLen = 255
	}
	header := []byte{
		dnp3SyncByte0, dnp3SyncByte1,
		byte(linkLen),
		0xC4,                      // control (PRM=1, FCB=1, FCV=0, function=4=user data)
		byte(dst), byte(dst >> 8), // dst LE
		byte(src), byte(src >> 8), // src LE
		0x00, 0x00, // CRC placeholder
	}
	// Append application data in 16-byte blocks each followed by 2-byte CRC.
	out := append([]byte{}, header...)
	for off := 0; off < len(app); off += 16 {
		end := off + 16
		if end > len(app) {
			end = len(app)
		}
		out = append(out, app[off:end]...)
		out = append(out, 0x00, 0x00) // CRC placeholder
	}
	return out
}

// =============================================================================
// Test fixtures
// =============================================================================

func newTestDNP3Factory(t *testing.T) (*DNP3StreamFactory, chan *models.CryptoDiscovery) {
	t.Helper()
	ch := make(chan *models.CryptoDiscovery, 4)
	connCache := cache.NewConnectionCache(60*time.Minute, 1000)
	return NewDNP3StreamFactory(ch, "test-sensor", connCache), ch
}

func preDNP3Stream(f *DNP3StreamFactory) (*DNP3Stream, *dnp3SessionState) {
	state := &dnp3SessionState{
		sessionID:  "s1",
		serverIP:   "10.0.0.5",
		serverPort: 20000,
		clientIP:   "10.0.0.10",
		iface:      "eth0",
	}
	f.mu.Lock()
	f.sessions[tlsFlowKey{}] = state
	f.mu.Unlock()
	return &DNP3Stream{factory: f, key: tlsFlowKey{}, state: state}, state
}

func feedDNP3(s tcpassembly.Stream, data []byte) {
	s.Reassembled([]tcpassembly.Reassembly{{Bytes: data, Seen: time.Now()}})
}

// =============================================================================
// End-to-end tests
// =============================================================================

func TestDNP3Assembler_PlaintextFrameEmitsNoSecurity(t *testing.T) {
	t.Parallel()
	factory, ch := newTestDNP3Factory(t)
	stream, _ := preDNP3Stream(factory)

	// Plaintext app payload: transport(1) + appCtrl(1) + funcCode(1=Read=0x01)
	// + objects (no Group 120 markers).
	app := []byte{0xC0, 0xC1, 0x01, 0x32, 0x01, 0x00, 0x00, 0x01}
	frame := buildDNP3Frame(0x0001, 0x0002, app)
	feedDNP3(stream, frame)

	select {
	case d := <-ch:
		if d.Protocol != "DNP3" {
			t.Errorf("Protocol=%s, want DNP3", d.Protocol)
		}
		if d.Version != "DNP3-Plaintext" {
			t.Errorf("Version=%s, want DNP3-Plaintext", d.Version)
		}
		if d.RawMetadata["security"] != "none" {
			t.Errorf("security=%v, want none", d.RawMetadata["security"])
		}
		if d.RawMetadata["sa_active"] != false {
			t.Errorf("sa_active=%v, want false", d.RawMetadata["sa_active"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected DNP3 plaintext discovery within 1s")
	}
}

func TestDNP3Assembler_SAv5StrongMACDetected(t *testing.T) {
	t.Parallel()
	factory, ch := newTestDNP3Factory(t)
	stream, _ := preDNP3Stream(factory)

	// App payload includes a Group 120 Variation 1 (Challenge) object with
	// MAC algorithm ID = 3 (HMAC-SHA-256-16, SAv5 strong).
	// Layout after the function-code byte: anything, then the SA marker
	// 0x78 0x01, qualifier 0x07, then ChallengeData(4) UserNumber(2)
	// MACAlgorithm(1=3).
	app := []byte{
		0xC0, 0xC1, 0x83, // transport, appCtrl, funcCode (0x83 = Auth Response)
		dnp3SAGroup, dnp3SAVarChallenge, 0x07, // SA Challenge object header
		0x00, 0x00, 0x00, 0x01, // ChallengeData
		0x00, 0x01, // UserNumber
		0x03, // MAC algorithm ID = HMAC-SHA-256-16
	}
	frame := buildDNP3Frame(0x0001, 0x0002, app)
	feedDNP3(stream, frame)

	select {
	case d := <-ch:
		if d.Version != "SAv5" {
			t.Errorf("Version=%s, want SAv5", d.Version)
		}
		if d.RawMetadata["sa_active"] != true {
			t.Errorf("sa_active=%v, want true", d.RawMetadata["sa_active"])
		}
		if d.RawMetadata["mac_algorithm_id"] != 3 {
			t.Errorf("mac_algorithm_id=%v, want 3", d.RawMetadata["mac_algorithm_id"])
		}
		if d.RawMetadata["mac_algorithm_name"] != "HMAC-SHA-256-16" {
			t.Errorf("mac_algorithm_name=%v", d.RawMetadata["mac_algorithm_name"])
		}
		if d.RawMetadata["security"] != "present" {
			t.Errorf("security=%v, want present", d.RawMetadata["security"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected SAv5 discovery")
	}
}

func TestDNP3Assembler_SAv2WeakMACDetected(t *testing.T) {
	t.Parallel()
	factory, ch := newTestDNP3Factory(t)
	stream, _ := preDNP3Stream(factory)

	// SA Challenge with MAC algorithm ID = 1 (HMAC-SHA-1-4, SAv2 weak).
	app := []byte{
		0xC0, 0xC1, 0x83,
		dnp3SAGroup, dnp3SAVarChallenge, 0x07,
		0x00, 0x00, 0x00, 0x02, // ChallengeData
		0x00, 0x01, // UserNumber
		0x01, // MAC algorithm ID = HMAC-SHA-1-4
	}
	frame := buildDNP3Frame(0x0001, 0x0002, app)
	feedDNP3(stream, frame)

	select {
	case d := <-ch:
		if d.Version != "SAv2" {
			t.Errorf("Version=%s, want SAv2", d.Version)
		}
		if d.RawMetadata["security"] != "weak" {
			t.Errorf("security=%v, want weak", d.RawMetadata["security"])
		}
		if d.RawMetadata["mac_algorithm_name"] != "HMAC-SHA-1-4" {
			t.Errorf("mac_algorithm_name=%v", d.RawMetadata["mac_algorithm_name"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected SAv2 discovery")
	}
}

func TestDNP3Assembler_NonDNP3BytesDropBuffer(t *testing.T) {
	t.Parallel()
	factory, ch := newTestDNP3Factory(t)
	stream, _ := preDNP3Stream(factory)

	// 100 bytes of garbage with no sync marker — should be dropped.
	garbage := make([]byte, 100)
	for i := range garbage {
		garbage[i] = 0xAA
	}
	feedDNP3(stream, garbage)

	select {
	case d := <-ch:
		t.Errorf("expected no discovery on garbage bytes, got %+v", d)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestDNP3Assembler_PartialFrameBuffersUntilComplete(t *testing.T) {
	t.Parallel()
	factory, ch := newTestDNP3Factory(t)
	stream, _ := preDNP3Stream(factory)

	app := []byte{0xC0, 0xC1, 0x01, 0x32, 0x01}
	frame := buildDNP3Frame(0x0001, 0x0002, app)
	feedDNP3(stream, frame[:6])
	select {
	case <-ch:
		t.Fatal("did not expect discovery before full frame")
	case <-time.After(20 * time.Millisecond):
	}
	feedDNP3(stream, frame[6:])
	select {
	case d := <-ch:
		if d.Protocol != "DNP3" {
			t.Errorf("Protocol=%s, want DNP3", d.Protocol)
		}
	case <-time.After(time.Second):
		t.Fatal("expected DNP3 discovery once frame completed")
	}
}

func TestDNP3Assembler_LinkAddresses(t *testing.T) {
	t.Parallel()
	frame := buildDNP3Frame(0x1234, 0xABCD, []byte{0xC0, 0xC1, 0x01})
	dst, src, ok := dnp3LinkAddresses(frame)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if dst != 0x1234 || src != 0xABCD {
		t.Errorf("dst=0x%04X src=0x%04X, want 0x1234 / 0xABCD", dst, src)
	}
}

// =============================================================================
// UDP DNP3 (parseDNP3Packet)
// =============================================================================

func TestDNP3UDP_PlaintextFrame(t *testing.T) {
	t.Parallel()
	app := []byte{0xC0, 0xC1, 0x01, 0x32, 0x01, 0x00, 0x00, 0x01}
	frame := buildDNP3Frame(0x0001, 0x0002, app)

	got := parseDNP3Packet(frame, "10.0.0.10", "10.0.0.5", 49152, 20000, "sensor", "eth0", nil)
	if got == nil {
		t.Fatal("expected discovery, got nil")
	}
	if got.Protocol != "DNP3" {
		t.Errorf("Protocol=%s, want DNP3", got.Protocol)
	}
	if got.Version != "DNP3-Plaintext" {
		t.Errorf("Version=%s, want DNP3-Plaintext", got.Version)
	}
	if got.RawMetadata["security"] != "none" {
		t.Errorf("security=%v, want none", got.RawMetadata["security"])
	}
	if got.RawMetadata["transport"] != "udp" {
		t.Errorf("transport=%v, want udp", got.RawMetadata["transport"])
	}
	if got.DestIP != "10.0.0.5" || got.Port != 20000 {
		t.Errorf("server pinning wrong: dest=%s port=%d", got.DestIP, got.Port)
	}
}

func TestDNP3UDP_SAv5StrongMAC(t *testing.T) {
	t.Parallel()
	app := []byte{
		0xC0, 0xC1, 0x83,
		dnp3SAGroup, dnp3SAVarChallenge, 0x07,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x01,
		0x03, // HMAC-SHA-256-16
	}
	frame := buildDNP3Frame(0x0001, 0x0002, app)

	got := parseDNP3Packet(frame, "10.0.0.10", "10.0.0.5", 49152, 20000, "sensor", "eth0", nil)
	if got == nil {
		t.Fatal("expected discovery")
	}
	if got.Version != "SAv5" {
		t.Errorf("Version=%s, want SAv5", got.Version)
	}
	if got.RawMetadata["sa_active"] != true {
		t.Errorf("sa_active=%v, want true", got.RawMetadata["sa_active"])
	}
	if got.RawMetadata["mac_algorithm_id"] != 3 {
		t.Errorf("mac_algorithm_id=%v, want 3", got.RawMetadata["mac_algorithm_id"])
	}
	if got.RawMetadata["security"] != "present" {
		t.Errorf("security=%v, want present", got.RawMetadata["security"])
	}
}

func TestDNP3UDP_SAv2WeakMAC(t *testing.T) {
	t.Parallel()
	app := []byte{
		0xC0, 0xC1, 0x83,
		dnp3SAGroup, dnp3SAVarChallenge, 0x07,
		0x00, 0x00, 0x00, 0x02,
		0x00, 0x01,
		0x01, // HMAC-SHA-1-4
	}
	frame := buildDNP3Frame(0x0001, 0x0002, app)

	got := parseDNP3Packet(frame, "10.0.0.10", "10.0.0.5", 49152, 20000, "sensor", "eth0", nil)
	if got == nil {
		t.Fatal("expected discovery")
	}
	if got.Version != "SAv2" {
		t.Errorf("Version=%s, want SAv2", got.Version)
	}
	if got.RawMetadata["security"] != "weak" {
		t.Errorf("security=%v, want weak", got.RawMetadata["security"])
	}
}

func TestDNP3UDP_NonDNP3PayloadReturnsNil(t *testing.T) {
	t.Parallel()
	if got := parseDNP3Packet([]byte("GET / HTTP/1.1\r\n\r\n"), "10.0.0.10", "10.0.0.5", 49152, 20000, "sensor", "eth0", nil); got != nil {
		t.Errorf("expected nil for non-DNP3 bytes, got %+v", got)
	}
	if got := parseDNP3Packet(nil, "10.0.0.10", "10.0.0.5", 49152, 20000, "sensor", "eth0", nil); got != nil {
		t.Errorf("expected nil for nil payload, got %+v", got)
	}
	if got := parseDNP3Packet([]byte{0x01, 0x02}, "10.0.0.10", "10.0.0.5", 49152, 20000, "sensor", "eth0", nil); got != nil {
		t.Errorf("expected nil for short payload, got %+v", got)
	}
}

func TestDNP3UDP_DedupRejectsRepeats(t *testing.T) {
	t.Parallel()
	connCache := cache.NewConnectionCache(60*time.Minute, 1000)
	app := []byte{0xC0, 0xC1, 0x01}
	frame := buildDNP3Frame(0x0001, 0x0002, app)

	first := parseDNP3Packet(frame, "10.0.0.10", "10.0.0.5", 49152, 20000, "sensor", "eth0", connCache)
	if first == nil {
		t.Fatal("first datagram should emit a discovery")
	}
	second := parseDNP3Packet(frame, "10.0.0.10", "10.0.0.5", 49152, 20000, "sensor", "eth0", connCache)
	if second != nil {
		t.Errorf("second datagram should dedup to nil, got %+v", second)
	}
}

func TestDNP3UDP_ServerSidePinningWhenSrcPortIs20000(t *testing.T) {
	t.Parallel()
	// Response from outstation: src port is 20000, dest is ephemeral.
	app := []byte{0xC0, 0xC1, 0x01}
	frame := buildDNP3Frame(0x0001, 0x0002, app)

	got := parseDNP3Packet(frame, "10.0.0.5", "10.0.0.10", 20000, 49152, "sensor", "eth0", nil)
	if got == nil {
		t.Fatal("expected discovery")
	}
	if got.DestIP != "10.0.0.5" || got.Port != 20000 {
		t.Errorf("server pinning wrong: dest=%s port=%d, want 10.0.0.5/20000", got.DestIP, got.Port)
	}
	if got.SourceIP != "10.0.0.10" {
		t.Errorf("client IP wrong: src=%s, want 10.0.0.10", got.SourceIP)
	}
}

func TestDNP3UDP_SAv6CertStatusResponse(t *testing.T) {
	t.Parallel()
	// SAv6 Cert Status Response (variation 10) — asymmetric PKI key mgmt.
	app := []byte{
		0xC0, 0xC1, 0x83,
		dnp3SAGroup, dnp3SAVarCertStatusResp, 0x07,
		0x00, 0x01, // user number
		0x00, 0x00, 0x00, 0x01, // sequence
		0x00, // cert status type
	}
	frame := buildDNP3Frame(0x0001, 0x0002, app)

	got := parseDNP3Packet(frame, "10.0.0.10", "10.0.0.5", 49152, 20000, "sensor", "eth0", nil)
	if got == nil {
		t.Fatal("expected discovery")
	}
	if got.Version != "SAv6" {
		t.Errorf("Version=%s, want SAv6", got.Version)
	}
	if got.RawMetadata["sa_version"] != "SAv6" {
		t.Errorf("sa_version=%v, want SAv6", got.RawMetadata["sa_version"])
	}
	if got.RawMetadata["security"] != "present" {
		t.Errorf("security=%v, want present", got.RawMetadata["security"])
	}
	if got.RawMetadata["mac_algorithm_name"] != "asymmetric-PKI" {
		t.Errorf("mac_algorithm_name=%v, want asymmetric-PKI", got.RawMetadata["mac_algorithm_name"])
	}
}

func TestDNP3UDP_SAv6PubKeyUpdate(t *testing.T) {
	t.Parallel()
	// SAv6 Public Key Update Request (variation 7).
	app := []byte{
		0xC0, 0xC1, 0x83,
		dnp3SAGroup, dnp3SAVarPubKeyUpdateReq, 0x07,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
	}
	frame := buildDNP3Frame(0x0001, 0x0002, app)

	got := parseDNP3Packet(frame, "10.0.0.10", "10.0.0.5", 49152, 20000, "sensor", "eth0", nil)
	if got == nil {
		t.Fatal("expected discovery")
	}
	if got.Version != "SAv6" {
		t.Errorf("Version=%s, want SAv6", got.Version)
	}
}

func TestDNP3ClassifyFrame_SAv6BeatsSAv5InWalk(t *testing.T) {
	t.Parallel()
	// First frame is SAv5 Challenge, second is SAv6 Cert Status — SAv6 wins.
	sav5 := []byte{
		0xC0, 0xC1, 0x83,
		dnp3SAGroup, dnp3SAVarChallenge, 0x07,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x01,
		0x03,
	}
	sav6 := []byte{
		0xC0, 0xC1, 0x83,
		dnp3SAGroup, dnp3SAVarCertStatusResp, 0x07,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
	}
	combined := append(buildDNP3Frame(0x0001, 0x0002, sav5), buildDNP3Frame(0x0001, 0x0002, sav6)...)

	c := dnp3WalkFrames(combined)
	if c.kind != dnp3ClassSAv6 {
		t.Errorf("kind=%v, want dnp3ClassSAv6", c.kind)
	}
	if c.info.Version != "SAv6" {
		t.Errorf("Version=%s, want SAv6", c.info.Version)
	}
}

func TestDNP3UDP_MultipleFramesInDatagramPrefersSA(t *testing.T) {
	t.Parallel()
	// First frame is plaintext, second carries an SA Challenge — SA should win.
	plain := []byte{0xC0, 0xC1, 0x01, 0x32, 0x01}
	sa := []byte{
		0xC0, 0xC1, 0x83,
		dnp3SAGroup, dnp3SAVarChallenge, 0x07,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x01,
		0x03,
	}
	combined := append(buildDNP3Frame(0x0001, 0x0002, plain), buildDNP3Frame(0x0001, 0x0002, sa)...)

	got := parseDNP3Packet(combined, "10.0.0.10", "10.0.0.5", 49152, 20000, "sensor", "eth0", nil)
	if got == nil {
		t.Fatal("expected discovery")
	}
	if got.Version != "SAv5" {
		t.Errorf("Version=%s, want SAv5 (SA must beat plaintext in the same datagram)", got.Version)
	}
}

// =============================================================================
// dnp3WalkFrames / dnp3ClassifyFrame — direct coverage
// =============================================================================

func TestDNP3ClassifyFrame_PlaintextAndSA(t *testing.T) {
	t.Parallel()
	plain := []byte{0xC0, 0xC1, 0x01, 0x32, 0x01}
	frame := buildDNP3Frame(0x0001, 0x0002, plain)
	if c := dnp3ClassifyFrame(frame, len(plain)+4); c.kind != dnp3ClassPlaintext {
		t.Errorf("plaintext frame classified as %v, want plaintext", c.kind)
	}

	sa := []byte{
		0xC0, 0xC1, 0x83,
		dnp3SAGroup, dnp3SAVarChallenge, 0x07,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x01,
		0x05, // AES-128-GMAC-12
	}
	frame2 := buildDNP3Frame(0x0001, 0x0002, sa)
	c2 := dnp3ClassifyFrame(frame2, len(sa)+4)
	if c2.kind != dnp3ClassSA {
		t.Fatalf("SA frame classified as %v, want SA", c2.kind)
	}
	if c2.macID != 5 || c2.info.Name != "AES-128-GMAC-12" {
		t.Errorf("classification wrong: macID=%d name=%s", c2.macID, c2.info.Name)
	}
}

func TestDNP3WalkFrames_EmptyOrJunkReturnsNone(t *testing.T) {
	t.Parallel()
	if c := dnp3WalkFrames(nil); c.kind != dnp3ClassNone {
		t.Errorf("nil buffer classified as %v, want none", c.kind)
	}
	garbage := make([]byte, 100)
	for i := range garbage {
		garbage[i] = 0xAA
	}
	if c := dnp3WalkFrames(garbage); c.kind != dnp3ClassNone {
		t.Errorf("garbage classified as %v, want none", c.kind)
	}
}

func TestDNP3Assembler_FlushOldSessions(t *testing.T) {
	t.Parallel()
	factory, _ := newTestDNP3Factory(t)
	old := &dnp3SessionState{lastSeen: time.Now().Add(-2 * time.Hour)}
	factory.mu.Lock()
	factory.sessions[tlsFlowKey{}] = old
	factory.mu.Unlock()
	factory.FlushOldSessions(time.Hour)
	factory.mu.Lock()
	if _, exists := factory.sessions[tlsFlowKey{}]; exists {
		t.Errorf("expected old session to be flushed")
	}
	factory.mu.Unlock()
}
