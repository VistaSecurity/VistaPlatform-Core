package discovery

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"

	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSSHServer is an in-process SSH server that speaks exactly as far as the
// probe reads: the identification string and one SSH_MSG_KEXINIT. It never
// performs a key exchange, which is the point — the probe must collect a
// server's whole algorithm posture without one.
type fakeSSHServer struct {
	preamble []string // lines sent before the identification string
	banner   string
	kex      []string
	hostKey  []string
	encC2S   []string
	encS2C   []string
	macC2S   []string
	macS2C   []string
	compC2S  []string
	compS2C  []string

	// omitKexInit makes the server send SSH_MSG_IGNORE forever instead of a
	// KEXINIT, to exercise the packet bound.
	omitKexInit bool
	// ignoresFirst makes the server send one SSH_MSG_IGNORE before its
	// KEXINIT, which a real server is permitted to do.
	ignoresFirst bool
}

// start listens on a loopback port and serves one connection. RFC 5737 is for
// documentation addresses; a test needs a real listener, so it binds 127.0.0.1
// with an ephemeral port.
func (f *fakeSSHServer) start(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// Serve in a loop: probeSSH opens two connections (the KEXINIT pass and
	// the x/crypto host-key handshake), so a single Accept would leave the
	// second hanging until the probe deadline.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()

	return ln.Addr().String()
}

func (f *fakeSSHServer) serve(conn net.Conn) {
	{
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		for _, line := range f.preamble {
			_, _ = conn.Write([]byte(line + "\r\n"))
		}
		_, _ = conn.Write([]byte(f.banner + "\r\n"))

		if f.ignoresFirst || f.omitKexInit {
			ignore := append([]byte{2}, []byte("padding-noise")...) // SSH_MSG_IGNORE
			n := 1
			if f.omitKexInit {
				n = sshMaxTransportPackets + 2
			}
			for i := 0; i < n; i++ {
				if _, err := conn.Write(sshWrapPacket(ignore)); err != nil {
					return
				}
			}
		}
		if !f.omitKexInit {
			_, _ = conn.Write(sshWrapPacket(f.kexInitPayload()))
		}

		// Drain whatever the client sends so its writes never block.
		_, _ = io.Copy(io.Discard, conn)
	}
}

func (f *fakeSSHServer) kexInitPayload() []byte {
	var buf bytes.Buffer
	buf.WriteByte(sshMsgKexInit)
	buf.Write(make([]byte, 16)) // cookie
	for _, l := range [][]string{
		f.kex, f.hostKey, f.encC2S, f.encS2C,
		f.macC2S, f.macS2C, f.compC2S, f.compS2C, nil, nil,
	} {
		sshWriteString(&buf, strings.Join(l, ","))
	}
	buf.WriteByte(0)
	buf.Write([]byte{0, 0, 0, 0})
	return buf.Bytes()
}

// modernServer is an OpenSSH-shaped offer whose lists are deliberately ordered
// WEAKEST FIRST. A server's own ordering is its preference, and the probe must
// ignore it: RFC 4253 §7.1 gives the choice to the CLIENT's ordering. A server
// list ordered strongest-first would let a probe that simply took the server's
// first entry pass these assertions by accident.
func modernServer() *fakeSSHServer {
	return &fakeSSHServer{
		banner:  "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
		kex:     []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha256", "curve25519-sha256"},
		hostKey: []string{"ssh-rsa", "rsa-sha2-512"},
		encC2S:  []string{"aes128-cbc", "aes256-ctr"},
		encS2C:  []string{"3des-cbc", "aes128-ctr"},
		macC2S:  []string{"hmac-md5", "hmac-sha2-256"},
		macS2C:  []string{"hmac-sha1", "hmac-sha2-512"},
		compC2S: []string{"none"},
		compS2C: []string{"none"},
	}
}

func captureFrom(t *testing.T, srv *fakeSSHServer) *sshKexInitCapture {
	t.Helper()
	addr := srv.start(t)
	capture, err := sshprobeKexInit(NewProber(5*time.Second), addr)
	if err != nil {
		t.Fatalf("sshprobeKexInit: %v", err)
	}
	return capture
}

func TestSSHKexInitCapturesBannerAndOfferedLists(t *testing.T) {
	capture := captureFrom(t, modernServer())

	if got, want := capture.Banner, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"; got != want {
		t.Errorf("Banner = %q, want %q", got, want)
	}
	if got, want := capture.ProtocolVersion, "SSH-2.0"; got != want {
		t.Errorf("ProtocolVersion = %q, want %q", got, want)
	}
	// The comments field ("Ubuntu-3ubuntu13.5") is not part of the software
	// identity and must not be folded into it.
	if got, want := capture.SoftwareVersion, "OpenSSH_9.6p1"; got != want {
		t.Errorf("SoftwareVersion = %q, want %q", got, want)
	}

	lists := []struct {
		name string
		got  []string
		want []string
	}{
		{"ServerKex", capture.ServerKex, []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha256", "curve25519-sha256"}},
		{"ServerHostKey", capture.ServerHostKey, []string{"ssh-rsa", "rsa-sha2-512"}},
		{"ServerEncryptionC2S", capture.ServerEncryptionC2S, []string{"aes128-cbc", "aes256-ctr"}},
		{"ServerEncryptionS2C", capture.ServerEncryptionS2C, []string{"3des-cbc", "aes128-ctr"}},
		{"ServerMACC2S", capture.ServerMACC2S, []string{"hmac-md5", "hmac-sha2-256"}},
		{"ServerMACS2C", capture.ServerMACS2C, []string{"hmac-sha1", "hmac-sha2-512"}},
		{"ServerCompressionC2S", capture.ServerCompressionC2S, []string{"none"}},
		{"ServerCompressionS2C", capture.ServerCompressionS2C, []string{"none"}},
	}
	for _, l := range lists {
		if strings.Join(l.got, ",") != strings.Join(l.want, ",") {
			t.Errorf("%s = %v, want %v (server order must be preserved verbatim)", l.name, l.got, l.want)
		}
	}
}

// TestSSHKexInitNegotiatesFirstClientMatch pins RFC 4253 §7.1 — the negotiated
// algorithm is the first entry of the CLIENT's list that the server also
// offers — and proves the fixture can tell that policy apart from the obvious
// wrong one.
//
// Every role below is checked twice: once against the first-client-match
// answer, and once against the LAST common algorithm, which must differ. That
// second assertion is the mutation check. Changing negotiate() to select the
// last common entry (or to take the server's preference instead of ours) makes
// the first assertion fail on all five roles; if a future edit to the fixture
// made the two answers coincide, the "want != lastCommon" guard fails instead
// and says the test has stopped measuring anything.
func TestSSHKexInitNegotiatesFirstClientMatch(t *testing.T) {
	srv := modernServer()
	capture := captureFrom(t, srv)

	cases := []struct {
		role       string
		clientList []string
		serverList []string
		got        string
		want       string
	}{
		{"kex", sshProbeOffer.Kex, srv.kex, capture.Kex, "curve25519-sha256"},
		{"host key", sshProbeOffer.HostKey, srv.hostKey, capture.HostKey, "rsa-sha2-512"},
		{"cipher c2s", sshProbeOffer.Encryption, srv.encC2S, capture.EncryptionC2S, "aes256-ctr"},
		{"cipher s2c", sshProbeOffer.Encryption, srv.encS2C, capture.EncryptionS2C, "aes128-ctr"},
		{"mac c2s", sshProbeOffer.MAC, srv.macC2S, capture.MACC2S, "hmac-sha2-256"},
		{"mac s2c", sshProbeOffer.MAC, srv.macS2C, capture.MACS2C, "hmac-sha2-512"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("negotiated %s = %q, want %q", c.role, c.got, c.want)
		}
		if last := lastCommon(c.clientList, c.serverList); last == c.want {
			t.Errorf("fixture for %s cannot distinguish first-match from last-match "+
				"(both are %q) — the mutation check is inert", c.role, last)
		}
	}

	if got, want := capture.CompressionC2S, "none"; got != want {
		t.Errorf("negotiated compression = %q, want %q", got, want)
	}
}

// lastCommon is the wrong-policy twin of cryptoparse.NegotiateSSHAlgorithm:
// the LAST client entry the server also offers. It exists only so the test
// above can assert that its fixture separates the two policies.
func lastCommon(clientList, serverList []string) string {
	var out string
	for _, c := range clientList {
		for _, s := range serverList {
			if strings.EqualFold(c, s) {
				out = c
			}
		}
	}
	return out
}

// TestSSHKexInitCapturesLegacyOnlyServer is the case the whole KEXINIT pass
// exists for. A server offering nothing but SHA-1 key exchange, CBC/3DES
// ciphers and hmac-md5 is what an SSH audit most needs to report, and it is
// exactly the server golang.org/x/crypto/ssh refuses to handshake with — the
// old probe fell back to reading a banner and recorded no algorithms at all.
// Reading KEXINIT needs no algorithm in common, so the weak server is
// inventoried in full.
func TestSSHKexInitCapturesLegacyOnlyServer(t *testing.T) {
	srv := &fakeSSHServer{
		banner:  "SSH-2.0-OpenSSH_5.3",
		kex:     []string{"diffie-hellman-group1-sha1"},
		hostKey: []string{"ssh-rsa", "ssh-dss"},
		encC2S:  []string{"3des-cbc", "aes128-cbc"},
		encS2C:  []string{"3des-cbc"},
		macC2S:  []string{"hmac-md5", "hmac-sha1"},
		macS2C:  []string{"hmac-md5"},
		compC2S: []string{"none"},
		compS2C: []string{"none"},
	}
	capture := captureFrom(t, srv)

	if got, want := capture.Kex, "diffie-hellman-group1-sha1"; got != want {
		t.Errorf("negotiated kex = %q, want %q", got, want)
	}
	if got, want := capture.HostKey, "ssh-rsa"; got != want {
		t.Errorf("negotiated host key = %q, want %q", got, want)
	}
	if got, want := capture.EncryptionC2S, "aes128-cbc"; got != want {
		t.Errorf("negotiated cipher = %q, want %q", got, want)
	}
	if got, want := capture.MACC2S, "hmac-sha1"; got != want {
		t.Errorf("negotiated MAC = %q, want %q", got, want)
	}
	if got, want := capture.SoftwareVersion, "OpenSSH_5.3"; got != want {
		t.Errorf("SoftwareVersion = %q, want %q", got, want)
	}
	// The weak offers the probe did NOT select must still be recorded: a
	// server that offers 3des-cbc will use it the moment a client asks.
	if strings.Join(capture.ServerEncryptionC2S, ",") != "3des-cbc,aes128-cbc" {
		t.Errorf("offered ciphers = %v, want both entries verbatim", capture.ServerEncryptionC2S)
	}
	if strings.Join(capture.ServerHostKey, ",") != "ssh-rsa,ssh-dss" {
		t.Errorf("offered host keys = %v, want both entries verbatim", capture.ServerHostKey)
	}
}

// TestSSHKexInitSkipsPreambleAndIgnoreMessages covers the two things a real
// server legitimately sends that are not what the probe is waiting for: free
// text before the identification string (RFC 4253 §4.2 — a legal banner) and
// SSH_MSG_IGNORE before its KEXINIT.
func TestSSHKexInitSkipsPreambleAndIgnoreMessages(t *testing.T) {
	srv := modernServer()
	srv.preamble = []string{
		"*****************************************************",
		"  UNAUTHORIZED ACCESS PROHIBITED. All activity logged.",
		"*****************************************************",
	}
	srv.ignoresFirst = true

	capture := captureFrom(t, srv)

	if !strings.HasPrefix(capture.Banner, "SSH-2.0-OpenSSH_9.6p1") {
		t.Fatalf("Banner = %q, want the identification string, not a preamble line", capture.Banner)
	}
	// The legal banner is operator free text with no cryptographic content;
	// it must not be stored anywhere in the capture.
	if strings.Contains(capture.Banner, "UNAUTHORIZED") {
		t.Errorf("preamble text leaked into the banner: %q", capture.Banner)
	}
	if got, want := capture.Kex, "curve25519-sha256"; got != want {
		t.Errorf("negotiated kex = %q, want %q (SSH_MSG_IGNORE must be skipped)", got, want)
	}
}

func TestSSHKexInitBoundsAPeerThatNeverSendsKexInit(t *testing.T) {
	srv := modernServer()
	srv.omitKexInit = true
	addr := srv.start(t)

	if _, err := sshprobeKexInit(NewProber(5*time.Second), addr); err == nil {
		t.Fatal("expected an error when the peer never sends SSH_MSG_KEXINIT")
	}
}

func TestSSHReadIdentificationRejectsANonSSHPeer(t *testing.T) {
	// A peer that answers with HTTP (a web server on a moved port) must be
	// rejected rather than recorded as an SSH server with a strange banner.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for i := 0; i <= sshMaxPreambleLines; i++ {
			if _, err := conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n")); err != nil {
				return
			}
		}
	}()

	if _, err := sshprobeKexInit(NewProber(5*time.Second), ln.Addr().String()); err == nil {
		t.Fatal("expected an error for a peer that never sends an SSH identification string")
	}
}

// TestSSHPacketFramingRoundTrips checks the binary packet protocol (RFC 4253
// §6) both ways: what sshWrapPacket emits is what sshReadPacket reads back,
// and the framing satisfies the protocol's own invariants.
func TestSSHPacketFramingRoundTrips(t *testing.T) {
	for _, payload := range [][]byte{
		{sshMsgKexInit},
		[]byte("a short payload"),
		bytes.Repeat([]byte("x"), 8),   // exactly a block
		bytes.Repeat([]byte("y"), 251), // forces minimum padding
		sshBuildKexInitPayload(),
	} {
		packet := sshWrapPacket(payload)

		if len(packet)%8 != 0 {
			t.Errorf("packet of %d bytes is not a multiple of the 8-byte block size", len(packet))
		}
		if got := int(packet[4]); got < 4 {
			t.Errorf("padding length = %d, RFC 4253 §6 requires at least 4", got)
		}
		if got, want := binary.BigEndian.Uint32(packet[0:4]), uint32(len(packet)-4); got != want {
			t.Errorf("packet_length = %d, want %d", got, want)
		}

		got, err := sshReadPacket(bytes.NewReader(packet))
		if err != nil {
			t.Fatalf("sshReadPacket: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("round trip = %q, want %q", got, payload)
		}
	}
}

func TestSSHReadPacketRejectsMalformedFraming(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			// A length field larger than RFC 4253 §6's guaranteed maximum
			// must be refused, not allocated: the only thing on the far side
			// is an unauthenticated peer.
			name:  "oversized packet length",
			input: append([]byte{0xff, 0xff, 0xff, 0xff, 0x04}, make([]byte, 16)...),
		},
		{
			name:  "padding longer than the packet",
			input: append([]byte{0, 0, 0, 5, 0xff}, make([]byte, 16)...),
		},
		{
			// RFC 4253 §6 requires at least 4 bytes of padding. sshWrapPacket
			// honours that on the way out, so the parser holds the peer to the
			// same rule rather than accepting a frame this implementation
			// would never produce. The frame is otherwise well formed — 3
			// bytes of padding and a valid length — so only the padding rule
			// rejects it.
			name:  "padding below the RFC minimum",
			input: append([]byte{0, 0, 0, 8, 3, sshMsgKexInit}, make([]byte, 16)...),
		},
		{
			name:  "zero padding",
			input: append([]byte{0, 0, 0, 8, 0, sshMsgKexInit}, make([]byte, 16)...),
		},
		{
			name:  "truncated header",
			input: []byte{0, 0, 0},
		},
		{
			name:  "body shorter than the length claims",
			input: []byte{0, 0, 0, 16, 4, 20, 1, 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := sshReadPacket(bytes.NewReader(tt.input)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestSSHKexInitParseRejectsMalformedPayloads(t *testing.T) {
	valid := sshBuildKexInitPayload()

	tests := []struct {
		name    string
		payload []byte
	}{
		{"wrong message number", append([]byte{21}, valid[1:]...)},
		{"shorter than the cookie", valid[:10]},
		{"truncated name-list", valid[:40]},
		{"name-list length past the end", append(append([]byte{sshMsgKexInit}, make([]byte, 16)...), 0xff, 0xff, 0xff, 0xff)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c sshKexInitCapture
			if err := c.parse(tt.payload); err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	var c sshKexInitCapture
	if err := c.parse(valid); err != nil {
		t.Fatalf("parse of the probe's own KEXINIT failed: %v", err)
	}
	if strings.Join(c.ServerKex, ",") != strings.Join(sshProbeOffer.Kex, ",") {
		t.Errorf("round trip of the probe's own offer lost entries: %v", c.ServerKex)
	}
}

func TestSSHSoftwareVersion(t *testing.T) {
	tests := map[string]string{
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5": "OpenSSH_9.6p1",
		"SSH-2.0-OpenSSH_5.3":                      "OpenSSH_5.3",
		"SSH-2.0-dropbear_2022.83":                 "dropbear_2022.83",
		"SSH-1.99-Cisco-1.25":                      "Cisco-1.25",
		"SSH-2.0-":                                 "",
		"SSH-2.0":                                  "",
		"not an ssh banner":                        "",
		"":                                         "",
	}
	for banner, want := range tests {
		if got := sshSoftwareVersion(banner); got != want {
			t.Errorf("sshSoftwareVersion(%q) = %q, want %q", banner, got, want)
		}
	}
}

func TestSSHSplitNameList(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"", nil},
		{"   ", nil},
		{",,", nil},
		{"a,,b", []string{"a", "b"}},
		{"single", []string{"single"}},
	}
	for _, tt := range tests {
		got := sshSplitNameList(tt.in)
		if strings.Join(got, "|") != strings.Join(tt.want, "|") {
			t.Errorf("sshSplitNameList(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// TestSSHProbeOfferIsOrderedStrongestFirst pins the property the negotiated
// values depend on. The offer's ORDER is what RFC 4253 §7.1 resolves against,
// so re-ordering these lists silently changes what every SSH asset on the
// platform reports as negotiated — a spot check that the known-weak entries
// sit behind their modern replacements catches that.
func TestSSHProbeOfferIsOrderedStrongestFirst(t *testing.T) {
	mustPrecede := []struct {
		list     []string
		stronger string
		weaker   string
	}{
		{sshProbeOffer.Kex, "curve25519-sha256", "diffie-hellman-group14-sha1"},
		{sshProbeOffer.Kex, "diffie-hellman-group14-sha256", "diffie-hellman-group1-sha1"},
		{sshProbeOffer.Kex, "mlkem768x25519-sha256", "curve25519-sha256"},
		{sshProbeOffer.HostKey, "ssh-ed25519", "ssh-rsa"},
		{sshProbeOffer.HostKey, "rsa-sha2-512", "ssh-rsa"},
		{sshProbeOffer.HostKey, "ssh-rsa", "ssh-dss"},
		{sshProbeOffer.Encryption, "aes256-gcm@openssh.com", "aes128-cbc"},
		{sshProbeOffer.Encryption, "aes128-ctr", "3des-cbc"},
		{sshProbeOffer.Encryption, "3des-cbc", "arcfour"},
		{sshProbeOffer.MAC, "hmac-sha2-256", "hmac-sha1"},
		{sshProbeOffer.MAC, "hmac-sha1", "hmac-md5"},
	}
	for _, c := range mustPrecede {
		si, wi := indexOf(c.list, c.stronger), indexOf(c.list, c.weaker)
		if si < 0 {
			t.Errorf("%q is missing from the offer", c.stronger)
			continue
		}
		if wi < 0 {
			// A weak algorithm MUST stay on the list: without it, a server
			// that offers only that algorithm shares nothing with the probe
			// and its posture goes unreported. Dropping one is the failure
			// this guard exists for, not a tidy-up.
			t.Errorf("%q is missing from the offer — a weak-only server that offers it "+
				"would negotiate nothing and report no posture", c.weaker)
			continue
		}
		if si >= wi {
			t.Errorf("%q (index %d) must be offered before %q (index %d)", c.stronger, si, c.weaker, wi)
		}
	}
}

func indexOf(list []string, want string) int {
	for i, s := range list {
		if strings.EqualFold(s, want) {
			return i
		}
	}
	return -1
}

// TestSSHKexInitExchangeSendsAWellFormedKexInit reads the probe's own side of
// the exchange off the wire and checks it parses as a KEXINIT — a server that
// rejects our packet answers nothing, and the probe would report an
// unreachable SSH server rather than a bug of its own.
func TestSSHKexInitExchangeSendsAWellFormedKexInit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type result struct {
		ident   string
		payload []byte
		err     error
	}
	done := make(chan result, 1)

	go func() {
		server, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer func() { _ = server.Close() }()
		_ = server.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := server.Write([]byte("SSH-2.0-TestServer_1.0\r\n")); err != nil {
			done <- result{err: err}
			return
		}

		identBuf := make([]byte, len(sshClientIdentification)+2)
		if _, err := io.ReadFull(server, identBuf); err != nil {
			done <- result{err: err}
			return
		}
		payload, err := sshReadPacket(server)
		if err != nil {
			done <- result{err: err}
			return
		}
		// Answer so the exchange completes and the client goroutine returns.
		_, _ = server.Write(sshWrapPacket(modernServer().kexInitPayload()))
		done <- result{ident: string(identBuf), payload: payload}
	}()

	if _, err := sshprobeKexInit(NewProber(5*time.Second), ln.Addr().String()); err != nil {
		t.Fatalf("sshprobeKexInit: %v", err)
	}

	got := <-done
	if got.err != nil {
		t.Fatalf("server side: %v", got.err)
	}
	if want := sshClientIdentification + "\r\n"; got.ident != want {
		t.Errorf("identification sent = %q, want %q", got.ident, want)
	}

	var parsed sshKexInitCapture
	if err := parsed.parse(got.payload); err != nil {
		t.Fatalf("the probe's own KEXINIT does not parse: %v", err)
	}
	if strings.Join(parsed.ServerEncryptionC2S, ",") != strings.Join(sshProbeOffer.Encryption, ",") {
		t.Errorf("cipher offer on the wire = %v, want %v", parsed.ServerEncryptionC2S, sshProbeOffer.Encryption)
	}
	// first_kex_packet_follows must be false: the probe sends no guessed
	// SSH_MSG_KEX_ECDH_INIT, and claiming otherwise would desynchronise a
	// server that believed it.
	if got.payload[len(got.payload)-5] != 0 {
		t.Error("first_kex_packet_follows is set; the probe sends no guess")
	}
}

// TestProbeSSHEmitsTheKeysTheIngestReads is the WIRING test: it drives the
// real probe dispatch (Prober.Probe, not applySSHKexInit in isolation)
// against a server that never completes a key exchange, and asserts the exact
// metadata key names inventory-service's SSH ingest reads.
//
// Those key names are a contract across several layers — shared/discovery
// emits them, the in-cluster Platform Sensor copies them into finding.Data,
// sensor-manager writes them into discovery_findings.details, and
// services/inventory-service/internal/services/ssh_ingest.go's sshRawKeys
// reads them. Renaming one on either side is silent: the ingest simply finds
// nothing and the configuration scores 0, which the product reads as "not
// assessed" rather than as a bug. This test fails if a key name moves.
func TestProbeSSHEmitsTheKeysTheIngestReads(t *testing.T) {
	srv := modernServer()
	addr := srv.start(t)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	// A short timeout on purpose: the fake server answers the KEXINIT pass
	// immediately but never completes a key exchange, so the x/crypto pass
	// runs its deadline out. Everything here is loopback, so one second is
	// ample for the pass that does answer.
	res, err := NewProber(time.Second).Probe(host, host, "SSH", port)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	// The fake server never performs a key exchange, so the x/crypto pass
	// yields nothing at all. That used to cost the whole finding; the KEXINIT
	// pass must carry it on its own.
	if res.SSHHostKeyFingerprint != "" {
		t.Fatalf("fixture completed a key exchange (%q) — it no longer exercises "+
			"the handshake-failed path", res.SSHHostKeyFingerprint)
	}

	wantStrings := map[string]string{
		"ssh_banner":             "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
		"ssh_protocol_version":   "SSH-2.0",
		"ssh_software_version":   "OpenSSH_9.6p1",
		"ssh_kex_algorithm":      "curve25519-sha256",
		"ssh_host_key_algorithm": "rsa-sha2-512",
		"ssh_encryption_alg_c2s": "aes256-ctr",
		"ssh_encryption_alg_s2c": "aes128-ctr",
		"ssh_mac_alg_c2s":        "hmac-sha2-256",
		"ssh_mac_alg_s2c":        "hmac-sha2-512",
		"ssh_compression_alg":    "none",
	}
	for k, want := range wantStrings {
		got, ok := res.Metadata[k].(string)
		if !ok {
			t.Errorf("metadata[%q] missing or not a string (got %T)", k, res.Metadata[k])
			continue
		}
		if got != want {
			t.Errorf("metadata[%q] = %q, want %q", k, got, want)
		}
	}

	wantLists := map[string][]string{
		"ssh_kex_algorithms_server":       srv.kex,
		"ssh_host_key_algs_server":        srv.hostKey,
		"ssh_encryption_algs_c2s_server":  srv.encC2S,
		"ssh_encryption_algs_s2c_server":  srv.encS2C,
		"ssh_mac_algs_c2s_server":         srv.macC2S,
		"ssh_mac_algs_s2c_server":         srv.macS2C,
		"ssh_compression_algs_c2s_server": srv.compC2S,
		"ssh_compression_algs_s2c_server": srv.compS2C,
	}
	for k, want := range wantLists {
		got, ok := res.Metadata[k].([]string)
		if !ok {
			t.Errorf("metadata[%q] missing or not a []string (got %T)", k, res.Metadata[k])
			continue
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("metadata[%q] = %v, want %v", k, got, want)
		}
	}

	// The typed fields the standalone sensor carries to the platform must
	// agree with the metadata the in-cluster Platform Sensor carries, or the
	// two runtimes report differently for the same server.
	if res.SSHKexAlgorithm != "curve25519-sha256" {
		t.Errorf("SSHKexAlgorithm = %q, want curve25519-sha256", res.SSHKexAlgorithm)
	}
	if res.SSHEncryptionAlgC2S != "aes256-ctr" {
		t.Errorf("SSHEncryptionAlgC2S = %q, want aes256-ctr", res.SSHEncryptionAlgC2S)
	}
	if res.SSHMACAlgC2S != "hmac-sha2-256" {
		t.Errorf("SSHMACAlgC2S = %q, want hmac-sha2-256", res.SSHMACAlgC2S)
	}
	if strings.Join(res.SSHServerKexAlgorithms, ",") != strings.Join(srv.kex, ",") {
		t.Errorf("SSHServerKexAlgorithms = %v, want %v", res.SSHServerKexAlgorithms, srv.kex)
	}
	if strings.Join(res.SSHServerHostKeyAlgorithms, ",") != strings.Join(srv.hostKey, ",") {
		t.Errorf("SSHServerHostKeyAlgorithms = %v, want %v", res.SSHServerHostKeyAlgorithms, srv.hostKey)
	}
}

// countingReader reports how many bytes were actually pulled from the source,
// which is the quantity the bound is about.
type countingReader struct {
	src  io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.read += n
	return n, err
}

// TestSSHReadIdentificationBoundsAPeerWithNoNewline is the memory-safety
// regression test.
//
// sshReadIdentification used to call bufio.Reader.ReadString, which grows a
// buffer until it finds the delimiter. The byte bound was only consulted once
// ReadString RETURNED, so a peer that streamed bytes with no newline at all
// was never bounded: the read continued to the connection deadline, allocating
// the whole time. Against a listener streaming 'A' a reviewer measured 9.3 GB
// in 3 seconds — with the in-cluster prober's 30-second timeout and its scan
// concurrency, that is an OOM of the pod or of a customer's sensor host. The
// peer is unauthenticated and arbitrary, so the bound has to hold DURING the
// read.
//
// The source here is a FINITE megabyte rather than an infinite stream on
// purpose: it keeps the test's own failure mode a clean assertion failure.
// Restore ReadString and this fails on bytes consumed (1 MiB against a bound
// of 8 KiB) instead of exhausting the machine — a mutation check that is safe
// to actually run.
func TestSSHReadIdentificationBoundsAPeerWithNoNewline(t *testing.T) {
	const streamed = 1 << 20 // 1 MiB, no newline anywhere in it

	cr := &countingReader{src: bytes.NewReader(bytes.Repeat([]byte("A"), streamed))}
	reader := bufio.NewReader(cr)

	got, err := sshReadIdentification(reader)
	if err == nil {
		t.Fatalf("expected an error for a peer that never sends a newline, got banner %q", got)
	}
	if !errors.Is(err, errSSHPreambleBound) {
		t.Errorf("error = %v, want it to wrap errSSHPreambleBound so the cause is legible", err)
	}

	// The read must stop within the budget plus at most one bufio buffer —
	// the chunk in flight when the cap is crossed. Anything approaching the
	// full megabyte means the bound is being checked after the fact again.
	maxConsumed := sshMaxPreambleBytes + reader.Size()
	if cr.read > maxConsumed {
		t.Errorf("consumed %d bytes, want at most %d (bound %d + one %d-byte bufio buffer) — "+
			"the byte cap must apply during the read, not after the line returns",
			cr.read, maxConsumed, sshMaxPreambleBytes, reader.Size())
	}
	if cr.read >= streamed {
		t.Errorf("consumed the entire %d-byte stream: the peer, not the probe, decided when to stop", streamed)
	}
}

// A long preamble line is legitimate — operators write multi-hundred-byte
// legal banners — so bounding the read must not break the ordinary case. The
// line is skipped (RFC 4253 §4.2 caps an identification string at 255 bytes,
// so a longer line cannot be one) and the identification behind it is found.
func TestSSHReadIdentificationSkipsAnOverlongPreambleLine(t *testing.T) {
	const version = "SSH-2.0-OpenSSH_9.6p1"
	// Longer than bufio's buffer, so ReadSlice returns ErrBufferFull and the
	// drain loop runs, but inside the preamble byte budget.
	long := strings.Repeat("legal notice ", 400)
	if len(long) <= bufio.NewReader(strings.NewReader("")).Size() {
		t.Fatalf("preamble line of %d bytes fits in one bufio buffer: the drain loop is not exercised", len(long))
	}
	if len(long) >= sshMaxPreambleBytes {
		t.Fatalf("preamble line of %d bytes exceeds the budget %d: the test would assert the bound, not the skip", len(long), sshMaxPreambleBytes)
	}

	reader := bufio.NewReader(strings.NewReader(long + "\r\n" + version + "\r\n"))
	got, err := sshReadIdentification(reader)
	if err != nil {
		t.Fatalf("sshReadIdentification: %v", err)
	}
	if got != version {
		t.Errorf("banner = %q, want %q", got, version)
	}
	if strings.Contains(got, "legal notice") {
		t.Errorf("preamble text leaked into the banner: %q", got)
	}
}

// TestSSHKexInitBoundsAStreamingPeer is the same protection at the level the
// probe actually runs at: a TCP peer that answers with an endless stream and
// no newline must fail, not consume the host.
func TestSSHKexInitBoundsAStreamingPeer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		chunk := bytes.Repeat([]byte("A"), 4096)
		for {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := sshprobeKexInit(NewProber(10*time.Second), ln.Addr().String())
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error against a peer that streams without ever sending a newline")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sshprobeKexInit did not return: the byte bound is not ending the read, " +
			"so only the connection deadline would — after unbounded allocation")
	}
}

// TestSSHKexInitRecordsNoNegotiationWithoutOverlap covers the honest-empty
// case. A server whose every name-list is disjoint from the probe's negotiates
// nothing, and the probe must say so rather than reach for the server's first
// entry — which is the shape of every "offer recorded as if it were in use"
// bug this code is written against. The offers are still recorded: they are
// the finding.
func TestSSHKexInitRecordsNoNegotiationWithoutOverlap(t *testing.T) {
	srv := &fakeSSHServer{
		banner:  "SSH-2.0-ExoticStack_1.0",
		kex:     []string{"kex-none@example.test", "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g=="},
		hostKey: []string{"x509v3-sign-rsa"},
		encC2S:  []string{"cast128-cbc", "blowfish-cbc"},
		encS2C:  []string{"idea-cbc"},
		macC2S:  []string{"hmac-ripemd160"},
		macS2C:  []string{"hmac-ripemd160@openssh.com"},
		compC2S: []string{"zlib@example.test"},
		compS2C: []string{"zlib@example.test"},
	}
	capture := captureFrom(t, srv)

	negotiated := map[string]string{
		"Kex":            capture.Kex,
		"HostKey":        capture.HostKey,
		"EncryptionC2S":  capture.EncryptionC2S,
		"EncryptionS2C":  capture.EncryptionS2C,
		"MACC2S":         capture.MACC2S,
		"MACS2C":         capture.MACS2C,
		"CompressionC2S": capture.CompressionC2S,
	}
	for name, got := range negotiated {
		if got != "" {
			t.Errorf("negotiated %s = %q, want \"\" — nothing is in common, so nothing was negotiated", name, got)
		}
	}

	// Guard against the fixture silently acquiring an overlap later.
	for _, l := range [][]string{srv.kex, srv.hostKey, srv.encC2S, srv.macC2S, srv.compC2S} {
		for _, offer := range [][]string{sshProbeOffer.Kex, sshProbeOffer.HostKey, sshProbeOffer.Encryption, sshProbeOffer.MAC, sshProbeOffer.Compression} {
			for _, s := range l {
				if indexOf(offer, s) >= 0 {
					t.Fatalf("fixture shares %q with the probe's offer: it no longer tests the zero-overlap case", s)
				}
			}
		}
	}

	offers := map[string]struct{ got, want []string }{
		"ServerKex":            {capture.ServerKex, srv.kex},
		"ServerHostKey":        {capture.ServerHostKey, srv.hostKey},
		"ServerEncryptionC2S":  {capture.ServerEncryptionC2S, srv.encC2S},
		"ServerEncryptionS2C":  {capture.ServerEncryptionS2C, srv.encS2C},
		"ServerMACC2S":         {capture.ServerMACC2S, srv.macC2S},
		"ServerMACS2C":         {capture.ServerMACS2C, srv.macS2C},
		"ServerCompressionC2S": {capture.ServerCompressionC2S, srv.compC2S},
	}
	for name, c := range offers {
		if strings.Join(c.got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s = %v, want %v — an unrecognised offer is still the asset's posture", name, c.got, c.want)
		}
	}

	if capture.Banner != "SSH-2.0-ExoticStack_1.0" || capture.ProtocolVersion != "SSH-2.0" {
		t.Errorf("banner/version lost on a zero-overlap server: %q / %q", capture.Banner, capture.ProtocolVersion)
	}
}
