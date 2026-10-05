package discovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
)

// speakServer runs a loopback TCP server on 127.0.0.1 that applies onConn to
// each accepted connection, and returns its host and port. Loopback only.
func speakServer(t testing.TB, onConn func(net.Conn)) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = c.Close() }()
				onConn(c)
			})
		}
	})
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

// recordingDialer wraps a real dialer, records every (requested) address it is
// asked to dial, optionally remaps a requested port to a real listener address
// (so a test can make Identify believe it is talking to port 502), and wraps
// each connection to count writes. Loopback only.
type recordingDialer struct {
	inner net.Dialer
	remap map[uint16]string // requested port -> actual "ip:port" to dial

	mu    sync.Mutex
	dials []netip.AddrPort
	conns []*recordingConn
}

func (d *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.dials = append(d.dials, ap)
	d.mu.Unlock()

	real := address
	if r, ok := d.remap[ap.Port()]; ok {
		real = r
	}
	c, err := d.inner.DialContext(ctx, network, real)
	if err != nil {
		return nil, err
	}
	rc := &recordingConn{Conn: c, requested: ap}
	d.mu.Lock()
	d.conns = append(d.conns, rc)
	d.mu.Unlock()
	return rc, nil
}

func (d *recordingDialer) dialedPorts() []int {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []int
	for _, ap := range d.dials {
		out = append(out, int(ap.Port()))
	}
	return out
}

// connsWithWrites returns, per requested port, how many connections to that
// port had any bytes written to them, and whether every such first write began
// a TLS record (0x16 0x03).
func (d *recordingDialer) connsWithWrites(port int) (count int, allTLS bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	allTLS = true
	for _, c := range d.conns {
		if int(c.requested.Port()) != port {
			continue
		}
		if c.bytesWritten() > 0 {
			count++
			if !c.firstWriteIsTLS() {
				allTLS = false
			}
		}
	}
	return count, allTLS
}

type recordingConn struct {
	net.Conn
	requested netip.AddrPort
	mu        sync.Mutex
	first     []byte
	written   int
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.first == nil && len(b) > 0 {
		c.first = append([]byte(nil), b...)
	}
	c.written += len(b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

// RemoteAddr reports the REQUESTED address, so a prober that re-dials (SSH)
// targets the logical address the test set, and MeasureTLSKeyExchange (when
// not suppressed) would redial it too.
func (c *recordingConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.requested) }

func (c *recordingConn) bytesWritten() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written
}

func (c *recordingConn) firstWriteIsTLS() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.first) >= 2 && c.first[0] == 0x16 && c.first[1] == 0x03
}

func newIdentifyScanner(t testing.TB, d Dialer) *Scanner {
	t.Helper()
	s, err := NewScanner(WithDialer(d), WithPaceProfile(testPace))
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	return s
}

func hostScan(addr netip.Addr, suspect bool, open ...int) HostScan {
	return HostScan{Addr: addr, Liveness: LivenessAssumedUp, Open: open, OpenCount: len(open), OTSuspect: suspect}
}

func findObs(t *testing.T, obs []Observation, port int) Observation {
	t.Helper()
	for _, o := range obs {
		if o.Port == port {
			return o
		}
	}
	t.Fatalf("no observation for port %d", port)
	return Observation{}
}

// ---- functional identification (loopback) -----------------------------------

func TestIdentify_SilentTLSPortYieldsCanonicalCertificates(t *testing.T) {
	srv := tlskextest.Start(t, []tls.CurveID{tls.X25519}, 0)
	addr := mustAddr(t, srv.Host)
	rec := &recordingDialer{}
	s := newIdentifyScanner(t, rec)

	obs, err := s.Identify(context.Background(), hostScan(addr, false, srv.Port), IdentifyOptions{Hostname: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	o := findObs(t, obs, srv.Port)
	if !o.Identified || o.Protocol != "TLS" || o.Result == nil {
		t.Fatalf("TLS port: identified=%v protocol=%q result=%v", o.Identified, o.Protocol, o.Result)
	}
	if len(o.Result.Certificates) == 0 {
		t.Error("TLS observation carries no canonical certificates array")
	}
	if len(o.Result.TLSVersions) == 0 {
		t.Error("TLS observation carries no version metadata")
	}
	// One speculative ClientHello to the port; once it succeeded, the one
	// key-exchange support handshake it left open (it negotiated classical
	// X25519, so only the hybrid-only offer is asked) and one forced-version
	// handshake per version it did not prove (identify_tls_enum_test.go,
	// identify_tls_kex_test.go). Nothing but TLS is ever written.
	n, allTLS := rec.connsWithWrites(srv.Port)
	if want := 1 + 1 + unitTLSEnumHandshakes; n != want || !allTLS {
		t.Errorf("TLS port: %d connections with writes (TLS-framed=%v), want exactly %d ClientHellos", n, allTLS, want)
	}
}

func TestIdentify_SSHBannerHandsToProber(t *testing.T) {
	host, port := speakServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6 testserver\r\n"))
		// No KEXINIT follows; the prober falls back to a banner read.
		time.Sleep(200 * time.Millisecond)
	})
	rec := &recordingDialer{}
	s := newIdentifyScanner(t, rec)
	obs, err := s.Identify(context.Background(), hostScan(mustAddr(t, host), false, port), IdentifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	o := findObs(t, obs, port)
	if !o.Identified || o.Protocol != "SSH" {
		t.Fatalf("SSH port: identified=%v protocol=%q notes=%q", o.Identified, o.Protocol, o.Notes)
	}
}

func TestIdentify_RecognisedPlaintextBannerNeedsNoProber(t *testing.T) {
	cases := []struct {
		name   string
		banner string
		hint   string
	}{
		{"smtp", "220 mail.example.com ESMTP Postfix\r\n", "smtp"},
		{"ftp", "220 (vsFTPd 3.0.5)\r\n", "ftp"},
		{"pop3", "+OK POP3 ready\r\n", "pop3"},
		{"imap", "* OK IMAP4rev1 ready\r\n", "imap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := speakServer(t, func(c net.Conn) {
				_, _ = c.Write([]byte(tc.banner))
				time.Sleep(100 * time.Millisecond)
			})
			rec := &recordingDialer{}
			s := newIdentifyScanner(t, rec)
			obs, err := s.Identify(context.Background(), hostScan(mustAddr(t, host), false, port), IdentifyOptions{})
			if err != nil {
				t.Fatal(err)
			}
			o := findObs(t, obs, port)
			if !o.Identified || o.ServiceHint != tc.hint {
				t.Fatalf("%s: identified=%v hint=%q", tc.name, o.Identified, o.ServiceHint)
			}
			// No prober, so no bytes should have been written to the port.
			if n, _ := rec.connsWithWrites(port); n != 0 {
				t.Errorf("%s: %d connections had writes, want 0 (recognition needs no payload)", tc.name, n)
			}
			// The raw banner must not be stored anywhere.
			assertBannerNotStored(t, o, tc.banner)
		})
	}
}

func TestIdentify_SilentPlainPortIsUnidentified(t *testing.T) {
	host, port := speakServer(t, func(c net.Conn) {
		// Accept and stay silent, never completing TLS.
		buf := make([]byte, 1)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Read(buf)
	})
	rec := &recordingDialer{}
	s := newIdentifyScanner(t, rec)
	obs, err := s.Identify(context.Background(), hostScan(mustAddr(t, host), false, port), IdentifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	o := findObs(t, obs, port)
	if o.Identified || o.Protocol != "" || o.ServiceHint != "" {
		t.Fatalf("silent plain port: identified=%v protocol=%q hint=%q, want unidentified", o.Identified, o.Protocol, o.ServiceHint)
	}
	if o.State != "open" {
		t.Errorf("state=%q, want open", o.State)
	}
	// At most the one speculative TLS ClientHello.
	if n, _ := rec.connsWithWrites(port); n > 1 {
		t.Errorf("%d connections with writes, want <= 1", n)
	}
}

func TestIdentify_GarbageBannerIsNeverStored(t *testing.T) {
	// Printable but matching no signature, so a leak into the observation is
	// visible after JSON encoding (binary bytes would be mangled by JSON and
	// could hide a leak the mutation test must catch).
	garbage := "WOMBATxyzzy-definitely-not-a-known-banner"
	host, port := speakServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte(garbage))
		time.Sleep(100 * time.Millisecond)
	})
	rec := &recordingDialer{}
	s := newIdentifyScanner(t, rec)
	obs, err := s.Identify(context.Background(), hostScan(mustAddr(t, host), false, port), IdentifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	o := findObs(t, obs, port)
	if o.Identified {
		t.Errorf("garbage banner wrongly identified as %q", o.Protocol)
	}
	if o.Metadata == nil || o.Metadata["banner_len"] == nil {
		t.Error("expected banner_len recorded for an unrecognised banner")
	}
	assertBannerNotStored(t, o, garbage)
}

func TestIdentify_AcceptThenResetIsHonest(t *testing.T) {
	host, port := speakServer(t, func(c net.Conn) {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0) // RST on close
		}
		_ = c.Close()
	})
	rec := &recordingDialer{}
	s := newIdentifyScanner(t, rec)
	obs, err := s.Identify(context.Background(), hostScan(mustAddr(t, host), false, port), IdentifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	o := findObs(t, obs, port)
	if o.Identified {
		t.Errorf("reset port wrongly identified as %q", o.Protocol)
	}
	if !strings.Contains(o.Notes, "during-identify") {
		t.Errorf("notes=%q, want a during-identify note", o.Notes)
	}
}

// ---- OT safety ---------------------------------------------------------------

func TestIdentify_OTPortIsConnectOnlyWithoutOptIn(t *testing.T) {
	rec := &recordingDialer{}
	s := newIdentifyScanner(t, rec)
	// 502 is Modbus (an OT port). No opt-in.
	obs, err := s.Identify(context.Background(), hostScan(mustAddr(t, "127.0.0.1"), false, 502), IdentifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	o := findObs(t, obs, 502)
	if o.Identified {
		t.Error("OT port identified without opt-in")
	}
	if o.ServiceHint != "modbus" {
		t.Errorf("hint=%q, want modbus (from the well-known port map)", o.ServiceHint)
	}
	// The strongest guarantee: identification never even dialled the OT port.
	for _, p := range rec.dialedPorts() {
		if p == 502 {
			t.Fatal("identification dialled an OT port without opt-in")
		}
	}
}

func TestIdentify_OTOptInRunsTheProber(t *testing.T) {
	// A loopback server standing in for a Modbus device; it need not parse —
	// we are proving the prober is dispatched only under opt-in.
	host, realPort := speakServer(t, func(c net.Conn) {
		buf := make([]byte, 64)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = c.Read(buf)
		_ = c.Close()
	})
	rec := &recordingDialer{remap: map[uint16]string{502: fmt.Sprintf("%s:%d", host, realPort)}}
	s := newIdentifyScanner(t, rec)

	// Without opt-in: no dial to 502.
	if obs, err := s.Identify(context.Background(), hostScan(mustAddr(t, "127.0.0.1"), false, 502), IdentifyOptions{}); err != nil {
		t.Fatal(err)
	} else if findObs(t, obs, 502).Identified {
		t.Error("identified without opt-in")
	}
	for _, p := range rec.dialedPorts() {
		if p == 502 {
			t.Fatal("dialled OT port without opt-in")
		}
	}

	// With opt-in: the prober is dispatched (it dials and writes to 502).
	rec2 := &recordingDialer{remap: map[uint16]string{502: fmt.Sprintf("%s:%d", host, realPort)}}
	s2 := newIdentifyScanner(t, rec2)
	if _, err := s2.Identify(context.Background(), hostScan(mustAddr(t, "127.0.0.1"), false, 502), IdentifyOptions{OTProbes: []string{"Modbus"}}); err != nil {
		t.Fatal(err)
	}
	dialed := false
	for _, p := range rec2.dialedPorts() {
		if p == 502 {
			dialed = true
		}
	}
	if !dialed {
		t.Error("opt-in did not dispatch the Modbus prober")
	}
}

func TestIdentify_RejectsUnknownOTProbe(t *testing.T) {
	s := newIdentifyScanner(t, &recordingDialer{})
	if _, err := s.Identify(context.Background(), hostScan(mustAddr(t, "127.0.0.1"), false, 502), IdentifyOptions{OTProbes: []string{"DNP3"}}); err == nil {
		t.Error("accepted an OT probe (DNP3) that has no safe prober")
	}
}

func TestIdentify_OTSuspectHostWithholdsSpeculativeTLS(t *testing.T) {
	// A silent non-TLS, non-well-known port on an OT-suspect host must get NO
	// speculative ClientHello.
	host, port := speakServer(t, func(c net.Conn) {
		buf := make([]byte, 1)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = c.Read(buf)
	})
	rec := &recordingDialer{}
	s := newIdentifyScanner(t, rec)
	obs, err := s.Identify(context.Background(), hostScan(mustAddr(t, host), true /*suspect*/, port), IdentifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	o := findObs(t, obs, port)
	if o.Identified {
		t.Errorf("suspect host: port %d identified=%v, want unidentified", port, o.Identified)
	}
	if n, _ := rec.connsWithWrites(port); n != 0 {
		t.Errorf("suspect host: %d writes to a non-TLS port, want 0 (no speculative payload)", n)
	}
	if !strings.Contains(o.Notes, "ot-suspect") {
		t.Errorf("notes=%q, want an ot-suspect note", o.Notes)
	}
}

// ---- property: raw banner bytes are never retained ---------------------------

func TestIdentify_SignatureTableNeverStoresRawBytes(t *testing.T) {
	// Every signature's sample banner: a recognised non-SSH service keeps a
	// hint, never the bytes. (SSH legitimately records its banner via the SSH
	// prober — that is posture, not an unknown greeting — so it is excluded.)
	samples := map[string]string{
		"smtp":  "220 mx.example.org ESMTP\r\n",
		"ftp":   "220 ProFTPD Server ready\r\n",
		"pop3":  "+OK dovecot ready\r\n",
		"imap":  "* OK [CAPABILITY IMAP4rev1] ready\r\n",
		"mysql": string([]byte{0x0a, 0x00, 0x00, 0x00, 0x0a, '8', '.', '0', '.', '3', '6', 0x00}),
	}
	for hint, banner := range samples {
		t.Run(hint, func(t *testing.T) {
			host, port := speakServer(t, func(c net.Conn) {
				_, _ = c.Write([]byte(banner))
				time.Sleep(80 * time.Millisecond)
			})
			s := newIdentifyScanner(t, &recordingDialer{})
			obs, err := s.Identify(context.Background(), hostScan(mustAddr(t, host), false, port), IdentifyOptions{})
			if err != nil {
				t.Fatal(err)
			}
			o := findObs(t, obs, port)
			assertBannerNotStored(t, o, banner)
		})
	}
}

// assertBannerNotStored serialises the observation and fails if any
// recognisable run of the raw banner appears in it.
func assertBannerNotStored(t *testing.T, o Observation, banner string) {
	t.Helper()
	blob, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(banner)
	// Check the longest printable token of the banner (>=4 bytes) is absent.
	for _, tok := range strings.Fields(trimmed) {
		if len(tok) >= 4 && bytes.Contains(blob, []byte(tok)) {
			t.Errorf("raw banner token %q leaked into the observation: %s", tok, blob)
		}
	}
}

// ---- envelope: only the input address is contacted ---------------------------

func TestIdentify_ContactsOnlyTheInputAddress(t *testing.T) {
	host, port := speakServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte("220 mail ESMTP\r\n"))
		time.Sleep(50 * time.Millisecond)
	})
	rec := &recordingDialer{}
	s := newIdentifyScanner(t, rec)
	want := mustAddr(t, host)
	if _, err := s.Identify(context.Background(), hostScan(want, false, port), IdentifyOptions{}); err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, ap := range rec.dials {
		if ap.Addr() != want {
			t.Errorf("identification dialled %s, outside the input set {%s}", ap.Addr(), want)
		}
	}
	if len(rec.dials) == 0 {
		t.Error("no dials recorded")
	}
}

func TestIdentify_RefusesAddressesThatMustNeverBeDialled(t *testing.T) {
	s := newIdentifyScanner(t, &recordingDialer{})
	for _, a := range []netip.Addr{{}, netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("224.0.0.1")} {
		if _, err := s.Identify(context.Background(), hostScan(a, false, 443), IdentifyOptions{}); err == nil {
			t.Errorf("Identify accepted %s", a)
		}
	}
}
