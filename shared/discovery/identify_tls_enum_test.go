package discovery

// TLS version enumeration in the engine ( WP1, spec V4 / decision D4) and
// mTLS detection in the shared TLS probe (V12).
//
// The listeners run on 127.0.0.1 at an ephemeral port; the engine is told it is
// talking to a documentation address (192.0.2.0/24) on the port under test, and
// the recording dialer maps that one port onto the listener. Every dial the
// engine makes is recorded, so the assertions count connections exactly.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

// enumTarget is the address the engine believes it is identifying.
var enumTarget = netip.MustParseAddr("192.0.2.10")

// versionServer is a loopback TLS listener accepting exactly [min, max], and
// recording each completed handshake's version.
type versionServer struct {
	addr string
	mu   sync.Mutex
	done []uint16
}

func (s *versionServer) handshakes() []uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint16(nil), s.done...)
}

// handshakesWhen returns the completed handshakes once there are at least n,
// or whatever there is after a short wait. The server records a handshake
// after its own Handshake returns, which can trail the client's by a
// scheduling slice: the client has its answer before the server has counted.
func (s *versionServer) handshakesWhen(n int) []uint16 {
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := s.handshakes()
		if len(got) >= n || time.Now().After(deadline) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func startVersionServer(t *testing.T, minV, maxV uint16, auth tls.ClientAuthType) *versionServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tls.example.test"},
		DNSNames:     []string{"tls.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   minV,
		MaxVersion:   maxV,
		ClientAuth:   auth,
	}
	srv := &versionServer{}
	host, port := speakServer(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
		if tc.Handshake() == nil {
			srv.mu.Lock()
			srv.done = append(srv.done, tc.ConnectionState().Version)
			srv.mu.Unlock()
		}
	})
	srv.addr = net.JoinHostPort(host, fmt.Sprint(port))
	return srv
}

// identifyVia runs Identify on enumTarget:port, with port mapped to realAddr.
func identifyVia(t *testing.T, port int, realAddr string, suspect bool, opts IdentifyOptions) (Observation, *recordingDialer) {
	t.Helper()
	rec := &recordingDialer{remap: map[uint16]string{uint16(port): realAddr}}
	s := newIdentifyScanner(t, rec)
	obs, err := s.Identify(context.Background(), hostScan(enumTarget, suspect, port), opts)
	if err != nil {
		t.Fatal(err)
	}
	return findObs(t, obs, port), rec
}

func dialsTo(rec *recordingDialer, port int) int {
	n := 0
	for _, p := range rec.dialedPorts() {
		if p == port {
			n++
		}
	}
	return n
}

func TestIdentify_TLSListenerEnumeratesEveryAcceptedVersion(t *testing.T) {
	srv := startVersionServer(t, tls.VersionTLS10, tls.VersionTLS13, tls.NoClientCert)
	o, rec := identifyVia(t, 8443, srv.addr, false, IdentifyOptions{Hostname: "tls.example.test"})
	if !o.Identified || o.Result == nil {
		t.Fatalf("TLS listener not identified: %+v", o)
	}
	want := []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"}
	if !slices.Equal(o.Result.TLSVersions, want) {
		t.Errorf("TLSVersions = %v, want %v", o.Result.TLSVersions, want)
	}
	// The negotiated version stays first: it is what the finding's "version"
	// reads (jobunits.TLSProbeMetadata; pinned there too).
	if o.Result.Metadata["tls_version_raw"] != uint16(tls.VersionTLS13) {
		t.Errorf("negotiated %v, want TLS 1.3 first", o.Result.Metadata["tls_version_raw"])
	}
	// One identifying handshake, one key-exchange support handshake (it
	// negotiated the hybrid group, so only the classical-only offer is asked;
	// identify_tls_kex_test.go) and one per version it did not prove — the
	// negotiated version is not tested twice — all through the engine's dialer.
	if n := dialsTo(rec, 8443); n != 5 {
		t.Errorf("%d dials to the TLS port, want 5 (1 identify + 1 kex support + 3 enumeration)", n)
	}
	if got := srv.handshakesWhen(5); len(got) != 5 {
		t.Errorf("server completed %d handshakes (%v), want 5", len(got), got)
	}
}

func TestIdentify_TLS13OnlyListenerReportsOnlyTLS13(t *testing.T) {
	srv := startVersionServer(t, tls.VersionTLS13, tls.VersionTLS13, tls.NoClientCert)
	o, rec := identifyVia(t, 8443, srv.addr, false, IdentifyOptions{})
	if !o.Identified || o.Result == nil {
		t.Fatalf("TLS listener not identified: %+v", o)
	}
	if want := []string{"TLS 1.3"}; !slices.Equal(o.Result.TLSVersions, want) {
		t.Errorf("TLSVersions = %v, want %v", o.Result.TLSVersions, want)
	}
	// The classical-only support offer was made, and the three older versions
	// were each tried, and refused.
	if n := dialsTo(rec, 8443); n != 5 {
		t.Errorf("%d dials to the TLS port, want 5 (1 identify + 1 kex support + 3 refused enumeration)", n)
	}
}

func TestIdentify_NonTLSPortGetsNoEnumeration(t *testing.T) {
	// Accepts and stays silent: the one speculative ClientHello goes unanswered.
	host, port := speakServer(t, func(c net.Conn) {
		buf := make([]byte, 1)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Read(buf)
	})
	o, rec := identifyVia(t, 8080, net.JoinHostPort(host, fmt.Sprint(port)), false, IdentifyOptions{ProbeTimeout: 300 * time.Millisecond})
	if o.Identified {
		t.Fatalf("silent port identified as %q", o.Protocol)
	}
	if n := dialsTo(rec, 8080); n != 1 {
		t.Errorf("%d dials to a non-TLS port, want 1 (no enumeration without a TLS handshake)", n)
	}
}

func TestIdentify_OTPortGetsNoEnumeration(t *testing.T) {
	// Even a TLS listener behind an OT port: no opt-in means no dial at all,
	// and an opt-in runs that protocol's prober once — never TLS, never
	// enumeration.
	srv := startVersionServer(t, tls.VersionTLS10, tls.VersionTLS13, tls.NoClientCert)
	o, rec := identifyVia(t, 502, srv.addr, false, IdentifyOptions{})
	if o.Identified {
		t.Errorf("OT port identified without opt-in")
	}
	if n := dialsTo(rec, 502); n != 0 {
		t.Errorf("%d dials to an OT port without opt-in, want 0", n)
	}
	_, rec = identifyVia(t, 502, srv.addr, false, IdentifyOptions{OTProbes: []string{"Modbus"}, ProbeTimeout: 300 * time.Millisecond})
	if n := dialsTo(rec, 502); n != 1 {
		t.Errorf("%d dials to an opted-in OT port, want 1 (its prober only)", n)
	}
	if got := srv.handshakes(); len(got) != 0 {
		t.Errorf("OT port saw %d TLS handshakes, want 0", len(got))
	}
}

func TestIdentify_OTSuspectHostGetsNoEnumeration(t *testing.T) {
	// 443 speaks TLS, so a suspect host still gets the one handshake — and
	// nothing after it.
	srv := startVersionServer(t, tls.VersionTLS10, tls.VersionTLS13, tls.NoClientCert)
	o, rec := identifyVia(t, 443, srv.addr, true, IdentifyOptions{})
	if !o.Identified || o.Result == nil {
		t.Fatalf("TLS on 443 not identified on a suspect host: %+v", o)
	}
	if n := dialsTo(rec, 443); n != 1 {
		t.Errorf("%d dials to 443 on an OT-suspect host, want 1 (no enumeration)", n)
	}
	if want := []string{"TLS 1.3"}; !slices.Equal(o.Result.TLSVersions, want) {
		t.Errorf("TLSVersions = %v, want only the negotiated %v", o.Result.TLSVersions, want)
	}
}

func TestIdentify_TLSEnumerationStopsWithTheContext(t *testing.T) {
	srv := startVersionServer(t, tls.VersionTLS10, tls.VersionTLS13, tls.NoClientCert)
	enumerate := func(ctx context.Context) (*ProbeResult, *recordingDialer) {
		rec := &recordingDialer{remap: map[uint16]string{8443: srv.addr}}
		id := identifier{run: newIdentifyScanner(t, rec).newRun(ctx, 1), prober: NewProber(time.Second), addr: enumTarget, hostSlot: make(chan struct{}, 1)}
		res := &ProbeResult{TLSVersions: []string{"TLS 1.3"}, Metadata: map[string]interface{}{"tls_version_raw": uint16(tls.VersionTLS13)}}
		id.enumerateTLSVersions(ctx, 8443, res, "")
		return res, rec
	}

	// Control: a live context enumerates the three other versions, through a
	// single per-host slot (each connection is closed before the next).
	if res, rec := enumerate(context.Background()); len(res.TLSVersions) != 4 || dialsTo(rec, 8443) != 3 {
		t.Fatalf("live context: TLSVersions = %v over %d dials, want 4 versions over 3", res.TLSVersions, dialsTo(rec, 8443))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, rec := enumerate(ctx)
	if !slices.Equal(res.TLSVersions, []string{"TLS 1.3"}) {
		t.Errorf("TLSVersions = %v after a cancelled enumeration, want the negotiated version only", res.TLSVersions)
	}
	if n := dialsTo(rec, 8443); n != 0 {
		t.Errorf("%d dials after cancel, want 0", n)
	}
}

// ---- mTLS (V12) ----------------------------------------------------------------

func TestProbeTLS_RecordsWhetherTheServerAskedForAClientCertificate(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth tls.ClientAuthType
		want bool
	}{
		{"requests a client certificate", tls.RequestClientCert, true},
		{"does not", tls.NoClientCert, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startVersionServer(t, tls.VersionTLS12, tls.VersionTLS13, tc.auth)
			o, _ := identifyVia(t, 8443, srv.addr, false, IdentifyOptions{})
			if o.Result == nil {
				t.Fatalf("TLS listener not identified: %+v", o)
			}
			got, present := o.Result.Metadata["server_requests_client_cert"]
			if !present {
				t.Fatal("server_requests_client_cert absent: an explicit answer must be recorded either way")
			}
			if got != tc.want {
				t.Errorf("server_requests_client_cert = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---- the single-endpoint entry point ------------------------------------------

func TestProbeTLSEndpoint_DialsOnlyThroughTheCallersDialer(t *testing.T) {
	srv := startVersionServer(t, tls.VersionTLS12, tls.VersionTLS13, tls.RequestClientCert)
	var mu sync.Mutex
	var asked []string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		asked = append(asked, address)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, srv.addr)
	}
	p := NewProber(2 * time.Second)

	res, err := p.ProbeTLSEndpoint(context.Background(), "192.0.2.20", 8443, TLSEndpointOptions{Hostname: "tls.example.test", Dial: dial, EnumerateVersions: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"TLS 1.3", "TLS 1.2"}; !slices.Equal(res.TLSVersions, want) {
		t.Errorf("TLSVersions = %v, want %v", res.TLSVersions, want)
	}
	if res.Metadata["server_requests_client_cert"] != true {
		t.Errorf("server_requests_client_cert = %v, want true", res.Metadata["server_requests_client_cert"])
	}
	if len(res.Certificates) == 0 || res.CertValidationStatus == "" {
		t.Errorf("certificates/validation missing: %d certs, status %q", len(res.Certificates), res.CertValidationStatus)
	}
	// The support handshakes ran, through Dial like everything else.
	if _, ok := res.Metadata[MetaTLSSupportsClassicalKex]; !ok {
		t.Errorf("%s absent: the key-exchange support handshake did not run", MetaTLSSupportsClassicalKex)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, a := range asked {
		if a != "192.0.2.20:8443" {
			t.Errorf("dialled %q, want only the endpoint 192.0.2.20:8443", a)
		}
	}
	// 1 main + 1 support handshake (a TLS 1.3 server answers the other
	// support question itself, see tlskextest) + 3 enumeration (1.2
	// accepted, 1.1 and 1.0 refused).
	if len(asked) != 5 {
		t.Errorf("%d dials, want 5: the main, support and enumeration handshakes, all through Dial", len(asked))
	}

	// WithoutSupportHandshakes promises one handshake: no support offers and
	// no enumeration, even when asked.
	asked = nil
	mu.Unlock()
	res, err = p.WithoutSupportHandshakes().ProbeTLSEndpoint(context.Background(), "192.0.2.20", 8443, TLSEndpointOptions{Dial: dial, EnumerateVersions: true})
	mu.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 {
		t.Errorf("WithoutSupportHandshakes: %d dials, want exactly 1", len(asked))
	}
	if !slices.Equal(res.TLSVersions, []string{"TLS 1.3"}) {
		t.Errorf("WithoutSupportHandshakes: TLSVersions = %v, want only the negotiated version", res.TLSVersions)
	}
}
