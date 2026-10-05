package deviceinterrogation

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/internal/dialguard"
	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/discovery/tlsendpointtest"
)

// Characterization of TLSProber's management-port probe ( WP6).
//
// The goldens under testdata/tls_characterization were recorded from
// TLSProber's own private TLS handshake and version enumeration, before they
// moved onto shared/discovery.ProbeTLSEndpoint. The CryptoAsset must stay the
// same for the same server; every difference is a named, justified Exception.
//
// The prober dials through dialguard.Dial, which these tests replace with a
// tlsendpointtest.Dialer: the prober is told the endpoint is
// device.example.test (or, for the address-only scenario, 192.0.2.10) on port
// 443, and the dialer lands each connection on the loopback fixture. The
// fixture's real address is also an alias, because the key-exchange support
// handshakes redial the address the main handshake reached.

const charAddressOnlyTarget = "192.0.2.10"

func charTarget(sc tlsendpointtest.Scenario) string {
	if sc.Target == "" {
		return charAddressOnlyTarget
	}
	return sc.Target
}

// withDialer routes dialguard.Dial through d for one test.
func withDialer(t *testing.T, d *tlsendpointtest.Dialer) {
	t.Helper()
	saved := dialguard.Dial
	dialguard.Dial = func(timeout time.Duration) func(ctx context.Context, network, address string) (net.Conn, error) {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
			return d.DialContext(ctx, network, address)
		}
	}
	t.Cleanup(func() { dialguard.Dial = saved })
}

// managementProbe is what both callers (UniFi's management interface, the
// HTTP interrogator) do: probe, and record every TLS version the server
// accepts. (Before WP6 it was ProbeTLS followed by a separate
// EnumerateTLSVersions; the goldens were recorded from that pair.)
func managementProbe(p *TLSProber, host string, port int) (*CryptoAsset, error) {
	return p.ProbeTLSWithVersions(host, port)
}

type tlsProberRun struct {
	asset  *CryptoAsset
	dialer *tlsendpointtest.Dialer
	srv    *tlsendpointtest.Server
}

func runTLSProber(t *testing.T, sc tlsendpointtest.Scenario, withVersions bool) tlsProberRun {
	t.Helper()
	srv := tlsendpointtest.Start(t, sc)
	d := tlsendpointtest.NewDialer(srv.Addr, tlsendpointtest.HostPort(charTarget(sc), 443), srv.Addr)
	withDialer(t, d)
	p := &TLSProber{timeout: 3 * time.Second}
	var asset *CryptoAsset
	var err error
	if withVersions {
		asset, err = managementProbe(p, charTarget(sc), 443)
	} else {
		asset, err = p.ProbeTLS(charTarget(sc), 443)
	}
	if err != nil {
		t.Fatalf("probe %s: %v", sc.Name, err)
	}
	return tlsProberRun{asset: asset, dialer: d, srv: srv}
}

func TestTLSProber_Characterization(t *testing.T) {
	for _, sc := range tlsendpointtest.Scenarios {
		for _, withVersions := range []bool{false, true} {
			name := sc.Name + "-probe"
			if withVersions {
				name = sc.Name + "-with-versions"
			}
			t.Run(name, func(t *testing.T) {
				r := runTLSProber(t, sc, withVersions)
				got := tlsendpointtest.Dump(*r.asset, tlsendpointtest.Certs(t).Tokens())
				tlsendpointtest.CheckGolden(t, filepath.Join("testdata", "tls_characterization", name+".json"),
					got, tlsProberExceptions(t, sc)...)
			})
		}
	}
}

// Every connection TLSProber makes — the handshake, the key-exchange support
// handshakes and, with versions, the version enumeration — goes through the
// appliance dial guard (dialguard.Dial). The guard must make exactly the
// connections the scenario needs and the server must see none it did not
// make.
func TestTLSProber_EveryConnectionGoesThroughTheDialGuard(t *testing.T) {
	for _, sc := range tlsendpointtest.Scenarios {
		t.Run(sc.Name+"/probe", func(t *testing.T) {
			r := runTLSProber(t, sc, false)
			tlsendpointtest.CheckEveryConnectionDialed(t, r.dialer, r.srv, 1+sc.SupportHandshakes())
		})
		t.Run(sc.Name+"/with-versions", func(t *testing.T) {
			r := runTLSProber(t, sc, true)
			tlsendpointtest.CheckEveryConnectionDialed(t, r.dialer, r.srv, 1+sc.SupportHandshakes()+tlsendpointtest.RefusedVersions)
			// Only the first connection asks for the name; the support
			// handshakes and the enumeration go to the address it reached.
			dials := r.dialer.Dials()
			if want := tlsendpointtest.HostPort(charTarget(sc), 443); dials[0] != want {
				t.Errorf("first dial = %s, want %s", dials[0], want)
			}
			for _, a := range dials[1:] {
				if a != r.srv.Addr {
					t.Errorf("later dial = %s, want the reached address %s", a, r.srv.Addr)
				}
			}
		})
	}
}

// The OCSP query certificate validation makes goes through a guard that
// refuses everything but public addresses: the responder URL is the probed
// device's data, and this prober runs inside the platform.
func TestTLSProber_OCSPGuardRefusesInternalAddresses(t *testing.T) {
	guard := tlsprobeOCSPGuard()
	for _, s := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "::1"} {
		if guard(netip.MustParseAddr(s)) == nil {
			t.Errorf("OCSP guard allowed %s", s)
		}
	}
	if err := guard(netip.MustParseAddr("203.0.113.9")); err != nil {
		t.Errorf("OCSP guard refused a public address: %v", err)
	}
}

// The guard is WIRED: a probed device whose certificate names a loopback OCSP
// responder gets no request out of TLSProber. The control run first proves the
// fixture really triggers an OCSP query from an unguarded shared prober, so
// the zero below is not a fixture that never asks.
func TestTLSProber_OCSPGuardIsWired(t *testing.T) {
	var hits atomic.Int32
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(responder.Close)
	srv := tlsendpointtest.StartWithOCSPResponder(t, responder.URL)

	if _, err := discovery.NewProber(3*time.Second).ProbeTLSEndpoint(context.Background(), "127.0.0.1", srv.Port,
		discovery.TLSEndpointOptions{Hostname: tlsendpointtest.Name}); err != nil {
		t.Fatalf("control probe: %v", err)
	}
	if hits.Load() == 0 {
		t.Fatal("control: an unguarded prober made no OCSP request — the fixture does not exercise the guard")
	}
	hits.Store(0)

	d := tlsendpointtest.NewDialer(srv.Addr, tlsendpointtest.HostPort(tlsendpointtest.Name, 443), srv.Addr)
	withDialer(t, d)
	if _, err := (&TLSProber{timeout: 3 * time.Second}).ProbeTLS(tlsendpointtest.Name, 443); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("TLSProber sent %d OCSP request(s) to a loopback responder named by the device's certificate", n)
	}
}

// tlsProberExceptions are the intended differences between TLSProber's
// previous private handshake (and separate version enumeration) and the
// shared probe, for scenario sc. Nothing else may differ: not the
// certificates, the key size, the key exchange, the negotiated or enumerated
// versions, nor any other field.
func tlsProberExceptions(t testing.TB, sc tlsendpointtest.Scenario) []tlsendpointtest.Exception {
	asset := func(g map[string]any) map[string]any {
		m, _ := tlsendpointtest.Node(g, "deviceinterrogation.CryptoAsset")
		return m
	}
	meta := func(g map[string]any) map[string]any {
		m, _ := tlsendpointtest.Node(g, "deviceinterrogation.CryptoAsset", "Metadata", "map[string]interface {}")
		return m
	}
	ptr := func(g map[string]any, field string) map[string]any {
		m, _ := tlsendpointtest.Node(g, "deviceinterrogation.CryptoAsset", field)
		return m
	}

	var ex []tlsendpointtest.Exception
	if sc.Name == "tls12-ecdsa-cbc" {
		ex = append(ex, tlsendpointtest.Exception{
			Name: "cipher suite named, not Unknown-0xC009",
			Why: "the private name table lacked the ECDHE-ECDSA CBC suites a default Go client still offers; the " +
				"shared name falls back to crypto/tls's IANA name, which is what the sensor TLS enricher always reported.",
			Apply: func(g map[string]any) bool {
				cs := ptr(g, "CipherSuite")
				if cs["*string"] != "string=Unknown-0xC009" {
					return false
				}
				cs["*string"] = "string=TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
				return true
			},
		})
	}
	ex = append(ex, tlsendpointtest.Exception{
		Name: "shared probe wire keys",
		Why: "the shared probe's metadata carries tls_version_raw, cipher_suite_raw and tls_fingerprint (the " +
			"negotiated version and suite as wire values); negotiated_protocol was already recorded.",
		Apply: func(g map[string]any) bool {
			m := meta(g)
			delete(m, "negotiated_protocol") // already present with the same value; re-added below
			return tlsendpointtest.AddSharedProbeWireKeys(m,
				tlsendpointtest.Leaf(ptr(g, "ProtocolVersion")["*string"]), tlsendpointtest.Leaf(ptr(g, "CipherSuite")["*string"]))
		},
	}, tlsendpointtest.Exception{
		Name: "certificate quality flags in metadata",
		Why: "the private handshake computed no quality flags; the shared probe records the same flags every " +
			"other TLS probe path does (SCT, known-bad CA, weak signature/key, incomplete chain, EV ...).",
		Apply: func(g map[string]any) bool { return tlsendpointtest.AddQualityFlags(t, meta(g), sc) },
	})
	if sc.Name != "tls13-client-cert-requested" {
		ex = append(ex, tlsendpointtest.Exception{
			Name: "server_requests_client_cert recorded",
			Why: "the private handshake did not record whether the server asked for a client certificate; the " +
				"shared probe always does, an explicit false when it did not ask (CLAUDE.md \"empty never wins\").",
			Apply: func(g map[string]any) bool {
				return tlsendpointtest.SetIfAbsent(meta(g), "server_requests_client_cert", "bool=false")
			},
		})
	} else {
		ex = append(ex, tlsendpointtest.Exception{
			Name: "server_requests_client_cert recorded (true)",
			Why:  "this server asks for a client certificate; the shared probe records that (mTLS configured).",
			Apply: func(g map[string]any) bool {
				return tlsendpointtest.SetIfAbsent(meta(g), "server_requests_client_cert", "bool=true")
			},
		})
	}

	switch sc.Name {
	case "tls12-rsa", "tls12-ecdsa-cbc", "tls13-ecdsa", "tls13-client-cert-requested":
		ex = append(ex, tlsendpointtest.Exception{
			Name: "chain validated with the presented certificates",
			Why: "the private check verified the leaf with no intermediate pool, so it never followed the chain " +
				"the server sent (a server with a valid intermediate read as untrusted_ca). The shared validation " +
				"uses the presented chain, as every other probe path does; this chain ends in a presented, " +
				"untrusted self-signed root, which the shared classifier reports as self_signed — what the sensor " +
				"and the Platform Sensor report for the same server.",
			Apply: func(g map[string]any) bool {
				a := asset(g)
				if a["CertValidationStatus"] != "string=untrusted_ca" {
					return false
				}
				a["CertValidationStatus"] = "string=self_signed"
				return true
			},
		})
	case "address-only":
		ex = append(ex, tlsendpointtest.Exception{
			Name: "address target not reported as hostname_mismatch",
			Why: "the private check passed the dialled IP as the DNS name, so every certificate without that IP " +
				"in its SANs — almost every valid one — read as hostname_mismatch. The shared probe resolves an " +
				"address identity against the leaf (discovery.ResolveVerifyHost), as the sensor and the Platform " +
				"Sensor do; the chain then fails on its untrusted root (self_signed, see the chain exception).",
			Apply: func(g map[string]any) bool {
				a := asset(g)
				if a["CertValidationStatus"] != "string=hostname_mismatch" {
					return false
				}
				a["CertValidationStatus"] = "string=self_signed"
				a["CertValidationError"] = "string=x509: certificate signed by unknown authority"
				return true
			},
		})
	}
	return ex
}
