package services

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

	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/discovery/tlsendpointtest"
)

// Characterization of the cloud handshake's TLSHandshakeResult ( WP6).
//
// The goldens under testdata/tls_characterization were recorded from
// TLSHandshakeService's own private TLS handshake and certificate converter,
// before they moved onto shared/discovery.ProbeTLSEndpoint and the shared
// certificate extractor. Every consumer of TLSHandshakeResult (the cloud
// collectors, EnrichCertificatesWithACM) must keep getting the same values
// under the same keys; every difference is a named, justified Exception.
//
// handshakeTo takes the SNI name and the dial address separately, so the
// collector-facing name (device.example.test, or 192.0.2.10 for an endpoint
// the cloud API reported only by address) is presented while the connection
// lands on the loopback fixture.

const charCloudAddressOnly = "192.0.2.10"

func charCloudName(sc tlsendpointtest.Scenario) string {
	if sc.Target == "" {
		return charCloudAddressOnly
	}
	return sc.Target
}

func dumpHandshake(t *testing.T, r *TLSHandshakeResult) map[string]any {
	t.Helper()
	if r == nil {
		t.Fatal("nil result")
	}
	// Validation ( item 3) did not exist when these goldens were
	// recorded; TestTLSHandshake_CarriesCertificateValidation pins it.
	c := *r
	c.Validation = nil
	r = &c
	return tlsendpointtest.Dump(*r, tlsendpointtest.Certs(t).Tokens()).(map[string]any)
}

func TestTLSHandshake_Characterization(t *testing.T) {
	for _, sc := range tlsendpointtest.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			srv := tlsendpointtest.Start(t, sc)
			r, err := NewTLSHandshakeService(3*time.Second).handshakeTo(context.Background(), charCloudName(sc), srv.Addr)
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
			tlsendpointtest.CheckGolden(t, filepath.Join("testdata", "tls_characterization", sc.Name+".json"),
				dumpHandshake(t, r), handshakeExceptions(sc.Name)...)
		})
	}

	t.Run("connection-refused", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		r, err := NewTLSHandshakeService(3*time.Second).handshakeTo(context.Background(), tlsendpointtest.Name, addr)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		tlsendpointtest.CheckGolden(t, filepath.Join("testdata", "tls_characterization", "connection-refused.json"),
			dumpHandshake(t, r), handshakeExceptions("connection-refused")...)
	})

	t.Run("not-tls", func(t *testing.T) {
		srv := tlsendpointtest.StartGarbage(t)
		r, err := NewTLSHandshakeService(3*time.Second).handshakeTo(context.Background(), tlsendpointtest.Name, srv.Addr)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		tlsendpointtest.CheckGolden(t, filepath.Join("testdata", "tls_characterization", "not-tls.json"),
			dumpHandshake(t, r), handshakeExceptions("not-tls")...)
	})
}

// Every connection the cloud handshake makes — the handshake and its
// key-exchange support handshakes — goes through the service's dial, and the
// support handshakes ask for the ADDRESS the first connection reached, never
// the name again.
func TestTLSHandshake_EveryConnectionGoesThroughTheDial(t *testing.T) {
	for _, sc := range tlsendpointtest.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			srv := tlsendpointtest.Start(t, sc)
			const lb = "lb.example.test:443"
			d := tlsendpointtest.NewDialer(srv.Addr, lb, srv.Addr)
			s := NewTLSHandshakeService(3 * time.Second)
			s.dial = d.DialContext
			r, err := s.handshakeTo(context.Background(), charCloudName(sc), lb)
			if err != nil || r == nil || !r.Success {
				t.Fatalf("handshake: %+v, %v", r, err)
			}
			tlsendpointtest.CheckEveryConnectionDialed(t, d, srv, 1+sc.SupportHandshakes())
			dials := d.Dials()
			if dials[0] != lb {
				t.Errorf("first dial = %s, want the name %s", dials[0], lb)
			}
			for _, a := range dials[1:] {
				if a != srv.Addr {
					t.Errorf("support dial = %s, want the reached address %s", a, srv.Addr)
				}
			}
		})
	}
}

// The OCSP query the shared probe makes goes through the platform fetch
// guard: a probed server's certificate cannot point this in-cluster service at
// loopback, the metadata service or private space.
func TestTLSHandshake_OCSPGuardRefusesInternalAddresses(t *testing.T) {
	guard := platformFetchGuard()
	for _, s := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "::1"} {
		if guard(netip.MustParseAddr(s)) == nil {
			t.Errorf("OCSP guard allowed %s", s)
		}
	}
}

// The guard is WIRED: an endpoint whose certificate names a loopback OCSP
// responder gets no request out of the cloud handshake. The control run first
// proves the fixture really triggers an OCSP query from an unguarded shared
// prober, so the zero below is not a fixture that never asks.
func TestTLSHandshake_OCSPGuardIsWired(t *testing.T) {
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

	r, err := NewTLSHandshakeService(3*time.Second).handshakeTo(context.Background(), tlsendpointtest.Name, srv.Addr)
	if err != nil || r == nil || !r.Success {
		t.Fatalf("handshake: %+v, %v", r, err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("cloud handshake sent %d OCSP request(s) to a loopback responder named by the endpoint's certificate", n)
	}
}

// handshakeExceptions are the intended differences between the service's
// previous private handshake and the shared probe, for one case. Nothing else
// may differ: not the certificate map keys or any other value, the version,
// ALPN, the key-exchange measurement, nor the error texts.
func handshakeExceptions(name string) []tlsendpointtest.Exception {
	ex := []tlsendpointtest.Exception{{
		Name: "Validation field exists",
		Why: "TLSHandshakeResult gained Validation (#2268 item 3) after these goldens were recorded. " +
			"dumpHandshake blanks it so these goldens keep describing the other fields; " +
			"TestTLSHandshake_CarriesCertificateValidation pins its values.",
		Apply: func(g map[string]any) bool {
			m, _ := tlsendpointtest.Node(g, "services.TLSHandshakeResult")
			return tlsendpointtest.SetIfAbsent(m, "Validation", "map[string]interface {}=nil")
		},
	}}
	switch name {
	case "tls12-ecdsa-cbc", "tls13-ecdsa", "tls13-client-cert-requested":
		ex = append(ex, tlsendpointtest.Exception{
			Name: "legacy server-gated-crypto EKUs named",
			Why: "the private extended-key-usage table stopped at OCSPSigning, so the Microsoft and Netscape " +
				"server-gated-crypto EKUs read Unknown(10)/Unknown(11); the shared extractor " +
				"(certificates.ExtractExtendedKeyUsage) names them, as the sensor and the Platform Sensor always have.",
			Apply: func(g map[string]any) bool {
				certs, _ := tlsendpointtest.List(g, "services.TLSHandshakeResult", "Certificates", "[]map[string]interface {}")
				changed := false
				for _, c := range certs {
					cm, _ := c.(map[string]any)
					m, _ := tlsendpointtest.Node(cm, "map[string]interface {}")
					ekus, _ := tlsendpointtest.List(m, "extended_key_usage", "[]string")
					for i, e := range ekus {
						switch e {
						case "string=Unknown(10)":
							ekus[i], changed = "string=MicrosoftServerGatedCrypto", true
						case "string=Unknown(11)":
							ekus[i], changed = "string=NetscapeServerGatedCrypto", true
						}
					}
				}
				return changed
			},
		})
	}
	if name == "tls12-ecdsa-cbc" {
		ex = append(ex, tlsendpointtest.Exception{
			Name: "cipher suite named, not Unknown-0xC009",
			Why: "the private name table lacked the ECDHE-ECDSA CBC suites a default Go client still offers; the " +
				"shared name falls back to crypto/tls's IANA name, which is what the sensor TLS enricher always reported.",
			Apply: func(g map[string]any) bool {
				m, _ := tlsendpointtest.Node(g, "services.TLSHandshakeResult")
				if m["CipherSuite"] != "string=Unknown-0xC009" {
					return false
				}
				m["CipherSuite"] = "string=TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
				return true
			},
		})
	}
	return ex
}
