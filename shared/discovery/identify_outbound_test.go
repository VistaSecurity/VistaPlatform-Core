package discovery

// Identify's TLS attempt validates the certificate it receives, and validation
// asks the OCSP responder the certificate names — a URL the SCANNED server
// chose. On the platform that fetch must go through the runtime's outbound
// guard (outbound.go), or a scanned host can make the platform send requests
// to loopback, cloud metadata or an in-cluster Service. These pin that
// IdentifyOptions.OutboundGuard reaches that fetch, in both polarities: with no
// guard the responder IS asked (so the fixture really triggers a fetch), with a
// guard that refuses it, it is not. Loopback only.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// ocspTrap is an HTTP listener that counts the requests that reached it.
func ocspTrap(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	var hits atomic.Int32
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String() + "/ocsp", &hits
}

// tlsWithOCSP serves a leaf+CA chain whose leaf names ocspURL, on loopback.
func tlsWithOCSP(t *testing.T, ocspURL string) int {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fixture CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture.example.com"}, DNSNames: []string{"fixture.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), OCSPServer: []string{ocspURL}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); time.Sleep(100 * time.Millisecond); _ = c.Close() }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func identifyTLSWithOCSP(t *testing.T, guard AddressGuard) int32 {
	t.Helper()
	url, hits := ocspTrap(t)
	port := tlsWithOCSP(t, url)
	s, err := NewScanner()
	if err != nil {
		t.Fatal(err)
	}
	h := HostScan{Addr: netip.MustParseAddr("127.0.0.1"), Open: []int{port}, OpenCount: 1}
	obs, err := s.Identify(context.Background(), h, IdentifyOptions{Hostname: "fixture.example.com", BannerWait: 200 * time.Millisecond, OutboundGuard: guard})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Protocol != "TLS" {
		t.Fatalf("observation = %+v, want the TLS listener identified", obs)
	}
	return hits.Load()
}

func TestIdentify_OCSPFetchGoesThroughTheOutboundGuard(t *testing.T) {
	refuseAll := func(netip.Addr) error { return errors.New("refused by test guard") }
	if n := identifyTLSWithOCSP(t, refuseAll); n != 0 {
		t.Fatalf("the OCSP responder the scanned certificate names was asked %d time(s) despite a guard refusing it", n)
	}
}

// The other polarity: without a guard the fixture really does trigger the
// fetch, so the test above is not green merely because nothing was fetched.
func TestIdentify_WithoutAGuardTheOCSPResponderIsAsked(t *testing.T) {
	if n := identifyTLSWithOCSP(t, nil); n == 0 {
		t.Fatal("no OCSP request reached the responder without a guard — the fixture does not exercise the fetch")
	}
}
