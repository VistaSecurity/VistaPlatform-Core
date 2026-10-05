package services

// Fixtures for the OCSP outbound-guard tests: a TLS server whose leaf names an
// OCSP responder of the test's choosing, and an HTTP listener that counts what
// reached it. The OCSP responder a scanned server names in its OWN certificate
// is data the server chose, so the platform must fetch it only through the
// platform fetch guard ( W5.13b review, B1);
// plan_execution_handler_integration_test.go drives a real scan against these.
// Kept from the deleted TLSProber tests ( WP5).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// recordingHTTP is an HTTP listener that counts what reached it.
type recordingHTTP struct {
	addr string
	hits int32
	last atomic.Value
}

func listenHTTP(t *testing.T, bind string, h func(w http.ResponseWriter, r *http.Request)) *recordingHTTP {
	t.Helper()
	ln, err := net.Listen("tcp", bind+":0")
	if err != nil {
		t.Skipf("cannot listen on %s: %v", bind, err)
	}
	rec := &recordingHTTP{addr: ln.Addr().String()}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&rec.hits, 1)
		rec.last.Store(r.Method + " " + r.URL.Path)
		h(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return rec
}

// serveLeafWithOCSP serves a leaf+CA chain whose leaf names ocspURL as its
// responder, and returns the TLS server's port.
func serveLeafWithOCSP(t *testing.T, ocspURL string) int {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Scanned Host CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "scanned.example.com"}, DNSNames: []string{"scanned.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), OCSPServer: []string{ocspURL}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
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
	_, portS, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portS)
	return port
}
