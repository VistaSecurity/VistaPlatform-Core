package services

// The OCSP responder a scanned server names in its OWN certificate is data the
// server chose. Before W5.13b's review fix (B1), the in-cluster prober
// POSTed to it with a default http.Client — any address, redirects followed —
// so a host being scanned could make the platform send a request to cloud
// instance metadata, loopback or any in-cluster Service. These drive the REAL
// TLSProber.ProbeTLS (adapted from the reviewer's reproduction): a TLS server on
// loopback presents a leaf whose OCSP URL points somewhere the platform must
// never reach, and a recording listener there proves whether anything arrived.
//
// Loopback listeners stand in for "internal". Where a test needs one listener
// to play a PUBLIC responder, it runs on 127.0.0.2 and the prober is built with
// a guard that allows exactly that address — every other refusal is the real
// dispatchguard.PlatformFetchGuard logic's job and is tested directly.

import (
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

func (r *recordingHTTP) count() int32 { return atomic.LoadInt32(&r.hits) }

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

func probe(t *testing.T, p *TLSProber, port int) {
	t.Helper()
	if _, err := p.ProbeTLS("scanned.example.com", "127.0.0.1", port, true); err != nil {
		t.Fatalf("ProbeTLS: %v", err)
	}
}

// onlyAllows is a guard that treats exactly one address as public.
func onlyAllows(hostport string) func(netip.Addr) error {
	host, _, _ := net.SplitHostPort(hostport)
	allowed := netip.MustParseAddr(host)
	return func(a netip.Addr) error {
		if a == allowed {
			return nil
		}
		return errors.New("refused by test guard")
	}
}

func metadataHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("AKIA-not-a-real-key"))
}

// Direct: the certificate names an internal listener outright. The REAL
// NewTLSProber must not reach it.
func TestProbeTLS_OCSPResponderCannotReachInternalAddresses(t *testing.T) {
	internal := listenHTTP(t, "127.0.0.1", metadataHandler)
	for name, url := range map[string]string{
		"literal loopback":  "http://" + internal.addr + "/latest/meta-data/iam/security-credentials/",
		"name → loopback":   "http://localhost:" + portOf(internal.addr) + "/latest/meta-data/",
		"https to loopback": "https://" + internal.addr + "/ocsp",
	} {
		t.Run(name, func(t *testing.T) {
			probe(t, NewTLSProber(5*time.Second), serveLeafWithOCSP(t, url))
			if n := internal.count(); n != 0 {
				t.Fatalf("SSRF: the internal listener received %d request(s) (%v)", n, internal.last.Load())
			}
		})
	}
}

// Redirect: a responder the guard allows answers 302 to an internal URL. The
// responder must be asked (so OCSP still happens) and the internal listener
// must not be.
func TestProbeTLS_OCSPRedirectIsNotFollowed(t *testing.T) {
	internal := listenHTTP(t, "127.0.0.1", metadataHandler)
	responder := listenHTTP(t, "127.0.0.2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+internal.addr+"/latest/meta-data/iam/security-credentials/", http.StatusFound)
	})
	probe(t, newTLSProberWithGuard(5*time.Second, onlyAllows(responder.addr)), serveLeafWithOCSP(t, "http://"+responder.addr+"/ocsp"))
	if responder.count() == 0 {
		t.Fatal("the allowed OCSP responder was never asked — the guard is refusing everything, not just internal addresses")
	}
	if n := internal.count(); n != 0 {
		t.Fatalf("SSRF via redirect: the internal listener received %d request(s) (%v)", n, internal.last.Load())
	}
}

// A redirect is never followed — not even to an address the guard would allow.
// The dialer guard already stops a redirect to an internal address; this pins
// the second, independent layer (CheckRedirect), which also keeps a scanned
// server from bouncing the platform on to a third party of its choosing.
func TestProbeTLS_OCSPRedirectIsNeverFollowed(t *testing.T) {
	onward := listenHTTP(t, "127.0.0.3", metadataHandler)
	responder := listenHTTP(t, "127.0.0.2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+onward.addr+"/ocsp", http.StatusFound)
	})
	allowBoth := func(a netip.Addr) error {
		if onlyAllows(responder.addr)(a) == nil || onlyAllows(onward.addr)(a) == nil {
			return nil
		}
		return errors.New("refused by test guard")
	}
	probe(t, newTLSProberWithGuard(5*time.Second, allowBoth), serveLeafWithOCSP(t, "http://"+responder.addr+"/ocsp"))
	if responder.count() == 0 {
		t.Fatal("the OCSP responder was never asked")
	}
	if n := onward.count(); n != 0 {
		t.Fatalf("a redirect was followed: the onward listener received %d request(s) (%v)", n, onward.last.Load())
	}
}

func portOf(hostport string) string {
	_, p, _ := net.SplitHostPort(hostport)
	return p
}
