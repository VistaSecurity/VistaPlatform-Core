package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

// A TLS port that refuses the nameless ClientHello may be offered the target's
// known names, one connection each. These pin when that happens (only after a
// TLS alert, never on an OT-suspect host), how much (at most MaxSNICandidates)
// and what is recorded.

// nameRecordingServer is a loopback TLS server that records the server name of
// every ClientHello in arrival order and accepts only the names in accept.
type nameRecordingServer struct {
	addr string
	mu   sync.Mutex
	seen []string
}

func (s *nameRecordingServer) names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func startNameRecordingServer(t *testing.T, accept ...string) *nameRecordingServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: accept[len(accept)-1]},
		DNSNames:     accept,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	named := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	srv := &nameRecordingServer{}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			srv.mu.Lock()
			srv.seen = append(srv.seen, hello.ServerName)
			srv.mu.Unlock()
			for _, a := range accept {
				if hello.ServerName == a {
					return named, nil
				}
			}
			return nil, errors.New("unknown server name")
		},
	}
	host, port := speakServer(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
		_ = tc.Handshake()
	})
	srv.addr = net.JoinHostPort(host, fmt.Sprint(port))
	return srv
}

func TestIdentify_RefusedPortIsTriedWithEachKnownNameUntilOneNegotiates(t *testing.T) {
	srv := startNameRecordingServer(t, "right.example.test")
	o, _ := identifyVia(t, 8443, srv.addr, false, IdentifyOptions{
		SNICandidates: []string{"wrong.example.test", "right.example.test"},
	})

	if o.Result == nil || len(o.Result.Certificates) == 0 || o.Notes != "" {
		t.Fatalf("result=%v notes=%q, want a full TLS result once a name worked", o.Result, o.Notes)
	}
	if got := o.Result.Metadata["sni_used"]; got != "right.example.test" {
		t.Errorf("sni_used=%v, want the name that negotiated", got)
	}
	// 1 nameless + 2 candidates BEFORE any follow-up: the first three hellos
	// are exactly these, in this order. Every later one (key-exchange support,
	// version enumeration) must present the name that worked.
	names := srv.names()
	if len(names) < 3 || !reflect.DeepEqual(names[:3], []string{"", "wrong.example.test", "right.example.test"}) {
		t.Fatalf("first ClientHello names = %q, want [\"\" wrong right]", names)
	}
	for i, n := range names[3:] {
		if n != "right.example.test" {
			t.Errorf("follow-up hello %d presented %q, want the name that worked", i, n)
		}
	}
}

func TestIdentify_NoCandidatesLeavesARefusedPortRefused(t *testing.T) {
	srv := startNameRecordingServer(t, "right.example.test")
	o, _ := identifyVia(t, 8443, srv.addr, false, IdentifyOptions{})
	if o.Notes != "tls-handshake-refused" || o.Result != nil {
		t.Fatalf("notes=%q result=%v, want the refusal recorded as before", o.Notes, o.Result)
	}
	if got := srv.names(); !reflect.DeepEqual(got, []string{""}) {
		t.Errorf("hellos = %q, want exactly the one nameless attempt", got)
	}
}

func TestIdentify_AllCandidatesRefusedKeepsTheRefusal(t *testing.T) {
	srv := startNameRecordingServer(t, "right.example.test")
	o, _ := identifyVia(t, 8443, srv.addr, false, IdentifyOptions{SNICandidates: []string{"a.example.test", "b.example.test"}})
	if o.Notes != "tls-handshake-refused" || o.Result != nil {
		t.Fatalf("notes=%q result=%v, want the refusal when no name worked", o.Notes, o.Result)
	}
	if got := srv.names(); !reflect.DeepEqual(got, []string{"", "a.example.test", "b.example.test"}) {
		t.Errorf("hellos = %q, want nameless then each candidate once", got)
	}
}

func TestIdentify_CandidateListIsTruncatedToThree(t *testing.T) {
	srv := startNameRecordingServer(t, "never.example.test")
	o, _ := identifyVia(t, 8443, srv.addr, false, IdentifyOptions{SNICandidates: []string{
		"a.example.test", "b.example.test", "c.example.test", "d.example.test", "e.example.test",
	}})
	if o.Notes != "tls-handshake-refused" {
		t.Fatalf("notes=%q", o.Notes)
	}
	if got := srv.names(); len(got) != 1+MaxSNICandidates {
		t.Fatalf("%d hellos (%q), want 1 nameless + %d candidates", len(got), got, MaxSNICandidates)
	}
}

func TestIdentify_InvalidCandidatesAreDroppedAndTheRestTried(t *testing.T) {
	srv := startNameRecordingServer(t, "right.example.test")
	o, _ := identifyVia(t, 8443, srv.addr, false, IdentifyOptions{SNICandidates: []string{
		"192.0.2.9", "bad name", "", "-x.example.test", "right.example.test",
	}})
	if o.Result == nil || o.Result.Metadata["sni_used"] != "right.example.test" {
		t.Fatalf("result=%v, want the one valid name used", o.Result)
	}
	if got := srv.names(); len(got) < 2 || !reflect.DeepEqual(got[:2], []string{"", "right.example.test"}) {
		t.Errorf("hellos = %q, want nameless then only the valid name", got)
	}
}

func TestIdentify_NoCandidatesOnAnOTSuspectHost(t *testing.T) {
	srv := startNameRecordingServer(t, "right.example.test")
	o, _ := identifyVia(t, 8443, srv.addr, true, IdentifyOptions{SNICandidates: []string{"right.example.test"}})
	if o.Result != nil {
		t.Fatalf("an OT-suspect host was retried with a name and negotiated: %+v", o.Result)
	}
	if got := srv.names(); !reflect.DeepEqual(got, []string{""}) {
		t.Errorf("hellos = %q, want only the one speculative attempt on a suspect host", got)
	}
}

func TestIdentify_CandidatesAreNotTriedWhenTheFirstAttemptSucceeds(t *testing.T) {
	srv := startNameRecordingServer(t, "right.example.test")
	// The target's own name is presented first, so there is nothing to retry.
	o, _ := identifyVia(t, 8443, srv.addr, false, IdentifyOptions{
		Hostname: "right.example.test", SNICandidates: []string{"other.example.test"},
	})
	if o.Result == nil {
		t.Fatalf("named attempt did not negotiate: %+v", o)
	}
	if _, used := o.Result.Metadata["sni_used"]; used {
		t.Error("sni_used set although the first attempt succeeded")
	}
	for _, n := range srv.names() {
		if n == "other.example.test" {
			t.Error("a candidate was presented although the first attempt succeeded")
		}
	}
}

func TestIdentify_CandidatesAreNotTriedAfterANonTLSFailure(t *testing.T) {
	var mu sync.Mutex
	conns := 0
	host, port := speakServer(t, func(c net.Conn) {
		mu.Lock()
		conns++
		mu.Unlock()
		buf := make([]byte, 512)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(buf); err != nil {
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	})
	o, _ := identifyVia(t, 8443, net.JoinHostPort(host, fmt.Sprint(port)), false, IdentifyOptions{SNICandidates: []string{"a.example.test"}})
	if o.Identified {
		t.Fatalf("plaintext reply identified: %+v", o)
	}
	mu.Lock()
	defer mu.Unlock()
	if conns != 1 {
		t.Errorf("%d connections, want 1: a non-TLS failure earns no name retries", conns)
	}
}

func TestSanitizeSNICandidates(t *testing.T) {
	got := SanitizeSNICandidates([]string{
		" Web.Example.Test. ", "web.example.test", "192.0.2.1", "2001:db8::1", "a b", "", "x..y",
		"under_score.example.test", "-lead.example.test", "b.example.test", "c.example.test", "d.example.test",
	})
	want := []string{"web.example.test", "under_score.example.test", "b.example.test"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
