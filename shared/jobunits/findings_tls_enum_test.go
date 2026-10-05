package jobunits

// A planned job's TLS finding carries the supported versions and the mTLS
// answer under the keys the legacy probe paths use ( WP1): driven through
// the real UnitEngine → Findings path, not a hand-built ProbeResult, so
// removing the engine's enumeration or the probe's mTLS wiring fails here.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// remapDialer sends every dial for the documentation address to one loopback
// listener, and refuses anything else.
type remapDialer struct {
	want netip.AddrPort
	to   string
}

func (d remapDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ap, err := netip.ParseAddrPort(address); err != nil || ap != d.want {
		return nil, &net.OpError{Op: "dial", Net: network, Err: net.ErrClosed}
	}
	return (&net.Dialer{}).DialContext(ctx, network, d.to)
}

// tlsListener serves TLS 1.0–1.3 on 127.0.0.1 at an ephemeral port.
func tlsListener(t *testing.T, auth tls.ClientAuthType) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tls.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS10, ClientAuth: auth}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			go func() {
				defer func() { _ = c.Close() }()
				tc := tls.Server(c, cfg)
				_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
				_ = tc.Handshake()
			}()
		}
	}()
	return ln.Addr().String()
}

func plannedTLSFinding(t *testing.T, auth tls.ClientAuthType) Finding {
	t.Helper()
	target := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.30"), 8443)
	engine, err := shareddisc.NewUnitEngine(shareddisc.PaceNormal, nil, nil, shareddisc.WithDialer(remapDialer{want: target, to: tlsListener(t, auth)}))
	if err != nil {
		t.Fatal(err)
	}
	ports, err := shareddisc.NewPortSet(int(target.Port()))
	if err != nil {
		t.Fatal(err)
	}
	out, err := engine.Run(context.Background(), shareddisc.UnitInput{Addr: target.Addr(), TCP: ports})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range Findings(target.Addr().String(), "", out) {
		if f.Port == int(target.Port()) && f.Protocol == "TLS" {
			return f
		}
	}
	t.Fatalf("no TLS finding on %s: %+v", target, out.TCP)
	return Finding{}
}

func TestPlannedTLSFinding_CarriesEnumeratedVersions(t *testing.T) {
	f := plannedTLSFinding(t, tls.NoClientCert)
	want := []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"}
	if got, _ := f.Data["tls_versions"].([]string); !slices.Equal(got, want) {
		t.Errorf("tls_versions = %v, want %v", f.Data["tls_versions"], want)
	}
	if f.Data["version"] != "TLS 1.3" {
		t.Errorf("version = %v, want the negotiated TLS 1.3", f.Data["version"])
	}
}

func TestPlannedTLSFinding_CarriesTheMTLSAnswerEitherWay(t *testing.T) {
	for auth, want := range map[tls.ClientAuthType]bool{tls.RequestClientCert: true, tls.NoClientCert: false} {
		t.Run(strconv.FormatBool(want), func(t *testing.T) {
			f := plannedTLSFinding(t, auth)
			got, present := f.Data["server_requests_client_cert"]
			if !present || got != want {
				t.Errorf("server_requests_client_cert = %v (present %v), want %v", got, present, want)
			}
		})
	}
}
