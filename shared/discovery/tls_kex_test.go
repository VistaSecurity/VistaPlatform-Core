package discovery

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
)

// The shared prober — what the standalone sensor's active scans and the
// in-cluster Platform Sensor both run — records the negotiated group and the
// server's classical / hybrid support for every fixture server.
func TestProbeTLS_RecordsKeyExchangeGroupAndSupport(t *testing.T) {
	for _, c := range tlskextest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
			res, err := NewProber(3*time.Second).Probe("example.com", srv.Host, "TLS", srv.Port)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			tlskextest.Check(t, c, res.Metadata)
			tlskextest.CheckConnections(t, c, srv)
		})
	}
}

// The support handshakes offer exactly one kind of group each, and the hybrid
// offer is TLS 1.3 only — the hybrid groups exist only there, and a TLS 1.2
// fallback would let a server answer a question the probe did not ask.
func TestProbeTLS_SupportOffersAreDisjointAndHybridIsTLS13Only(t *testing.T) {
	// X25519-only: the main handshake proves classical, so the one extra
	// handshake is the hybrid-only offer.
	srv := tlskextest.Start(t, []tls.CurveID{tls.X25519}, 0)
	if _, err := NewProber(3*time.Second).Probe("example.com", srv.Host, "TLS", srv.Port); err != nil {
		t.Fatalf("probe: %v", err)
	}
	hellos := srv.Hellos()
	if len(hellos) != 2 {
		t.Fatalf("server saw %d ClientHellos, want 2 (main + hybrid-only)", len(hellos))
	}
	hybrid := hellos[1]
	for _, g := range hybrid.Groups {
		if !IsPQCHybridTLSGroup(g) {
			t.Errorf("hybrid-only offer includes non-hybrid group %v", g)
		}
	}
	if len(hybrid.Versions) != 1 || hybrid.Versions[0] != tls.VersionTLS13 {
		t.Errorf("hybrid-only offer versions = %x, want only TLS 1.3 (0x0304)", hybrid.Versions)
	}

	// Hybrid-only: the main handshake proves hybrid, so the extra handshake is
	// the classical-only offer.
	hsrv := tlskextest.Start(t, []tls.CurveID{tls.X25519MLKEM768}, 0)
	if _, err := NewProber(3*time.Second).Probe("example.com", hsrv.Host, "TLS", hsrv.Port); err != nil {
		t.Fatalf("probe: %v", err)
	}
	hh := hsrv.Hellos()
	if len(hh) != 2 {
		t.Fatalf("server saw %d ClientHellos, want 2 (main + classical-only)", len(hh))
	}
	for _, g := range hh[1].Groups {
		if !isClassicalTLSGroup(g) {
			t.Errorf("classical-only offer includes non-classical group %v", g)
		}
	}
}

// The support handshakes share ONE deadline: a peer that stalls them costs the
// probe at most one budget, not one per question, and a question the budget
// ran out before is unknown — absent — never false.
func TestMeasureTLSKeyExchange_StalledPeerSharesOneBudgetAndStaysUnknown(t *testing.T) {
	addr := tlskextest.StartSilent(t)
	dial := func(timeout time.Duration) (net.Conn, error) { return net.DialTimeout("tcp", addr, timeout) }
	// No named group on the main handshake, so BOTH questions are open and both
	// support handshakes are attempted.
	state := tls.ConnectionState{Version: tls.VersionTLS13}
	const budget = 400 * time.Millisecond

	start := time.Now()
	kx := MeasureTLSKeyExchange(state, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}, dial, budget) //nolint:gosec // loopback test
	elapsed := time.Since(start)

	if elapsed > budget+budget/2 {
		t.Errorf("support handshakes took %v against a stalled peer, want at most one shared budget (%v)", elapsed, budget)
	}
	if kx.SupportsClassical != nil {
		t.Errorf("SupportsClassical = %v, want nil (timed out)", *kx.SupportsClassical)
	}
	if kx.SupportsPQCHybrid != nil {
		t.Errorf("SupportsPQCHybrid = %v, want nil (budget exhausted before it could be asked)", *kx.SupportsPQCHybrid)
	}
}

// A prober told to make no support handshakes makes exactly its one handshake
// and still records the group.
func TestProbeTLS_WithoutSupportHandshakes(t *testing.T) {
	for _, c := range tlskextest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
			res, err := NewProber(3*time.Second).WithoutSupportHandshakes().Probe("example.com", srv.Host, "TLS", srv.Port)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if n := srv.Handshakes(); n != 1 {
				t.Errorf("server saw %d connections, want exactly 1", n)
			}
			if res.Metadata[MetaKeyExchangeAlgorithm] != c.WantGroup {
				t.Errorf("key_exchange_algorithm = %v, want %q", res.Metadata[MetaKeyExchangeAlgorithm], c.WantGroup)
			}
			tlskextest.CheckOnlyProvenFlags(t, c, res.Metadata)
		})
	}
}

// E-02: the negotiated suite is not the server's supported set. Nothing here
// enumerates suites, so the probe must not claim a supported set at all.
func TestProbeTLS_DoesNotPresentNegotiatedSuiteAsSupportedSet(t *testing.T) {
	srv := tlskextest.Start(t, []tls.CurveID{tls.X25519}, 0)
	res, err := NewProber(3*time.Second).Probe("example.com", srv.Host, "TLS", srv.Port)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.SelectedCipher == "" {
		t.Fatal("SelectedCipher empty — the negotiated suite must still be recorded")
	}
	if len(res.SupportedCiphers) != 0 {
		t.Errorf("SupportedCiphers = %v, want empty: one negotiated suite is not the supported set", res.SupportedCiphers)
	}
}

// An extra handshake that cannot be made is not a "no". With no way to dial,
// the question the main handshake did not answer stays absent.
func TestMeasureTLSKeyExchange_ErrorIsNotFalse(t *testing.T) {
	state := tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519}
	failingDial := func(time.Duration) (net.Conn, error) { return nil, errors.New("connection refused") }

	kx := MeasureTLSKeyExchange(state, &tls.Config{ServerName: "example.com"}, failingDial, time.Second) //nolint:gosec // test config, never dials
	meta := map[string]interface{}{}
	kx.ApplyTo(meta)

	if meta[MetaTLSSupportsClassicalKex] != true {
		t.Errorf("classical = %v, want true (proved by the main handshake)", meta[MetaTLSSupportsClassicalKex])
	}
	if v, ok := meta[MetaTLSSupportsPQCHybridKex]; ok {
		t.Errorf("tls_supports_pqc_hybrid_kex = %v, want absent — a failed dial says nothing about the server", v)
	}
}

// A server that closes on the hybrid offer without sending an alert has not
// refused the offer; it has told us nothing.
func TestMeasureTLSKeyExchange_SilentCloseIsUnknown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	dial := func(timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout("tcp", ln.Addr().String(), timeout)
	}
	state := tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519}

	kx := MeasureTLSKeyExchange(state, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}, dial, 2*time.Second) //nolint:gosec // loopback test
	if kx.SupportsPQCHybrid != nil {
		t.Errorf("SupportsPQCHybrid = %v, want nil for a close with no alert", *kx.SupportsPQCHybrid)
	}
}

// Unknown stays unknown: an id with no catalogue mapping records the raw id and
// no name. And id 0 (no named group) records nothing at all.
func TestTLSKeyExchange_UnknownGroupRecordsRawIDOnly(t *testing.T) {
	meta := map[string]interface{}{}
	MeasureTLSKeyExchange(tls.ConnectionState{Version: tls.VersionTLS13, CurveID: 0x1234}, nil, nil, 0).ApplyTo(meta)
	if _, ok := meta[MetaKeyExchangeAlgorithm]; ok {
		t.Errorf("key_exchange_algorithm = %v for an unknown group, want absent", meta[MetaKeyExchangeAlgorithm])
	}
	if meta[MetaKeyExchangeGroupRaw] != uint16(0x1234) {
		t.Errorf("key_exchange_group_raw = %v, want 4660", meta[MetaKeyExchangeGroupRaw])
	}

	none := map[string]interface{}{}
	MeasureTLSKeyExchange(tls.ConnectionState{Version: tls.VersionTLS12}, nil, nil, 0).ApplyTo(none)
	if _, ok := none[MetaKeyExchangeGroupRaw]; ok {
		t.Error("key_exchange_group_raw written for CurveID 0 (no named group)")
	}
	if _, ok := none[MetaKeyExchangeAlgorithm]; ok {
		t.Error("key_exchange_algorithm written for CurveID 0 (no named group)")
	}
}

// The mapping must agree with the rest of the platform's opinion of each name:
// hybrids read as post-quantum to the shared family classifier, classical
// groups as elliptic-curve, and every name is one the table maps from the
// right Go constant.
func TestTLSKeyExchangeGroupName_AgreesWithPQCTokenLogic(t *testing.T) {
	want := map[tls.CurveID]struct {
		name   string
		family cryptoparse.KexFamily
	}{
		tls.X25519:             {"X25519", cryptoparse.KexFamilyEllipticCurve},
		tls.CurveP256:          {"DH-ECP-256", cryptoparse.KexFamilyEllipticCurve},
		tls.CurveP384:          {"DH-ECP-384", cryptoparse.KexFamilyEllipticCurve},
		tls.CurveP521:          {"DH-ECP-521", cryptoparse.KexFamilyEllipticCurve},
		tls.X25519MLKEM768:     {"X25519MLKEM768", cryptoparse.KexFamilyPostQuantum},
		tls.SecP256r1MLKEM768:  {"SecP256r1MLKEM768", cryptoparse.KexFamilyPostQuantum},
		tls.SecP384r1MLKEM1024: {"SecP384r1MLKEM1024", cryptoparse.KexFamilyPostQuantum},
	}
	for id, w := range want {
		got := TLSKeyExchangeGroupName(id)
		if got != w.name {
			t.Errorf("TLSKeyExchangeGroupName(%v) = %q, want %q", id, got, w.name)
		}
		if fam := cryptoparse.KeyAlgorithmFamily(got); fam != w.family {
			t.Errorf("%q classifies as %v, want %v", got, fam, w.family)
		}
		if IsPQCHybridTLSGroup(id) != (w.family == cryptoparse.KexFamilyPostQuantum) {
			t.Errorf("IsPQCHybridTLSGroup(%v) = %v", id, IsPQCHybridTLSGroup(id))
		}
	}
}
