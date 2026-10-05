package discovery

// The engine's TLS key-exchange support handshakes ( WP1b): after a
// confirmed TLS handshake, Identify asks the question that handshake left open
// — does the server also accept a classical-only offer, or a hybrid-only one —
// through the run's gate and the scanner's dialer, so its findings carry the
// same tls_supports_classical_kex / tls_supports_pqc_hybrid_kex the legacy
// paths record (the parity harness pins that at finding level).
//
// As in identify_tls_enum_test.go, the engine is told it is talking to a
// documentation address (192.0.2.0/24) and the recording dialer maps the port
// under test onto a 127.0.0.1 listener: a dial that bypassed the injected
// dialer would go to 192.0.2.10 itself and never reach the server.

import (
	"context"
	"crypto/tls"
	"slices"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
)

// kexSupportHellos counts the ClientHellos that were key-exchange support
// offers: a classical-only offer at the default versions, or a hybrid-only
// offer. The identifying hello offers both kinds of group; a forced-version
// enumeration hello offers exactly one version (and below TLS 1.3 crypto/tls
// drops the hybrid groups from it, which is why the version count matters).
func kexSupportHellos(s *tlskextest.Server) int {
	n := 0
	for _, h := range s.Hellos() {
		classical, hybrid := 0, 0
		for _, g := range h.Groups {
			switch {
			case IsPQCHybridTLSGroup(g):
				hybrid++
			case isClassicalTLSGroup(g):
				classical++
			}
		}
		switch {
		case hybrid > 0 && classical == 0:
			n++
		case classical > 0 && hybrid == 0 && len(h.Versions) > 1:
			n++
		}
	}
	return n
}

// identifyKex runs Identify on enumTarget:port with port mapped onto srv.
func identifyKex(t *testing.T, port int, srv *tlskextest.Server, suspect bool) (Observation, *recordingDialer) {
	t.Helper()
	return identifyVia(t, port, srv.Addr, suspect, IdentifyOptions{Hostname: "example.com"})
}

func TestIdentify_TLSKexSupport_HybridNegotiatedServerAlsoAcceptsClassical(t *testing.T) {
	// The configuration both legacy paths answer and the engine used not to:
	// the main handshake negotiates the hybrid group, so only a separate
	// classical-only handshake shows classical is accepted too.
	srv := tlskextest.Start(t, []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}, 0)
	o, rec := identifyKex(t, 8443, srv, false)
	if !o.Identified || o.Result == nil {
		t.Fatalf("TLS listener not identified: %+v", o)
	}
	meta := o.Result.Metadata
	if got, ok := meta[MetaTLSSupportsClassicalKex]; !ok || got != true {
		t.Errorf("%s = %v (present %v), want true", MetaTLSSupportsClassicalKex, got, ok)
	}
	if got := meta[MetaTLSSupportsPQCHybridKex]; got != true {
		t.Errorf("%s = %v, want true (proven by the main handshake)", MetaTLSSupportsPQCHybridKex, got)
	}
	if got := meta[MetaKeyExchangeAlgorithm]; got != "X25519MLKEM768" {
		t.Errorf("%s = %v, want the negotiated X25519MLKEM768", MetaKeyExchangeAlgorithm, got)
	}
	// 1 identifying + 1 classical-only support + 3 enumeration, every one
	// through the engine's dialer.
	if n := dialsTo(rec, 8443); n != 1+1+unitTLSEnumHandshakes {
		t.Errorf("%d dials to the TLS port, want %d (1 identify + 1 kex support + %d enumeration)", n, 1+1+unitTLSEnumHandshakes, unitTLSEnumHandshakes)
	}
	if n := srv.Handshakes(); n != 1+1+unitTLSEnumHandshakes {
		t.Errorf("server saw %d connections, want %d", n, 1+1+unitTLSEnumHandshakes)
	}
	if n := kexSupportHellos(srv); n != 1 {
		t.Errorf("%d key-exchange support offers, want exactly 1 (the classical-only one)", n)
	}
}

func TestIdentify_TLSKexSupport_ClassicalOnlyServerRecordsExplicitFalse(t *testing.T) {
	srv := tlskextest.Start(t, []tls.CurveID{tls.X25519, tls.CurveP256}, 0)
	o, rec := identifyKex(t, 8443, srv, false)
	if !o.Identified || o.Result == nil {
		t.Fatalf("TLS listener not identified: %+v", o)
	}
	meta := o.Result.Metadata
	// An explicit false is an answer (the server refused the hybrid-only
	// offer with an alert) and must be present, not absent.
	got, present := meta[MetaTLSSupportsPQCHybridKex]
	if !present {
		t.Fatalf("%s absent: the hybrid-only support handshake's refusal was not recorded", MetaTLSSupportsPQCHybridKex)
	}
	if got != false {
		t.Errorf("%s = %v, want false", MetaTLSSupportsPQCHybridKex, got)
	}
	if _, ok := meta[MetaTLSPQCHybridKexGroup]; ok {
		t.Errorf("%s written beside a false", MetaTLSPQCHybridKexGroup)
	}
	if got := meta[MetaTLSSupportsClassicalKex]; got != true {
		t.Errorf("%s = %v, want true (proven by the main handshake)", MetaTLSSupportsClassicalKex, got)
	}
	if n := dialsTo(rec, 8443); n != 1+1+unitTLSEnumHandshakes {
		t.Errorf("%d dials to the TLS port, want %d (1 identify + 1 kex support + %d enumeration)", n, 1+1+unitTLSEnumHandshakes, unitTLSEnumHandshakes)
	}
	if n := kexSupportHellos(srv); n != 1 {
		t.Errorf("%d key-exchange support offers, want exactly 1 (the hybrid-only one)", n)
	}
}

func TestIdentify_TLSKexSupport_MatchesEveryFixtureCase(t *testing.T) {
	// The same servers every other live-handshake site is held to: the engine
	// records what they record, with exactly the support handshakes they make.
	for _, c := range tlskextest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
			o, _ := identifyKex(t, 8443, srv, false)
			if !o.Identified || o.Result == nil {
				t.Fatalf("TLS listener not identified: %+v", o)
			}
			tlskextest.Check(t, c, o.Result.Metadata)
			if n := kexSupportHellos(srv); n != c.WantExtraHandshakes {
				t.Errorf("%d key-exchange support offers, want exactly %d", n, c.WantExtraHandshakes)
			}
		})
	}
}

func TestIdentify_TLSKexSupport_NoExtraDialsWithoutAConfirmedHandshake(t *testing.T) {
	hybrid := []tls.CurveID{tls.X25519MLKEM768, tls.X25519}

	t.Run("non-TLS port", func(t *testing.T) {
		silent := tlskextest.StartSilent(t)
		o, rec := identifyVia(t, 8080, silent, false, IdentifyOptions{ProbeTimeout: 300 * time.Millisecond})
		if o.Identified {
			t.Fatalf("silent port identified as %q", o.Protocol)
		}
		if n := dialsTo(rec, 8080); n != 1 {
			t.Errorf("%d dials to a port whose handshake failed, want 1 (no support handshake)", n)
		}
	})

	t.Run("OT port", func(t *testing.T) {
		srv := tlskextest.Start(t, hybrid, 0)
		_, rec := identifyKex(t, 502, srv, false)
		if n := dialsTo(rec, 502); n != 0 {
			t.Errorf("%d dials to an OT port without opt-in, want 0", n)
		}
		_, rec = identifyVia(t, 502, srv.Addr, false, IdentifyOptions{OTProbes: []string{"Modbus"}, ProbeTimeout: 300 * time.Millisecond})
		if n := dialsTo(rec, 502); n != 1 {
			t.Errorf("%d dials to an opted-in OT port, want 1 (its prober only)", n)
		}
		if n := kexSupportHellos(srv); n != 0 {
			t.Errorf("OT port saw %d key-exchange support offers, want 0", n)
		}
	})

	t.Run("OT-suspect host", func(t *testing.T) {
		// 443 speaks TLS, so a suspect host still gets the one handshake —
		// and nothing after it.
		srv := tlskextest.Start(t, hybrid, 0)
		o, rec := identifyKex(t, 443, srv, true)
		if !o.Identified || o.Result == nil {
			t.Fatalf("TLS on 443 not identified on a suspect host: %+v", o)
		}
		if n := dialsTo(rec, 443); n != 1 {
			t.Errorf("%d dials to 443 on an OT-suspect host, want 1", n)
		}
		if _, ok := o.Result.Metadata[MetaTLSSupportsClassicalKex]; ok {
			t.Errorf("%s recorded on an OT-suspect host: a support handshake ran", MetaTLSSupportsClassicalKex)
		}
		if n := kexSupportHellos(srv); n != 0 {
			t.Errorf("OT-suspect host saw %d key-exchange support offers, want 0", n)
		}
	})
}

// hybridNegotiated is a follow-up for a TLS 1.3 handshake that negotiated the
// hybrid group: the one open question is classical support.
func hybridNegotiated() *tlsKexFollowUp {
	return &tlsKexFollowUp{
		state:  tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519MLKEM768},
		config: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test: self-signed fixture
	}
}

func TestIdentify_TLSKexSupportStopsWithTheContext(t *testing.T) {
	srv := tlskextest.Start(t, []tls.CurveID{tls.X25519MLKEM768, tls.X25519}, 0)
	measure := func(ctx context.Context, slots int) (*ProbeResult, *recordingDialer) {
		rec := &recordingDialer{remap: map[uint16]string{8443: srv.Addr}}
		id := identifier{run: newIdentifyScanner(t, rec).newRun(ctx, 1), prober: NewProber(time.Second), addr: enumTarget, hostSlot: make(chan struct{}, slots)}
		res := &ProbeResult{Metadata: map[string]interface{}{}}
		id.measureTLSKeyExchangeSupport(ctx, 8443, res, hybridNegotiated())
		return res, rec
	}

	// Control: a live context asks the classical question once, through a
	// single per-host slot, via the engine's dialer.
	res, rec := measure(context.Background(), 1)
	if res.Metadata[MetaTLSSupportsClassicalKex] != true || dialsTo(rec, 8443) != 1 {
		t.Fatalf("live context: %s = %v over %d dials, want true over 1", MetaTLSSupportsClassicalKex, res.Metadata[MetaTLSSupportsClassicalKex], dialsTo(rec, 8443))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, rec = measure(ctx, 1)
	if v, ok := res.Metadata[MetaTLSSupportsClassicalKex]; ok {
		t.Errorf("%s = %v after cancel, want absent (unanswered, not false)", MetaTLSSupportsClassicalKex, v)
	}
	if n := dialsTo(rec, 8443); n != 0 {
		t.Errorf("%d dials after cancel, want 0", n)
	}
}

func TestIdentify_TLSKexSupportCancellationEndsAStalledHandshake(t *testing.T) {
	// A peer that accepts and never answers: the support handshake would wait
	// out the whole probe timeout, but the unit's context ending must end it
	// at once — and free the per-host slot it held.
	silent := tlskextest.StartSilent(t)
	rec := &recordingDialer{remap: map[uint16]string{8443: silent}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	slots := make(chan struct{}, 1)
	id := identifier{run: newIdentifyScanner(t, rec).newRun(ctx, 1), prober: NewProber(10 * time.Second), addr: enumTarget, hostSlot: slots}
	res := &ProbeResult{Metadata: map[string]interface{}{}}

	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	id.measureTLSKeyExchangeSupport(ctx, 8443, res, hybridNegotiated())
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("support handshake ran %v after the context ended at 200ms; want it cut short", took)
	}
	if v, ok := res.Metadata[MetaTLSSupportsClassicalKex]; ok {
		t.Errorf("%s = %v from a cancelled handshake, want absent", MetaTLSSupportsClassicalKex, v)
	}
	if n := dialsTo(rec, 8443); n != 1 {
		t.Errorf("%d dials, want 1", n)
	}
	if len(slots) != 0 {
		t.Errorf("%d per-host slot(s) still held after the support handshake ended", len(slots))
	}
}

func TestProbeTLSEndpoint_WithoutSupportHandshakesStillMeansOneHandshake(t *testing.T) {
	// The engine's split must not leak into other callers: a prober built
	// WithoutSupportHandshakes still makes no support offer on its own.
	srv := tlskextest.Start(t, []tls.CurveID{tls.X25519MLKEM768, tls.X25519}, 0)
	p := NewProber(2 * time.Second).WithoutSupportHandshakes()
	res, err := p.ProbeTLSEndpoint(context.Background(), srv.Host, srv.Port, TLSEndpointOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := srv.Handshakes(); n != 1 {
		t.Errorf("server saw %d connections, want 1", n)
	}
	if _, ok := res.Metadata[MetaTLSSupportsClassicalKex]; ok {
		t.Errorf("%s recorded without support handshakes", MetaTLSSupportsClassicalKex)
	}
	if !slices.Equal(res.TLSVersions, []string{"TLS 1.3"}) {
		t.Errorf("TLSVersions = %v", res.TLSVersions)
	}
}
