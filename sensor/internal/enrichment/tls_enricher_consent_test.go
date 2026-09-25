package enrichment

import (
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
)

// Whose endpoints the enricher may handshake with ( W5.13, owner decision
// Q10: "we never want to, by default, run a blanket scan on third parties").
//
// Every test here drives the REAL entry point — MaybeEnrich with a passive TLS
// discovery — and then runs whatever it queued through the real worker step,
// counting the connections a loopback fixture server ACCEPTS. A withheld probe
// must produce zero connections, not merely an empty queue: the queue is an
// implementation detail, the connection is what a third party sees.
//
// Destinations are RFC 5737 documentation addresses (never owned by address
// class) or RFC 1918; the dial seam lands every connection on the fixture.

func redirectTo(host string, port int) func(string, time.Duration) (net.Conn, error) {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	return func(_ string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout("tcp", target, timeout)
	}
}

type consentFixture struct {
	srv *tlskextest.Server
	cfg *config.Config
	e   *TLSEnricher
	out chan *models.CryptoDiscovery
}

func newConsentFixture(t *testing.T, optIn bool, owned *OwnedNetworks) *consentFixture {
	t.Helper()
	srv := tlskextest.Start(t, []tls.CurveID{tls.X25519}, 0)
	cfg := &config.Config{Capture: config.CaptureConfig{ActiveProbing: true, ThirdPartyTLSEnrichment: optIn}}
	out := make(chan *models.CryptoDiscovery, 16)
	e := NewTLSEnricher(cfg, "sensor-1", out, owned)
	e.dial = redirectTo(srv.Host, srv.Port)
	return &consentFixture{srv: srv, cfg: cfg, e: e, out: out}
}

// observe feeds one passive TLS observation of ip:port through MaybeEnrich and
// runs everything it queued, returning how many connections the fixture
// accepted as a result.
func (f *consentFixture) observe(ip string, port int) int {
	before := f.srv.Handshakes()
	f.e.MaybeEnrich(&models.CryptoDiscovery{
		DiscoveryMethod: "passive",
		Protocol:        "TLS",
		SourceIP:        "10.0.0.5",
		DestIP:          ip,
		Port:            port,
		Version:         "TLS 1.3",
		RawMetadata:     map[string]interface{}{"handshake_types": []string{"ClientHello"}},
	})
	for len(f.e.queue) > 0 {
		f.e.probeAndEmit(<-f.e.queue)
	}
	return f.srv.Handshakes() - before
}

// (a) A third party, opt-in off (the default): zero connections. This is the
// behaviour change — the enricher used to handshake with every destination.
func TestConsent_ThirdPartyNotProbedByDefault(t *testing.T) {
	f := newConsentFixture(t, false, nil)
	// Refused at observation time, not merely at dial time: nothing is queued,
	// so nothing is marked as probed either.
	f.e.MaybeEnrich(&models.CryptoDiscovery{
		DiscoveryMethod: "passive", Protocol: "TLS", DestIP: "198.51.100.7", Port: 443,
		RawMetadata: map[string]interface{}{"handshake_types": []string{"ClientHello"}},
	})
	if len(f.e.queue) != 0 {
		t.Fatalf("a third-party probe was queued with the opt-in off")
	}
	if n := f.observe("198.51.100.7", 443); n != 0 {
		t.Errorf("third party saw %d connections with the opt-in off, want 0", n)
	}
	if _, _, _, withheld := f.stats(); withheld != 2 {
		t.Errorf("withheld = %d, want both observations counted", withheld)
	}
}

// (b) The tenant opted in: the third party is probed — once, with no extra
// support handshakes (see TestTLSEnricher_ThirdPartyDestinationGetsNoSupportHandshakes).
func TestConsent_ThirdPartyProbedWhenTenantOptsIn(t *testing.T) {
	f := newConsentFixture(t, true, nil)
	if n := f.observe("198.51.100.7", 443); n != 1 {
		t.Errorf("third party saw %d connections with the opt-in on, want exactly 1", n)
	}
	select {
	case d := <-f.out:
		if d.DestIP != "198.51.100.7" {
			t.Errorf("enrichment discovery for %s, want 198.51.100.7", d.DestIP)
		}
	default:
		t.Error("the probe emitted no enrichment discovery")
	}
}

// (c) A private destination is the tenant's own and is probed with the opt-in
// off. The owned case must stay probed, or the fix degrades into "no
// enrichment at all".
func TestConsent_PrivateDestinationProbed(t *testing.T) {
	f := newConsentFixture(t, false, nil)
	if n := f.observe("10.0.0.20", 443); n < 1 {
		t.Errorf("private destination saw %d connections, want it probed", n)
	}
}

// (d) Inside a public prefix the tenant DECLARED as a network segment: owned,
// probed with the opt-in off.
func TestConsent_DeclaredPublicPrefixProbed(t *testing.T) {
	owned := NewOwnedNetworks()
	owned.Update(&probeconsent.OwnedNetworks{Prefixes: []string{"203.0.113.0/24"}})
	f := newConsentFixture(t, false, owned)
	if n := f.observe("203.0.113.5", 443); n < 1 {
		t.Errorf("declared destination saw %d connections, want it probed", n)
	}
	// And the prefix is the boundary: a neighbour outside it is a third party.
	if n := f.observe("198.51.100.7", 443); n != 0 {
		t.Errorf("destination outside the declared prefix saw %d connections, want 0", n)
	}
}

// (e) Inside a LEARNED public prefix: not probed. The platform never sends a
// learned segment (pinned platform-side by
// TestIntegration_SensorHeartbeatCarriesThirdPartyConsent), so on the sensor a
// learned 198.51.100.0/24 is simply absent from what it was given — and an
// address in it is a third party like any other.
func TestConsent_LearnedPublicPrefixNotProbed(t *testing.T) {
	owned := NewOwnedNetworks()
	// What the platform sends for a tenant with declared 203.0.113.0/24 and a
	// learned 198.51.100.0/24: only the declared one.
	owned.Update(&probeconsent.OwnedNetworks{Prefixes: []string{"203.0.113.0/24"}})
	f := newConsentFixture(t, false, owned)
	if n := f.observe("198.51.100.7", 443); n != 0 {
		t.Errorf("destination in a learned prefix saw %d connections, want 0", n)
	}
}

// (f) An older platform sends neither the opt-in nor the owned networks: the
// sensor treats the opt-in as off and only private space as owned. A nil
// update — the same silence — changes nothing, in either direction.
func TestConsent_OlderPlatformProbesOnlyPrivateSpace(t *testing.T) {
	owned := NewOwnedNetworks()
	owned.Update(nil) // the reply carried no owned_networks
	f := newConsentFixture(t, false, owned)
	if n := f.observe("203.0.113.5", 443); n != 0 {
		t.Errorf("public destination saw %d connections from a sensor told nothing, want 0", n)
	}
	if n := f.observe("10.0.0.21", 443); n < 1 {
		t.Errorf("private destination saw %d connections, want it probed", n)
	}

	// Silence after a real statement keeps the statement.
	owned.Update(&probeconsent.OwnedNetworks{Prefixes: []string{"203.0.113.0/24"}})
	owned.Update(nil)
	if n := f.observe("203.0.113.6", 443); n < 1 {
		t.Errorf("declared destination saw %d connections after a silent beat, want it still owned", n)
	}
}

// An elevated connection is "configured within their own tenant": that one
// endpoint is probed, not every port on the vendor's host.
func TestConsent_ElevatedEndpointProbed(t *testing.T) {
	owned := NewOwnedNetworks()
	f := newConsentFixture(t, false, owned)
	owned.Update(&probeconsent.OwnedNetworks{Endpoints: []string{probeconsent.EndpointString("198.51.100.7", f.srv.Port)}})
	if n := f.observe("198.51.100.7", f.srv.Port); n < 1 {
		t.Errorf("elevated endpoint saw %d connections, want it probed", n)
	}
	if n := f.observe("198.51.100.7", 443); n != 0 {
		t.Errorf("another port on the elevated host saw %d connections, want 0", n)
	}
}

// An exclusion (a segment marked sensitive or active-probes-disabled, or an
// automatic-scan exclusion) beats both ownership and the opt-in.
func TestConsent_ExclusionBeatsOwnershipAndOptIn(t *testing.T) {
	owned := NewOwnedNetworks()
	owned.Update(&probeconsent.OwnedNetworks{
		Prefixes: []string{"203.0.113.0/24"},
		Excluded: []string{"203.0.113.0/28", "10.9.0.0/16"},
	})
	f := newConsentFixture(t, true, owned)
	for _, ip := range []string{"203.0.113.5", "10.9.1.1"} {
		if n := f.observe(ip, 443); n != 0 {
			t.Errorf("excluded %s saw %d connections, want 0", ip, n)
		}
	}
}

// The worker asks again at dial time. A probe queued while the opt-in was on
// must not go out if the tenant switched it off before a worker picked it up.
func TestConsent_OptInWithdrawnBeforeTheWorkerRuns(t *testing.T) {
	f := newConsentFixture(t, true, nil)
	f.e.MaybeEnrich(&models.CryptoDiscovery{
		DiscoveryMethod: "passive", Protocol: "TLS", DestIP: "198.51.100.7", Port: 443,
		RawMetadata: map[string]interface{}{"handshake_types": []string{"ClientHello"}},
	})
	if len(f.e.queue) != 1 {
		t.Fatalf("queue = %d, want the opted-in probe queued", len(f.e.queue))
	}
	f.cfg.SetThirdPartyTLSEnrichment(false)
	f.e.probeAndEmit(<-f.e.queue)
	if n := f.srv.Handshakes(); n != 0 {
		t.Errorf("third party saw %d connections after the opt-in was withdrawn, want 0", n)
	}
	// Withheld, so not marked probed: turning the opt-in back on enriches it
	// at its next observation instead of an hour later.
	f.cfg.SetThirdPartyTLSEnrichment(true)
	if n := f.observe("198.51.100.7", 443); n != 1 {
		t.Errorf("third party saw %d connections once re-enabled, want 1", n)
	}
}

// Active probing off still means off, for owned destinations too — including
// for a probe already queued when it was switched off.
func TestConsent_ActiveProbingOffWins(t *testing.T) {
	f := newConsentFixture(t, true, nil)
	f.e.MaybeEnrich(&models.CryptoDiscovery{
		DiscoveryMethod: "passive", Protocol: "TLS", DestIP: "10.0.0.23", Port: 443,
		RawMetadata: map[string]interface{}{"handshake_types": []string{"ClientHello"}},
	})
	if len(f.e.queue) != 1 {
		t.Fatalf("queue = %d, want the owned probe queued", len(f.e.queue))
	}
	f.cfg.SetActiveProbing(false)
	f.e.probeAndEmit(<-f.e.queue)
	if n := f.srv.Handshakes(); n != 0 {
		t.Errorf("owned destination saw %d connections after active probing was switched off, want 0", n)
	}
	for _, ip := range []string{"10.0.0.22", "198.51.100.7"} {
		if n := f.observe(ip, 443); n != 0 {
			t.Errorf("%s saw %d connections with active probing off, want 0", ip, n)
		}
	}
}

func (f *consentFixture) stats() (attempted, succeeded, failed, withheld int64) {
	f.e.mu.Lock()
	defer f.e.mu.Unlock()
	return f.e.probesAttempted, f.e.probesSucceeded, f.e.probesFailed, f.e.probesWithheld
}

// The probe switches are written by the heartbeat and command handlers while
// the enricher's workers read them on every probe ( review). Run under
// -race this fails if either switch is read or written as a plain field on
// the concurrent path.
func TestConsent_SwitchesAreSafeToFlipWhileWorkersRun(t *testing.T) {
	f := newConsentFixture(t, false, nil)
	f.e.Start(2)
	stop := make(chan struct{})
	flipped := make(chan struct{})
	go func() {
		defer close(flipped)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			f.cfg.SetThirdPartyTLSEnrichment(i%2 == 0)
			f.cfg.SetActiveProbing(i%3 != 0)
		}
	}()
	for i := 0; i < 40; i++ {
		f.e.MaybeEnrich(&models.CryptoDiscovery{
			DiscoveryMethod: "passive", Protocol: "TLS", DestIP: "10.0.1." + strconv.Itoa(i+1), Port: 443,
			RawMetadata: map[string]interface{}{"handshake_types": []string{"ClientHello"}},
		})
		time.Sleep(time.Millisecond)
	}
	close(stop)
	<-flipped
	f.e.Stop()
}

// Delivered ownership expires ( review): a sensor that stopped hearing from
// its platform does not keep treating yesterday's declared ranges and elevated
// endpoints as the tenant's. Exclusions never expire. The local list — the
// operator's own file — does not expire either.
func TestConsent_DeliveredOwnershipExpiresExclusionsDoNot(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	owned := NewOwnedNetworks()
	owned.now = func() time.Time { return now }
	owned.Update(&probeconsent.OwnedNetworks{
		Prefixes:  []string{"203.0.113.0/24"},
		Endpoints: []string{"198.51.100.7:443"},
		Excluded:  []string{"10.9.0.0/16"},
	})
	f := newConsentFixture(t, false, owned)

	now = now.Add(DeliveredOwnershipTTL - time.Minute)
	if !f.e.Permits("203.0.113.5", 443) || !f.e.Permits("198.51.100.7", 443) {
		t.Fatal("delivered ownership lapsed before its TTL")
	}
	now = now.Add(2 * time.Minute)
	if f.e.Permits("203.0.113.5", 443) || f.e.Permits("198.51.100.7", 443) {
		t.Error("delivered ownership still counted past its TTL")
	}
	if !f.e.Permits("10.0.0.5", 443) {
		t.Error("private space stopped counting when delivered ownership lapsed")
	}
	if f.e.Permits("10.9.1.1", 443) {
		t.Error("an exclusion expired with the ownership; exclusions never expire")
	}
	// The next delivery makes it fresh again.
	owned.Update(&probeconsent.OwnedNetworks{Prefixes: []string{"203.0.113.0/24"}})
	if !f.e.Permits("203.0.113.5", 443) {
		t.Error("a fresh delivery did not restore ownership")
	}

	local := NewOwnedNetworks()
	local.now = func() time.Time { return now.Add(30 * 24 * time.Hour) }
	local.SetLocal(probeconsent.OwnedNetworks{Prefixes: []string{"192.0.2.0/24"}})
	if !local.Scope().Owns("192.0.2.10", 443) {
		t.Error("the local list expired; it is the operator's file, not a delivery")
	}
}

// An incomplete delivery (the platform could not build the set) carries no
// ownership, and ADDS its exclusions to the ones already held.
func TestConsent_IncompleteDeliveryDropsOwnershipKeepsExclusions(t *testing.T) {
	owned := NewOwnedNetworks()
	owned.Update(&probeconsent.OwnedNetworks{
		Prefixes: []string{"203.0.113.0/24"},
		Excluded: []string{"10.9.0.0/16"},
	})
	owned.Update(&probeconsent.OwnedNetworks{Prefixes: []string{}, Endpoints: []string{}, Excluded: []string{"10.8.0.0/16"}, Incomplete: true})
	f := newConsentFixture(t, false, owned)
	if f.e.Permits("203.0.113.5", 443) {
		t.Error("ownership survived an incomplete delivery")
	}
	for _, ip := range []string{"10.9.1.1", "10.8.1.1"} {
		if f.e.Permits(ip, 443) {
			t.Errorf("%s: an exclusion was lost across an incomplete delivery", ip)
		}
	}
	if !f.e.Permits("10.0.0.5", 443) {
		t.Error("private space stopped counting")
	}
}
