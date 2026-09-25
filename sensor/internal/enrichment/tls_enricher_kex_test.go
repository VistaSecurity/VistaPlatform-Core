package enrichment

import (
	"crypto/tls"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
)

// The standalone sensor's TLS enricher builds a discovery from its own live
// handshake. It must record the negotiated group and the server's classical /
// hybrid support the same way the shared prober does, and carry them into the
// discovery it emits — which is what reaches the platform.
func TestTLSEnricher_RecordsKeyExchangeGroupAndSupport(t *testing.T) {
	for _, c := range tlskextest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
			e := NewTLSEnricher(&config.Config{Capture: config.CaptureConfig{ActiveProbing: true}}, "sensor-1", make(chan *models.CryptoDiscovery, 1), nil)

			finding, err := e.probeTLS(srv.Host, srv.Port, "example.com")
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			tlskextest.Check(t, c, finding.RawMetadata)

			d := e.buildEnrichmentDiscovery(enrichRequest{destIP: srv.Host, port: srv.Port, protocol: "TLS"}, finding)
			tlskextest.Check(t, c, d.RawMetadata)

			// A non-third-party (here loopback) destination gets the support
			// handshake — exactly as many as the case needs, no more.
			tlskextest.CheckConnections(t, c, srv)
		})
	}
}

// With the tenant's opt-in on, the enricher also probes third parties its
// hosts talked to. The opt-in is consent to read their certificates, not to
// question them further: the key-exchange support handshakes are EXTRA traffic,
// so for a third-party destination the fixture server must see exactly the one
// handshake enrichment itself made, the group must still be recorded from it,
// and both support flags must be absent — unknown, not false.
//
// The destination is an RFC 5737 address, which is not the tenant's own; the
// dial seam lands the connection on the loopback fixture that counts it.
func TestTLSEnricher_ThirdPartyDestinationGetsNoSupportHandshakes(t *testing.T) {
	for _, c := range tlskextest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
			e := NewTLSEnricher(&config.Config{Capture: config.CaptureConfig{ActiveProbing: true, ThirdPartyTLSEnrichment: true}}, "sensor-1", make(chan *models.CryptoDiscovery, 1), nil)
			e.dial = redirectTo(srv.Host, srv.Port)

			finding, err := e.probeTLS("203.0.113.5", srv.Port, "example.com")
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if n := srv.Handshakes(); n != 1 {
				t.Errorf("third-party server saw %d connections, want exactly 1 (the enrichment handshake itself)", n)
			}
			if got := finding.RawMetadata["key_exchange_algorithm"]; got != c.WantGroup {
				t.Errorf("key_exchange_algorithm = %v, want %q from the one handshake that happens anyway", got, c.WantGroup)
			}
			// Only what the enrichment handshake itself proves may be
			// recorded; the question that would need an extra handshake must
			// be absent.
			tlskextest.CheckOnlyProvenFlags(t, c, finding.RawMetadata)
		})
	}
}

// A destination the tenant DECLARED as its own gets the support handshakes
// exactly as a private one does — owned is owned, whatever its address class.
func TestTLSEnricher_DeclaredPublicDestinationGetsSupportHandshakes(t *testing.T) {
	for _, c := range tlskextest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
			owned := NewOwnedNetworks()
			owned.Update(&probeconsent.OwnedNetworks{Prefixes: []string{"203.0.113.0/24"}})
			e := NewTLSEnricher(&config.Config{Capture: config.CaptureConfig{ActiveProbing: true}}, "sensor-1", make(chan *models.CryptoDiscovery, 1), owned)
			e.dial = redirectTo(srv.Host, srv.Port)

			finding, err := e.probeTLS("203.0.113.5", srv.Port, "example.com")
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			tlskextest.Check(t, c, finding.RawMetadata)
			tlskextest.CheckConnections(t, c, srv)
		})
	}
}

// E-02: the enricher negotiates one suite; it must not present it as the
// server's supported set.
func TestTLSEnricher_DoesNotPresentNegotiatedSuiteAsSupportedSet(t *testing.T) {
	srv := tlskextest.Start(t, []tls.CurveID{tls.X25519}, 0)
	e := NewTLSEnricher(&config.Config{Capture: config.CaptureConfig{ActiveProbing: true}}, "sensor-1", make(chan *models.CryptoDiscovery, 1), nil)
	finding, err := e.probeTLS(srv.Host, srv.Port, "example.com")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if finding.SelectedCipher == "" {
		t.Fatal("SelectedCipher empty — the negotiated suite must still be recorded")
	}
	if len(finding.SupportedCiphers) != 0 {
		t.Errorf("SupportedCiphers = %v, want empty", finding.SupportedCiphers)
	}
}
