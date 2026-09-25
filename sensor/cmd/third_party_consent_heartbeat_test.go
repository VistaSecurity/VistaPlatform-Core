package main

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/api"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
)

// The third-party consent ( W5.13) travels from the platform to the TLS
// enricher through the sensor's REAL heartbeat wiring: sendHeartbeat against a
// stub sensor-manager, the production applier (setupAgentConfig), and the one
// enricher constructor both startup and capture rebuilds use (newTLSEnricher).
//
// The enricher's own decisions are pinned in internal/enrichment; this pins
// that the platform's answer REACHES it — including an enricher built before
// the answer arrived, and one rebuilt after (an interface change rebuilds it
// live).
//
// Mutation checks: delete `s.owned().Update(commands.OwnedNetworks)` from
// applyHeartbeatReply, or construct the enricher without s.owned(), and the
// declared-prefix assertions fail; unregister the third_party_tls_enrichment
// handler and the opt-in assertion fails.
func TestHeartbeatDeliversThirdPartyConsentToTheEnricher(t *testing.T) {
	cp := &stubControlPlane{}
	server := httptest.NewServer(cp.handler())
	defer server.Close()

	cfg := &config.Config{
		SensorID:        "44444444-4444-4444-4444-444444444444",
		ControlPlaneURL: server.URL,
		Capture:         config.CaptureConfig{ActiveProbing: true},
	}
	s := &Sensor{config: cfg, apiClient: api.NewOutboundClient(cfg), startTime: time.Now()}
	s.setupAgentConfig("test")

	early := s.newTLSEnricher(make(chan *models.CryptoDiscovery, 1))

	// Before the platform has said anything: private space only.
	if !early.Permits("10.0.0.5", 443) {
		t.Error("a private destination must be enriched before any heartbeat")
	}
	if early.Permits("203.0.113.5", 443) || early.Permits("198.51.100.7", 443) {
		t.Fatal("a public destination was permitted before the platform declared anything")
	}

	// The platform declares 203.0.113.0/24 and elevates one endpoint.
	cp.setOwned(&probeconsent.OwnedNetworks{
		Prefixes:  []string{"203.0.113.0/24"},
		Endpoints: []string{"198.51.100.9:8443"},
	})
	s.sendHeartbeat()

	rebuilt := s.newTLSEnricher(make(chan *models.CryptoDiscovery, 1))
	for name, e := range map[string]interface {
		Permits(string, int) bool
	}{"enricher built before the beat": early, "enricher rebuilt after it": rebuilt} {
		if !e.Permits("203.0.113.5", 443) {
			t.Errorf("%s: declared prefix not permitted after the heartbeat delivered it", name)
		}
		if !e.Permits("198.51.100.9", 8443) {
			t.Errorf("%s: elevated endpoint not permitted after the heartbeat delivered it", name)
		}
		if e.Permits("198.51.100.7", 443) {
			t.Errorf("%s: a third party was permitted with the opt-in off", name)
		}
	}

	// An older platform's reply — no owned_networks, no config — changes
	// nothing.
	cp.setOwned(nil)
	s.sendHeartbeat()
	if !rebuilt.Permits("203.0.113.5", 443) {
		t.Error("a reply without owned_networks erased the declared prefix; silence is not an instruction")
	}

	// The tenant opts in through the desired-state values.
	cp.setAnswer(&agentconfig.ExchangePayload{
		Revision: "rev-optin",
		Values:   agentconfig.Values{agentconfig.KeyThirdPartyTLSEnrichment: agentconfig.Bool(true)},
	})
	s.sendHeartbeat()
	if !rebuilt.Permits("198.51.100.7", 443) {
		t.Error("third party not permitted after the platform delivered the opt-in")
	}

	// And withdraws it.
	cp.setAnswer(&agentconfig.ExchangePayload{
		Revision: "rev-optout",
		Values:   agentconfig.Values{agentconfig.KeyThirdPartyTLSEnrichment: agentconfig.Bool(false)},
	})
	s.sendHeartbeat()
	if rebuilt.Permits("198.51.100.7", 443) {
		t.Error("third party still permitted after the opt-in was withdrawn")
	}
}
