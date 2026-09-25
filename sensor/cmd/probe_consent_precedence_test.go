package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/api"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
)

// Local probe consent vs the platform's (owner decision on): the sensor's
// own `thirdPartyTLSEnrichment` and `ownedNetworks` apply only while the
// platform has never delivered a value; once it has, the platform's wins — and
// keeps winning across a restart. Driven through the production wiring:
// setupAgentConfig, sendHeartbeat against a stub sensor-manager, and
// newTLSEnricher.
//
// Mutation checks: skip restoreProbeConsent's recorded-state branch (the
// restarted sensor probes on its local opt-in); drop the setter's
// recordPlatformProbeConsent (same); drop the owned-networks record in
// applyHeartbeatReply (the restarted sensor owns its local prefix again); report
// the local opt-in in sensorLocalValues (the laundering assertion fails).

type consentRig struct {
	t        *testing.T
	cp       *stubControlPlane
	dataDir  string
	local    config.CaptureConfig
	url      string
	sensorID string
}

func newConsentRig(t *testing.T, local config.CaptureConfig) *consentRig {
	t.Helper()
	cp := &stubControlPlane{}
	server := httptest.NewServer(cp.handler())
	t.Cleanup(server.Close)
	local.ActiveProbing = true
	return &consentRig{t: t, cp: cp, dataDir: t.TempDir(), local: local, url: server.URL, sensorID: "55555555-5555-5555-5555-555555555555"}
}

// start is one run of the sensor process: the same local configuration and
// data directory each time, fresh in-memory state.
func (r *consentRig) start() (*Sensor, interface{ Permits(string, int) bool }) {
	r.t.Helper()
	capture := r.local
	capture.OwnedNetworks = append([]string(nil), r.local.OwnedNetworks...)
	cfg := &config.Config{
		SensorID:        r.sensorID,
		ControlPlaneURL: r.url,
		Storage:         config.StorageConfig{DataPath: r.dataDir},
		Capture:         capture,
	}
	s := &Sensor{config: cfg, apiClient: api.NewOutboundClient(cfg), startTime: time.Now()}
	s.setupAgentConfig("test")
	return s, s.newTLSEnricher(make(chan *models.CryptoDiscovery, 1))
}

const thirdParty = "198.51.100.7"

func optInPayload(rev string, on bool) *agentconfig.ExchangePayload {
	return &agentconfig.ExchangePayload{Revision: rev, Values: agentconfig.Values{agentconfig.KeyThirdPartyTLSEnrichment: agentconfig.Bool(on)}}
}

// A local opt-in governs a sensor the platform has never told; the platform's
// "off" then wins, including after a restart, before any heartbeat.
func TestLocalOptInYieldsToThePlatformAndStaysYielded(t *testing.T) {
	r := newConsentRig(t, config.CaptureConfig{ThirdPartyTLSEnrichment: true})

	s, e := r.start()
	if !e.Permits(thirdParty, 443) {
		t.Fatal("the local opt-in was not in force on a sensor the platform has never told")
	}
	// An older platform: answers, but knows nothing of the setting.
	r.cp.setAnswer(&agentconfig.ExchangePayload{Revision: "old", Values: agentconfig.Values{agentconfig.KeyActiveProbing: agentconfig.Bool(true)}})
	s.sendHeartbeat()
	if !e.Permits(thirdParty, 443) {
		t.Error("a platform that does not send the setting overrode the local opt-in")
	}

	r.cp.setAnswer(optInPayload("off", false))
	s.sendHeartbeat()
	if e.Permits(thirdParty, 443) {
		t.Error("the platform's off did not override the local opt-in")
	}

	// Restart with the same local file, and no heartbeat yet.
	_, e2 := r.start()
	if e2.Permits(thirdParty, 443) {
		t.Error("after a restart the local opt-in was back in force; the platform's recorded off must keep winning")
	}
}

// The other direction: a local "off" (or nothing) yields to the platform's
// "on", and the platform's "on" persists across a restart too.
func TestPlatformOptInOverridesLocalOffAndPersists(t *testing.T) {
	r := newConsentRig(t, config.CaptureConfig{})

	s, e := r.start()
	if e.Permits(thirdParty, 443) {
		t.Fatal("third party permitted with no opt-in anywhere")
	}
	r.cp.setAnswer(optInPayload("on", true))
	s.sendHeartbeat()
	if !e.Permits(thirdParty, 443) {
		t.Error("the platform's opt-in did not take effect over the local off")
	}
	_, e2 := r.start()
	if !e2.Permits(thirdParty, 443) {
		t.Error("after a restart the platform's recorded opt-in was lost")
	}
}

// A local owned-networks list governs until the platform sends its own; the
// platform's (here: nothing declared) then replaces it, across a restart.
func TestLocalOwnedNetworksYieldToThePlatform(t *testing.T) {
	r := newConsentRig(t, config.CaptureConfig{OwnedNetworks: []string{"203.0.113.0/24"}})

	s, e := r.start()
	if !e.Permits("203.0.113.5", 443) {
		t.Fatal("the local owned network was not in force on a sensor the platform has never told")
	}
	r.cp.setAnswer(nil)
	s.sendHeartbeat() // no owned_networks in the reply: nothing changes
	if !e.Permits("203.0.113.5", 443) {
		t.Error("a reply without owned_networks dropped the local list")
	}

	r.cp.setOwned(&probeconsent.OwnedNetworks{Prefixes: []string{}, Endpoints: []string{}, Excluded: []string{}})
	s.sendHeartbeat()
	if e.Permits("203.0.113.5", 443) {
		t.Error("the platform's owned networks did not replace the local list")
	}

	_, e2 := r.start()
	if e2.Permits("203.0.113.5", 443) {
		t.Error("after a restart the local list was back in force; the platform's recorded owned networks must keep winning")
	}
}

// The local list is held to the same sanity cap as the platform's: a /0 is not
// ownership, while a narrow prefix beside it is.
func TestLocalOwnedNetworksAreCapped(t *testing.T) {
	r := newConsentRig(t, config.CaptureConfig{OwnedNetworks: []string{"0.0.0.0/0", "192.0.0.0/7", "203.0.113.0/24"}})
	_, e := r.start()
	if e.Permits("192.0.2.10", 443) || e.Permits(thirdParty, 443) {
		t.Error("a too-broad local owned network counted as ownership")
	}
	if !e.Permits("203.0.113.5", 443) {
		t.Error("the narrow local owned network beside it stopped counting")
	}
}

// A consent written into one host's file must not be laundered into the
// platform's record: the platform's first-beat bootstrap adopts reported
// running values as the sensor's own, so the local opt-in is never reported.
func TestLocalOptInIsNotReportedToThePlatform(t *testing.T) {
	r := newConsentRig(t, config.CaptureConfig{ThirdPartyTLSEnrichment: true})
	s, _ := r.start()
	s.sendHeartbeat()
	if v, ok := r.cp.lastBeat().ConfigRunning[agentconfig.KeyThirdPartyTLSEnrichment]; ok {
		t.Errorf("config_running carries third_party_tls_enrichment = %s; a local opt-in must not reach the platform's bootstrap", v.String())
	}
}

// An unreadable record means the platform DID govern once and we cannot say
// how: the local opt-in must not come back on the strength of a corrupt file.
func TestCorruptConsentRecordFailsClosed(t *testing.T) {
	r := newConsentRig(t, config.CaptureConfig{ThirdPartyTLSEnrichment: true, OwnedNetworks: []string{"203.0.113.0/24"}})
	if err := os.WriteFile(filepath.Join(r.dataDir, probeConsentStateFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, e := r.start()
	if e.Permits(thirdParty, 443) || e.Permits("203.0.113.5", 443) {
		t.Error("a corrupt consent record handed control back to the local values")
	}
	if !e.Permits("10.0.0.5", 443) {
		t.Error("private space must still be enriched")
	}
}

// The record is bound to the enrolment that received it ( review): a data
// directory reused for a sensor re-enrolled elsewhere must not carry the old
// tenant's consent. The new enrolment starts from its local values, and its
// first delivery overwrites the old record.
func TestConsentRecordIsIgnoredForAnotherSensor(t *testing.T) {
	r := newConsentRig(t, config.CaptureConfig{})
	s, _ := r.start()
	r.cp.setAnswer(optInPayload("on", true))
	r.cp.setOwned(&probeconsent.OwnedNetworks{Prefixes: []string{"203.0.113.0/24"}, Endpoints: []string{}, Excluded: []string{}})
	s.sendHeartbeat()

	// Same data directory, re-enrolled as a different sensor.
	r.sensorID = "66666666-6666-6666-6666-666666666666"
	_, e := r.start()
	if e.Permits(thirdParty, 443) {
		t.Error("the previous enrolment's opt-in carried over to a different sensor")
	}
	if e.Permits("203.0.113.5", 443) {
		t.Error("the previous enrolment's owned networks carried over to a different sensor")
	}

	// And the original sensor, restarted, still has its own record.
	r.sensorID = "55555555-5555-5555-5555-555555555555"
	_, e2 := r.start()
	if !e2.Permits(thirdParty, 443) || !e2.Permits("203.0.113.5", 443) {
		t.Error("the sensor's own record was not restored")
	}
}

// A recorded delivery keeps its age across a restart: a sensor restarted after
// its ownership TTL has passed does not treat the record as fresh.
func TestRestoredOwnershipKeepsItsAge(t *testing.T) {
	r := newConsentRig(t, config.CaptureConfig{})
	st := probeConsentState{
		SensorID:                 r.sensorID,
		OwnedNetworks:            &probeconsent.OwnedNetworks{Prefixes: []string{"203.0.113.0/24"}, Excluded: []string{"10.9.0.0/16"}},
		OwnedNetworksDeliveredAt: time.Now().Add(-25 * time.Hour),
	}
	data, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(r.dataDir, probeConsentStateFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, e := r.start()
	if e.Permits("203.0.113.5", 443) {
		t.Error("ownership recorded 25h ago was treated as fresh after a restart")
	}
	if e.Permits("10.9.1.1", 443) {
		t.Error("the recorded exclusion was lost")
	}
}

// An incomplete delivery is recorded as what is in force after merging — no
// ownership, every exclusion known — so a restart does not lose an exclusion
// the incomplete answer could not read.
func TestIncompleteDeliveryIsRecordedMerged(t *testing.T) {
	r := newConsentRig(t, config.CaptureConfig{})
	s, e := r.start()
	r.cp.setOwned(&probeconsent.OwnedNetworks{Prefixes: []string{"203.0.113.0/24"}, Endpoints: []string{}, Excluded: []string{"10.9.0.0/16"}})
	s.sendHeartbeat()
	r.cp.setOwned(&probeconsent.OwnedNetworks{Prefixes: []string{}, Endpoints: []string{}, Excluded: []string{"10.8.0.0/16"}, Incomplete: true})
	s.sendHeartbeat()
	if e.Permits("203.0.113.5", 443) || e.Permits("10.9.1.1", 443) || e.Permits("10.8.1.1", 443) {
		t.Fatal("the incomplete delivery was not applied as no-ownership plus merged exclusions")
	}
	_, e2 := r.start()
	if e2.Permits("203.0.113.5", 443) || e2.Permits("10.9.1.1", 443) || e2.Permits("10.8.1.1", 443) {
		t.Error("after a restart the recorded state lost an exclusion or regained ownership")
	}
}
