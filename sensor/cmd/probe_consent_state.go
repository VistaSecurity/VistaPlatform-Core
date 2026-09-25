package main

// Precedence between the platform's probe consent and a sensor's local one
// ( W5.13, owner decision on).
//
// The sensor's config file and environment can supply a local third-party
// opt-in (`thirdPartyTLSEnrichment` / THIRD_PARTY_TLS_ENRICHMENT) and a local
// list of owned public prefixes (`ownedNetworks` / OWNED_NETWORKS). They exist
// for a sensor the platform has NEVER told anything: an air-gapped one, or one
// talking to a platform older than the setting.
//
// Once the platform delivers a value, the platform's wins — and it must keep
// winning after a restart, or a sensor would come back up on its local file
// and probe on it until its first heartbeat was answered (and indefinitely if
// the platform were then unreachable). So every value the platform delivers is
// recorded in a small state file beside the enrolment certificates, and at
// startup a recorded value replaces the local one before the enricher runs.
//
// The local opt-in is also deliberately NOT reported in config_running: the
// platform's first-beat bootstrap adopts reported values as the sensor's own,
// and a consent written into a file on one host must not be laundered into the
// platform's record, past the confirmation the console demands.
//
// The record names the sensor (and tenant, when known) it was written for. A
// record left behind by a previous enrolment — the data directory reused for a
// sensor re-enrolled into another tenant — is ignored, and overwritten on the
// new enrolment's first delivery ( review). Delivered ownership also
// carries its delivery time, so a restart cannot make stale ownership fresh
// (enrichment.DeliveredOwnershipTTL).
//
// Deleting the state file hands control back to the local values — the step
// for a sensor that is being taken off the platform for good.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/enrichment"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
)

// probeConsentStateFile holds what the platform last delivered, in the
// sensor's data directory.
const probeConsentStateFile = "platform-probe-consent.json"

// probeConsentState is every value the platform has delivered. A nil field is
// one the platform has never sent — which is what leaves the local value in
// force.
type probeConsentState struct {
	// SensorID and TenantID bind the record to the enrolment that received
	// it. A record for another sensor is not this sensor's platform speaking.
	SensorID string `json:"sensor_id"`
	TenantID string `json:"tenant_id,omitempty"`

	ThirdPartyTLSEnrichment  *bool                       `json:"third_party_tls_enrichment,omitempty"`
	OwnedNetworks            *probeconsent.OwnedNetworks `json:"owned_networks,omitempty"`
	OwnedNetworksDeliveredAt time.Time                   `json:"owned_networks_delivered_at,omitempty"`
}

// belongsTo reports whether a record was written for this enrolment. A record
// with no sensor id predates binding and cannot be shown to be ours.
func (st probeConsentState) belongsTo(sensorID, tenantID string) bool {
	if st.SensorID == "" || st.SensorID != sensorID {
		return false
	}
	return st.TenantID == "" || tenantID == "" || st.TenantID == tenantID
}

func (s *Sensor) probeConsentStatePath() string {
	if s.config == nil || s.config.Storage.DataPath == "" {
		return ""
	}
	return filepath.Join(s.config.Storage.DataPath, probeConsentStateFile)
}

func readProbeConsentState(path string) (probeConsentState, error) {
	var st probeConsentState
	if path == "" {
		return st, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return probeConsentState{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return st, nil
}

// recordPlatformProbeConsent writes a value the platform just delivered. A
// failure is logged, not returned: the value is already in force for this run,
// and a read-only data directory must not turn a delivered setting into a
// reported failure. What it costs is that a restart would fall back to the
// local values until the next heartbeat — which the log says.
func (s *Sensor) recordPlatformProbeConsent(update func(*probeConsentState)) {
	s.consentStateMu.Lock()
	defer s.consentStateMu.Unlock()
	path := s.probeConsentStatePath()
	if path == "" || s.config.SensorID == "" {
		// Nothing to bind the record to: a sensor the platform has not
		// enrolled cannot have been told anything by it.
		return
	}
	st, err := readProbeConsentState(path)
	if err != nil {
		// Left as it is, not rewritten: a partial rewrite would record this
		// one value and silently hand the OTHER back to the local file on the
		// next restart. An unreadable record already fails closed at startup
		// (restoreProbeConsent), and what the platform sent is in force now.
		log.Printf("⚠️  Probe consent state unreadable (%v); not recording the platform's value — remove %s to let it be rewritten", err, path)
		return
	}
	if !st.belongsTo(s.config.SensorID, s.config.TenantID) {
		// Another enrolment's record: start this one afresh rather than
		// inherit that tenant's answers.
		st = probeConsentState{}
	}
	st.SensorID, st.TenantID = s.config.SensorID, s.config.TenantID
	before, _ := json.Marshal(st)
	update(&st)
	after, err := json.Marshal(st)
	if err != nil || string(before) == string(after) {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.Printf("⚠️  Could not record the platform's probe consent (%v); after a restart the local values apply until the next heartbeat", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, after, 0o600); err != nil {
		log.Printf("⚠️  Could not record the platform's probe consent (%v); after a restart the local values apply until the next heartbeat", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		log.Printf("⚠️  Could not record the platform's probe consent (%v); after a restart the local values apply until the next heartbeat", err)
	}
}

// restoreProbeConsent decides, once at startup, which values are in force
// before the platform has said anything this run: what the platform last
// delivered if it ever delivered anything, otherwise the local file and
// environment. Called from owned(), which every enricher construction goes
// through, so it has happened before the first probe.
func (s *Sensor) restoreProbeConsent(owned *enrichment.OwnedNetworks) {
	st, err := readProbeConsentState(s.probeConsentStatePath())
	if err != nil {
		// Unreadable: the platform did deliver something once, but we cannot
		// say what. The safe reading is "the platform governs and has not
		// said yet" — no local opt-in, no local ownership — rather than
		// letting a corrupt file hand control back to the local values.
		log.Printf("⚠️  Probe consent state unreadable (%v); ignoring the local third-party opt-in and owned networks until the platform answers", err)
		if s.config != nil && !s.platformOptInDelivered.Load() {
			s.config.SetThirdPartyTLSEnrichment(false)
		}
		return
	}
	if s.config == nil {
		return
	}
	if (st != probeConsentState{}) && !st.belongsTo(s.config.SensorID, s.config.TenantID) {
		log.Printf("⚠️  Probe consent record belongs to sensor %q, not this one (%q); ignoring it — the local configuration applies until this enrolment's platform answers", st.SensorID, s.config.SensorID)
		st = probeConsentState{}
	}
	switch {
	case s.platformOptInDelivered.Load():
		// The platform answered before the enricher was first built; its
		// value is already in the config.
	case st.ThirdPartyTLSEnrichment != nil:
		if s.config.Capture.ThirdPartyTLSEnrichment != *st.ThirdPartyTLSEnrichment {
			log.Printf("🔬 Third-party TLS enrichment: the platform's recorded value (%t) overrides the local one (%t)",
				*st.ThirdPartyTLSEnrichment, s.config.Capture.ThirdPartyTLSEnrichment)
		}
		s.config.SetThirdPartyTLSEnrichment(*st.ThirdPartyTLSEnrichment)
	case s.config.Capture.ThirdPartyTLSEnrichment:
		log.Printf("🔬 Third-party TLS enrichment is ON from the local configuration; the platform's setting replaces it once delivered")
	}
	switch {
	case st.OwnedNetworks != nil:
		// Restored with its original delivery time: a record older than the
		// ownership TTL grants nothing beyond private space.
		owned.UpdateAt(st.OwnedNetworks, st.OwnedNetworksDeliveredAt)
	case len(s.config.Capture.OwnedNetworks) > 0:
		owned.SetLocal(probeconsent.OwnedNetworks{Prefixes: append([]string(nil), s.config.Capture.OwnedNetworks...)})
	}
}
