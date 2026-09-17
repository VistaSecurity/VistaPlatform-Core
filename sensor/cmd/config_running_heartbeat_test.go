package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/api"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
)

// stubControlPlane is a minimal sensor-manager stand-in: it decodes each
// heartbeat body and can be told what desired-state answer to hand back next,
// just enough to drive the sensor's REAL heartbeat wiring end to end rather
// than approximating it.
type stubControlPlane struct {
	mu     sync.Mutex
	beats  []models.SensorHealth
	answer *agentconfig.ExchangePayload
}

func (p *stubControlPlane) setAnswer(payload *agentconfig.ExchangePayload) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.answer = payload
}

func (p *stubControlPlane) lastBeat() models.SensorHealth {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.beats[len(p.beats)-1]
}

func (p *stubControlPlane) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var health models.SensorHealth
		if err := json.NewDecoder(r.Body).Decode(&health); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		p.beats = append(p.beats, health)
		resp := models.SensorCommands{Config: p.answer}
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// The sensor's first heartbeat has to carry what its OWN config file says for
// every managed setting, not the built-in defaults — sensor-manager's platform
// bootstrap adopts config_running verbatim as a first-reporting
// device's starting position. Before this fix the sensor never populated the
// field at all: a sensor with locally customised active_probing,
// host_observation_dns or dedup_ttl_minutes would be bootstrapped to nothing
// and, on its very next beat, silently reset to built-in defaults.
//
// Driven through the REAL wiring — setupAgentConfig (the production startup
// code shared by main() and startSensorWithConfig()) and sendHeartbeat (the
// production heartbeat code) — against a stub HTTP server standing in for
// sensor-manager. Every previous bug in this feature area was a missing call
// in one of several near-identical copies of this wiring, not a broken
// function, so a test that builds its own plumbing instead of calling the
// production entry points cannot see one.
//
// Mutation check: delete the `s.applier.SetLocal(...)` call inside
// setupAgentConfig and the first assertion block fails (config_running comes
// back empty); delete `health.ConfigRunning = s.applier.Running()` from
// sendHeartbeat and it fails the same way.
func TestFirstHeartbeatCarriesTheSensorsOwnConfiguration(t *testing.T) {
	cp := &stubControlPlane{}
	server := httptest.NewServer(cp.handler())
	defer server.Close()

	verbose := true
	cfg := &config.Config{
		SensorID:          "22222222-2222-2222-2222-222222222222",
		ControlPlaneURL:   server.URL,
		ReportingInterval: 45 * time.Second, // registry default: 300
		Verbose:           &verbose,         // registry default log level: "info"
		Capture: config.CaptureConfig{
			ActiveProbing:                false, // registry default: true
			NetworkDiscovery:             false, // registry default: true
			HostObservation:              false, // registry default: true
			HostObservationWindowSeconds: 120,   // registry default: 60
			HostObservationDNS:           true,  // registry default: false
			DedupTTLMinutes:              15,    // registry default: 60
		},
	}

	s := &Sensor{
		config:    cfg,
		apiClient: api.NewOutboundClient(cfg),
		startTime: time.Now(),
	}
	// The exact call main() and startSensorWithConfig() make at startup.
	s.setupAgentConfig("test")

	s.sendHeartbeat()

	want := agentconfig.Values{
		agentconfig.KeyActiveProbing:         agentconfig.Bool(false),
		agentconfig.KeyNetworkDiscovery:      agentconfig.Bool(false),
		agentconfig.KeyHostObservation:       agentconfig.Bool(false),
		agentconfig.KeyHostObservationWindow: agentconfig.Int(120),
		agentconfig.KeyHostObservationDNS:    agentconfig.Bool(true),
		agentconfig.KeyDedupTTLMinutes:       agentconfig.Int(15),
		agentconfig.KeyReportingInterval:     agentconfig.Int(45),
		agentconfig.KeyLogLevel:              agentconfig.Text("debug"),
	}

	got := cp.lastBeat().ConfigRunning
	for k, wantVal := range want {
		gotVal, ok := got[k]
		if !ok {
			t.Errorf("config_running is missing %s; the platform cannot bootstrap a sensor it is told nothing about", k)
			continue
		}
		if !gotVal.Equal(wantVal) {
			t.Errorf("config_running[%s] = %s, want the file's own %s", k, gotVal.String(), wantVal.String())
		}
	}
	if len(got) != len(want) {
		t.Errorf("config_running = %v, want exactly the %d managed sensor settings", got, len(want))
	}

	// The platform now sets one of them. Running() overlays what the applier
	// has successfully applied onto the local values, so the NEXT beat after
	// convergence must report the platform's value — not the stale file value
	// forever, and not for settings the platform never touched.
	cp.setAnswer(&agentconfig.ExchangePayload{
		Revision: "rev-1",
		Values: agentconfig.Values{
			agentconfig.KeyActiveProbing: agentconfig.Bool(true),
		},
	})
	s.sendHeartbeat() // carries rev-1 back; Apply() runs after this beat's own report is built
	s.sendHeartbeat() // now converged: this beat reports the applied value

	got2 := cp.lastBeat().ConfigRunning
	if v, ok := got2[agentconfig.KeyActiveProbing]; !ok || v.B == nil || !*v.B {
		t.Errorf("config_running[active_probing] = %v, want true after the platform set it", got2[agentconfig.KeyActiveProbing])
	}
	if v, ok := got2[agentconfig.KeyDedupTTLMinutes]; !ok || v.I == nil || *v.I != 15 {
		t.Errorf("config_running[dedup_ttl_minutes] = %v, want the file's own 15 to survive an unrelated platform change", got2[agentconfig.KeyDedupTTLMinutes])
	}
}

// A build with no applier wired must send the heartbeat exactly as it always
// has — additive in both directions, matching device-agent's equivalent test.
func TestHeartbeatWithoutAnApplierOmitsConfigRunning(t *testing.T) {
	cp := &stubControlPlane{}
	server := httptest.NewServer(cp.handler())
	defer server.Close()

	cfg := &config.Config{SensorID: "33333333-3333-3333-3333-333333333333", ControlPlaneURL: server.URL}
	s := &Sensor{
		config:    cfg,
		apiClient: api.NewOutboundClient(cfg),
		startTime: time.Now(),
	}

	s.sendHeartbeat()

	if got := cp.lastBeat().ConfigRunning; len(got) != 0 {
		t.Errorf("config_running = %v from a sensor with no applier wired, want none", got)
	}
}
