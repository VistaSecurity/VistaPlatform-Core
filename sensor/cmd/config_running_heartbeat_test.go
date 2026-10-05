package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/api"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
)

// stubControlPlane is a minimal sensor-manager stand-in: it decodes each
// heartbeat body and can be told what desired-state answer to hand back next,
// just enough to drive the sensor's REAL heartbeat wiring end to end rather
// than approximating it.
type stubControlPlane struct {
	mu     sync.Mutex
	beats  []models.SensorHealth
	answer *agentconfig.ExchangePayload
	owned  *probeconsent.OwnedNetworks
}

func (p *stubControlPlane) setOwned(owned *probeconsent.OwnedNetworks) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.owned = owned
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
		resp := models.SensorCommands{Config: p.answer, OwnedNetworks: p.owned}
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
			ActiveProbing:                false,              // registry default: true
			NetworkDiscovery:             false,              // registry default: true
			HostObservation:              false,              // registry default: true
			HostObservationWindowSeconds: 120,                // registry default: 60
			HostObservationDNS:           true,               // registry default: false
			DedupTTLMinutes:              15,                 // registry default: 60
			ExtraPortsToMonitor:          []int{10443, 9443}, // registry default: none
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
		agentconfig.KeyExtraTLSPorts:         agentconfig.Text("9443,10443"),
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

// The WIRING test for additional TLS ports ( WP5): a list the platform
// stores reaches the field the capture filter is built from.
//
// The answer is the platform's wire form, written as JSON exactly as
// sensor-manager's exchange encodes it (TestIntegration_SensorDesiredConfig_
// ExtraTLSPortsReachTheExchange pins that side), and it travels the REAL path:
// sendHeartbeat -> the HTTP client's decode -> applyHeartbeatReply -> the
// applier -> the registered setter -> cfg.Capture.ExtraPortsToMonitor and the
// sensor's file. Then a restart: the file is reloaded the way the next process
// loads it, and the next beat reports the list as running with nothing pending.
//
// Mutation check: delete `s.config.Capture.ExtraPortsToMonitor = ports` in
// managed_config.go and the first assertion fails; delete the
// persistCaptureSetting call and the post-restart assertion fails; register
// no handler and the beat reports a failure instead of pending-restart.
func TestPlatformExtraTLSPortsReachTheCaptureConfig(t *testing.T) {
	cp := &stubControlPlane{}
	server := httptest.NewServer(cp.handler())
	defer server.Close()

	path := filepath.Join(t.TempDir(), "sensor-config.yaml")
	if err := os.WriteFile(path, []byte("sensorId: 44444444-4444-4444-4444-444444444444\ncontrolPlaneUrl: "+server.URL+"\ncapture:\n  interfaces: [eth0]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := &Sensor{config: cfg, configPath: path, apiClient: api.NewOutboundClient(cfg), startTime: time.Now()}
	s.setupAgentConfig("test")

	var answer agentconfig.ExchangePayload
	if err := json.Unmarshal([]byte(`{"revision":"rev-ports","values":{"extra_tls_ports":"9443,10443"}}`), &answer); err != nil {
		t.Fatal(err)
	}
	cp.setAnswer(&answer)

	s.sendHeartbeat() // delivers the answer
	if got := agentconfig.FormatPortList(s.config.Capture.ExtraPortsToMonitor); got != "9443,10443" {
		t.Fatalf("cfg.Capture.ExtraPortsToMonitor = %q after the platform sent 9443,10443", got)
	}

	s.sendHeartbeat() // reports what the first one applied
	beat := cp.lastBeat()
	if beat.ConfigRevision != "rev-ports" || len(beat.ConfigFailures) != 0 {
		t.Fatalf("report: revision=%q failures=%v", beat.ConfigRevision, beat.ConfigFailures)
	}
	if len(beat.ConfigPendingRestart) != 1 || beat.ConfigPendingRestart[0] != string(agentconfig.KeyExtraTLSPorts) {
		t.Errorf("pending restart = %v, want [extra_tls_ports]: the running capture filter does not admit these ports", beat.ConfigPendingRestart)
	}
	if got := beat.ConfigRunning[agentconfig.KeyExtraTLSPorts]; !got.Equal(agentconfig.Text("")) {
		t.Errorf("running = %v before the restart, want the startup list", got)
	}

	// The next process.
	reloaded, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := agentconfig.FormatPortList(reloaded.Capture.ExtraPortsToMonitor); got != "9443,10443" {
		t.Fatalf("after restart the capture would watch %q, want 9443,10443", got)
	}
	next := &Sensor{config: reloaded, configPath: path, apiClient: api.NewOutboundClient(reloaded), startTime: time.Now()}
	next.setupAgentConfig("test")
	next.sendHeartbeat()
	next.sendHeartbeat()
	beat = cp.lastBeat()
	if len(beat.ConfigPendingRestart) != 0 || len(beat.ConfigFailures) != 0 {
		t.Errorf("after restart: pending=%v failures=%v, want applied", beat.ConfigPendingRestart, beat.ConfigFailures)
	}
	if got := beat.ConfigRunning[agentconfig.KeyExtraTLSPorts]; !got.Equal(agentconfig.Text("9443,10443")) {
		t.Errorf("after restart running = %v, want 9443,10443 in effect", got)
	}
}
