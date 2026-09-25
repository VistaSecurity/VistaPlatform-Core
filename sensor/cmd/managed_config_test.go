package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/desiredstate"
)

func testSensor(t *testing.T) *Sensor {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sensor-config.yaml")
	if err := os.WriteFile(path, []byte("sensorId: test\ncapture:\n  hostObservation: true\n  hostObservationDNS: false\n  hostObservationWindowSeconds: 60\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return &Sensor{
		configPath: path,
		config: &config.Config{
			Capture: config.CaptureConfig{
				ActiveProbing:                true,
				NetworkDiscovery:             true,
				HostObservation:              true,
				HostObservationWindowSeconds: 60,
				DedupTTLMinutes:              60,
			},
			ReportingInterval: 5 * time.Minute,
		},
		startTime: time.Now(),
	}
}

// Every setting the registry says a SENSOR has must have a handler, or the
// console offers knobs this binary silently cannot honour. This is the check
// that catches a setting added to the platform and never wired here.
func TestEverySensorSettingHasAHandler(t *testing.T) {
	s := testSensor(t)
	a := desiredstate.New()
	s.registerManagedSettings(a)

	values := agentconfig.Values{}
	for _, f := range agentconfig.FieldsFor(agentconfig.RuntimeSensor) {
		values[f.Key] = f.Default
	}
	a.Apply("rev-1", values)

	_, failures, _ := a.Report()
	for k, why := range failures {
		t.Errorf("%s was not applied: %s", k, why)
	}
}

// The two capture settings are recorded but NOT in force until a restart: the
// BPF filter is fixed when the interface handle opens, so switching a decoder
// on mid-run leaves it running and receiving nothing. Reporting them as applied
// would claim a change the sensor is not making.
func TestCaptureFilterSettingsReportPendingRestart(t *testing.T) {
	s := testSensor(t)
	a := desiredstate.New()
	s.registerManagedSettings(a)

	a.Apply("rev-1", agentconfig.Values{
		agentconfig.KeyHostObservation:    agentconfig.Bool(false),
		agentconfig.KeyHostObservationDNS: agentconfig.Bool(true),
		agentconfig.KeyActiveProbing:      agentconfig.Bool(false),
	})

	_, failures, pending := a.Report()
	if len(failures) != 0 {
		t.Fatalf("failures = %v, want none — a restart-only setting is not a failure", failures)
	}
	if len(pending) != 2 {
		t.Errorf("pending restart = %v, want both capture-filter settings", pending)
	}
	// Recorded even so: the sensor runs them the moment it restarts.
	if s.config.Capture.HostObservation {
		t.Error("host observation was not recorded")
	}
	if !s.config.Capture.HostObservationDNS {
		t.Error("DNS decoding was not recorded")
	}
	// And the setting that CAN change live did.
	if s.config.Capture.ActiveProbing {
		t.Error("active probing did not take effect, and it needs no restart")
	}
}

// The sentinel must come back on EVERY apply while the value is not in force,
// not only when it changes — otherwise the pending flag clears at the next
// unrelated revision bump and the console shows "applied" for a decoder that
// is not running.
func TestCaptureFilterSettingsStayPendingWhenUnchanged(t *testing.T) {
	s := testSensor(t)
	a := desiredstate.New()
	s.registerManagedSettings(a)

	// First request a real change, then receive that same desired value again.
	a.Apply("rev-0", agentconfig.Values{agentconfig.KeyHostObservation: agentconfig.Bool(false)})
	a.Apply("rev-1", agentconfig.Values{agentconfig.KeyHostObservation: agentconfig.Bool(false)})
	if _, _, pending := a.Report(); len(pending) != 1 {
		t.Errorf("pending = %v, want host_observation even though the value did not change", pending)
	}
}

// Each setting must write ITS OWN field. The has-a-handler test only asserts no
// error, so a setter writing the wrong field passed everything — review proved
// it by pointing the observation-window setter at DedupTTLMinutes and watching
// the suite stay green.
func TestEachSettingWritesItsOwnField(t *testing.T) {
	s := testSensor(t)
	a := desiredstate.New()
	s.registerManagedSettings(a)

	a.Apply("rev-1", agentconfig.Values{
		agentconfig.KeyActiveProbing:           agentconfig.Bool(false),
		agentconfig.KeyThirdPartyTLSEnrichment: agentconfig.Bool(true),
		agentconfig.KeyNetworkDiscovery:        agentconfig.Bool(false),
		agentconfig.KeyHostObservation:         agentconfig.Bool(false),
		agentconfig.KeyHostObservationDNS:      agentconfig.Bool(true),
		agentconfig.KeyHostObservationWindow:   agentconfig.Int(120),
		agentconfig.KeyDedupTTLMinutes:         agentconfig.Int(15),
		agentconfig.KeyReportingInterval:       agentconfig.Int(120),
	})

	c := s.config.Capture
	for _, tc := range []struct {
		name string
		got  any
		want any
	}{
		{"active_probing", c.ActiveProbing, false},
		{"third_party_tls_enrichment", c.ThirdPartyTLSEnrichment, true},
		{"network_discovery", c.NetworkDiscovery, false},
		{"host_observation", c.HostObservation, false},
		{"host_observation_dns", c.HostObservationDNS, true},
		{"host_observation_window_seconds", c.HostObservationWindowSeconds, 120},
		{"dedup_ttl_minutes", c.DedupTTLMinutes, 15},
		{"reporting_interval_seconds", s.config.ReportingInterval, 2 * time.Minute},
	} {
		if tc.got != tc.want {
			t.Errorf("%s wrote %v, want %v — check the setter is writing its own field", tc.name, tc.got, tc.want)
		}
	}
}

// dedup_ttl_minutes is MINUTES. Running it through the seconds-based helper
// would divide an operator's value by sixty and nothing would notice.
func TestDedupTTLIsTreatedAsMinutes(t *testing.T) {
	s := testSensor(t)
	a := desiredstate.New()
	s.registerManagedSettings(a)

	a.Apply("rev-1", agentconfig.Values{agentconfig.KeyDedupTTLMinutes: agentconfig.Int(15)})

	if _, failures, _ := a.Report(); len(failures) != 0 {
		t.Fatalf("failures = %v", failures)
	}
	if s.config.Capture.DedupTTLMinutes != 15 {
		t.Errorf("dedup TTL = %d minutes, want 15 — a seconds conversion would give 0",
			s.config.Capture.DedupTTLMinutes)
	}
}

func TestReportingIntervalIsTreatedAsSeconds(t *testing.T) {
	s := testSensor(t)
	a := desiredstate.New()
	s.registerManagedSettings(a)

	a.Apply("rev-1", agentconfig.Values{agentconfig.KeyReportingInterval: agentconfig.Int(120)})

	if s.config.ReportingInterval != 2*time.Minute {
		t.Errorf("reporting interval = %v, want 2m", s.config.ReportingInterval)
	}
}

// A value of the wrong type is refused rather than coerced, and an unknown log
// level is refused rather than silently mapped to something.
func TestBadValuesAreRefused(t *testing.T) {
	s := testSensor(t)
	a := desiredstate.New()
	s.registerManagedSettings(a)

	a.Apply("rev-1", agentconfig.Values{
		agentconfig.KeyActiveProbing: agentconfig.Text("yes"),
		agentconfig.KeyLogLevel:      agentconfig.Text("shout"),
	})

	_, failures, _ := a.Report()
	if len(failures) != 2 {
		t.Errorf("failures = %v, want both refused", failures)
	}
}

// The observation window is fixed when the capture pipeline is built, so it
// must report pending-restart too. It declared ApplyImmediate and returned nil
// until review found that the console therefore showed "Applied" for a merge
// window the sensor was not using.
func TestObservationWindowReportsPendingRestart(t *testing.T) {
	s := testSensor(t)
	a := desiredstate.New()
	s.registerManagedSettings(a)

	a.Apply("rev-1", agentconfig.Values{agentconfig.KeyHostObservationWindow: agentconfig.Int(120)})

	_, failures, pending := a.Report()
	if len(failures) != 0 {
		t.Fatalf("failures = %v, want none", failures)
	}
	if len(pending) != 1 || pending[0] != string(agentconfig.KeyHostObservationWindow) {
		t.Errorf("pending = %v, want [host_observation_window_seconds]", pending)
	}
	// The registry has to agree, or the console renders "immediate" beside a
	// setting the sensor reports as pending.
	if f := agentconfig.Registry[agentconfig.KeyHostObservationWindow]; f.Apply != agentconfig.ApplyOnRestart {
		t.Errorf("registry says apply=%s; the sensor cannot honour that", f.Apply)
	}
}

// The dedup setter is hand-rolled, so it has to apply the registry's bounds
// itself. Without them 0 was accepted and then ignored by every consumer
// (`ttl <= 0` keeps the old value), so the sensor reported a setting it was not
// using — reported config and running behaviour diverging silently.
func TestDedupTTLRespectsTheRegistryBounds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		minutes int64
		wantErr bool
	}{
		{"zero is refused", 0, true},
		{"negative is refused", -5, true},
		{"above the maximum is refused", 5000, true},
		{"the minimum is accepted", 1, false},
		{"an ordinary value is accepted", 60, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testSensor(t)
			a := desiredstate.New()
			s.registerManagedSettings(a)

			a.Apply("rev-"+tc.name, agentconfig.Values{agentconfig.KeyDedupTTLMinutes: agentconfig.Int(tc.minutes)})

			_, failures, _ := a.Report()
			if tc.wantErr && len(failures) == 0 {
				t.Errorf("%d minutes was accepted; the consumers would ignore it and the console would show it as applied", tc.minutes)
			}
			if !tc.wantErr && len(failures) != 0 {
				t.Errorf("%d minutes was refused: %v", tc.minutes, failures)
			}
		})
	}
}

// Exercise startup, a real change, another revision, cancellation, and a new
// process loading the saved file. None of these require opening a capture NIC.
func TestRestartSettingsConvergeAgainstRunningCapture(t *testing.T) {
	s := testSensor(t)
	s.setupAgentConfig("test")
	baseline := sensorLocalValues(s.config)
	s.applier.Apply("initial", baseline)
	if _, failures, pending := s.applier.Report(); len(failures) != 0 || len(pending) != 0 {
		t.Fatalf("unchanged startup: failures=%v pending=%v", failures, pending)
	}
	changed := agentconfig.Values{
		agentconfig.KeyHostObservation:       agentconfig.Bool(false),
		agentconfig.KeyHostObservationDNS:    agentconfig.Bool(true),
		agentconfig.KeyHostObservationWindow: agentconfig.Int(120),
	}
	for _, rev := range []string{"changed", "unrelated-revision"} {
		s.applier.Apply(rev, changed)
		if _, failures, pending := s.applier.Report(); len(failures) != 0 || len(pending) != 3 {
			t.Fatalf("%s: failures=%v pending=%v", rev, failures, pending)
		}
		running := s.applier.Running()
		for k := range changed {
			if !running[k].Equal(baseline[k]) {
				t.Fatalf("%s reported desired as running", k)
			}
		}
	}
	// Config reload uses the same loader as the next real process.
	reloaded, err := config.LoadFromFile(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Sensor{config: reloaded, configPath: s.configPath}
	restarted.setupAgentConfig("test")
	restarted.applier.Apply("changed", changed)
	if _, failures, pending := restarted.applier.Report(); len(failures) != 0 || len(pending) != 0 {
		t.Fatalf("after restart: failures=%v pending=%v", failures, pending)
	}
	// Cancelling before restart restores the original process's baseline.
	s.applier.Apply("cancelled", baseline)
	if _, failures, pending := s.applier.Report(); len(failures) != 0 || len(pending) != 0 {
		t.Fatalf("cancelled: failures=%v pending=%v", failures, pending)
	}
}

func TestRestartSettingPersistenceFailureIsNotAccepted(t *testing.T) {
	s := testSensor(t)
	invalid := []byte("capture: [invalid-mapping]\n")
	if err := os.WriteFile(s.configPath, invalid, 0600); err != nil {
		t.Fatal(err)
	}
	s.setupAgentConfig("test")
	s.applier.Apply("change", agentconfig.Values{agentconfig.KeyHostObservation: agentconfig.Bool(false)})
	_, failures, pending := s.applier.Report()
	if len(failures) != 1 || len(pending) != 0 || !s.config.Capture.HostObservation {
		t.Fatalf("failed persistence accepted: %v %v", failures, pending)
	}
	data, err := os.ReadFile(s.configPath)
	if err != nil || string(data) != string(invalid) {
		t.Fatalf("invalid config was changed: %s %v", data, err)
	}
}

func TestCaptureSettingPersistencePreservesUnrelatedConfiguration(t *testing.T) {
	s := testSensor(t)
	input := "# installation notes\ncontrolPlaneUrl: https://control.example.test\nsecurity:\n  clientKeyPath: key.pem\ncapture:\n  interfaces: [eth0]\n  hostObservation: true # operator note\n  futureSetting: kept\n"
	if err := os.WriteFile(s.configPath, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.persistCaptureSetting("hostObservation", false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, retained := range []string{"# installation notes", "https://control.example.test", "clientKeyPath: key.pem", "interfaces: [eth0]", "hostObservation: false # operator note", "futureSetting: kept"} {
		if !strings.Contains(string(raw), retained) {
			t.Fatalf("lost %q in %s", retained, raw)
		}
	}
	info, err := os.Stat(s.configPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("file permissions changed: %v %v", info, err)
	}
}

func TestPersistCaptureSettingKeepsInterfaceEditsWorking(t *testing.T) {
	s := testSensor(t)
	if err := os.WriteFile(s.configPath, []byte("capture:\n  interfaces:\n    - eth0\n  hostObservation: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.persistCaptureSetting("hostObservation", false); err != nil {
		t.Fatal(err)
	}
	if err := s.persistMonitoredInterfaces([]string{"eth1"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFromFile(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Capture.Interfaces) != 1 || cfg.Capture.Interfaces[0] != "eth1" || cfg.Capture.HostObservation {
		t.Fatalf("capture settings changed incorrectly: %+v", cfg.Capture)
	}
}
