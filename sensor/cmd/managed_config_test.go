package main

import (
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/desiredstate"
)

func testSensor() *Sensor {
	return &Sensor{
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
	s := testSensor()
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
	s := testSensor()
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
	s := testSensor()
	a := desiredstate.New()
	s.registerManagedSettings(a)

	// Apply the value the sensor already holds.
	a.Apply("rev-1", agentconfig.Values{agentconfig.KeyHostObservation: agentconfig.Bool(true)})
	if _, _, pending := a.Report(); len(pending) != 1 {
		t.Errorf("pending = %v, want host_observation even though the value did not change", pending)
	}
}

// Each setting must write ITS OWN field. The has-a-handler test only asserts no
// error, so a setter writing the wrong field passed everything — review proved
// it by pointing the observation-window setter at DedupTTLMinutes and watching
// the suite stay green.
func TestEachSettingWritesItsOwnField(t *testing.T) {
	s := testSensor()
	a := desiredstate.New()
	s.registerManagedSettings(a)

	a.Apply("rev-1", agentconfig.Values{
		agentconfig.KeyActiveProbing:         agentconfig.Bool(false),
		agentconfig.KeyNetworkDiscovery:      agentconfig.Bool(false),
		agentconfig.KeyHostObservation:       agentconfig.Bool(false),
		agentconfig.KeyHostObservationDNS:    agentconfig.Bool(true),
		agentconfig.KeyHostObservationWindow: agentconfig.Int(120),
		agentconfig.KeyDedupTTLMinutes:       agentconfig.Int(15),
		agentconfig.KeyReportingInterval:     agentconfig.Int(120),
	})

	c := s.config.Capture
	for _, tc := range []struct {
		name string
		got  any
		want any
	}{
		{"active_probing", c.ActiveProbing, false},
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
	s := testSensor()
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
	s := testSensor()
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
	s := testSensor()
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
	s := testSensor()
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
			s := testSensor()
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
