package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeSensorConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sensor-config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestHostObservationConfigPlumbing pins the three-valued config path for the
// passive host-observation switch.
//
// The failure this guards against is a silent one. If the yaml tag were wrong,
// or the pointer collapsed to a plain bool, an operator writing
// `hostObservation: false` would see the setting ignored and the sensor would
// keep decoding — with nothing logged and nothing failing. Every branch below
// is a distinct answer:
//
//	key absent  → the default (on), because "said nothing" is not "said off"
//	key true    → on
//	key false   → OFF, and this is the case a plain bool would get right by
//	              accident while getting "absent" wrong
func TestHostObservationConfigPlumbing(t *testing.T) {
	const base = `sensorId: "8d08afae-1a43-4c56-99b0-f462754d152d"
controlPlaneUrl: "https://agents.example.test:8444"
capture:
  interfaces:
    - "eth0"
`

	t.Run("absent means on", func(t *testing.T) {
		cfg, err := LoadFromFile(writeSensorConfig(t, base))
		if err != nil {
			t.Fatalf("LoadFromFile: %v", err)
		}
		if !cfg.Capture.HostObservation {
			t.Error("a config file that says nothing about host observation disabled it")
		}
	})

	t.Run("explicitly true", func(t *testing.T) {
		cfg, err := LoadFromFile(writeSensorConfig(t, base+"  hostObservation: true\n"))
		if err != nil {
			t.Fatalf("LoadFromFile: %v", err)
		}
		if !cfg.Capture.HostObservation {
			t.Error("hostObservation: true did not enable it")
		}
	})

	t.Run("explicitly false", func(t *testing.T) {
		cfg, err := LoadFromFile(writeSensorConfig(t, base+"  hostObservation: false\n"))
		if err != nil {
			t.Fatalf("LoadFromFile: %v", err)
		}
		if cfg.Capture.HostObservation {
			t.Error("hostObservation: false was ignored — the operator turned it off and the sensor kept decoding")
		}
	})

	t.Run("environment overrides the file", func(t *testing.T) {
		t.Setenv("HOST_OBSERVATION", "false")
		cfg, err := LoadFromFile(writeSensorConfig(t, base+"  hostObservation: true\n"))
		if err != nil {
			t.Fatalf("LoadFromFile: %v", err)
		}
		if cfg.Capture.HostObservation {
			t.Error("HOST_OBSERVATION=false did not override the config file")
		}
	})

	t.Run("window is configurable", func(t *testing.T) {
		cfg, err := LoadFromFile(writeSensorConfig(t, base+"  hostObservationWindowSeconds: 120\n"))
		if err != nil {
			t.Fatalf("LoadFromFile: %v", err)
		}
		if cfg.Capture.HostObservationWindowSeconds != 120 {
			t.Errorf("window = %d, want 120", cfg.Capture.HostObservationWindowSeconds)
		}
	})
}

// TestHostObservationDNSDefaultsOff pins the opposite default to its
// neighbours, which is exactly why it needs its own test.
//
// `hostObservation` defaults ON, so an absent key has to read as true.
// `hostObservationDNS` defaults OFF, so an absent key has to read as false —
// and the bug that would hide is the same shape either way: a reader copied
// from the line above (`== nil || *p`) turns silence into "on" and quietly
// starts decoding every DNS answer on the segment.
func TestHostObservationDNSDefaultsOff(t *testing.T) {
	const base = `sensorId: "8d08afae-1a43-4c56-99b0-f462754d152d"
controlPlaneUrl: "https://agents.example.test:8444"
capture:
  interfaces:
    - "eth0"
`

	for _, tc := range []struct {
		name string
		yaml string
		want bool
	}{
		{"absent means off", base, false},
		{"explicitly false", base + "  hostObservationDNS: false\n", false},
		{"explicitly true", base + "  hostObservationDNS: true\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadFromFile(writeSensorConfig(t, tc.yaml))
			if err != nil {
				t.Fatalf("LoadFromFile: %v", err)
			}
			if cfg.Capture.HostObservationDNS != tc.want {
				t.Errorf("HostObservationDNS = %v, want %v", cfg.Capture.HostObservationDNS, tc.want)
			}
			// The parent switch is unaffected by the sub-knob in every case.
			if !cfg.Capture.HostObservation {
				t.Error("the DNS sub-knob disabled host observation itself")
			}
		})
	}
}

// TestHostObservationDNSEnvDefaultsOff covers the other config path. Load()
// builds from the environment rather than a file, and a default of `true`
// copied from its neighbours there would switch DNS on for every sensor that
// never reads a config file at all.
func TestHostObservationDNSEnvDefaultsOff(t *testing.T) {
	t.Setenv("HOST_OBSERVATION_DNS", "")
	cfg := Load()
	if cfg.Capture.HostObservationDNS {
		t.Error("HOST_OBSERVATION_DNS unset enabled the DNS decoder")
	}
	if !cfg.Capture.HostObservation {
		t.Error("HOST_OBSERVATION unset disabled host observation")
	}

	t.Setenv("HOST_OBSERVATION_DNS", "true")
	if cfg := Load(); !cfg.Capture.HostObservationDNS {
		t.Error("HOST_OBSERVATION_DNS=true did not enable the DNS decoder")
	}
}
