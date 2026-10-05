package config

import (
	"reflect"
	"testing"
)

// The sensor's file is where an additional TLS port list starts life — it is
// what the sensor reports on its first heartbeat and what the platform adopts
// at bootstrap — and it is where the managed setting is persisted so a restart
// reads the platform's list ( WP5). Both directions go through this
// loader, so it has to read the YAML key into the field the capture uses.
func TestExtraPortsToMonitorIsReadFromTheFile(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want []int
	}{
		{"block list", "capture:\n  extraPortsToMonitor:\n    - 9443\n    - 10443\n", []int{9443, 10443}},
		{"flow list", "capture:\n  extraPortsToMonitor: [8444, 9443]\n", []int{8444, 9443}},
		{"empty list, as the sensor persists no extra ports", "capture:\n  extraPortsToMonitor: []\n", []int{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadFromFile(writeSensorConfig(t, tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			got := cfg.Capture.ExtraPortsToMonitor
			if len(got) != len(tc.want) || (len(got) > 0 && !reflect.DeepEqual(got, tc.want)) {
				t.Errorf("ExtraPortsToMonitor = %v, want %v", got, tc.want)
			}
		})
	}
}
