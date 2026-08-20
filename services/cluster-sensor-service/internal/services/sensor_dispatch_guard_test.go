package services

import (
	"errors"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
)

// execution_mode "sensors" asks for a scan to run on a tenant-deployed sensor.
// Nothing dispatches that: no code turns a discovery job into a sensor command,
// the sensor's command switch has no discovery case, and requested_sensor_ids is
// written and read back but consumed by nothing. Such jobs used to fall through
// to the in-cluster nmap path — running from the platform cluster, reaching
// nothing on a target only the sensor can see, and finishing `completed` with
// zero findings and no sign the sensor was never involved.
func TestRejectSensorDispatch(t *testing.T) {
	sensorID := "5f7d1b34-6c0a-4c1e-9c8f-2b1d3e4f5a6b"

	cases := []struct {
		name       string
		mode       string
		sensorIDs  []string
		wantReject bool
	}{
		{"sensors", "sensors", nil, true},
		{"SENSORS uppercase", "SENSORS", nil, true},
		{"padded", "  sensors  ", nil, true},
		{"preferred sensor ids on a supported mode", "auto", []string{sensorID}, true},
		{"preferred sensor ids with no mode", "", []string{sensorID}, true},
		{"auto", "auto", nil, false},
		{"cloud", "cloud", nil, false},
		{"async (internal re-validation)", "async", nil, false},
		{"empty", "", nil, false},
		{"empty sensor id slice is not a request", "auto", []string{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rejectSensorDispatch(tc.mode, tc.sensorIDs)
			if tc.wantReject {
				if !errors.Is(err, ErrSensorDispatchUnsupported) {
					t.Fatalf("rejectSensorDispatch(%q, %v) = %v, want ErrSensorDispatchUnsupported", tc.mode, tc.sensorIDs, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejectSensorDispatch(%q, %v) = %v, want nil — this is a supported mode", tc.mode, tc.sensorIDs, err)
			}
		})
	}
}

// The job processor is the last line: a `sensors` row written before the
// creation guard existed must FAIL, never run somewhere the caller did not ask
// for. The branch returns before any DB access, so a zero-value processor is
// enough to exercise it.
func TestProcessDiscoveryJob_FailsSensorExecutionMode(t *testing.T) {
	jp := &JobProcessor{}

	err := jp.processDiscoveryJob(&models.DiscoveryJob{
		ID:            "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f42",
		TenantID:      "1c9e7a05-4d2b-4a63-9f18-7e5c2b0a3d64",
		ExecutionMode: "sensors",
	})
	if err == nil {
		t.Fatal("processDiscoveryJob accepted a sensors job — it would run in-cluster and report completed with zero findings")
	}
	if !strings.Contains(err.Error(), "sensors") {
		t.Errorf("error = %v, want it to name the unsupported execution mode", err)
	}
}
