package sensordispatch

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const jobID = "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f42"

func TestParsePayload_RoundTripsThroughToMap(t *testing.T) {
	in := Payload{
		JobID:     jobID,
		TenantID:  "1c9e7a05-4d2b-4a63-9f18-7e5c2b0a3d64",
		Targets:   []string{"192.0.2.10", "192.0.2.11"},
		Protocols: []string{"TLS", "SSH"},
		Ports:     []int{443, 22},
		Options:   map[string]interface{}{"active_scan": true},
	}
	got, err := ParsePayload(in.ToMap())
	if err != nil {
		t.Fatalf("ParsePayload(ToMap()) = %v", err)
	}
	if got.JobID != in.JobID || got.TenantID != in.TenantID {
		t.Errorf("ids: got %+v", got)
	}
	if strings.Join(got.Targets, ",") != "192.0.2.10,192.0.2.11" {
		t.Errorf("targets = %v", got.Targets)
	}
	if strings.Join(got.Protocols, ",") != "TLS,SSH" {
		t.Errorf("protocols = %v", got.Protocols)
	}
	if len(got.Ports) != 2 || got.Ports[0] != 443 || got.Ports[1] != 22 {
		t.Errorf("ports = %v", got.Ports)
	}
	if v, _ := got.Options["active_scan"].(bool); !v {
		t.Errorf("options = %v", got.Options)
	}
}

// The wire shape: sensor_commands.payload is jsonb, and encoding/json decodes
// every number into float64 and every list into []interface{}.
func TestParsePayload_AcceptsTheJSONDecodedShape(t *testing.T) {
	got, err := ParsePayload(map[string]interface{}{
		"job_id":    jobID,
		"targets":   []interface{}{"192.0.2.10"},
		"protocols": []interface{}{"TLS"},
		"ports":     []interface{}{float64(443), float64(8443)},
	})
	if err != nil {
		t.Fatalf("ParsePayload = %v", err)
	}
	if len(got.Ports) != 2 || got.Ports[1] != 8443 {
		t.Errorf("ports = %v", got.Ports)
	}
}

// Every refusal must be ErrMalformedPayload: the sensor answers those with a
// FAILED acknowledgement the platform records, never with silence.
func TestParsePayload_RejectsWhatCannotBeRun(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]interface{}
	}{
		{"nil", nil},
		{"no job id", map[string]interface{}{"targets": []interface{}{"192.0.2.10"}}},
		{"job id not a uuid", map[string]interface{}{"job_id": "job-1", "targets": []interface{}{"192.0.2.10"}}},
		{"no targets", map[string]interface{}{"job_id": jobID}},
		{"empty targets", map[string]interface{}{"job_id": jobID, "targets": []interface{}{}}},
		{"blank targets only", map[string]interface{}{"job_id": jobID, "targets": []interface{}{"  "}}},
		{"target not a string", map[string]interface{}{"job_id": jobID, "targets": []interface{}{42}}},
		{"targets not a list", map[string]interface{}{"job_id": jobID, "targets": "192.0.2.10"}},
		{"port out of range", map[string]interface{}{"job_id": jobID, "targets": []interface{}{"192.0.2.10"}, "ports": []interface{}{float64(70000)}}},
		{"port zero", map[string]interface{}{"job_id": jobID, "targets": []interface{}{"192.0.2.10"}, "ports": []interface{}{float64(0)}}},
		{"port not integral", map[string]interface{}{"job_id": jobID, "targets": []interface{}{"192.0.2.10"}, "ports": []interface{}{443.5}}},
		{"port not a number", map[string]interface{}{"job_id": jobID, "targets": []interface{}{"192.0.2.10"}, "ports": []interface{}{"443"}}},
		{"protocol not a string", map[string]interface{}{"job_id": jobID, "targets": []interface{}{"192.0.2.10"}, "protocols": []interface{}{1}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePayload(tc.in)
			if !errors.Is(err, ErrMalformedPayload) {
				t.Fatalf("ParsePayload(%v) = %v, want ErrMalformedPayload", tc.in, err)
			}
		})
	}
}

// Empty protocols and ports are NOT malformed — the executor treats them as
// "sweep the default crypto ports", which is a real job shape.
func TestParsePayload_AllowsSweepShape(t *testing.T) {
	got, err := ParsePayload(map[string]interface{}{"job_id": jobID, "targets": []interface{}{"192.0.2.0/29"}})
	if err != nil {
		t.Fatalf("ParsePayload = %v", err)
	}
	if len(got.Protocols) != 0 || len(got.Ports) != 0 {
		t.Errorf("got protocols=%v ports=%v, want both empty", got.Protocols, got.Ports)
	}
}

func TestLivenessWindow(t *testing.T) {
	cases := []struct {
		interval int
		want     time.Duration
	}{
		{0, DefaultLivenessWindow},
		{-5, DefaultLivenessWindow},
		{10, minLivenessWindow},   // 50s → floor
		{60, 5 * time.Minute},     // 5 × 60s
		{120, 10 * time.Minute},   // 5 × 120s
		{600, maxLivenessWindow},  // 50 min → ceiling
		{3600, maxLivenessWindow}, // 5h → ceiling
	}
	for _, tc := range cases {
		if got := LivenessWindow(tc.interval); got != tc.want {
			t.Errorf("LivenessWindow(%d) = %v, want %v", tc.interval, got, tc.want)
		}
	}
	if DispatchTimeout(60) != LivenessWindow(60) {
		t.Error("DispatchTimeout must equal LivenessWindow — a sensor that was live at dispatch has this long to collect")
	}
}

func TestIsLive(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-30 * time.Second)
	stale := now.Add(-20 * time.Minute)
	future := now.Add(time.Minute)

	cases := []struct {
		name      string
		status    string
		heartbeat *time.Time
		interval  int
		want      bool
	}{
		{"active and fresh", "active", &fresh, 30, true},
		{"active, case-insensitive", "ACTIVE ", &fresh, 30, true},
		{"active but stale", "active", &stale, 30, false},
		{"active, never beat", "active", nil, 30, false},
		{"active, zero beat", "active", &time.Time{}, 30, false},
		{"active, clock skew (future beat)", "active", &future, 30, false},
		{"offline, fresh", "offline", &fresh, 30, false},
		{"pending, fresh", "pending", &fresh, 30, false},
		{"inactive, fresh", "inactive", &fresh, 30, false},
		{"error, fresh", "error", &fresh, 30, false},
		// The window follows the cadence: a 4-minute-old beat is fine for a
		// sensor reporting every 2 minutes (window 10m) and dead for one
		// reporting every 10 seconds (window floors at 3m).
		{"cadence widens the window", "active", ptr(now.Add(-4 * time.Minute)), 120, true},
		{"cadence narrows the window", "active", ptr(now.Add(-4 * time.Minute)), 10, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLive(tc.status, tc.heartbeat, tc.interval, now); got != tc.want {
				t.Fatalf("IsLive(%q, %v, %d) = %v, want %v", tc.status, tc.heartbeat, tc.interval, got, tc.want)
			}
		})
	}
}

func ptr(t time.Time) *time.Time { return &t }

func TestCompletionValidate(t *testing.T) {
	if err := (Completion{Status: "completed"}).Validate(); err != nil {
		t.Errorf("completed with zero counts is legitimate: %v", err)
	}
	if err := (Completion{Status: "failed", ErrorMessage: "x"}).Validate(); err != nil {
		t.Errorf("failed: %v", err)
	}
	if err := (Completion{Status: "partial"}).Validate(); err == nil {
		t.Error("unknown status accepted")
	}
	if err := (Completion{Status: "completed", FailedTargets: -1}).Validate(); err == nil {
		t.Error("negative count accepted")
	}
}

func TestSensorOfflineMessage(t *testing.T) {
	if got := SensorOfflineMessage("", nil); got != "sensor offline; nothing was scanned" {
		t.Errorf("bare message = %q", got)
	}
	beat := time.Date(2026, 9, 17, 11, 58, 0, 0, time.UTC)
	got := SensorOfflineMessage("xps16-sensor", &beat)
	for _, want := range []string{"xps16-sensor", "nothing was scanned", "2026-09-17T11:58:00Z"} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q lacks %q", got, want)
		}
	}
}
