package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor/internal/capture"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

func commandSensor(t *testing.T) *Sensor {
	t.Helper()
	s := testSensor(t)
	s.config.SensorID = "sensor-1"
	body := "sensorId: \"sensor-1\"\nreportingIntervalSeconds: 300\ncapture:\n  activeProbing: true\n  networkDiscovery: true\n  hostObservation: true\n  dedupTTLMinutes: 60\n"
	if err := os.WriteFile(s.configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}

func cmd(payload map[string]interface{}) models.Command {
	return models.Command{ID: uuid.NewString(), Payload: payload}
}

func TestHandleUpdateConfig(t *testing.T) {
	cases := []struct {
		name        string
		payload     map[string]interface{}
		wantStatus  string
		wantInMsg   []string
		wantFile    []string
		wantApplied int
	}{
		{
			name: "wrong types are rejected by name",
			payload: map[string]interface{}{"config": map[string]interface{}{
				"reporting_interval": "60",
				"capture_config": map[string]interface{}{
					"active_probing":    "yes",
					"dedup_ttl_minutes": "30",
				},
			}},
			wantStatus: "error",
			wantInMsg:  []string{"reporting_interval", "capture_config.active_probing", "capture_config.dedup_ttl_minutes"},
		},
		{
			name:       "empty payload is an error, not success",
			payload:    map[string]interface{}{"config": map[string]interface{}{}},
			wantStatus: "error",
			wantInMsg:  []string{"no settings"},
		},
		{
			name:       "unknown field only is an error",
			payload:    map[string]interface{}{"config": map[string]interface{}{"bogus": 1.0}},
			wantStatus: "error",
			wantInMsg:  []string{"bogus"},
		},
		{
			name: "partial: applied and skipped are both listed",
			payload: map[string]interface{}{"config": map[string]interface{}{
				"capture_config": map[string]interface{}{
					"network_discovery": false,
					"dedup_ttl_minutes": "x",
				},
			}},
			wantStatus:  "success",
			wantInMsg:   []string{"1 settings changed", "skipped", "capture_config.dedup_ttl_minutes"},
			wantFile:    []string{"networkDiscovery: false"},
			wantApplied: 1,
		},
		{
			name: "valid: applied in memory and persisted",
			payload: map[string]interface{}{"config": map[string]interface{}{
				"reporting_interval": 120.0,
				"capture_config": map[string]interface{}{
					"active_probing":    false,
					"network_discovery": false,
					"host_observation":  false,
					"dedup_ttl_minutes": 15, // int, as a Go-built payload carries it
				},
			}},
			wantStatus:  "success",
			wantInMsg:   []string{"5 settings changed"},
			wantFile:    []string{"reportingIntervalSeconds: 120", "activeProbing: false", "networkDiscovery: false", "hostObservation: false", "dedupTTLMinutes: 15"},
			wantApplied: 5,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := commandSensor(t)
			resp := s.handleUpdateConfig(cmd(tc.payload))
			if resp.Status != tc.wantStatus {
				t.Fatalf("status = %q (%s), want %q", resp.Status, resp.Message, tc.wantStatus)
			}
			for _, w := range tc.wantInMsg {
				if !strings.Contains(resp.Message, w) {
					t.Errorf("message %q lacks %q", resp.Message, w)
				}
			}
			if got := resp.ResponseData["updates_applied"]; got != tc.wantApplied {
				t.Errorf("updates_applied = %v, want %d", got, tc.wantApplied)
			}
			data, _ := os.ReadFile(s.configPath)
			for _, w := range tc.wantFile {
				if !strings.Contains(string(data), w) {
					t.Errorf("config file lacks %q:\n%s", w, data)
				}
			}
			if tc.wantStatus == "error" && tc.wantApplied == 0 {
				if !s.config.ActiveProbingEnabled() || !s.config.Capture.NetworkDiscovery || s.config.Capture.DedupTTLMinutes != 60 {
					t.Errorf("rejected update changed the running config")
				}
			}
		})
	}
}

func TestHandleUpdateConfigAppliesInMemory(t *testing.T) {
	s := commandSensor(t)
	resp := s.handleUpdateConfig(cmd(map[string]interface{}{"config": map[string]interface{}{
		"reporting_interval": 90.0,
		"capture_config":     map[string]interface{}{"active_probing": false, "dedup_ttl_minutes": 15.0},
	}}))
	if resp.Status != "success" {
		t.Fatal(resp.Message)
	}
	if s.config.ActiveProbingEnabled() || s.config.Capture.DedupTTLMinutes != 15 || s.config.ReportingInterval != 90*time.Second {
		t.Errorf("running config not updated: %+v", s.config.Capture)
	}
}

func TestHandleUpdateConfigUnpersistableIsAnError(t *testing.T) {
	s := commandSensor(t)
	s.configPath = filepath.Join(t.TempDir(), "missing", "config.yaml")
	resp := s.handleUpdateConfig(cmd(map[string]interface{}{"config": map[string]interface{}{
		"capture_config": map[string]interface{}{"network_discovery": false},
	}}))
	if resp.Status != "error" || !strings.Contains(resp.Message, "revert") {
		t.Fatalf("an unsaved change must not report success: %q %q", resp.Status, resp.Message)
	}
}

func TestHandleSetLogLevel(t *testing.T) {
	prev := log.Flags()
	t.Cleanup(func() { log.SetFlags(prev) })
	s := commandSensor(t)

	resp := s.handleSetLogLevel(cmd(map[string]interface{}{"level": "debug"}))
	if resp.Status != "success" || log.Flags()&log.Lshortfile == 0 {
		t.Fatalf("debug not applied: %q flags=%d", resp.Status, log.Flags())
	}
	resp = s.handleSetLogLevel(cmd(map[string]interface{}{"level": "warn"}))
	if resp.Status != "success" || log.Flags()&log.Lshortfile != 0 {
		t.Fatalf("warn not applied: %q flags=%d", resp.Status, log.Flags())
	}
	if resp.ResponseData["log_level"] != "info" || !strings.Contains(resp.Message, "applied as") {
		t.Errorf("response must say warn runs as info: %q %v", resp.Message, resp.ResponseData)
	}
	for _, bad := range []interface{}{"loud", "", 5} {
		before := log.Flags()
		resp = s.handleSetLogLevel(cmd(map[string]interface{}{"level": bad}))
		if resp.Status != "error" || log.Flags() != before {
			t.Errorf("level %v: status %q, flags changed=%v", bad, resp.Status, log.Flags() != before)
		}
	}
}

// A replacement that cannot start (twice: the new set, then the revert) must
// leave the running capture and its channels exactly as they were.
func TestReinitCaptureFailureKeepsRunningCapture(t *testing.T) {
	s := commandSensor(t)
	old := capture.NewPacketCapture(&config.Config{Capture: config.CaptureConfig{DedupTTLMinutes: 60}})
	s.packetCapture = old
	calls := 0
	s.captureFactory = func(*config.Config) (*capture.PacketCapture, error) {
		calls++
		return nil, errors.New("no such interface")
	}

	for i := 0; i < 2; i++ {
		if err := s.reinitCapture(); err == nil {
			t.Fatal("expected the failed start to be reported")
		}
	}
	if calls != 2 || s.packetCapture != old {
		t.Fatalf("calls=%d, capture replaced=%v", calls, s.packetCapture != old)
	}
	select {
	case d, ok := <-old.GetDiscoveries():
		t.Fatalf("running capture's channel was disturbed: %v %v", d, ok)
	case e, ok := <-old.GetErrors():
		t.Fatalf("running capture's channel was disturbed: %v %v", e, ok)
	default: // open and quiet, as a live capture is
	}
}

// A closed channel is a restart condition: it must neither panic on the nil
// discovery nor be reported as "carry on" (which is what spins the main loop).
func TestClosedCaptureChannelsStopTheLoop(t *testing.T) {
	s := commandSensor(t)
	done := make(chan [2]bool, 1)
	go func() {
		done <- [2]bool{s.onCaptureDiscovery(nil, false), s.onCaptureError(nil, false)}
	}()
	select {
	case got := <-done:
		if !got[0] || !got[1] {
			t.Fatalf("closed channels must stop the loop, got %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return")
	}
	if s.onCaptureError(errors.New("boom"), true) {
		t.Error("a real capture error must not stop the loop")
	}
}
