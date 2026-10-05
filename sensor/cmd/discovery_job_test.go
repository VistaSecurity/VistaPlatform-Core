package main

// The sensor's dispatch case: a malformed command is acknowledged as
// FAILED on the spot, a well-formed planned one is queued for the single
// worker and acknowledged later, an overflowing queue refuses rather than
// piling up, and a protocols × ports command — which only a platform older
// than this sensor sends — is refused with a reason ( WP5).

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

const dispatchTestJobID = "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f42"

func dispatchSensor(t *testing.T) *Sensor {
	t.Helper()
	s := &Sensor{config: &config.Config{SensorID: "sensor-1", TestMode: true}}
	// The queue without the worker, so what was queued can be inspected.
	s.jobQueue = make(chan models.Command, discoveryJobQueueDepth)
	return s
}

// goodCommand is a planned discovery_job command, the only kind this sensor
// runs.
func goodCommand(id string) models.Command {
	return planCommand(id, dispatchTestJobID, planTarget("10.0.0.10", "443"))
}

// legacyCommand is the protocols × ports payload an older platform sends.
func legacyCommand(id string) models.Command {
	return models.Command{ID: id, Type: sensordispatch.CommandType, Payload: map[string]interface{}{
		"job_id":    dispatchTestJobID,
		"targets":   []interface{}{"10.0.0.10"},
		"protocols": []interface{}{"TLS"},
		"ports":     []interface{}{float64(443)},
	}}
}

func TestHandleDiscoveryJob_MalformedPayloadIsRefusedNotSilentlyDropped(t *testing.T) {
	s := dispatchSensor(t)
	cases := []struct {
		name    string
		payload map[string]interface{}
	}{
		{"empty", nil},
		{"no targets", map[string]interface{}{"job_id": dispatchTestJobID}},
		{"job id not a uuid", map[string]interface{}{"job_id": "job-1", "targets": []interface{}{"10.0.0.10"}}},
		{"plan and targets both", map[string]interface{}{"job_id": dispatchTestJobID, "targets": []interface{}{"10.0.0.10"}, "plan": goodCommand("x").Payload["plan"]}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := s.handleDiscoveryJob(models.Command{ID: "cmd-" + tc.name, Type: sensordispatch.CommandType, Payload: tc.payload})
			if result == nil {
				t.Fatal("a malformed command produced no acknowledgement — the platform would wait on it forever")
			}
			if result.Status != "error" || !strings.Contains(result.Message, "malformed") {
				t.Errorf("ack = %s / %q, want a failed ack naming the malformed payload", result.Status, result.Message)
			}
			if result.CommandID != "cmd-"+tc.name {
				t.Errorf("ack names command %q", result.CommandID)
			}
			if len(s.jobQueue) != 0 {
				t.Errorf("a malformed command was queued")
			}
		})
	}
}

// WP5: this sensor has no protocols × ports executor. A well-formed
// legacy command is refused at once, through the same refusal path, with a
// reason telling the operator to upgrade the platform — never queued, never
// half-run. Mutation: drop the payload.Plan == nil refusal in
// handleDiscoveryJob and the command is queued, turning this red.
func TestHandleDiscoveryJob_LegacyPayloadIsRefusedWithTheUpgradeReason(t *testing.T) {
	s := dispatchSensor(t)
	result := s.handleDiscoveryJob(legacyCommand("cmd-legacy"))
	if result == nil {
		t.Fatal("a protocols × ports command was accepted by a sensor with no executor for it")
	}
	if result.Status != "error" || result.CommandID != "cmd-legacy" {
		t.Fatalf("ack = %+v, want a failed ack for cmd-legacy", result)
	}
	for _, want := range []string{"scan plan", "protocols × ports", "upgrade the platform"} {
		if !strings.Contains(result.Message, want) {
			t.Errorf("refusal %q lacks %q", result.Message, want)
		}
	}
	if refused, _ := result.ResponseData["refused"].(bool); !refused {
		t.Errorf("ack data = %v, want refused=true (the platform fails the job on it)", result.ResponseData)
	}
	if len(s.jobQueue) != 0 {
		t.Error("a protocols × ports command was queued")
	}
}

func TestHandleDiscoveryJob_WellFormedCommandIsQueuedAndAcknowledgedLater(t *testing.T) {
	s := dispatchSensor(t)
	if result := s.handleDiscoveryJob(goodCommand("cmd-1")); result != nil {
		t.Fatalf("an accepted command was acknowledged immediately: %+v — the ack must carry the job's outcome", result)
	}
	if len(s.jobQueue) != 1 {
		t.Fatalf("queue holds %d, want the one command", len(s.jobQueue))
	}
	if queued := <-s.jobQueue; queued.ID != "cmd-1" {
		t.Errorf("queued command = %q", queued.ID)
	}
}

func TestHandleDiscoveryJob_FullQueueRefusesRatherThanBacklogs(t *testing.T) {
	s := dispatchSensor(t)
	for i := 0; i < discoveryJobQueueDepth; i++ {
		if result := s.handleDiscoveryJob(goodCommand("cmd-fill")); result != nil {
			t.Fatalf("command %d refused before the queue was full: %+v", i, result)
		}
	}
	result := s.handleDiscoveryJob(goodCommand("cmd-overflow"))
	if result == nil || result.Status != "error" || !strings.Contains(result.Message, "busy") {
		t.Fatalf("overflow ack = %+v, want a failed 'sensor busy' ack", result)
	}
}

func TestHandleDiscoveryJob_NoWorkerIsRefused(t *testing.T) {
	s := &Sensor{config: &config.Config{SensorID: "sensor-1"}}
	result := s.handleDiscoveryJob(goodCommand("cmd-1"))
	if result == nil || result.Status != "error" {
		t.Fatalf("ack = %+v, want a refusal when no worker is running", result)
	}
}

// The command switch reaches the handler: an unknown-type ack for
// "discovery_job" would mean the case was never wired.
func TestProcessCommand_RoutesDiscoveryJob(t *testing.T) {
	s := dispatchSensor(t)
	s.processCommand(goodCommand("cmd-routed"))
	if len(s.jobQueue) != 1 {
		t.Fatal("processCommand did not route a discovery_job command to the job queue")
	}
}

func TestStartDiscoveryJobWorker_IsIdempotent(t *testing.T) {
	s := &Sensor{config: &config.Config{SensorID: "sensor-1"}}
	s.startDiscoveryJobWorker()
	first := s.jobQueue
	s.startDiscoveryJobWorker()
	if s.jobQueue != first {
		t.Fatal("a second start replaced the queue — two workers would now race")
	}
}
