package main

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"testing"
	"time"
)

func TestIdentityDNSCommandRejectsMalformedPayload(t *testing.T) {
	s := &Sensor{config: &config.Config{SensorID: "sensor"}}
	result := s.handleIdentityDNS(models.Command{ID: "request", Type: sensordispatch.IdentityDNSCommand, Payload: map[string]interface{}{"hostname": "*.local"}})
	if result == nil || result.Status != "error" || result.CommandID != "request" {
		t.Fatalf("result=%+v", result)
	}
}

func TestIdentityDNSDispatchIsBoundedAndRejectsExpiredWork(t *testing.T) {
	s := &Sensor{config: &config.Config{SensorID: "sensor"}, identityDNSQueue: make(chan models.Command, 8), identityDNSPending: map[string]bool{}}
	expires := time.Now().Add(time.Minute)
	req := sensordispatch.IdentityDNSRequest{RequestID: uuid.NewString(), ObservationID: uuid.NewString(), Hostname: "host.local", NetworkScope: uuid.NewString(), SegmentCIDR: "192.0.2.0/24", TimeoutMS: 2000, MaxAddresses: 8}
	raw, _ := json.Marshal(req)
	payload := map[string]interface{}{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		s.processCommand(models.Command{ID: uuid.NewString(), Type: sensordispatch.IdentityDNSCommand, Payload: payload, ExpiresAt: &expires})
	}
	if len(s.identityDNSQueue) != 8 {
		t.Fatalf("actual dispatcher queued %d", len(s.identityDNSQueue))
	}
	overflow := models.Command{ID: uuid.NewString(), Type: sensordispatch.IdentityDNSCommand, Payload: payload, ExpiresAt: &expires}
	if result := s.queueIdentityDNS(overflow); result == nil || result.Status != "error" {
		t.Fatal("unbounded DNS backlog")
	}
	expired := time.Now().Add(-time.Second)
	overflow.ExpiresAt = &expired
	if result := s.handleIdentityDNS(overflow); result == nil || result.Status != "error" || result.Message != "DNS command expired or missing expiry" {
		t.Fatalf("expired work reached resolver: %+v", result)
	}
}

func TestIdentityDNSCapabilityReachesHeartbeat(t *testing.T) {
	health := sendHeartbeatAndCapture(t, heartbeatTestSensor("http://127.0.0.1:0"))
	found := false
	for _, capability := range health.Capabilities {
		if capability == sensordispatch.IdentityDNSCapability {
			found = true
		}
	}
	if !found {
		t.Fatal("scoped DNS capability absent from actual heartbeat")
	}
}
