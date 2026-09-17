package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/api"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// TestSendHeartbeat_HostBlock_FirstBeatAlwaysReports pins the "never sent"
// case: a fresh sensor's very first heartbeat must carry a Host block, since
// lastHostSentAt is zero.
//
// Mutation check: changing shouldReportHost's `stale` computation to
// `s.lastHostSentAt.IsZero()` alone (dropping the `|| now.Sub(...) >=
// hostReportInterval` half) would still pass this one test — the interval
// half is what TestSendHeartbeat_HostBlock_ThrottledWhenUnchanged and
// TestSendHeartbeat_HostBlock_ResentAfterInterval below actually exercise.
func TestSendHeartbeat_HostBlock_FirstBeatAlwaysReports(t *testing.T) {
	sensor := heartbeatTestSensor("")
	health := sendHeartbeatAndCapture(t, sensor)
	if health.Host == nil {
		t.Fatal("first heartbeat must carry a Host block")
	}
	if health.Host.OS == "" {
		t.Fatalf("Host block = %+v, want OS populated", health.Host)
	}
}

// TestSendHeartbeat_HostBlock_ThrottledWhenUnchanged pins the throttle's
// core behaviour: two heartbeats sent back-to-back (well within
// hostReportInterval) with nothing about the host having changed must send
// the block on the FIRST and omit it on the SECOND.
//
// Mutation check: deleting the `if reportHost { health.Host = hostBlock }`
// guard in sendHeartbeat (always attaching it) makes this test fail on the
// second capture.
func TestSendHeartbeat_HostBlock_ThrottledWhenUnchanged(t *testing.T) {
	sensor := heartbeatTestSensor("")

	first := sendHeartbeatAndCapture(t, sensor)
	if first.Host == nil {
		t.Fatal("first heartbeat must carry a Host block")
	}

	second := sendHeartbeatAndCapture(t, sensor)
	if second.Host != nil {
		t.Fatalf("second heartbeat (unchanged, immediate) carried a Host block; want it throttled")
	}
}

// TestSendHeartbeat_HostBlock_ResentAfterInterval pins the "an hour has
// passed" half of the throttle independently of content change.
//
// Mutation check: deleting the `stale` disjunct in shouldReportHost (so only
// `changed` can trigger a resend) makes this test fail — an unchanged host
// would never be re-reported, and sensor-manager's own throttle assumes it
// eventually will be (so a database restored from backup, or state lost some
// other way, still converges within the hour).
func TestSendHeartbeat_HostBlock_ResentAfterInterval(t *testing.T) {
	sensor := heartbeatTestSensor("")

	first := sendHeartbeatAndCapture(t, sensor)
	if first.Host == nil {
		t.Fatal("first heartbeat must carry a Host block")
	}

	// Force the throttle's clock back past the interval without waiting an
	// hour in the test.
	sensor.mu.Lock()
	sensor.lastHostSentAt = time.Now().Add(-hostReportInterval - time.Minute)
	sensor.mu.Unlock()

	second := sendHeartbeatAndCapture(t, sensor)
	if second.Host == nil {
		t.Fatal("heartbeat after the throttle interval must re-carry the Host block")
	}
}

// TestSendHeartbeat_HostBlock_ChangeBypassesThrottle: a heartbeat sent
// immediately after a change (not just after the interval) still reports.
func TestSendHeartbeat_HostBlock_ChangeBypassesThrottle(t *testing.T) {
	sensor := heartbeatTestSensor("")
	first := sendHeartbeatAndCapture(t, sensor)
	if first.Host == nil {
		t.Fatal("first heartbeat must carry a Host block")
	}

	// Simulate a change without waiting for the interval: poke the recorded
	// hash so it no longer matches what the next Build() will produce.
	sensor.mu.Lock()
	sensor.lastHostHash = "not-the-real-hash"
	sensor.mu.Unlock()

	second := sendHeartbeatAndCapture(t, sensor)
	if second.Host == nil {
		t.Fatal("a changed host block must be sent immediately, not held for the throttle interval")
	}
}

// TestSendHeartbeat_HostBlock_FailedSendDoesNotCommitThrottle: a heartbeat
// that fails to send must NOT advance the throttle state, so the next
// attempt still tries — otherwise an outage during the one heartbeat that
// happened to carry the Host block would silently suppress it for up to an
// hour once connectivity returns.
//
// Mutation check: moving the `s.commitHostReport(...)` call in sendHeartbeat
// out of the `else` branch (committing unconditionally, even on error) makes
// this test fail.
func TestSendHeartbeat_HostBlock_FailedSendDoesNotCommitThrottle(t *testing.T) {
	sensor := heartbeatTestSensor("")

	// First attempt: server is down, heartbeat fails.
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	sensor.config.ControlPlaneURL = failing.URL
	sensor.apiClient = api.NewOutboundClient(sensor.config)
	sensor.sendHeartbeat()
	failing.Close()

	if !sensor.lastHostSentAt.IsZero() {
		t.Fatalf("throttle state committed despite a failed heartbeat: lastHostSentAt = %v", sensor.lastHostSentAt)
	}

	// Second attempt: server is up. It must still carry the Host block —
	// the failed first attempt must not have "used up" the send.
	var captured *models.SensorHealth
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var health models.SensorHealth
		if err := json.NewDecoder(r.Body).Decode(&health); err != nil {
			t.Fatalf("decode heartbeat body: %v", err)
		}
		captured = &health
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"commands":[]}`))
	}))
	defer up.Close()
	sensor.config.ControlPlaneURL = up.URL
	sensor.apiClient = api.NewOutboundClient(sensor.config)
	sensor.sendHeartbeat()

	if captured == nil {
		t.Fatal("second heartbeat was never sent")
	}
	if captured.Host == nil {
		t.Fatal("Host block was not sent on retry after a failed send")
	}
}

// TestOldSensorHeartbeat_NoHostBlock_IsUnchanged pins backward compatibility
// the other direction: the throttle machinery must not make a heartbeat with
// NO host information at all (hostid.Build returning an identity with nothing
// resolvable — simulated here by directly checking shouldReportHost never
// panics or errors on a fresh Sensor) behave any differently from before this
// feature existed once the block itself is omitted by the caller.
//
// This is a narrower unit check than a full "old sensor" scenario (which
// belongs to sensor-manager/inventory-service, since the sensor binary itself
// has no "old" mode to simulate) — it pins that shouldReportHost is total and
// side-effect-free on its read path regardless of what has been built.
func TestShouldReportHost_ReadOnly(t *testing.T) {
	sensor := heartbeatTestSensor("")
	hash := "some-hash"
	first := sensor.shouldReportHost(hash, time.Now())
	second := sensor.shouldReportHost(hash, time.Now())
	if !first || !second {
		t.Fatalf("shouldReportHost(%q) = %v, %v; want true both times (read-only, never sent before)", hash, first, second)
	}
	if !sensor.lastHostSentAt.IsZero() {
		t.Fatal("shouldReportHost must not commit state on its own")
	}
}
