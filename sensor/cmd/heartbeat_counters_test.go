package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor/internal/api"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

const heartbeatTestSensorID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

// TestDiscoveriesMade_MonotonicAcrossBufferDrain pins the actual production bug:
// discoveries_made used to be read from len(s.discoveries), the CURRENT batch
// buffer, which processDiscoveries() drains on every successful report. A
// sensor that had accepted hundreds of discoveries across many report
// intervals would therefore report discoveries_made: 0 on every heartbeat
// after its first successful submission. The counter must instead be
// cumulative for the life of the process and must never go DOWN, including
// across a drain.
//
// Mutation check: reverting sendHeartbeat's discoveriesMade computation back
// to `int64(len(s.discoveries))` makes this test fail, because the counter
// would drop to 0 right after the successful drain.
func TestDiscoveriesMade_MonotonicAcrossBufferDrain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sensor := heartbeatTestSensor(server.URL)

	sensor.handleDiscovery(retryTestDiscovery("d1"))
	sensor.handleDiscovery(retryTestDiscovery("d2"))
	sensor.handleDiscovery(retryTestDiscovery("d3"))

	if got := atomic.LoadInt64(&sensor.discoveriesMade); got != 3 {
		t.Fatalf("discoveriesMade after 3 acceptances = %d, want 3", got)
	}

	// Drain the batch buffer via a successful submission, exactly as the
	// report-interval ticker does.
	sensor.processDiscoveries()

	if len(sensor.discoveries) != 0 {
		t.Fatalf("discoveries buffer after successful drain = %d, want 0", len(sensor.discoveries))
	}
	if got := atomic.LoadInt64(&sensor.discoveriesMade); got != 3 {
		t.Fatalf("discoveriesMade after buffer drain = %d, want unchanged at 3 (must not drop)", got)
	}

	// A heartbeat sent right after the drain — the exact moment the live bug
	// showed discoveries_made: 0 — must still report the cumulative total.
	if health := sendHeartbeatAndCapture(t, sensor); health.DiscoveriesMade != 3 {
		t.Fatalf("heartbeat DiscoveriesMade after drain = %d, want 3", health.DiscoveriesMade)
	}

	// Further acceptances keep accumulating rather than resetting.
	sensor.handleDiscovery(retryTestDiscovery("d4"))
	if got := atomic.LoadInt64(&sensor.discoveriesMade); got != 4 {
		t.Fatalf("discoveriesMade after a 4th acceptance = %d, want 4", got)
	}
}

// TestRecordDiscoveriesAccepted_CountsFlushedCaptureBatches pins that
// discoveries drained directly from a stopped capture (interface
// reconfiguration and shutdown flush) are counted too, since those bypass
// handleDiscovery entirely.
func TestRecordDiscoveriesAccepted_CountsFlushedCaptureBatches(t *testing.T) {
	sensor := heartbeatTestSensor("http://127.0.0.1:0")

	sensor.recordDiscoveriesAccepted(5)
	if got := atomic.LoadInt64(&sensor.discoveriesMade); got != 5 {
		t.Fatalf("discoveriesMade after recordDiscoveriesAccepted(5) = %d, want 5", got)
	}

	// A zero/negative count (e.g. an empty flushed-discoveries slice) must be a
	// no-op, not a decrement.
	sensor.recordDiscoveriesAccepted(0)
	sensor.recordDiscoveriesAccepted(-1)
	if got := atomic.LoadInt64(&sensor.discoveriesMade); got != 5 {
		t.Fatalf("discoveriesMade after no-op calls = %d, want unchanged at 5", got)
	}
}

// TestErrorsCount_IncrementsOnSubmitFailureAndSurvivesReport pins that a real
// failure path (discovery submission failing, the exact case that previously
// reported errors_count: 0 unconditionally) increments the cumulative
// errors_count, and that value is what reaches the heartbeat.
func TestErrorsCount_IncrementsOnSubmitFailureAndSurvivesReport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	sensor := heartbeatTestSensor(server.URL)
	sensor.discoveries = []*models.CryptoDiscovery{retryTestDiscovery("will-fail")}

	sensor.processDiscoveries()

	if got := atomic.LoadInt64(&sensor.errorsCount); got != 1 {
		t.Fatalf("errorsCount after one failed submit = %d, want 1", got)
	}

	sensor.discoveries = []*models.CryptoDiscovery{retryTestDiscovery("will-fail-again")}
	sensor.processDiscoveries()

	if got := atomic.LoadInt64(&sensor.errorsCount); got != 2 {
		t.Fatalf("errorsCount after two failed submits = %d, want 2 (cumulative)", got)
	}

	if health := sendHeartbeatAndCapture(t, sensor); health.Errors != 2 {
		t.Fatalf("heartbeat Errors = %d, want 2", health.Errors)
	}
}

// TestErrorsCount_IncrementsOnHeartbeatSendFailure pins the heartbeat-send
// failure path specifically (as opposed to discovery submission).
func TestErrorsCount_IncrementsOnHeartbeatSendFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	sensor := heartbeatTestSensor(server.URL)
	sensor.sendHeartbeat()

	if got := atomic.LoadInt64(&sensor.errorsCount); got != 1 {
		t.Fatalf("errorsCount after one failed heartbeat send = %d, want 1", got)
	}
}

// heartbeatTestSensor builds a minimal Sensor wired to baseURL, reusing the
// discovery-retry test helpers for the API client and config.
func heartbeatTestSensor(baseURL string) *Sensor {
	cfg := &config.Config{
		SensorID:        heartbeatTestSensorID,
		ControlPlaneURL: baseURL,
	}
	return &Sensor{
		config:      cfg,
		apiClient:   api.NewOutboundClient(cfg),
		discoveries: make([]*models.CryptoDiscovery, 0),
	}
}

// sendHeartbeatAndCapture runs a real heartbeat POST against sensor's
// apiClient (backed by an httptest server that always answers 200 with an
// empty command list) and returns the health payload sendHeartbeat actually
// built and sent, so tests can assert on DiscoveriesMade/Errors as reported
// to the control plane rather than only on the internal counters.
func sendHeartbeatAndCapture(t *testing.T, sensor *Sensor) *models.SensorHealth {
	t.Helper()

	var captured *models.SensorHealth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var health models.SensorHealth
		if err := json.NewDecoder(r.Body).Decode(&health); err != nil {
			t.Fatalf("decode heartbeat body: %v", err)
		}
		captured = &health
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"commands":[]}`))
	}))
	defer server.Close()

	original := sensor.apiClient
	defer func() { sensor.apiClient = original }()

	sensor.config.ControlPlaneURL = server.URL
	sensor.apiClient = api.NewOutboundClient(sensor.config)

	sensor.sendHeartbeat()

	if captured == nil {
		t.Fatalf("heartbeat handler was never invoked")
	}
	return captured
}
