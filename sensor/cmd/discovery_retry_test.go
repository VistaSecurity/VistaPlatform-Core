package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/api"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

const retryTestSensorID = "11111111-2222-3333-4444-555555555555"

func TestProcessDiscoveries_RetainsFailedBatchAndRetriesBeforeNewDiscoveries(t *testing.T) {
	var batches []models.DiscoveryBatch
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sensor-manager/sensors/"+retryTestSensorID+"/discoveries" {
			t.Fatalf("unexpected discovery path %q", r.URL.Path)
		}
		var batch models.DiscoveryBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		batches = append(batches, batch)
		if len(batches) == 1 {
			http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sensor := retryTestSensor(server.URL)
	sensor.discoveries = []*models.CryptoDiscovery{retryTestDiscovery("failed-first")}

	sensor.processDiscoveries()

	if len(batches) != 1 {
		t.Fatalf("first tick submitted %d batches, want 1", len(batches))
	}
	assertDiscoveryIDs(t, batches[0].Discoveries, []string{"failed-first"})
	if got := discoveryIDs(sensor.pendingRetry); fmt.Sprint(got) != "[failed-first]" {
		t.Fatalf("pendingRetry after failure = %v, want [failed-first]", got)
	}
	if len(sensor.discoveries) != 0 {
		t.Fatalf("discoveries after failure = %d, want drained into retry queue", len(sensor.discoveries))
	}
	if sensor.retryCount != 1 {
		t.Fatalf("retryCount after failure = %d, want 1", sensor.retryCount)
	}

	sensor.discoveries = []*models.CryptoDiscovery{retryTestDiscovery("new-second")}
	sensor.processDiscoveries()

	if len(batches) != 2 {
		t.Fatalf("second tick submitted %d batches total, want 2", len(batches))
	}
	assertDiscoveryIDs(t, batches[1].Discoveries, []string{"failed-first", "new-second"})
	if len(sensor.pendingRetry) != 0 {
		t.Fatalf("pendingRetry after successful retry = %v, want empty", discoveryIDs(sensor.pendingRetry))
	}
	if len(sensor.discoveries) != 0 {
		t.Fatalf("discoveries after successful retry = %v, want empty", discoveryIDs(sensor.discoveries))
	}
	if sensor.retryCount != 0 {
		t.Fatalf("retryCount after success = %d, want reset to 0", sensor.retryCount)
	}
}

func TestProcessDiscoveries_CapsRetryQueueByDroppingOldestDiscoveries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "still down", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	sensor := retryTestSensor(server.URL)
	for i := 0; i < retryCapLimit+2; i++ {
		sensor.discoveries = append(sensor.discoveries, retryTestDiscovery(fmt.Sprintf("d-%04d", i)))
	}

	sensor.processDiscoveries()

	if len(sensor.pendingRetry) != retryCapLimit {
		t.Fatalf("pendingRetry length = %d, want cap %d", len(sensor.pendingRetry), retryCapLimit)
	}
	if got := sensor.pendingRetry[0].ID; got != "d-0002" {
		t.Fatalf("oldest retained discovery = %q, want d-0002 after dropping d-0000 and d-0001", got)
	}
	if got := sensor.pendingRetry[len(sensor.pendingRetry)-1].ID; got != "d-1001" {
		t.Fatalf("newest retained discovery = %q, want d-1001", got)
	}
}

func TestProcessDiscoveries_LeavesBufferedDiscoveriesUntilRegistrationCompletes(t *testing.T) {
	sensor := &Sensor{
		config:      &config.Config{},
		discoveries: []*models.CryptoDiscovery{retryTestDiscovery("pending-registration")},
	}

	sensor.processDiscoveries()

	if got := discoveryIDs(sensor.discoveries); fmt.Sprint(got) != "[pending-registration]" {
		t.Fatalf("discoveries after unregistered tick = %v, want retained until registration succeeds", got)
	}
	if len(sensor.pendingRetry) != 0 {
		t.Fatalf("pendingRetry = %v, want empty before any submission attempt", discoveryIDs(sensor.pendingRetry))
	}
}

func retryTestSensor(baseURL string) *Sensor {
	cfg := &config.Config{
		SensorID:        retryTestSensorID,
		ControlPlaneURL: baseURL,
	}
	return &Sensor{
		config:      cfg,
		apiClient:   api.NewOutboundClient(cfg),
		discoveries: make([]*models.CryptoDiscovery, 0),
	}
}

func retryTestDiscovery(id string) *models.CryptoDiscovery {
	return &models.CryptoDiscovery{
		ID:              id,
		SensorID:        retryTestSensorID,
		Timestamp:       time.Unix(1, 0).UTC(),
		SourceIP:        "192.0.2.10",
		DestIP:          "198.51.100.20",
		Port:            443,
		Protocol:        "tls",
		Version:         "TLS 1.3",
		CipherSuite:     "TLS_AES_128_GCM_SHA256",
		DiscoveryMethod: "passive",
		Confidence:      0.95,
	}
}

func assertDiscoveryIDs(t *testing.T, discoveries []models.CryptoDiscovery, want []string) {
	t.Helper()
	got := make([]string, 0, len(discoveries))
	for _, discovery := range discoveries {
		got = append(got, discovery.ID)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("discovery IDs = %v, want %v", got, want)
	}
}

func discoveryIDs(discoveries []*models.CryptoDiscovery) []string {
	ids := make([]string, 0, len(discoveries))
	for _, discovery := range discoveries {
		ids = append(ids, discovery.ID)
	}
	return ids
}
