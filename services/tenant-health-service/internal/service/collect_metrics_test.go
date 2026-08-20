package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/models"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/scoring"
)

// B-12: collectMetricsFromServices used to swallow every peer failure and fill
// the metric block with hardcoded constants. These tests pin that an
// unreachable peer is NAMED and its metrics left at zero, so the scorer can
// report the factor as unknown instead of scoring an invention.

// unreachableService builds a HealthService whose four peer URLs all point at
// a closed port, i.e. every collector fails.
func unreachableService(t *testing.T) *HealthService {
	t.Helper()
	// A server we immediately close: connections are refused, which is exactly
	// what an mTLS handshake failure against :8443 looks like to the caller.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead := srv.URL
	srv.Close()

	return &HealthService{
		scorer:                    scoring.NewHealthScorer(),
		httpClient:                &http.Client{},
		monitoringServiceURL:      dead,
		authServiceURL:            dead,
		inventoryServiceURL:       dead,
		resourceTrackerServiceURL: dead,
	}
}

func TestCollectMetrics_UnreachablePeers_AreNamedAndNotFabricated(t *testing.T) {
	s := unreachableService(t)

	got, err := s.collectMetricsFromServices(uuid.New())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	for _, src := range []string{
		models.SourceMonitoring, models.SourceAuth,
		models.SourceInventory, models.SourceResourceTracker,
	} {
		if !got.IsSourceUnavailable(src) {
			t.Errorf("source %q was unreachable but is not listed in UnavailableSources (%v)", src, got.UnavailableSources)
		}
	}

	// The exact placeholders that used to be substituted. Any of them
	// reappearing means a peer failure is once again indistinguishable from a
	// measurement.
	if got.Uptime != 0 {
		t.Errorf("Uptime = %v, want 0 (was fabricated as 99.9)", got.Uptime)
	}
	if got.ErrorRate != 0 {
		t.Errorf("ErrorRate = %v, want 0 (was fabricated as 0.005)", got.ErrorRate)
	}
	if got.AvgResponseTime != 0 {
		t.Errorf("AvgResponseTime = %v, want 0 (was fabricated as 150)", got.AvgResponseTime)
	}
	if got.ComplianceScore != 0 {
		t.Errorf("ComplianceScore = %v, want 0 (was fabricated as 85)", got.ComplianceScore)
	}
	if got.CPUUtilization != 0 {
		t.Errorf("CPUUtilization = %v, want 0 (was fabricated as 50)", got.CPUUtilization)
	}
	if got.MemoryUtilization != 0 {
		t.Errorf("MemoryUtilization = %v, want 0 (was fabricated as 60)", got.MemoryUtilization)
	}
	if got.CostEfficiency != 0 {
		t.Errorf("CostEfficiency = %v, want 0 (was fabricated as 75)", got.CostEfficiency)
	}
	if got.UserEngagement != 0 {
		t.Errorf("UserEngagement = %v, want 0 (was fabricated as 50)", got.UserEngagement)
	}

	// End to end: an all-peers-down collection must score as UNKNOWN.
	scored := s.scorer.CalculateHealthScore(*got)
	if scored.HealthStatus != models.HealthStatusUnknown {
		t.Fatalf("health status = %q, want %q", scored.HealthStatus, models.HealthStatusUnknown)
	}
}

func TestCollectMetrics_RelaysInventoryServiceOwnUnavailablePeers(t *testing.T) {
	// inventory-service answers, but reports that IT could not reach
	// resource-tracker-service (so api_calls is unknown, not measured).
	inv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(ActivityMetrics{
			ActiveUsers:        4,
			APICalls:           0,
			UserEngagement:     55,
			UnavailableSources: []string{models.SourceResourceTracker},
		})
	}))
	defer inv.Close()

	s := unreachableService(t)
	s.inventoryServiceURL = inv.URL

	got, err := s.collectMetricsFromServices(uuid.New())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if got.IsSourceUnavailable(models.SourceInventory) {
		t.Error("inventory-service answered; it must not be listed as unavailable")
	}
	if !got.IsSourceUnavailable(models.SourceResourceTracker) {
		t.Errorf("inventory-service reported resource-tracker-service unreachable; it must be relayed (%v)", got.UnavailableSources)
	}
	// It is named once, not twice, even though our own poll also failed.
	n := 0
	for _, s := range got.UnavailableSources {
		if s == models.SourceResourceTracker {
			n++
		}
	}
	if n != 1 {
		t.Errorf("resource-tracker-service listed %d times, want 1", n)
	}
	if got.ActiveUsers != 4 {
		t.Errorf("ActiveUsers = %d, want 4 (measured value must survive)", got.ActiveUsers)
	}
}
