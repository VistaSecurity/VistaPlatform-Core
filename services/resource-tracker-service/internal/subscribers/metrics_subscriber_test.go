package subscribers

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// TestConvertMetricsEventToRequest_ReadsTheKeyThePublisherWrites is the
// regression test for the dropped metrics key (audit finding B-38, defect 1,
// the same class as the storage key in and in the same map literal).
//
// monitoring-service publishes the costable network figure under
// "network_bytes". This subscriber looked it up under that name while the
// publisher only ever wrote "network_bytes_in" and "network_bytes_out", so the
// lookup missed on every event and the value was discarded in silence — no
// error, no log, a zero in the column.
//
// The payload below is built to match what resource_collector.go actually
// publishes, including the raw since-boot counters that must NOT be read as
// usage.
func TestConvertMetricsEventToRequest_ReadsTheKeyThePublisherWrites(t *testing.T) {
	tenantID := uuid.New()

	e := &events.MetricsEvent{
		EventID:   uuid.New(),
		Source:    "monitoring-service",
		Timestamp: time.Now(),
		Metrics: map[string]interface{}{
			"tenant_id": tenantID.String(),
			// Since-boot counters, published for observability only.
			"network_bytes_in":  float64(9_000_000_000),
			"network_bytes_out": float64(4_000_000_000),
			// The per-interval delta — the only costable network figure.
			"network_bytes": float64(1_500_000),
		},
	}

	req := convertMetricsEventToRequest(e)
	if req == nil {
		t.Fatal("event with a tenant_id produced no request")
	}
	if req.NetworkBytes == nil {
		t.Fatal("network_bytes was dropped: the subscriber is not reading the key the publisher writes")
	}
	if *req.NetworkBytes != 1_500_000 {
		t.Fatalf("network_bytes = %d, want 1500000 (the interval delta)", *req.NetworkBytes)
	}

	// The since-boot counters must not leak into the costable figure. 13e9 is
	// what a naive in+out rename would have produced.
	if *req.NetworkBytes >= 9_000_000_000 {
		t.Fatalf("network_bytes = %d looks like a since-boot counter, not an interval", *req.NetworkBytes)
	}
}

// TestConvertMetricsEventToRequest_AbsentKeysStayUnmeasured pins the
// honesty rule at the ingest boundary: a key the publisher omitted means it had
// no measurement, and must arrive as nil rather than as a measured zero that
// then gets priced.
func TestConvertMetricsEventToRequest_AbsentKeysStayUnmeasured(t *testing.T) {
	tenantID := uuid.New()

	// A first-tick event: no baseline yet, so no network delta is published.
	e := &events.MetricsEvent{
		EventID:   uuid.New(),
		Timestamp: time.Now(),
		Metrics: map[string]interface{}{
			"tenant_id":        tenantID.String(),
			"network_bytes_in": float64(9_000_000_000),
		},
	}

	req := convertMetricsEventToRequest(e)
	if req == nil {
		t.Fatal("event with a tenant_id produced no request")
	}

	for name, got := range map[string]bool{
		"network_bytes":    req.NetworkBytes != nil,
		"api_calls":        req.APICalls != nil,
		"database_queries": req.DatabaseQueries != nil,
		"storage_used_mb":  req.StorageUsedMB != nil,
		"cpu_usage":        req.CPUUsagePercent != nil,
		"memory_usage_mb":  req.MemoryUsageMB != nil,
	} {
		if got {
			t.Errorf("%s was recorded despite the publisher omitting it", name)
		}
	}
}

// TestConvertMetricsEventToRequest_MeasuredZeroSurvives is the other polarity:
// an explicitly published zero is a measurement and must not be demoted to
// "not measured".
func TestConvertMetricsEventToRequest_MeasuredZeroSurvives(t *testing.T) {
	e := &events.MetricsEvent{
		EventID:   uuid.New(),
		Timestamp: time.Now(),
		Metrics: map[string]interface{}{
			"tenant_id":     uuid.New().String(),
			"network_bytes": float64(0),
		},
	}

	req := convertMetricsEventToRequest(e)
	if req == nil {
		t.Fatal("event with a tenant_id produced no request")
	}
	if req.NetworkBytes == nil {
		t.Fatal("an explicitly published zero was demoted to not-measured")
	}
	if *req.NetworkBytes != 0 {
		t.Fatalf("network_bytes = %d, want 0", *req.NetworkBytes)
	}
}

// TestConvertMetricsEventToRequest_NoTenantIsSkipped keeps the existing guard:
// metrics with no tenant are not attributed to anyone.
func TestConvertMetricsEventToRequest_NoTenantIsSkipped(t *testing.T) {
	e := &events.MetricsEvent{
		EventID:   uuid.New(),
		Timestamp: time.Now(),
		Metrics:   map[string]interface{}{"network_bytes": float64(1000)},
	}

	if req := convertMetricsEventToRequest(e); req != nil {
		t.Fatalf("metrics with no tenant_id were attributed to %v", req.TenantID)
	}
}
