package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
)

// The evaluator's other tests use a fakeMetrics that ignores the requested
// window and always returns a reading. That makes them green regardless of
// whether the window it asks for has any rows in production — which is exactly
// how metric_threshold shipped unable to fire: it asked for the 1-hour window,
// and MetricsAggregator's hourly rollup is written with window_start set to the
// PREVIOUS hour, so GetServiceMetrics' `window_start >= now - window` filter
// excluded it always. The Trend came back empty every cycle.
//
// windowRecordingMetrics closes that hole by honouring the window: it returns a
// reading ONLY for the window the aggregator populates for the current moment.
// TestIntegration_HourlyRollupIsNeverInsideTheOneHourWindow (monitoring-service
// internal/services) pins the database-side half of the same fact.
type windowRecordingMetrics struct {
	populated time.Duration
	asked     []time.Duration
	p95       float64
}

func (m *windowRecordingMetrics) GetServiceMetrics(serviceName string, window time.Duration) (*models.ServiceMetrics, error) {
	m.asked = append(m.asked, window)
	metrics := &models.ServiceMetrics{ServiceName: serviceName, Status: "degraded"}
	if window == m.populated {
		v := m.p95
		metrics.Trend = []models.PlatformMetricsSnapshot{{LatencyP95: &v}}
	}
	return metrics, nil
}

func TestThresholdEvaluationReadsAWindowTheAggregatorPopulates(t *testing.T) {
	store := &fakeAlertStore{}
	// Only the 60-second window has rows for "now" — that is what
	// processServiceMetrics writes on every one-minute tick.
	metrics := &windowRecordingMetrics{populated: time.Minute, p95: 300}

	ae, notifications := newTestEvaluator(store, nil)
	ae.metricsService = metrics

	serviceName := "inventory-service"
	threshold := models.AlertThreshold{
		ID:                 uuid.New(),
		ThresholdName:      "response-time",
		MetricType:         "response_time",
		ServiceName:        &serviceName,
		WarningThreshold:   float64Ptr(200),
		CriticalThreshold:  float64Ptr(500),
		ComparisonOperator: "gt",
		Enabled:            true,
	}

	if err := ae.evaluateThreshold(context.Background(), threshold); err != nil {
		t.Fatalf("evaluateThreshold: %v", err)
	}

	if len(metrics.asked) != 1 {
		t.Fatalf("asked for %d windows, want 1", len(metrics.asked))
	}
	if metrics.asked[0] != metrics.populated {
		t.Fatalf("evaluation read the %v window, which the aggregator does not populate for the "+
			"current moment; want %v", metrics.asked[0], metrics.populated)
	}
	if *notifications == 0 && store.recorded == 0 {
		t.Fatal("a p95 of 300 over a warning threshold of 200 produced no alert at all")
	}
}
