package services

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The metric_threshold detector reads GetServiceMetrics(service, window) and
// gives up when the returned Trend is empty. Which window it asks for therefore
// decides whether the detector can fire at all — and that is not visible from
// reading the evaluator, only from the shape of the rows the aggregator writes.
//
// MetricsAggregator writes:
//   - a 60-second snapshot every minute, window_start = now truncated to the minute
//   - a 3600-second rollup only when now.Minute() == 0, window_start = the
//     PREVIOUS hour
//
// GetServiceMetrics filters `window_start >= now - window`. For the hourly
// rollup that bound is unsatisfiable: the row's window_start is a whole hour
// before the moment it is written, so it is already outside the window when it
// lands. These tests pin both halves.

func seedSnapshot(t *testing.T, db *sqlx.DB, service string, windowStart time.Time, durationSecs int, latencyP95 float64) {
	t.Helper()
	if _, err := db.Exec(`
		INSERT INTO platform_metrics_snapshots
		    (id, service_name, window_start, window_duration, latency_p95, error_rate, status)
		VALUES ($1,$2,$3,$4,$5,0.0,'healthy')`,
		uuid.New(), service, windowStart, durationSecs, latencyP95); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
}

func TestIntegration_HourlyRollupIsNeverInsideTheOneHourWindow(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	// Same-package construction: NewMetricsService opens its own pools from
	// config/env, which this test has no need to reproduce.
	svc := &MetricsService{db: raw, bypassDB: raw}
	service := "window-probe-" + uuid.NewString()[:8]
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM platform_metrics_snapshots WHERE service_name = $1`, service)
	})

	// Exactly what aggregateToHourly writes at the top of the hour.
	now := time.Now()
	seedSnapshot(t, db, service, now.Truncate(time.Hour).Add(-time.Hour), 3600, 900)

	metrics, err := svc.GetServiceMetrics(service, time.Hour)
	if err != nil {
		t.Fatalf("GetServiceMetrics(1h): %v", err)
	}
	if len(metrics.Trend) != 0 {
		t.Fatalf("hourly rollup unexpectedly visible in the 1h window (%d rows) — if this now "+
			"passes, GetServiceMetrics' window bound changed and the detector comment above is stale",
			len(metrics.Trend))
	}
}

func TestIntegration_MinuteSnapshotIsVisibleToThresholdEvaluation(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	// Same-package construction: NewMetricsService opens its own pools from
	// config/env, which this test has no need to reproduce.
	svc := &MetricsService{db: raw, bypassDB: raw}
	service := "window-probe-" + uuid.NewString()[:8]
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM platform_metrics_snapshots WHERE service_name = $1`, service)
	})

	// Exactly what processServiceMetrics writes every minute.
	seedSnapshot(t, db, service, time.Now().Truncate(time.Minute), 60, 900)

	metrics, err := svc.GetServiceMetrics(service, time.Minute)
	if err != nil {
		t.Fatalf("GetServiceMetrics(1m): %v", err)
	}
	if len(metrics.Trend) == 0 {
		t.Fatal("the minute snapshot the aggregator writes every minute is not visible in the 1m " +
			"window — the metric_threshold detector would have no value to compare")
	}
	if metrics.Trend[0].LatencyP95 == nil || *metrics.Trend[0].LatencyP95 != 900 {
		t.Fatalf("latency_p95 = %v, want 900", metrics.Trend[0].LatencyP95)
	}
}
