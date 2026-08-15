package jobs

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// fakeAlertStore is an in-memory stand-in for the monitoring_alert_history
// table: enough state to prove the alert lifecycle without a database.
type fakeAlertStore struct {
	thresholds []models.AlertThreshold
	alerts     []*models.AlertHistory
	recorded   int
	resolved   int
}

func (f *fakeAlertStore) GetAlertThresholds(_ *string, _ *bool) ([]models.AlertThreshold, error) {
	return f.thresholds, nil
}

func (f *fakeAlertStore) RecordAlert(alert *models.AlertHistory) error {
	cp := *alert
	f.alerts = append(f.alerts, &cp)
	f.recorded++
	return nil
}

func (f *fakeAlertStore) GetActiveAlertForThreshold(thresholdID uuid.UUID) (*models.AlertHistory, error) {
	for i := len(f.alerts) - 1; i >= 0; i-- {
		a := f.alerts[i]
		if a.ThresholdID != nil && *a.ThresholdID == thresholdID &&
			(a.Status == "active" || a.Status == "acknowledged") {
			return a, nil
		}
	}
	return nil, nil
}

func (f *fakeAlertStore) ResolveAlertsForThreshold(thresholdID uuid.UUID, observed float64) (int64, error) {
	var n int64
	now := time.Now()
	for _, a := range f.alerts {
		if a.ThresholdID != nil && *a.ThresholdID == thresholdID &&
			(a.Status == "active" || a.Status == "acknowledged") {
			a.Status = "resolved"
			a.ResolvedAt = &now
			a.ActualValue = observed
			n++
		}
	}
	f.resolved += int(n)
	return n, nil
}

// fakeMetrics returns one fixed latency reading.
type fakeMetrics struct{ p95 float64 }

func (f *fakeMetrics) GetServiceMetrics(serviceName string, _ time.Duration) (*models.ServiceMetrics, error) {
	v := f.p95
	return &models.ServiceMetrics{
		ServiceName: serviceName,
		Status:      "degraded",
		Trend: []models.PlatformMetricsSnapshot{
			{LatencyP95: &v},
		},
	}, nil
}

func float64Ptr(v float64) *float64 { return &v }

// newTestEvaluator builds an evaluator with no network and no database.
func newTestEvaluator(store *fakeAlertStore, metrics *fakeMetrics) (*AlertEvaluator, *int) {
	notifications := 0
	ae := &AlertEvaluator{
		alertingService: store,
		metricsService:  metrics,
		logger:          log.New(log.Writer(), "[AlertEvaluatorTest] ", 0),
		interval:        time.Minute,
	}
	ae.notify = func(map[string]interface{}) error {
		notifications++
		return nil
	}
	return ae, &notifications
}

func latencyThreshold() models.AlertThreshold {
	svc := "inventory-service"
	return models.AlertThreshold{
		ID:                 uuid.New(),
		ThresholdName:      "inventory-latency",
		MetricType:         "response_time",
		ServiceName:        &svc,
		WarningThreshold:   float64Ptr(200),
		CriticalThreshold:  float64Ptr(500),
		Severity:           "high",
		Enabled:            true,
		ComparisonOperator: "gt",
		DurationMinutes:    5,
	}
}

// TestAlertEvaluator_FiresOnceWhileConditionHolds is the regression test.
// Before the fix the evaluator built an AlertHistory, logged it and threw it
// away ("Save alert to database ... For now, log it"), so its de-duplication
// guard queried an always-empty table and every ~5-minute cycle re-notified the
// same alert. Ten cycles must produce exactly one alert and one notification.
func TestAlertEvaluator_FiresOnceWhileConditionHolds(t *testing.T) {
	th := latencyThreshold()
	store := &fakeAlertStore{thresholds: []models.AlertThreshold{th}}
	ae, notifications := newTestEvaluator(store, &fakeMetrics{p95: 300}) // > warning, < critical

	for i := 0; i < 10; i++ {
		if err := ae.evaluateThreshold(context.Background(), th); err != nil {
			t.Fatalf("cycle %d: evaluateThreshold = %v, want nil", i, err)
		}
	}

	if store.recorded != 1 {
		t.Fatalf("recorded %d alerts over 10 cycles, want 1", store.recorded)
	}
	if *notifications != 1 {
		t.Fatalf("sent %d notifications over 10 cycles, want 1", *notifications)
	}
	if store.alerts[0].Severity != "high" {
		t.Fatalf("severity = %q, want %q", store.alerts[0].Severity, "high")
	}
	if store.alerts[0].Status != "active" {
		t.Fatalf("status = %q, want %q", store.alerts[0].Status, "active")
	}
}

// TestAlertEvaluator_ResolvesWhenConditionClears — an alert that is never closed
// would suppress every future breach of the same threshold forever, so the
// recovery half matters as much as the fire-once half.
func TestAlertEvaluator_ResolvesWhenConditionClears(t *testing.T) {
	th := latencyThreshold()
	store := &fakeAlertStore{thresholds: []models.AlertThreshold{th}}
	metrics := &fakeMetrics{p95: 300}
	ae, notifications := newTestEvaluator(store, metrics)

	if err := ae.evaluateThreshold(context.Background(), th); err != nil {
		t.Fatalf("breach cycle: %v", err)
	}
	if store.recorded != 1 || *notifications != 1 {
		t.Fatalf("after breach: recorded=%d notifications=%d, want 1/1", store.recorded, *notifications)
	}

	// Metric recovers.
	metrics.p95 = 50
	if err := ae.evaluateThreshold(context.Background(), th); err != nil {
		t.Fatalf("recovery cycle: %v", err)
	}
	if store.resolved != 1 {
		t.Fatalf("resolved %d alerts, want 1", store.resolved)
	}
	if store.alerts[0].Status != "resolved" || store.alerts[0].ResolvedAt == nil {
		t.Fatalf("alert not closed: status=%q resolved_at=%v", store.alerts[0].Status, store.alerts[0].ResolvedAt)
	}

	// A repeat recovery cycle must be a no-op, not a resolve storm.
	if err := ae.evaluateThreshold(context.Background(), th); err != nil {
		t.Fatalf("second recovery cycle: %v", err)
	}
	if store.resolved != 1 {
		t.Fatalf("resolved %d alerts after a second clear cycle, want 1", store.resolved)
	}

	// And the threshold must be able to fire again afterwards.
	metrics.p95 = 300
	if err := ae.evaluateThreshold(context.Background(), th); err != nil {
		t.Fatalf("re-breach cycle: %v", err)
	}
	if store.recorded != 2 || *notifications != 2 {
		t.Fatalf("after re-breach: recorded=%d notifications=%d, want 2/2", store.recorded, *notifications)
	}
}

// TestAlertEvaluator_EscalatesSeverityOnce — crossing from warning into critical
// is new information and should notify, but only on the transition.
func TestAlertEvaluator_EscalatesSeverityOnce(t *testing.T) {
	th := latencyThreshold()
	store := &fakeAlertStore{thresholds: []models.AlertThreshold{th}}
	metrics := &fakeMetrics{p95: 300} // high
	ae, notifications := newTestEvaluator(store, metrics)

	if err := ae.evaluateThreshold(context.Background(), th); err != nil {
		t.Fatalf("warning cycle: %v", err)
	}

	metrics.p95 = 900 // critical
	for i := 0; i < 3; i++ {
		if err := ae.evaluateThreshold(context.Background(), th); err != nil {
			t.Fatalf("critical cycle %d: %v", i, err)
		}
	}

	if store.recorded != 2 {
		t.Fatalf("recorded %d alerts, want 2 (one high, one critical)", store.recorded)
	}
	if *notifications != 2 {
		t.Fatalf("sent %d notifications, want 2", *notifications)
	}
	if store.alerts[0].Status != "resolved" {
		t.Fatalf("superseded high alert status = %q, want resolved", store.alerts[0].Status)
	}
	if store.alerts[1].Severity != "critical" || store.alerts[1].Status != "active" {
		t.Fatalf("escalated alert = %q/%q, want critical/active", store.alerts[1].Severity, store.alerts[1].Status)
	}
}

// TestAlertEvaluator_DoesNotNotifyWhenPersistenceFails — notifying on a failed
// write would restore the old behaviour: no open alert next cycle means notify
// again, forever.
func TestAlertEvaluator_DoesNotNotifyWhenPersistenceFails(t *testing.T) {
	th := latencyThreshold()
	store := &failingAlertStore{fakeAlertStore{thresholds: []models.AlertThreshold{th}}}
	ae, notifications := newTestEvaluator(&store.fakeAlertStore, &fakeMetrics{p95: 300})
	ae.alertingService = store

	if err := ae.evaluateThreshold(context.Background(), th); err == nil {
		t.Fatal("evaluateThreshold = nil, want the persistence error surfaced")
	}
	if *notifications != 0 {
		t.Fatalf("sent %d notifications despite a failed write, want 0", *notifications)
	}
}

type failingAlertStore struct{ fakeAlertStore }

func (f *failingAlertStore) RecordAlert(*models.AlertHistory) error {
	return errRecordFailed
}

var errRecordFailed = &recordError{}

type recordError struct{}

func (*recordError) Error() string { return "record failed" }

// --- stateful alert rail (alerts.raise / alerts.resolve) ---------------------

// railSinks attaches capturing rail sinks to an evaluator built by
// newTestEvaluator, mimicking a reachable NATS.
func railSinks(ae *AlertEvaluator) (*[]events.AlertRaiseEvent, *[]events.AlertResolveEvent) {
	raises := []events.AlertRaiseEvent{}
	resolves := []events.AlertResolveEvent{}
	ae.raise = func(ev events.AlertRaiseEvent) error {
		raises = append(raises, ev)
		return nil
	}
	ae.resolve = func(ev events.AlertResolveEvent) error {
		resolves = append(resolves, ev)
		return nil
	}
	return &raises, &resolves
}

// TestAlertEvaluator_RaisesOnTheAlertRail is the regression test for the
// orphaned-type defect: metric_threshold was `status: live` in the registry
// while monitoring-service only wrote monitoring_alert_history and published a
// notification, so a breached threshold never became a row in `alerts` and never
// appeared at Remediation → Alerts.
func TestAlertEvaluator_RaisesOnTheAlertRail(t *testing.T) {
	th := latencyThreshold()
	store := &fakeAlertStore{thresholds: []models.AlertThreshold{th}}
	ae, notifications := newTestEvaluator(store, &fakeMetrics{p95: 300})
	raises, _ := railSinks(ae)

	if err := ae.evaluateThreshold(context.Background(), th); err != nil {
		t.Fatalf("evaluateThreshold = %v, want nil", err)
	}

	if len(*raises) != 1 {
		t.Fatalf("published %d raises, want 1", len(*raises))
	}
	ev := (*raises)[0]
	if ev.AlertType != "metric_threshold" {
		t.Errorf("AlertType = %q, want %q", ev.AlertType, "metric_threshold")
	}
	if ev.AlertType == th.ThresholdName {
		t.Errorf("AlertType is the operator-authored threshold name, want the registry id")
	}
	if ev.TenantID != events.PlatformAlertTenantID {
		t.Errorf("TenantID = %s, want the platform sentinel %s", ev.TenantID, events.PlatformAlertTenantID)
	}
	if ev.Source != "monitoring" {
		t.Errorf("Source = %q, want %q", ev.Source, "monitoring")
	}
	if ev.SubjectType != "service" {
		t.Errorf("SubjectType = %q, want %q (registry subject_type)", ev.SubjectType, "service")
	}
	if ev.SubjectID == nil || *ev.SubjectID != th.ID {
		t.Errorf("SubjectID = %v, want the threshold id %s", ev.SubjectID, th.ID)
	}
	if ev.Severity != "high" {
		t.Errorf("Severity = %q, want %q", ev.Severity, "high")
	}
	// The alert engine notifies on open; publishing both rails would notify twice.
	if *notifications != 0 {
		t.Errorf("sent %d direct notifications alongside the raise, want 0", *notifications)
	}
}

// TestAlertEvaluator_RailSubjectIsStableWhileFiring — the engine dedupes on
// (tenant, alert_type, subject_id), so the subject must not vary per cycle.
func TestAlertEvaluator_RailSubjectIsStableWhileFiring(t *testing.T) {
	th := latencyThreshold()
	store := &fakeAlertStore{thresholds: []models.AlertThreshold{th}}
	ae, _ := newTestEvaluator(store, &fakeMetrics{p95: 300})
	raises, _ := railSinks(ae)

	for i := 0; i < 5; i++ {
		if err := ae.evaluateThreshold(context.Background(), th); err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
	}
	if len(*raises) != 1 {
		t.Fatalf("published %d raises over 5 cycles, want 1", len(*raises))
	}
	if *(*raises)[0].SubjectID != th.ID {
		t.Fatalf("SubjectID = %s, want the threshold id %s", *(*raises)[0].SubjectID, th.ID)
	}
}

// TestAlertEvaluator_ResolvesOnTheAlertRail — the registry declares
// `auto_resolve: metric recovers` for this type, and the evaluator does observe
// recovery, so it must publish alerts.resolve for the same subject.
func TestAlertEvaluator_ResolvesOnTheAlertRail(t *testing.T) {
	th := latencyThreshold()
	store := &fakeAlertStore{thresholds: []models.AlertThreshold{th}}
	metrics := &fakeMetrics{p95: 300}
	ae, _ := newTestEvaluator(store, metrics)
	raises, resolves := railSinks(ae)

	if err := ae.evaluateThreshold(context.Background(), th); err != nil {
		t.Fatalf("breach cycle: %v", err)
	}
	metrics.p95 = 50
	if err := ae.evaluateThreshold(context.Background(), th); err != nil {
		t.Fatalf("recovery cycle: %v", err)
	}

	if len(*resolves) != 1 {
		t.Fatalf("published %d resolves, want 1", len(*resolves))
	}
	rv := (*resolves)[0]
	if rv.AlertType != "metric_threshold" {
		t.Errorf("AlertType = %q, want %q", rv.AlertType, "metric_threshold")
	}
	if rv.SubjectID == nil || *rv.SubjectID != *(*raises)[0].SubjectID {
		t.Errorf("resolve subject %v does not match the raised subject %v", rv.SubjectID, (*raises)[0].SubjectID)
	}
	if rv.TenantID != events.PlatformAlertTenantID {
		t.Errorf("TenantID = %s, want the platform sentinel", rv.TenantID)
	}

	// A second clear cycle must not resolve again.
	if err := ae.evaluateThreshold(context.Background(), th); err != nil {
		t.Fatalf("second recovery cycle: %v", err)
	}
	if len(*resolves) != 1 {
		t.Fatalf("published %d resolves after a second clear cycle, want 1", len(*resolves))
	}
}

// TestAlertEvaluator_RailEscalationKeepsSubject — crossing high → critical must
// re-raise on the SAME subject so the engine escalates the open alert instead of
// opening a second one.
func TestAlertEvaluator_RailEscalationKeepsSubject(t *testing.T) {
	th := latencyThreshold()
	store := &fakeAlertStore{thresholds: []models.AlertThreshold{th}}
	metrics := &fakeMetrics{p95: 300}
	ae, _ := newTestEvaluator(store, metrics)
	raises, _ := railSinks(ae)

	if err := ae.evaluateThreshold(context.Background(), th); err != nil {
		t.Fatalf("warning cycle: %v", err)
	}
	metrics.p95 = 900
	if err := ae.evaluateThreshold(context.Background(), th); err != nil {
		t.Fatalf("critical cycle: %v", err)
	}

	if len(*raises) != 2 {
		t.Fatalf("published %d raises, want 2 (open + escalation)", len(*raises))
	}
	if (*raises)[1].Severity != "critical" {
		t.Fatalf("escalation severity = %q, want critical", (*raises)[1].Severity)
	}
	if *(*raises)[1].SubjectID != *(*raises)[0].SubjectID {
		t.Fatal("escalation changed the subject id — the engine would open a second alert")
	}
}

// TestAlertEvaluator_RailUnavailableFallsBackToNotification — a NATS outage must
// degrade to a notification, never to silence.
func TestAlertEvaluator_RailUnavailableFallsBackToNotification(t *testing.T) {
	th := latencyThreshold()
	store := &fakeAlertStore{thresholds: []models.AlertThreshold{th}}
	ae, notifications := newTestEvaluator(store, &fakeMetrics{p95: 300})
	ae.raise = func(events.AlertRaiseEvent) error { return errRecordFailed }

	if err := ae.evaluateThreshold(context.Background(), th); err != nil {
		t.Fatalf("evaluateThreshold = %v, want nil", err)
	}
	if *notifications != 1 {
		t.Fatalf("sent %d notifications with the rail down, want 1", *notifications)
	}
}
