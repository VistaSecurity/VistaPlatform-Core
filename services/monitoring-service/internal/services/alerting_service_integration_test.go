package services

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedThreshold inserts a monitoring alert threshold and registers cleanup for
// it and any alerts raised against it. monitoring_alert_* are platform-scoped
// (no tenant_id), so cleanup is explicit rather than tenant-cascade.
func seedThreshold(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	id := uuid.New()
	name := "it-threshold-" + id.String()[:8]
	if _, err := db.Exec(`
		INSERT INTO monitoring_alert_thresholds
			(id, threshold_name, metric_type, service_name, warning_threshold, critical_threshold,
			 severity, enabled, comparison_operator, duration_minutes)
		VALUES ($1, $2, 'response_time', 'inventory-service', 200, 500, 'high', true, 'gt', 5)`,
		id, name,
	); err != nil {
		t.Fatalf("seed threshold: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM monitoring_alert_history WHERE threshold_id = $1`, id)
		_, _ = db.Exec(`DELETE FROM monitoring_alert_thresholds WHERE id = $1`, id)
	})
	return id
}

func newAlert(thresholdID uuid.UUID, severity string, actual float64) *models.AlertHistory {
	svc := "inventory-service"
	msg := "threshold exceeded"
	return &models.AlertHistory{
		ThresholdID:    &thresholdID,
		ThresholdName:  "it-threshold",
		MetricType:     "response_time",
		ServiceName:    &svc,
		ThresholdValue: 200,
		ActualValue:    actual,
		Severity:       severity,
		Message:        &msg,
		Metadata:       map[string]interface{}{"comparison_operator": "gt"},
	}
}

// TestIntegration_AlertingService_AlertLifecycle exercises the persistence layer
// the alert evaluator was missing against real SQL: record → find open →
// resolve → find nothing open. Everything here previously existed only as a
// struct the evaluator built and discarded.
func TestIntegration_AlertingService_AlertLifecycle(t *testing.T) {
	db := testdb.Connect(t)
	svc := NewAlertingService(db)
	thresholdID := seedThreshold(t, db)

	// Nothing open to begin with.
	open, err := svc.GetActiveAlertForThreshold(thresholdID)
	if err != nil {
		t.Fatalf("GetActiveAlertForThreshold = %v, want nil", err)
	}
	if open != nil {
		t.Fatalf("GetActiveAlertForThreshold = %+v, want nil on a fresh threshold", open)
	}

	alert := newAlert(thresholdID, "high", 300)
	if err := svc.RecordAlert(alert); err != nil {
		t.Fatalf("RecordAlert = %v, want nil", err)
	}
	if alert.ID == uuid.Nil {
		t.Fatal("RecordAlert left the alert id unset")
	}

	open, err = svc.GetActiveAlertForThreshold(thresholdID)
	if err != nil {
		t.Fatalf("GetActiveAlertForThreshold = %v, want nil", err)
	}
	if open == nil {
		t.Fatal("GetActiveAlertForThreshold = nil after RecordAlert, want the open alert")
	}
	if open.ID != alert.ID || open.Severity != "high" || open.Status != "active" {
		t.Fatalf("open alert = %s/%s/%s, want %s/high/active", open.ID, open.Severity, open.Status, alert.ID)
	}

	n, err := svc.ResolveAlertsForThreshold(thresholdID, 42.5)
	if err != nil {
		t.Fatalf("ResolveAlertsForThreshold = %v, want nil", err)
	}
	if n != 1 {
		t.Fatalf("ResolveAlertsForThreshold closed %d, want 1", n)
	}

	open, err = svc.GetActiveAlertForThreshold(thresholdID)
	if err != nil {
		t.Fatalf("GetActiveAlertForThreshold = %v, want nil", err)
	}
	if open != nil {
		t.Fatalf("GetActiveAlertForThreshold = %+v after resolve, want nil", open)
	}

	// The resolved row must still be readable through the history API, with the
	// observed recovery value recorded.
	var status string
	var resolvedAt sql.NullTime
	var actual float64
	if err := db.QueryRow(
		`SELECT status, resolved_at, actual_value FROM monitoring_alert_history WHERE id = $1`, alert.ID,
	).Scan(&status, &resolvedAt, &actual); err != nil {
		t.Fatalf("read resolved alert: %v", err)
	}
	if status != "resolved" || !resolvedAt.Valid {
		t.Fatalf("resolved row = status %q resolved_at %v, want resolved/non-null", status, resolvedAt)
	}
	if actual != 42.5 {
		t.Fatalf("resolved actual_value = %v, want 42.5", actual)
	}

	// Resolving again is a no-op, not an error.
	if n, err := svc.ResolveAlertsForThreshold(thresholdID, 40); err != nil || n != 0 {
		t.Fatalf("second ResolveAlertsForThreshold = (%d, %v), want (0, nil)", n, err)
	}
}

// TestIntegration_AlertingService_AcknowledgedCountsAsOpen — an operator who has
// acknowledged an alert must not be re-notified, so 'acknowledged' has to keep
// suppressing new alerts exactly like 'active'.
func TestIntegration_AlertingService_AcknowledgedCountsAsOpen(t *testing.T) {
	db := testdb.Connect(t)
	svc := NewAlertingService(db)
	thresholdID := seedThreshold(t, db)

	alert := newAlert(thresholdID, "high", 300)
	if err := svc.RecordAlert(alert); err != nil {
		t.Fatalf("RecordAlert = %v, want nil", err)
	}
	if _, err := db.Exec(
		`UPDATE monitoring_alert_history SET status = 'acknowledged', acknowledged_at = NOW() WHERE id = $1`,
		alert.ID,
	); err != nil {
		t.Fatalf("acknowledge alert: %v", err)
	}

	open, err := svc.GetActiveAlertForThreshold(thresholdID)
	if err != nil {
		t.Fatalf("GetActiveAlertForThreshold = %v, want nil", err)
	}
	if open == nil {
		t.Fatal("GetActiveAlertForThreshold = nil for an acknowledged alert, want it treated as open")
	}
}

// TestIntegration_AlertingService_OpenAlertIsPerThreshold — the old evaluator
// asked for "the newest active alert for this service" and compared names, so
// one busy threshold could mask another on the same service. Keying on
// threshold_id has to isolate them.
func TestIntegration_AlertingService_OpenAlertIsPerThreshold(t *testing.T) {
	db := testdb.Connect(t)
	svc := NewAlertingService(db)
	thresholdA := seedThreshold(t, db)
	thresholdB := seedThreshold(t, db)

	if err := svc.RecordAlert(newAlert(thresholdA, "high", 300)); err != nil {
		t.Fatalf("RecordAlert(A) = %v, want nil", err)
	}

	openB, err := svc.GetActiveAlertForThreshold(thresholdB)
	if err != nil {
		t.Fatalf("GetActiveAlertForThreshold(B) = %v, want nil", err)
	}
	if openB != nil {
		t.Fatalf("threshold B reported open alert %+v raised against threshold A", openB)
	}

	if n, err := svc.ResolveAlertsForThreshold(thresholdB, 10); err != nil || n != 0 {
		t.Fatalf("ResolveAlertsForThreshold(B) = (%d, %v), want (0, nil) — must not touch A", n, err)
	}
	openA, err := svc.GetActiveAlertForThreshold(thresholdA)
	if err != nil || openA == nil {
		t.Fatalf("threshold A's alert = (%v, %v), want it still open", openA, err)
	}
}
