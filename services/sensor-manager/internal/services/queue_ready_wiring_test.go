package services

// The discovery.queue.ready WIRING of sensor-manager's two sensor_discoveries
// writers ( WP1): StoreDiscoveries (passive sensor batches, TLS
// enrichment, self-observation) and RecordSensorUnits (a tenant sensor's
// planned-scan units, mirrored into the queue by jobunits.Commit).
//
// Each test drives the real method with a recording NATS stand-in and asserts
// exactly one wake-up carrying the tenant and batch. Delete the publish line
// in either method and its test goes red.

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/events/eventstest"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

func oneTLSBatch(sensorID uuid.UUID) *models.DiscoveryBatch {
	return &models.DiscoveryBatch{
		SensorID:  sensorID,
		BatchID:   uuid.New(),
		Timestamp: time.Now(),
		Discoveries: []models.SensorDiscoveryInput{{
			Protocol: "TLS", SourceIP: "192.0.2.5", DestIP: "203.0.113.40", Port: 443,
			DiscoveryMethod: "passive",
		}},
	}
}

func TestStoreDiscoveries_PublishesQueueReadyAfterCommit(t *testing.T) {
	tenantID, sensorID := uuid.New(), uuid.New()
	svc, mock, _ := newStoreMock(t, tenantID, sensorID)
	rec := &eventstest.Recorder{}
	svc.SetQueuePublisher(rec)

	batch := oneTLSBatch(sensorID)
	if err := svc.StoreDiscoveries(batch); err != nil {
		t.Fatalf("StoreDiscoveries: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
	got := rec.QueueReady()
	if len(got) != 1 {
		t.Fatalf("StoreDiscoveries published %d discovery.queue.ready event(s), want exactly 1 — without it discovery-processor only sees the batch on its fallback poll", len(got))
	}
	if got[0].TenantID != tenantID || got[0].BatchID != batch.BatchID.String() {
		t.Fatalf("event = tenant %s batch %s, want tenant %s batch %s", got[0].TenantID, got[0].BatchID, tenantID, batch.BatchID)
	}
}

// The other polarity: a write that did not commit wakes nobody. Publishing
// from inside the transaction would fire here too.
func TestStoreDiscoveries_FailedCommitPublishesNothing(t *testing.T) {
	tenantID, sensorID := uuid.New(), uuid.New()
	svc, mock, _ := newStoreMockCommitFails(t, tenantID, sensorID)
	rec := &eventstest.Recorder{}
	svc.SetQueuePublisher(rec)

	if err := svc.StoreDiscoveries(oneTLSBatch(sensorID)); err == nil {
		t.Fatal("StoreDiscoveries succeeded although its commit failed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
	if n := len(rec.Messages()); n != 0 {
		t.Fatalf("a batch whose commit failed published %d message(s); the publish must follow the commit", n)
	}
}

func TestIntegration_RecordSensorUnits_PublishesQueueReadyForAcceptedUnits(t *testing.T) {
	f := newCompletionFixture(t)
	rec := &eventstest.Recorder{}
	f.svc.SetQueuePublisher(rec)
	jobID, targetID := f.plannedJob(t, "10.183.9.1")
	batch := sensordispatch.UnitBatch{Units: []sensordispatch.UnitResult{sshHost(targetID, "10.183.9.1")}}

	resp, err := f.svc.RecordSensorUnits(context.Background(), f.tenant, f.sensor, jobID, batch)
	if err != nil || resp.Accepted != 1 {
		t.Fatalf("report = %+v %v", resp, err)
	}
	if n := f.count(t, `SELECT COUNT(*) FROM sensor_discoveries WHERE batch_id = $1`, jobID); n != 1 {
		t.Fatalf("%d row(s) queued, want 1 — the fixture no longer mirrors, so this test proves nothing", n)
	}
	got := rec.QueueReady()
	if len(got) != 1 {
		t.Fatalf("RecordSensorUnits published %d discovery.queue.ready event(s), want exactly 1", len(got))
	}
	if got[0].TenantID != f.tenant || got[0].BatchID != jobID.String() {
		t.Fatalf("event = tenant %s batch %s, want tenant %s batch %s (the job id the mirror rows carry)",
			got[0].TenantID, got[0].BatchID, f.tenant, jobID)
	}

	// Re-sent: nothing new was stored, so nothing new is announced.
	if resp, err = f.svc.RecordSensorUnits(context.Background(), f.tenant, f.sensor, jobID, batch); err != nil || resp.Duplicate != 1 {
		t.Fatalf("re-sent report = %+v %v", resp, err)
	}
	if n := len(rec.QueueReady()); n != 1 {
		t.Fatalf("a duplicate report published again (%d events total)", n)
	}
}

// newStoreMockCommitFails is newStoreMock with a COMMIT that fails.
func newStoreMockCommitFails(t *testing.T, tenantID, sensorID uuid.UUID) (*SensorService, sqlmock.Sqlmock, *[]driverArgs) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	bypassDB, bypassMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock bypass: %v", err)
	}
	t.Cleanup(func() { _ = bypassDB.Close() })
	bypassMock.ExpectQuery(`SELECT tenant_id FROM sensors WHERE id = \$1`).
		WithArgs(sensorID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID.String()))
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WillReturnResult(sqlmock.NewResult(0, 1))
	var captured []driverArgs
	caps := make([]driver.Value, 13)
	for i := range caps {
		caps[i] = argCapture{out: &captured}
	}
	mock.ExpectExec(`INSERT INTO sensor_discoveries`).WithArgs(caps...).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit().WillReturnError(errors.New("commit failed"))
	return NewSensorService(db, bypassDB), mock, &captured
}
