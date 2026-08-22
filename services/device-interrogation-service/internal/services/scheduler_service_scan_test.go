package services

import (
	"context"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// Regression tests for: description and last_run_status are nullable
// columns (NULL on every fresh schedule), and scanning them into plain
// strings made every CreateSchedule and ListSchedules call fail once a fresh
// row existed — while the failing create's INSERT still committed.

var scheduleColumns = []string{
	"id", "tenant_id", "name", "description", "cron_expression",
	"target_type", "target_id", "is_enabled", "last_run_at", "last_run_status",
	"last_run_job_id", "next_run_at", "success_count", "failure_count",
	"parameters", "created_at", "updated_at", "deleted_at",
}

// nullishScheduleRow returns a row shaped like a freshly inserted schedule:
// description, last_run_at, last_run_status, last_run_job_id and deleted_at
// are all NULL.
func nullishScheduleRow(id, tenantID, targetID uuid.UUID, now time.Time) []driver.Value {
	return []driver.Value{
		id.String(), tenantID.String(), "Nightly scan", nil, "0 2 * * *",
		"device", targetID.String(), true, nil, nil,
		nil, now, 0, 0,
		[]byte(`{}`), now, now, nil,
	}
}

func TestCreateSchedule_ToleratesNullColumns(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	id, tenantID, targetID := uuid.New(), uuid.New(), uuid.New()
	now := time.Now()
	// CreateSchedule now runs inside WithTenantTx: each call adds a leading
	// SELECT set_tenant_context($1) inside a transaction.
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO interrogation_schedules`).
		WillReturnRows(sqlmock.NewRows(scheduleColumns).AddRow(nullishScheduleRow(id, tenantID, targetID, now)...))
	mock.ExpectCommit()

	svc := NewSchedulerService(db, db, nil)
	schedule, err := svc.CreateSchedule(context.Background(), tenantID, CreateScheduleRequest{
		Name:           "Nightly scan",
		CronExpression: "0 2 * * *",
		TargetType:     "device",
		TargetID:       targetID,
	})
	if err != nil {
		t.Fatalf("CreateSchedule with NULL description/last_run_status = %v, want nil (regression #498)", err)
	}
	if schedule.LastRunStatus != "" || schedule.Description != "" {
		t.Fatalf("NULL columns should scan as empty strings, got status=%q description=%q", schedule.LastRunStatus, schedule.Description)
	}
	if schedule.LastRunJobID != nil || schedule.LastRunAt != nil {
		t.Fatalf("NULL job id / last run should stay nil, got %v / %v", schedule.LastRunJobID, schedule.LastRunAt)
	}
}

func TestListSchedules_ToleratesNullColumns(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID := uuid.New()
	now := time.Now()
	rows := sqlmock.NewRows(scheduleColumns).
		AddRow(nullishScheduleRow(uuid.New(), tenantID, uuid.New(), now)...)
	// A second, fully populated row alongside the nullish one.
	full := nullishScheduleRow(uuid.New(), tenantID, uuid.New(), now)
	full[3], full[8], full[9], full[10] = "described", now, "success", uuid.New().String()
	rows.AddRow(full...)

	// ListSchedules now runs inside WithTenantTx.
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT (.+) FROM interrogation_schedules`).
		WithArgs(tenantID).
		WillReturnRows(rows)
	mock.ExpectCommit()

	svc := NewSchedulerService(db, db, nil)
	schedules, err := svc.ListSchedules(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("ListSchedules with a NULL-status row = %v, want nil (regression #498)", err)
	}
	if len(schedules) != 2 {
		t.Fatalf("len = %d, want 2", len(schedules))
	}
	if schedules[0].LastRunStatus != "" {
		t.Fatalf("nullish row status = %q, want empty", schedules[0].LastRunStatus)
	}
	if schedules[1].LastRunStatus != "success" || schedules[1].LastRunJobID == nil {
		t.Fatalf("populated row lost data: status=%q jobID=%v", schedules[1].LastRunStatus, schedules[1].LastRunJobID)
	}
}
