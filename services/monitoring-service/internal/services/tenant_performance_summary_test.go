package services

// GetTenantPerformanceSummary used to ask resource-tracker-service, through a
// gateway URL that does not exist in the Kubernetes deployment, for the
// tenant's API-call count, and swallowed every failure into throughput 0.
// It now reads the metering table itself.

import (
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestGetTenantPerformanceSummary_ThroughputFromMeteredAPICalls(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	tenant := uuid.New()
	s := &MetricsService{db: db, bypassDB: db}

	// RLS-scoped read of the tenant's own rows.
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WithArgs(tenant).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COALESCE\(SUM\(api_calls\), 0\)\s+FROM tenant_resource_usage`).
		WithArgs(tenant).
		WillReturnRows(sqlmock.NewRows([]string{"sum"}).AddRow(int64(86400)))
	mock.ExpectCommit()
	// Platform-wide uptime from service health events (bypass role).
	mock.ExpectQuery(`FROM service_health_events`).
		WillReturnRows(sqlmock.NewRows([]string{"healthy_count", "unhealthy_count"}).AddRow(9, 1))

	got, err := s.GetTenantPerformanceSummary(tenant)
	if err != nil {
		t.Fatalf("GetTenantPerformanceSummary: %v", err)
	}
	if got.Throughput != 1 {
		t.Errorf("throughput = %v rps, want 1 (86400 calls over 24 h)", got.Throughput)
	}
	if got.Uptime != 90 {
		t.Errorf("uptime = %v, want 90", got.Uptime)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestGetTenantPerformanceSummary_ReadFailureIsAnErrorNotADefault(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	tenant := uuid.New()
	s := &MetricsService{db: db, bypassDB: db}

	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WithArgs(tenant).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM tenant_resource_usage`).WithArgs(tenant).WillReturnError(sqlmock.ErrCancelled)
	mock.ExpectRollback()

	if _, err := s.GetTenantPerformanceSummary(tenant); err == nil {
		t.Fatal("a metering read failure must surface as an error; the old code answered with defaults that tenant-health scored as real")
	}
}
