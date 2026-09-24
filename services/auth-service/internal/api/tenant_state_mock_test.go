package api

import (
	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// expectLiveTenantState queues the tenant-state read that RequireAuth now
// performs for every tenant token (RC-4 /) before any handler query, and
// answers "active, not deleted". sqlmock tests that drive the real router with
// a tenant token must queue it first; without it the middleware fails closed
// with 503 tenant_status_unavailable — which is the behaviour a real database
// error gets, and exactly why the read cannot be silently skipped.
func expectLiveTenantState(mock sqlmock.Sqlmock, tenantID uuid.UUID) {
	mock.ExpectQuery(`FROM tenants WHERE id = \$1`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"payment_status", "deleted", "session_version"}).AddRow("active", false, 0))
}
