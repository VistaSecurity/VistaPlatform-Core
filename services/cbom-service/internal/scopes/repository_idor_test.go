package scopes

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/database"
)

// Regression tests for (cross-tenant Scope IDOR). The by-id Get/Update/
// Delete queries used to filter only `WHERE id = $1` and leaned on Postgres
// RLS — which is inert here (the service connects as the table owner) — so a
// tenant could read/edit/delete another tenant's scope by UUID. The fix adds
// an explicit `AND tenant_id = $N` predicate bound to the caller's tenant.
//
// sqlmock proves both that the SQL carries the tenant_id predicate and that
// the caller's tenant id is bound to it; a foreign tenant therefore matches no
// row and the repository returns ErrNotFound.
func newMockRepo(t *testing.T) (*Repository, sqlmock.Sqlmock) {
	t.Helper()
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	db := &database.DB{DB: sqlx.NewDb(mockDB, "postgres")}
	return NewRepository(db), mock
}

func TestIDOR_GetScopeForeignTenantNotFound(t *testing.T) {
	repo, mock := newMockRepo(t)
	callerTenant := uuid.New() // does NOT own the scope
	scopeID := uuid.New()      // belongs to another tenant

	mock.ExpectBegin()
	mock.ExpectExec("set_config").WithArgs(callerTenant.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("tenant_id = $2")).
		WithArgs(scopeID, callerTenant).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "name", "description", "predicate", "version",
			"is_default", "is_system", "deleted_at", "created_by", "updated_by",
			"created_at", "updated_at",
		}))
	mock.ExpectRollback()

	_, err := repo.Get(context.Background(), callerTenant, scopeID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get cross-tenant = %v, want ErrNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (query not tenant-scoped?): %v", err)
	}
}

func TestIDOR_UpdateScopeForeignTenantNotFound(t *testing.T) {
	repo, mock := newMockRepo(t)
	callerTenant := uuid.New()
	scopeID := uuid.New()
	updatedBy := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec("set_config").WithArgs(callerTenant.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// tenant_id must be the 6th bind ($6) and equal the caller's tenant.
	mock.ExpectQuery(regexp.QuoteMeta("tenant_id = $6")).
		WithArgs("renamed", sqlmock.AnyArg(), sqlmock.AnyArg(), updatedBy, scopeID, callerTenant).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "name", "description", "predicate", "version",
			"is_default", "is_system", "deleted_at", "created_by", "updated_by",
			"created_at", "updated_at",
		}))
	mock.ExpectRollback()

	_, err := repo.Update(context.Background(), callerTenant, scopeID, updatedBy, UpdateRequest{Name: "renamed"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Update cross-tenant = %v, want ErrNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (query not tenant-scoped?): %v", err)
	}
}

func TestIDOR_DeleteScopeForeignTenantNotFound(t *testing.T) {
	repo, mock := newMockRepo(t)
	callerTenant := uuid.New()
	scopeID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec("set_config").WithArgs(callerTenant.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// The is_system pre-check is itself tenant-scoped; a foreign-tenant scope
	// matches no row, so Delete short-circuits to ErrNotFound and never reaches
	// the UPDATE.
	mock.ExpectQuery(regexp.QuoteMeta("tenant_id = $2")).
		WithArgs(scopeID, callerTenant).
		WillReturnRows(sqlmock.NewRows([]string{"is_system"}))
	mock.ExpectRollback()

	err := repo.Delete(context.Background(), callerTenant, scopeID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete cross-tenant = %v, want ErrNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (query not tenant-scoped?): %v", err)
	}
}
