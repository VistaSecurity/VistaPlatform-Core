package cbom

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

// Regression tests for (cross-tenant CBOM artifact IDOR). The by-id
// queries used to filter only `WHERE id = $1` and leaned on Postgres RLS for
// isolation — but RLS is inert in this deployment (the service connects as the
// table owner), so a tenant could read/download/delete another tenant's
// artifact by UUID. The fix adds an explicit `AND tenant_id = $N` predicate
// bound to the caller's tenant on every by-id query.
//
// These tests assert two things with sqlmock: (1) the SQL actually carries the
// tenant_id predicate, and (2) the caller's tenant id is bound to it. A
// foreign tenant therefore matches no row and the repository returns
// ErrNotFound — never the victim's data. Reverting the fix breaks both the
// query-text regexp and the two-arg expectation, failing these tests loudly.
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

func TestIDOR_ListArtifactsTenantScoped(t *testing.T) {
	repo, mock := newMockRepo(t)
	callerTenant := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec("set_config").WithArgs(callerTenant.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Listing is also an IDOR surface: artifact metadata includes tenant IDs,
	// storage keys, hashes, and optional attestation layers. The service DB user
	// owns the table, so RLS is not the isolation boundary here.
	mock.ExpectQuery(regexp.QuoteMeta("tenant_id = $1")).
		WithArgs(callerTenant).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "scope_id", "scope_version", "scope_name_snapshot",
			"name", "storage_key", "has_inline", "content_hash", "size_bytes",
			"component_count", "cyclonedx_spec_version", "input_data_freshness_at",
			"generated_at", "generated_by", "signature_hmac", "signature_kid",
			"provenance", "layers", "created_at",
		}))
	mock.ExpectCommit()

	artifacts, err := repo.List(context.Background(), callerTenant, nil, 50)
	if err != nil {
		t.Fatalf("List tenant-scoped = %v", err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("List returned %d artifacts, want 0", len(artifacts))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (list query not tenant-scoped?): %v", err)
	}
}

func TestIDOR_GetArtifactForeignTenantNotFound(t *testing.T) {
	repo, mock := newMockRepo(t)
	callerTenant := uuid.New() // a tenant that does NOT own the artifact
	artifactID := uuid.New()   // belongs to some other tenant

	mock.ExpectBegin()
	mock.ExpectExec("set_config").WithArgs(callerTenant.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// The query must be tenant-scoped and bind the caller's tenant; with no
	// matching row the scan returns no rows.
	mock.ExpectQuery(regexp.QuoteMeta("tenant_id = $2")).
		WithArgs(artifactID, callerTenant).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "scope_id", "scope_version", "scope_name_snapshot",
			"name", "storage_key", "has_inline", "content_hash", "size_bytes",
			"component_count", "cyclonedx_spec_version", "input_data_freshness_at",
			"generated_at", "generated_by", "signature_hmac", "signature_kid",
			"provenance", "layers", "created_at",
		}))
	mock.ExpectRollback()

	_, err := repo.Get(context.Background(), callerTenant, artifactID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get cross-tenant = %v, want ErrNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (query not tenant-scoped?): %v", err)
	}
}

func TestIDOR_GetInlineContentForeignTenantNotFound(t *testing.T) {
	repo, mock := newMockRepo(t)
	callerTenant := uuid.New()
	artifactID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec("set_config").WithArgs(callerTenant.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("tenant_id = $2")).
		WithArgs(artifactID, callerTenant).
		WillReturnRows(sqlmock.NewRows([]string{"inline_content"}))
	mock.ExpectRollback()

	_, err := repo.GetInlineContent(context.Background(), callerTenant, artifactID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetInlineContent cross-tenant = %v, want ErrNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (query not tenant-scoped?): %v", err)
	}
}

func TestIDOR_SoftDeleteForeignTenantNotFound(t *testing.T) {
	repo, mock := newMockRepo(t)
	callerTenant := uuid.New()
	artifactID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec("set_config").WithArgs(callerTenant.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// A foreign-tenant artifact matches no row → 0 rows affected → ErrNotFound.
	mock.ExpectExec(regexp.QuoteMeta("tenant_id = $2")).
		WithArgs(artifactID, callerTenant).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err := repo.SoftDelete(context.Background(), callerTenant, artifactID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("SoftDelete cross-tenant = %v, want ErrNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (query not tenant-scoped?): %v", err)
	}
}
