package api

// Regression tests for the invite role allowlist (B-32).
//
// mapInviteRoleName validated the requested role against a hardcoded list of
// four system role names. billing_admin — seeded into every tenant by
// ensureTenantRoles — was not on it, and custom tenant roles could never match,
// so the invite dialog (whose dropdown is populated from the UNFILTERED
// GET /tenant/{id}/roles list) offered options that always returned
// 400 "Invalid role". Role existence is the tenant_roles table's business;
// mapInviteRoleName now only normalizes aliases.

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestMapInviteRoleName_AcceptsSeededAndCustomRoles(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		// The role that the dropdown always offered and the endpoint always
		// rejected — seeded into every tenant by ensureTenantRoles.
		{"billing_admin is invitable", "billing_admin", "billing_admin"},
		// A custom tenant role (shipped in). Nothing about the name is
		// knowable ahead of time, which is why an allowlist can never work.
		{"custom role passes through", "content_reviewer", "content_reviewer"},
		{"custom role is case-normalized", "Content_Reviewer", "content_reviewer"},
		{"custom role is trimmed", "  content_reviewer  ", "content_reviewer"},

		// System roles keep working.
		{"tenant_admin", "tenant_admin", "tenant_admin"},
		{"viewer", "viewer", "viewer"},
		{"security_admin", "security_admin", "security_admin"},
		{"api_user", "api_user", "api_user"},

		// Legacy aliases must survive — old invites and clients still send them.
		{"legacy member alias", "member", "viewer"},
		{"legacy analyst alias", "analyst", "viewer"},
		{"legacy admin alias", "admin", "tenant_admin"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mapInviteRoleName(tc.in)
			if err != nil {
				t.Fatalf("mapInviteRoleName(%q) error = %v, want nil", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("mapInviteRoleName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A blank role is still a client error — it is the one thing that can be
// rejected without asking the database.
func TestMapInviteRoleName_RejectsBlank(t *testing.T) {
	for _, in := range []string{"", "   ", "\t"} {
		if _, err := mapInviteRoleName(in); err == nil {
			t.Errorf("mapInviteRoleName(%q) error = nil, want an error", in)
		}
	}
}

// Now that role names are resolved against tenant_roles, "no such role" must be
// distinguishable so the invite handler can answer 400 instead of 500.
func TestEnsureRoleGrantableByName_UnknownRoleIsNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID := uuid.New()
	actorID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT id FROM tenant_roles`).
		WithArgs(tenantID, "emperor").
		WillReturnRows(sqlmock.NewRows([]string{"id"})) // no such role
	mock.ExpectRollback()

	err = ensureRoleGrantableByName(context.Background(), db, tenantID, actorID, "emperor")
	if !errors.Is(err, errTenantRoleNotFound) {
		t.Fatalf("error = %v, want errTenantRoleNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

// A custom role the tenant actually built, whose permissions the inviter holds,
// must be grantable — the whole point of removing the allowlist.
func TestEnsureRoleGrantableByName_CustomRoleGrantable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID := uuid.New()
	actorID := uuid.New()
	roleID := uuid.New()
	permissionID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT id FROM tenant_roles`).
		WithArgs(tenantID, "content_reviewer").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(roleID))
	// The ceiling resolves the role's owning tenant before reading its grants,
	// so a role id from another tenant can never reach the comparison.
	mock.ExpectQuery(`SELECT tenant_id FROM tenant_roles`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	mock.ExpectQuery(`SELECT p\.id, p\.name`).
		WithArgs(roleID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(permissionID, "inventory.read"))
	// Delegation lookup: a CUSTOM role can never be a delegation grantee, so
	// the lookup short-circuits on is_system_role and exempts nothing.
	mock.ExpectQuery(`SELECT name, is_system_role FROM tenant_roles`).
		WithArgs(roleID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name", "is_system_role"}).
			AddRow("content_reviewer", false))
	mock.ExpectQuery(`SELECT DISTINCT p\.id`).
		WithArgs(actorID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(permissionID))
	mock.ExpectCommit()

	if err := ensureRoleGrantableByName(context.Background(), db, tenantID, actorID, "content_reviewer"); err != nil {
		t.Fatalf("ensureRoleGrantableByName(custom role) = %v, want nil", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}
