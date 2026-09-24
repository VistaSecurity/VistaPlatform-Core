package middleware

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
)

// liveTenants reports every tenant usable.
type liveTenants struct{}

func (liveTenants) Check(context.Context, uuid.UUID) (string, bool, error) { return "", false, nil }

// TestMain installs an explicit "every tenant is live" checker for this
// package. None of these tests is about tenant state, and leaving the checker
// unset is NOT "no check": RequireAuth then falls back to the checker built
// from DATABASE_URL. The nightly test-backend job sets DATABASE_URL, the tokens
// here name random tenant ids with no tenants row, and a missing tenant is
// refused 403 tenant_deleted ( item 2) — so these tests passed locally and
// failed only in the nightly. Tenant-state enforcement through RequireAuth is
// covered against the real router and a real database in
// internal/api/tenant_suspension_integration_test.go.
func TestMain(m *testing.M) {
	SetTenantStateChecker(liveTenants{})
	os.Exit(m.Run())
}
