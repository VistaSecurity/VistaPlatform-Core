package services

// Non-owner-role coverage for the usage counters behind every limit check.
//
// The counters read RLS-protected tables (sensors, users, invitations,
// tenant_framework_licenses). Run unwrapped on the RLS-scoped crypto_app handle
// they return 0 with no error, so every cap reports zero usage and nothing is
// ever enforced — an entitlement bypass that no owner-connection test can see,
// because the owner bypasses RLS and the counts come back correct either way.
//
// Skips unless TEST_DATABASE_URL is set.

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_LimitEnforcement_CountsUnderNonOwnerRole(t *testing.T) {
	owner := testdb.Connect(t)
	appDB := testdb.ConnectAsAppRole(t, owner)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	// A create_system_sensors_on_tenant_create trigger seeds platform sensors for
	// every new tenant, so assert relative to that baseline rather than an
	// absolute count.
	var baseline int
	if err := owner.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sensors WHERE tenant_id = $1 AND deleted_at IS NULL`,
		tenantID).Scan(&baseline); err != nil {
		t.Fatalf("baseline sensor count: %v", err)
	}

	// Seed two sensors and one user for this tenant on the owner connection.
	for i := 0; i < 2; i++ {
		if _, err := owner.ExecContext(ctx, `
			INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, created_at, updated_at)
			VALUES ($1, $2, $3, 'linux', '1.0.0', 'standard', 'active', NOW(), NOW())
		`, uuid.New(), tenantID, "limit-count-sensor"); err != nil {
			t.Fatalf("seed sensor: %v", err)
		}
	}
	if _, err := owner.ExecContext(ctx, `
		INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name)
		VALUES ($1, $2, $3, 'x', 'Limit', 'Counter')
	`, uuid.New(), tenantID, "limit-"+tenantID.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Constructed exactly as production constructs it: the RLS-scoped handle.
	svc := NewLimitEnforcementService(appDB)

	t.Run("countSensors", func(t *testing.T) {
		n, err := svc.countSensors(tenantID)
		if err != nil {
			t.Fatalf("countSensors as %s: %v", testdb.RLSAppRole, err)
		}
		if n != baseline+2 {
			t.Fatalf("countSensors = %d, want %d — a zero here means the cap can never trip", n, baseline+2)
		}
	})

	t.Run("countUsers", func(t *testing.T) {
		n, err := svc.countUsers(tenantID)
		if err != nil {
			t.Fatalf("countUsers as %s: %v", testdb.RLSAppRole, err)
		}
		if n != 1 {
			t.Fatalf("countUsers = %d, want 1", n)
		}
	})

	// Pins the failure direction: the same COUNT issued the old way — straight on
	// the RLS-scoped pool with no tenant context — must see nothing. If this ever
	// starts returning 2, the harness has stopped connecting as a non-owner role
	// and the tests above prove nothing.
	t.Run("unwrapped read still sees nothing", func(t *testing.T) {
		var n int
		if err := appDB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sensors WHERE tenant_id = $1 AND deleted_at IS NULL`,
			tenantID).Scan(&n); err != nil {
			t.Fatalf("unwrapped count: %v", err)
		}
		if n != 0 {
			t.Fatalf("unwrapped count = %d, want 0: %s is not subject to RLS, "+
				"so this suite cannot detect the regression it exists to catch", n, testdb.RLSAppRole)
		}
	})
}
