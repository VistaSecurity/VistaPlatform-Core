package tenantstate

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_TenantState_LookupAndGateOnAppRole reads the real tenants row
// through the RLS-enforcing app role (what DATABASE_URL points at in an
// enforcing deployment) with no tenant context set — the situation every JWT
// middleware is in. A grant or policy change that made `tenants` unreadable
// there would turn every tenant request into a 503, and this is where that
// shows up first.
func TestIntegration_TenantState_LookupAndGateOnAppRole(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	ctx := context.Background()
	id := testdb.NewTenant(t, owner)
	gate := Gate(app)

	s, err := Lookup(ctx, app, id)
	if err != nil {
		t.Fatalf("lookup on app role: %v", err)
	}
	if !s.Found || s.Deleted {
		t.Fatalf("fresh tenant state = %+v", s)
	}
	if err := gate(ctx, id); err != nil {
		t.Fatalf("live tenant gated: %v", err)
	}

	steps := []struct {
		sql  string
		code string
	}{
		{`UPDATE tenants SET payment_status = 'suspended' WHERE id = $1`, CodeSuspended},
		{`UPDATE tenants SET payment_status = 'canceled' WHERE id = $1`, CodeSuspended},
		{`UPDATE tenants SET payment_status = 'active', deleted_at = NOW() WHERE id = $1`, CodeDeleted},
	}
	for _, st := range steps {
		if _, err := owner.Exec(st.sql, id); err != nil {
			t.Fatalf("%s: %v", st.sql, err)
		}
		be, ok := AsBlocked(gate(ctx, id))
		if !ok || be.Code != st.code {
			t.Fatalf("after %q gate = %v, want %s", st.sql, be, st.code)
		}
	}

	// A purged tenant (no row) is refused as deleted, not treated as an error.
	be, ok := AsBlocked(gate(ctx, uuid.New()))
	if !ok || be.Code != CodeDeleted {
		t.Fatalf("unknown tenant gate = %v, want %s", be, CodeDeleted)
	}
	//...and so is it on the per-request check ( item 2): a purged
	// tenant's still-unexpired tokens must not come back to life.
	if code, blocked, err := NewChecker(app, 0).Check(ctx, uuid.New()); err != nil || !blocked || code != CodeDeleted {
		t.Fatalf("unknown tenant per-request check = (%q, %v, %v), want refused %s", code, blocked, err, CodeDeleted)
	}
}
