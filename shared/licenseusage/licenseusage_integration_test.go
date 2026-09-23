package licenseusage_test

// DB-integration tests for the lifecycle ledger. Skip unless TEST_DATABASE_URL
// is set; `make test-integration-db` runs them.

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/licenseusage"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_LicenseUsage_RecordWritesOnlyForARealTenant(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	bypass := testdb.ConnectAsBypassRole(t, owner)
	ctx := context.Background()

	tenant := testdb.NewTenant(t, owner)
	ghost := uuid.New()
	t.Cleanup(func() {
		_, _ = owner.Exec(`DELETE FROM license_usage_events WHERE tenant_id = ANY($1)`, "{"+tenant.String()+","+ghost.String()+"}")
	})

	if err := licenseusage.Record(ctx, bypass, tenant, licenseusage.Suspended, licenseusage.PlatformActor(uuid.NewString())); err != nil {
		t.Fatalf("Record on the bypass pool: %v", err)
	}
	var typ, actor string
	if err := owner.QueryRow(`SELECT type, actor FROM license_usage_events WHERE tenant_id = $1`, tenant).Scan(&typ, &actor); err != nil {
		t.Fatalf("read the event back: %v", err)
	}
	if typ != "suspended" || !strings.HasPrefix(actor, "platform_user:") {
		t.Fatalf("event = (%s, %s)", typ, actor)
	}

	// A tenant id that does not exist leaves no row: an admin action on a
	// mistyped id must not put a phantom customer into a report.
	if err := licenseusage.Record(ctx, bypass, ghost, licenseusage.Deleted, licenseusage.ActorSystem); err != nil {
		t.Fatalf("Record for a missing tenant: %v", err)
	}
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM license_usage_events WHERE tenant_id = $1`, ghost).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d event(s) recorded for a tenant that does not exist", n)
	}
}

// The ledger is read-only for the RLS app role. A call site that hands Record
// the app pool by mistake fails loudly instead of writing — which is also what
// keeps an injection in a tenant-facing handler from forging lifecycle facts.
func TestIntegration_LicenseUsage_AppRoleCannotWrite(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	t.Cleanup(func() { _, _ = owner.Exec(`DELETE FROM license_usage_events WHERE tenant_id = $1`, tenant) })

	err := licenseusage.Record(context.Background(), app, tenant, licenseusage.Created, licenseusage.ActorSignup)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("Record on the app pool = %v, want permission denied", err)
	}
	var n int
	if err := app.QueryRow(`SELECT count(*) FROM license_usage_events WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
		t.Fatalf("the app role must still be able to READ the ledger: %v", err)
	}
}
