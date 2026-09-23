package entitlements_test

// A real database with no platform_license table — what a new service image
// sees before the schema-migration Job has created it. Both licence read paths
// must resolve Core instead of failing, and the transaction path must leave the
// caller's transaction usable (a failed SELECT inside a transaction aborts it,
// which is why that path probes for the table instead of catching the error).
//
// Scratch database: the test drops a global table. Skips without
// TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"testing"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_NoLicenceTable_ResolvesAsCore(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	tenant := testdb.NewTenant(t, db)
	mustExec(t, db, `DROP TABLE platform_license`)
	entitlements.FlushLicenseCache()
	entitlements.ForgetLicenseTableForTest()
	t.Cleanup(entitlements.FlushLicenseCache)
	t.Cleanup(entitlements.ForgetLicenseTableForTest)
	ctx := context.Background()

	// Pool path (Resolve / RequireFeature): Core, no error.
	lic, err := entitlements.LoadLicense(ctx, db)
	if err != nil || lic != nil {
		t.Fatalf("LoadLicense with no platform_license table: lic=%+v err=%v, want nil, nil", lic, err)
	}
	on, err := entitlements.IsEnabled(ctx, entitlements.NewPostgresResolver(db), tenant, "custom_policies")
	if err != nil || on {
		t.Fatalf("gated capability with no licence table: enabled=%v err=%v, want false, nil", on, err)
	}

	// Transaction path (GetQuantityInTx, admission): Core, and the caller's
	// transaction still works afterwards and commits.
	err = shareddatabase.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
		if _, err := entitlements.GetQuantityInTx(ctx, tx, tenant, "max_sensors"); err != nil {
			t.Fatalf("GetQuantityInTx with no platform_license table: %v", err)
		}
		var one int
		if err := tx.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
			t.Fatalf("the caller's transaction is unusable after the licence read: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("committing the caller's transaction: %v", err)
	}
}
