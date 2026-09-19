package jobs

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_IdentityEnrichmentEnumeratesEligibleTenants(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	eligible := testdb.NewTenant(t, db)
	canceled := testdb.NewTenant(t, db)
	if _, err := db.Exec(`UPDATE tenants SET payment_status='canceled' WHERE id=$1`, canceled); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []uuid.UUID{eligible, canceled} {
		observation := uuid.New()
		if _, err := db.Exec(`INSERT INTO identity_observations(tenant_id,id,fingerprint,source_kind,source_ref,evidence,first_seen_at,last_seen_at) VALUES($1,$2,$3,'measured','sensor:test','{}',now(),now())`, tenant, observation, observation.String()); err != nil {
			t.Fatal(err)
		}
	}

	tenants, err := identityEnrichmentTenants(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	foundEligible, foundCanceled := false, false
	for _, tenant := range tenants {
		foundEligible = foundEligible || tenant == eligible
		foundCanceled = foundCanceled || tenant == canceled
	}
	if !foundEligible {
		t.Fatal("eligible tenant with retained observations was not enumerated")
	}
	if foundCanceled {
		t.Fatal("canceled tenant must not receive automatic identity enrichment")
	}
}
