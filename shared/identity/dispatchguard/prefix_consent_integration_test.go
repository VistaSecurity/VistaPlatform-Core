package dispatchguard

// DCIM row 1.4: probe consent follows IPAM prefixes as well as network
// segments. A DECLARED public prefix whose network type grants ownership is
// what sensors are told the tenant owns; a prefix marked sensitive or
// active-probes-disabled is excluded; a LEARNED prefix claims nothing.
//
// Mutation: delete the prefixes read in OwnedNetworks and every assertion
// below goes red.

import (
	"database/sql"
	"slices"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_OwnedNetworks_FollowsPrefixes(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	testdb.EnsureRLSAppRole(t, db)
	tenant := testdb.NewTenant(t, db)

	for _, row := range []struct {
		prefix, networkType, sourceKind string
		sensitive, probesDisabled       bool
	}{
		{"93.184.219.0/28", "public", "declared", false, false},  // owned
		{"93.184.219.16/28", "public", "measured", false, false}, // learned: nothing
		{"93.184.219.32/28", "public", "declared", true, false},  // sensitive: excluded
		{"93.184.219.48/28", "public", "measured", false, true},  // probes disabled: excluded
	} {
		if _, err := db.Exec(`INSERT INTO public.prefixes (tenant_id, prefix, network_type, source_kind, sensitive, active_probes_disabled, status)
			VALUES ($1, $2::cidr, $3, $4, $5, $6, 'active')`, tenant, row.prefix, row.networkType, row.sourceKind, row.sensitive, row.probesDisabled); err != nil {
			t.Fatalf("seed prefix %s: %v", row.prefix, err)
		}
	}

	testdb.AsTenant(t, db, tenant, func(tx *sql.Tx) {
		got, err := OwnedNetworks(tx, tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		for prefix, want := range map[string]bool{
			"93.184.219.0/28":  true,
			"93.184.219.16/28": false,
			"93.184.219.32/28": false,
			"93.184.219.48/28": false,
		} {
			if has := slices.Contains(got.Prefixes, prefix); has != want {
				t.Errorf("Prefixes has %s = %v, want %v (got %v)", prefix, has, want, got.Prefixes)
			}
		}
		for _, prefix := range []string{"93.184.219.32/28", "93.184.219.48/28"} {
			if !slices.Contains(got.Excluded, prefix) {
				t.Errorf("Excluded lacks %s (got %v)", prefix, got.Excluded)
			}
		}
	})
}
