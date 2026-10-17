package postgres_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_ScopeForAddress_DHCPPosture pins how the persistent scope
// resolver reads a prefix's DHCP posture for identity (DCIM row 1.6).
//
// A prefix a collector learned without saying whether the network serves DHCP
// (`dhcp_managed` NULL, source measured) must read as dynamic — in every later
// run and every other intake — or a bare address on it can join two devices
// that held the same lease. A prefix a person declared and said nothing about
// stays static: that default is the safe one for silence, and it is not what
// an unmeasured network is. A stated posture is read as stated.
//
// Mutation: change scope.go's `coalesce(dhcp_managed, source_kind <>
// 'declared')` default and the silent rows go red.
func TestIntegration_ScopeForAddress_DHCPPosture(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)

	prefixes := []struct {
		cidr, sourceKind string
		dhcp             *bool
		wantDynamic      bool
	}{
		{"10.61.1.0/24", "measured", nil, true},
		{"10.61.2.0/24", "measured", boolPtr(true), true},
		{"10.61.3.0/24", "measured", boolPtr(false), false},
		{"10.61.4.0/24", "declared", nil, false},
		{"10.61.5.0/24", "declared", boolPtr(true), true},
		{"10.61.6.0/24", "imported", nil, true},
	}
	ids := map[string]string{}
	for _, p := range prefixes {
		var id string
		if err := db.QueryRow(`INSERT INTO prefixes(tenant_id,prefix,source_kind,status,dhcp_managed)
			VALUES($1,$2::cidr,$3,'active',$4) RETURNING id::text`, tenant, p.cidr, p.sourceKind, p.dhcp).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids[p.cidr] = id
	}
	repo := pgrepo.New(db)
	for _, p := range prefixes {
		pf := netip.MustParsePrefix(p.cidr)
		addr := pf.Addr().Next().Next()
		scope, dynamic, err := repo.ScopeForAddress(context.Background(), tenant.String(), addr, "")
		if err != nil {
			t.Fatal(err)
		}
		if scope != ids[p.cidr] || scope == identity.ScopeTenantDefault {
			t.Errorf("%s: scope = %q, want the prefix %q", addr, scope, ids[p.cidr])
		}
		if dynamic != p.wantDynamic {
			t.Errorf("%s in a %s prefix (dhcp %v): dynamic = %v, want %v", addr, p.sourceKind, p.dhcp, dynamic, p.wantDynamic)
		}
	}
}
