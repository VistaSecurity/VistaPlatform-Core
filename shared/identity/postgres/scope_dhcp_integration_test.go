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
// resolver reads a segment's DHCP posture for identity.
//
// A segment learned from a device that reported the network but not whether
// it serves DHCP is stored `dhcp: unknown` with no `dynamic` flag. For identity
// that must read as dynamic — in every later run and every other intake, not
// only in the interrogation that learned it — or a bare address on it can join
// two devices that held the same lease. A segment nobody said anything about
// (an operator's, no metadata) stays non-dynamic: that default is the safe one
// for silence, and it is not what `unknown` is.
func TestIntegration_ScopeForAddress_DHCPPosture(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)

	segments := []struct {
		cidr, metadata string
		wantDynamic    bool
	}{
		{"10.61.1.0/24", `{"source":"interrogation","dhcp":"unknown"}`, true},
		{"10.61.2.0/24", `{"source":"interrogation","dhcp":"enabled","dynamic":true}`, true},
		{"10.61.3.0/24", `{"source":"interrogation","dhcp":"disabled","dynamic":false}`, false},
		{"10.61.4.0/24", `{}`, false},
		{"10.61.5.0/24", `{"source":"unifi","dynamic":false}`, false},
		// A measured answer that later gained an unknown key cannot happen
		// (the intake never overwrites known with unknown), but if it did the
		// conservative reading wins.
		{"10.61.6.0/24", `{"dhcp":"unknown","dynamic":false}`, true},
	}
	ids := map[string]string{}
	for _, s := range segments {
		var id string
		if err := db.QueryRow(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,metadata)
			VALUES($1,$2,'cidr',$2,'private','production',true,$3::jsonb) RETURNING id::text`, tenant, s.cidr, s.metadata).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids[s.cidr] = id
	}
	repo := pgrepo.New(db)
	for _, s := range segments {
		p := netip.MustParsePrefix(s.cidr)
		addr := p.Addr().Next().Next()
		scope, dynamic, err := repo.ScopeForAddress(context.Background(), tenant.String(), addr, "")
		if err != nil {
			t.Fatal(err)
		}
		if scope != ids[s.cidr] || scope == identity.ScopeTenantDefault {
			t.Errorf("%s: scope = %q, want the segment %q", addr, scope, ids[s.cidr])
		}
		if dynamic != s.wantDynamic {
			t.Errorf("%s in %s: dynamic = %v, want %v", addr, s.metadata, dynamic, s.wantDynamic)
		}
	}
}
