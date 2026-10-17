package postgres_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_Identity_AddressLookupNeverCrossesTenants: an `ip_address`
// or `mac_address` lookup is answered from ip_addresses ⋈ interfaces (and
// mac_addresses) since DCIM row 1.4, no longer from asset_identifiers. Two
// tenants holding the SAME address and MAC must each resolve to their own
// asset — over the owner connection (which bypasses RLS, so the tenant
// predicate and the tenant-paired joins are what hold) and over the app role
// (RLS on, so the engine's writes must also pass WITH CHECK).
//
// Mutation: drop `ip.tenant_id = $1` from findAddressOwners (or pair the
// interfaces join on id alone) and the owner-connection case resolves tenant
// B's sighting onto tenant A's asset.
func TestIntegration_Identity_AddressLookupNeverCrossesTenants(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	for _, c := range []struct {
		name string
		db   *sql.DB
	}{{"owner", owner}, {"app_role", app}} {
		t.Run(c.name, func(t *testing.T) {
			tenantA := testdb.NewTenant(t, owner).String()
			tenantB := testdb.NewTenant(t, owner).String()
			repo := pgrepo.New(c.db)
			engine, err := identity.New(identity.Config{Repo: repo})
			if err != nil {
				t.Fatal(err)
			}
			intake, err := identity.NewIntake(repo)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			h := &ifaceHarness{t: t, db: c.db, repo: repo, engine: engine, intake: intake}
			resolveAs := func(tenant string, s identity.Sighting) identity.Resolution {
				t.Helper()
				h.tenant = tenant
				s.TenantID = tenant
				return h.resolve(s)
			}

			a := resolveAs(tenantA, h.agent(
				identity.SightedIdentifier{Kind: identity.KindHostname, Value: "rls-a"},
				mac("00:00:5e:00:91:01", "eth0"), ipOn("10.91.0.10", "eth0")))
			if a.Outcome != identity.OutcomeCreated {
				t.Fatalf("tenant A: outcome %s, want created", a.Outcome)
			}
			// Tenant B sees the same address and MAC, nothing else.
			b := resolveAs(tenantB, h.passive(ipOn("10.91.0.10", ""), mac("00:00:5e:00:91:01", "")))
			if b.Outcome != identity.OutcomeCreated || b.Asset.ID == a.Asset.ID {
				t.Fatalf("tenant B's sighting resolved %s onto %q (tenant A's asset is %q), want a new asset of its own",
					b.Outcome, b.Asset.ID, a.Asset.ID)
			}

			for _, tc := range []struct {
				tenant, want string
			}{{tenantA, a.Asset.ID}, {tenantB, b.Asset.ID}} {
				for _, k := range []struct {
					kind         identity.Kind
					value, scope string
				}{{identity.KindIPAddress, "10.91.0.10", identity.ScopeTenantDefault}, {identity.KindMACAddress, "00:00:5e:00:91:01", ""}} {
					refs, err := repo.FindByIdentifier(ctx, tc.tenant, k.kind, k.value, k.scope)
					if err != nil {
						t.Fatalf("FindByIdentifier(%s): %v", k.kind, err)
					}
					if len(refs) != 1 || refs[0].ID != tc.want || refs[0].TenantID != tc.tenant {
						t.Errorf("tenant %s %s=%s → %+v, want only its own asset %s", tc.tenant, k.kind, k.value, refs, tc.want)
					}
				}
			}
			var rows int
			if err := owner.QueryRow(`SELECT count(*) FROM ip_addresses WHERE host = '10.91.0.10'::inet AND tenant_id IN ($1, $2)`,
				tenantA, tenantB).Scan(&rows); err != nil || rows != 2 {
				t.Fatalf("ip_addresses rows for the shared address = %d (%v), want one per tenant", rows, err)
			}
		})
	}
}
