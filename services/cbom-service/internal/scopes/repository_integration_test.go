package scopes

// Real-Postgres proof that Scope listing is tenant-isolated by the query
// itself, not by RLS.
//
// testdb.Connect opens the OWNER connection, which BYPASSES row-level
// security — and that is the point rather than a shortcut. It is exactly the
// configuration the defect was live in: docker-compose dev, and any install
// with the chart's serviceRls disabled, which is mandatory on managed Postgres
// where the restricted role cannot be provisioned. If the predicate is ever
// dropped again in favour of "RLS covers it", this test fails here even though
// an RLS-enabled environment would look fine.
//
// The sqlmock tests next door prove the SQL carries the predicate; this proves
// the resulting behaviour against the real table, including the seeding
// short-circuit that CountForTenant drives.

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ScopesAreTenantIsolatedWithoutRLS(t *testing.T) {
	owner := testdb.Connect(t) // skips if TEST_DATABASE_URL unset
	tenantA := testdb.NewTenant(t, owner)
	tenantB := testdb.NewTenant(t, owner)

	// scopes.tenant_id has no FK to tenants, so dropping the tenant rows does
	// not take the scopes with it — clean them up explicitly rather than leave
	// orphans behind in a shared dev database.
	t.Cleanup(func() {
		_, _ = owner.Exec(`DELETE FROM public.scopes WHERE tenant_id = ANY($1)`,
			pq.Array([]uuid.UUID{tenantA, tenantB}))
	})

	repo := NewRepository(&database.DB{DB: sqlx.NewDb(owner, "postgres")})
	ctx := context.Background()
	actor := uuid.New()

	// Tenant A gets its defaults plus one scope of its own.
	if _, err := repo.SeedDefaultsIfMissing(ctx, tenantA, actor); err != nil {
		t.Fatalf("seed defaults for tenant A: %v", err)
	}
	aScope := Scope{
		TenantID:  tenantA,
		Name:      "A-only Payments",
		Predicate: Predicate{Include: &PredicateClause{Environment: []string{"production"}}},
		CreatedBy: actor,
		UpdatedBy: actor,
	}
	if err := repo.Create(ctx, &aScope); err != nil {
		t.Fatalf("create tenant A scope: %v", err)
	}

	// Tenant B must see none of it — not the private scope, not A's defaults.
	bList, err := repo.List(ctx, tenantB)
	if err != nil {
		t.Fatalf("list for tenant B: %v", err)
	}
	for _, s := range bList {
		if s.TenantID != tenantB {
			t.Fatalf("tenant B's scope list leaked tenant %s's scope %q", s.TenantID, s.Name)
		}
	}
	if len(bList) != 0 {
		t.Fatalf("tenant B has %d scopes before seeding, want 0", len(bList))
	}

	// The count is SeedDefaultsIfMissing's short-circuit. A global count would
	// be non-zero here (tenant A has rows) and B would silently never be seeded.
	n, err := repo.CountForTenant(ctx, tenantB)
	if err != nil {
		t.Fatalf("count for tenant B: %v", err)
	}
	if n != 0 {
		t.Fatalf("CountForTenant(B) = %d, want 0 — the count is not tenant-scoped", n)
	}

	seeded, err := repo.SeedDefaultsIfMissing(ctx, tenantB, actor)
	if err != nil {
		t.Fatalf("seed defaults for tenant B: %v", err)
	}
	if !seeded {
		t.Fatal("tenant B was not seeded — another tenant's scopes suppressed its defaults")
	}

	bList, err = repo.List(ctx, tenantB)
	if err != nil {
		t.Fatalf("re-list for tenant B: %v", err)
	}
	if len(bList) != len(systemDefaults(tenantB, actor)) {
		t.Fatalf("tenant B sees %d scopes after seeding, want its %d defaults",
			len(bList), len(systemDefaults(tenantB, actor)))
	}
	for _, s := range bList {
		if s.TenantID != tenantB {
			t.Errorf("tenant B's list contains a scope owned by %s (%q)", s.TenantID, s.Name)
		}
		if s.Name == aScope.Name {
			t.Errorf("tenant A's private scope %q is visible to tenant B", s.Name)
		}
	}

	// And A still sees its own — isolation, not a blanket empty result.
	aList, err := repo.List(ctx, tenantA)
	if err != nil {
		t.Fatalf("list for tenant A: %v", err)
	}
	var foundA bool
	for _, s := range aList {
		if s.ID == aScope.ID {
			foundA = true
		}
		if s.TenantID != tenantA {
			t.Errorf("tenant A's list contains a scope owned by %s (%q)", s.TenantID, s.Name)
		}
	}
	if !foundA {
		t.Error("tenant A can no longer see its own scope; the predicate filters too much")
	}
}
