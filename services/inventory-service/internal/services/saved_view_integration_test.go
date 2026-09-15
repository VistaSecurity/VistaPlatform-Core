package services

// Saved views against a real Postgres: RLS, ownership, sharing, and
// validate-on-write.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_SavedViews_RLSAndOwnership(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewSavedViewService(db)
	ctx := context.Background()

	tenantA := testdb.NewTenant(t, raw)
	tenantB := testdb.NewTenant(t, raw)
	alice, bob := uuid.New(), uuid.New()

	mine, err := svc.Create(ctx, tenantA, alice, SavedViewInput{
		Name: "My production servers", Query: "class:server and environment:production",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	shared := true
	team, err := svc.Create(ctx, tenantA, alice, SavedViewInput{
		Name: "Team: quantum exposure", Query: "crypto:(algorithm.deprecated:true)", IsShared: &shared,
	})
	if err != nil {
		t.Fatalf("create shared: %v", err)
	}
	if _, err := svc.Create(ctx, tenantB, bob, SavedViewInput{Name: "Other tenant", Query: "class:server"}); err != nil {
		t.Fatalf("create in tenant B: %v", err)
	}

	t.Run("the query is stored in canonical form", func(t *testing.T) {
		// Not the text as typed: two spellings of one predicate stored verbatim
		// are two rows a diff cannot match.
		got, err := svc.Create(ctx, tenantA, alice, SavedViewInput{
			Name: "Canonical", Query: "environment:production   class:server",
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if got.Query != "environment:production and class:server" {
			t.Errorf("stored %q; the implicit AND must be written out", got.Query)
		}
	})

	t.Run("an invalid query is refused at WRITE time", func(t *testing.T) {
		_, err := svc.Create(ctx, tenantA, alice, SavedViewInput{Name: "Broken", Query: "hostnaem:web"})
		if err == nil {
			t.Fatal("a view that would fail when opened must not be savable")
		}
		if _, ok := AsQueryError(err); !ok {
			t.Fatalf("expected structured diagnostics, got %T: %v", err, err)
		}
	})

	t.Run("a table-less target is refused", func(t *testing.T) {
		// `observation` and `measurement` name no rows a view could open.
		for _, target := range []string{"observation", "measurement", "nonsense"} {
			if _, err := svc.Create(ctx, tenantA, alice, SavedViewInput{
				Name: "T " + target, Target: target, Query: "",
			}); err == nil {
				t.Errorf("target %q must be refused", target)
			}
		}
	})

	t.Run("bob sees the shared view and not the private one", func(t *testing.T) {
		views, err := svc.List(ctx, tenantA, bob, "")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		ids := map[uuid.UUID]bool{}
		for _, v := range views {
			ids[v.ID] = true
		}
		if !ids[team.ID] {
			t.Error("a shared view must be visible to everyone in the tenant")
		}
		if ids[mine.ID] {
			t.Error("a private view must not be visible to another user")
		}
	})

	t.Run("tenant B sees nothing of tenant A", func(t *testing.T) {
		views, err := svc.List(ctx, tenantB, alice, "")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, v := range views {
			if v.ID == mine.ID || v.ID == team.ID {
				t.Fatalf("RLS leak: tenant B returned tenant A's view %s", v.ID)
			}
		}
		if _, err := svc.Get(ctx, tenantB, alice, mine.ID); !errors.Is(err, ErrSavedViewNotFound) {
			t.Fatalf("a cross-tenant read must be not-found, got %v", err)
		}
	})

	t.Run("sharing is publishing, not handing over", func(t *testing.T) {
		if _, err := svc.Update(ctx, tenantA, bob, team.ID, SavedViewInput{
			Name: "Bob's edit", Query: "class:server",
		}); !errors.Is(err, ErrSavedViewNotFound) {
			t.Fatalf("only the owner may edit a shared view, got %v", err)
		}
		if err := svc.Delete(ctx, tenantA, bob, team.ID); !errors.Is(err, ErrSavedViewNotFound) {
			t.Fatalf("only the owner may delete a shared view, got %v", err)
		}
	})

	t.Run("a name is unique per owner, not per tenant", func(t *testing.T) {
		// Two people may each keep a view called "Mine"; a tenant-wide unique
		// name would let the first one to save block everybody else.
		if _, err := svc.Create(ctx, tenantA, bob, SavedViewInput{Name: "My production servers", Query: "class:server"}); err != nil {
			t.Fatalf("a second owner must be able to reuse a name: %v", err)
		}
		if _, err := svc.Create(ctx, tenantA, alice, SavedViewInput{Name: "My production servers", Query: "class:server"}); !errors.Is(err, ErrSavedViewDuplicate) {
			t.Fatalf("the SAME owner reusing a name must conflict, got %v", err)
		}
	})

	t.Run("update and delete round-trip", func(t *testing.T) {
		updated, err := svc.Update(ctx, tenantA, alice, mine.ID, SavedViewInput{
			Name: "My production servers", Query: "class:server and environment:staging",
		})
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		if updated.Query != "class:server and environment:staging" {
			t.Errorf("update did not store the new query: %q", updated.Query)
		}
		if err := svc.Delete(ctx, tenantA, alice, mine.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, err := svc.Get(ctx, tenantA, alice, mine.ID); !errors.Is(err, ErrSavedViewNotFound) {
			t.Fatalf("a deleted view must be gone, got %v", err)
		}
	})
}
