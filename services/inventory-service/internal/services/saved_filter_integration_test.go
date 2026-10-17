package services

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// BUILD_PLAN row 5.4 at the service layer, through the app-role pool so RLS is
// live. Mutations: drop the CheckAssetQuery call in normalizeSavedFilter -> the
// invalid-query cases go green-to-red; drop the owner check in mayEdit -> the
// "someone else's personal filter" cases go red; drop `shared OR user_id` from
// visibleFilter -> the visibility case goes red.

func savedFilterCtx(user uuid.UUID) context.Context {
	return changes.WithSource(changes.WithActor(context.Background(), changes.Actor{UserID: user, UserName: "op@example.test"}), changes.SourceUI)
}

func TestIntegration_SavedFilters(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	a, b := testdb.NewTenant(t, owner), testdb.NewTenant(t, owner)
	svc := NewSavedFilterService(app)

	alice, bob := uuid.New(), uuid.New()
	asAlice := SavedFilterCaller{UserID: alice}
	asBob := SavedFilterCaller{UserID: bob}
	admin := SavedFilterCaller{UserID: bob, CanShare: true}
	in := func(name, q string, shared bool, kinds ...dcim.ObjectKind) SavedFilterInput {
		if len(kinds) == 0 {
			kinds = []dcim.ObjectKind{dcim.ObjectKindAsset}
		}
		return SavedFilterInput{Name: name, ObjectKinds: kinds, Query: q, Shared: shared}
	}

	t.Run("an invalid query is refused on save", func(t *testing.T) {
		for _, q := range []string{`risk >=`, `no_such_field = 1`, `((`} {
			_, err := svc.Create(savedFilterCtx(alice), a, asAlice, in("bad", q, false))
			if _, ok := AsQueryError(err); !ok {
				t.Errorf("query %q: err = %v, want a *QueryError", q, err)
			}
		}
		// Valid for the asset target, refused for the interface target: every
		// named kind is checked, not just the first.
		_, err := svc.Create(savedFilterCtx(alice), a, asAlice, in("two kinds", `hostname:web*`, false, dcim.ObjectKindAsset, dcim.ObjectKindInterface))
		if _, ok := AsQueryError(err); !ok {
			t.Errorf("a query illegal for the second kind was saved: %v", err)
		}
		// A kind with no query catalogue is refused outright.
		_, err = svc.Create(savedFilterCtx(alice), a, asAlice, in("prefixes", `status:active`, false, dcim.ObjectKindPrefix))
		if !errors.Is(err, ErrSavedFilterInvalid) {
			t.Errorf("kind without a catalogue: err = %v, want ErrSavedFilterInvalid", err)
		}
		got, err := svc.List(savedFilterCtx(alice), a, alice, "")
		if err != nil || len(got) != 0 {
			t.Fatalf("a refused filter was stored: %v %+v", err, got)
		}
	})

	var personal, shared SavedFilter
	t.Run("a valid query is stored canonically", func(t *testing.T) {
		var err error
		personal, err = svc.Create(savedFilterCtx(alice), a, asAlice, in("Mine", `risk  >= high`, false))
		if err != nil {
			t.Fatalf("create personal: %v", err)
		}
		if personal.Query != `risk >= high` || personal.Slug != "mine" || personal.Shared || personal.UserID == nil || *personal.UserID != alice {
			t.Fatalf("stored %+v", personal)
		}
		shared, err = svc.Create(savedFilterCtx(bob), a, admin, in("Mine", `hostname:web*`, true))
		if err != nil {
			t.Fatalf("create shared: %v", err)
		}
		if shared.Slug == personal.Slug {
			t.Fatalf("two filters named Mine share slug %q", shared.Slug)
		}
	})

	t.Run("a personal filter is invisible to another user; a shared one is not", func(t *testing.T) {
		bobs, err := svc.List(savedFilterCtx(bob), a, bob, "asset")
		if err != nil || len(bobs) != 1 || bobs[0].ID != shared.ID {
			t.Fatalf("bob sees %+v (%v), want only the shared filter", bobs, err)
		}
		alices, err := svc.List(savedFilterCtx(alice), a, alice, "asset")
		if err != nil || len(alices) != 2 || alices[0].ID != shared.ID {
			t.Fatalf("alice sees %+v (%v), want shared first then hers", alices, err)
		}
		if other, _ := svc.List(savedFilterCtx(alice), a, alice, "interface"); len(other) != 0 {
			t.Fatalf("kind filter leaked: %+v", other)
		}
		if _, err := svc.Update(savedFilterCtx(bob), a, admin, personal.ID, in("stolen", `risk >= low`, false)); !errors.Is(err, ErrSavedFilterNotFound) {
			t.Errorf("bob (with share rights) edited alice's personal filter: %v", err)
		}
		if err := svc.Delete(savedFilterCtx(bob), a, admin, personal.ID); !errors.Is(err, ErrSavedFilterNotFound) {
			t.Errorf("bob deleted alice's personal filter: %v", err)
		}
	})

	t.Run("sharing needs the share right", func(t *testing.T) {
		if _, err := svc.Create(savedFilterCtx(bob), a, asBob, in("pub", `risk >= high`, true)); !errors.Is(err, ErrSavedFilterForbidden) {
			t.Errorf("publish without the right: %v", err)
		}
		if _, err := svc.Update(savedFilterCtx(alice), a, asAlice, personal.ID, in("Mine", `risk >= high`, true)); !errors.Is(err, ErrSavedFilterForbidden) {
			t.Errorf("promoting a personal filter without the right: %v", err)
		}
		if _, err := svc.Update(savedFilterCtx(alice), a, asAlice, shared.ID, in("Mine", `hostname:db*`, true)); !errors.Is(err, ErrSavedFilterForbidden) {
			t.Errorf("editing a shared filter without the right: %v", err)
		}
		if err := svc.Delete(savedFilterCtx(alice), a, asAlice, shared.ID); !errors.Is(err, ErrSavedFilterForbidden) {
			t.Errorf("deleting a shared filter without the right: %v", err)
		}
		up, err := svc.Update(savedFilterCtx(bob), a, admin, shared.ID, in("Web hosts", `hostname:web*`, true))
		if err != nil || up.Name != "Web hosts" || up.Slug != shared.Slug {
			t.Fatalf("editing a shared filter with the right: %v %+v", err, up)
		}
	})

	t.Run("another tenant sees nothing, and cannot write across", func(t *testing.T) {
		if got, err := svc.List(savedFilterCtx(alice), b, alice, ""); err != nil || len(got) != 0 {
			t.Fatalf("tenant B sees %+v (%v)", got, err)
		}
		err := database.WithTenantTx(context.Background(), app, a, func(tx *sql.Tx) error {
			_, e := tx.Exec(`INSERT INTO saved_filters (tenant_id, name, slug, object_kinds, query) VALUES ($1, 'x', 'x', '{asset}', 'risk >= high')`, b)
			return e
		})
		if err == nil {
			t.Fatal("a row for tenant B was written under tenant A's context (RLS WITH CHECK is not live)")
		}
	})

	t.Run("every write is recorded as a change", func(t *testing.T) {
		if err := svc.Delete(savedFilterCtx(alice), a, asAlice, personal.ID); err != nil {
			t.Fatalf("delete own personal filter: %v", err)
		}
		var n int
		if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'saved_filter'`, a).Scan(&n); err != nil {
			t.Fatal(err)
		}
		// create personal, create shared, update shared, delete personal.
		if n != 4 {
			t.Fatalf("recorded %d saved_filter changes, want 4", n)
		}
	})
}
