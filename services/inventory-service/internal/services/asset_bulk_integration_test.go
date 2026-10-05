package services

// Bulk actions on a selection of assets, against a real Postgres and
// as the non-owner app role, so RLS is in force as it is in production.
//
// The selection test's load-bearing assertion is that "select all matching"
// resolves to EXACTLY the set the asset list shows for the same query —
// default status scope, deleted rows and other tenants included — because
// that is what the person was looking at when they confirmed the count.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type bulkFixture struct {
	raw    *sql.DB
	db     *database.DB
	tenant uuid.UUID
	other  uuid.UUID
	actor  uuid.UUID
}

func newBulkFixture(t *testing.T) bulkFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	f := bulkFixture{raw: raw, tenant: testdb.NewTenant(t, raw), other: testdb.NewTenant(t, raw), actor: uuid.New()}
	if _, err := raw.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, f.actor, f.tenant, "bulk-"+f.actor.String()[:8]+"@example.com"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	f.db = &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, raw), "postgres")}
	return f
}

// asset inserts one asset through the owner connection and returns its id.
func (f bulkFixture) asset(t *testing.T, tenant uuid.UUID, status, env string, deleted bool, tags string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if tags == "" {
		tags = "{}"
	}
	var envArg any
	if env != "" {
		envArg = env
	}
	if _, err := f.raw.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, environment, tags, deleted_at, last_seen_at, first_discovered_at)
		VALUES ($1, $2, $3, 'server', 'hardware.computer.server', $4, $5::environment_type, $6::jsonb, CASE WHEN $7 THEN NOW() END, NOW(), NOW())`,
		id, tenant, "bulk-"+id.String()[:8]+".example.test", status, envArg, tags, deleted); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	return id
}

func sortedIDs(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	sort.Strings(out)
	return out
}

func intp(n int) *int { return &n }

func TestIntegration_AssetSelection_QueryResolvesToExactlyTheListedSet(t *testing.T) {
	f := newBulkFixture(t)
	prod := f.asset(t, f.tenant, "monitoring", "production", false, "")
	stag := f.asset(t, f.tenant, "monitoring", "staging", false, "")
	pending := f.asset(t, f.tenant, "pending_approval", "production", false, "")
	f.asset(t, f.tenant, "monitoring", "production", true, "") // deleted
	f.asset(t, f.other, "monitoring", "production", false, "") // another tenant
	svc := &AssetService{db: f.db}

	cases := []struct {
		name  string
		query string
		want  []uuid.UUID
	}{
		// The list's default scope: monitoring only, so the pending asset is
		// not part of "everything" — it is not on the screen either.
		{"empty query is the default scope", "", []uuid.UUID{prod, stag}},
		{"a facet", "environment:production", []uuid.UUID{prod}},
		// A query that names a status steps the default aside, as on the list.
		{"a status the query names", "status:pending_approval", []uuid.UUID{pending}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.ResolveAssetSelection(f.tenant, AssetSelection{Query: strp(tc.query), ExpectedCount: intp(100)}, MaxBulkAssets)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			listed, total, err := svc.GetAssets(f.tenant, models.AssetFilters{Query: tc.query, Page: 1, PageSize: 100})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if total != len(got) {
				t.Errorf("selection has %d assets, the list says %d", len(got), total)
			}
			if a, b := sortedIDs(got), sortedIDs(assetIDs(listed)); !equalStrings(a, b) {
				t.Errorf("selection %v != listed %v", a, b)
			}
			if a, b := sortedIDs(got), sortedIDs(tc.want); !equalStrings(a, b) {
				t.Errorf("selection %v, want %v", a, b)
			}
		})
	}

	// Never more than the person confirmed.
	_, err := svc.ResolveAssetSelection(f.tenant, AssetSelection{Query: strp(""), ExpectedCount: intp(1)}, MaxBulkAssets)
	var changed *SelectionChangedError
	if !errors.As(err, &changed) || changed.Count != 2 || changed.Expected != 1 {
		t.Errorf("query matching 2 with 1 confirmed: err = %v, want SelectionChangedError{1, 2}", err)
	}
	// Fewer than confirmed is fine: an asset that left the set was not asked about.
	if got, err := svc.ResolveAssetSelection(f.tenant, AssetSelection{Query: strp(""), ExpectedCount: intp(5)}, MaxBulkAssets); err != nil || len(got) != 2 {
		t.Errorf("query matching 2 with 5 confirmed: %d, %v; want 2, nil", len(got), err)
	}
	// Over the cap.
	var tooLarge *SelectionTooLargeError
	if _, err := svc.ResolveAssetSelection(f.tenant, AssetSelection{Query: strp(""), ExpectedCount: intp(2)}, 1); !errors.As(err, &tooLarge) {
		t.Errorf("2 matching with a cap of 1: err = %v, want SelectionTooLargeError", err)
	}
	// A query with no confirmed count, both forms, neither form.
	for name, sel := range map[string]AssetSelection{
		"query without expected_count": {Query: strp("")},
		"both forms":                   {Query: strp(""), ExpectedCount: intp(2), AssetIDs: []string{prod.String()}},
		"neither form":                 {},
	} {
		if _, err := svc.ResolveAssetSelection(f.tenant, sel, MaxBulkAssets); !errors.Is(err, ErrSelectionInvalid) {
			t.Errorf("%s: err = %v, want ErrSelectionInvalid", name, err)
		}
	}
	// A query nothing matches.
	if _, err := svc.ResolveAssetSelection(f.tenant, AssetSelection{Query: strp("environment:test"), ExpectedCount: intp(0)}, MaxBulkAssets); !errors.Is(err, ErrSelectionEmpty) {
		t.Errorf("no match: err = %v, want ErrSelectionEmpty", err)
	}
	// A query that does not parse is the list's own structured error.
	if _, err := svc.ResolveAssetSelection(f.tenant, AssetSelection{Query: strp("environment:"), ExpectedCount: intp(1)}, MaxBulkAssets); err == nil {
		t.Error("an unparseable query resolved")
	} else if _, ok := AsQueryError(err); !ok {
		t.Errorf("unparseable query: err = %v, want a QueryError", err)
	}
}

func (f bulkFixture) historyCount(t *testing.T, asset uuid.UUID, action string) int {
	t.Helper()
	var n int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM asset_history WHERE asset_id = $1 AND action = $2 AND actor_user_id = $3`, asset, action, f.actor).Scan(&n); err != nil {
		t.Fatalf("history: %v", err)
	}
	return n
}

func TestIntegration_BulkUpdateAssets_MergesTagsAndRecordsOnlyRealChanges(t *testing.T) {
	f := newBulkFixture(t)
	x := f.asset(t, f.tenant, "monitoring", "staging", false, `{"team":"a","keep":"1"}`)
	y := f.asset(t, f.tenant, "monitoring", "", false, "")
	// Already exactly what the edit asks for: not written, no history row.
	same := f.asset(t, f.tenant, "monitoring", "production", false, `{"zone":"dmz"}`)
	if _, err := f.raw.Exec(`UPDATE assets SET owner_email = 'ops@example.com' WHERE id = $1`, same); err != nil {
		t.Fatal(err)
	}
	foreign := f.asset(t, f.other, "monitoring", "staging", false, "")
	svc := &AssetService{db: f.db}

	changed, err := svc.BulkUpdateAssets(f.tenant, []uuid.UUID{x, y, same, foreign}, BulkAssetChanges{
		OwnerEmail:  strp(" ops@example.com "),
		Environment: strp("Production"),
		AddTags:     map[string]string{"zone": "dmz"},
		RemoveTags:  []string{"team"},
	}, f.actor)
	if err != nil {
		t.Fatalf("bulk update: %v", err)
	}
	if changed != 2 {
		t.Errorf("changed = %d, want 2 (x and y; `same` already matched, `foreign` is another tenant's)", changed)
	}

	var tagsText, env, owner string
	if err := f.raw.QueryRow(`SELECT tags::text, environment::text, owner_email FROM assets WHERE id = $1`, x).Scan(&tagsText, &env, &owner); err != nil {
		t.Fatal(err)
	}
	var tags map[string]string
	_ = json.Unmarshal([]byte(tagsText), &tags)
	if len(tags) != 2 || tags["keep"] != "1" || tags["zone"] != "dmz" {
		t.Errorf("x tags = %v, want keep=1 and zone=dmz merged in, team removed", tags)
	}
	if env != "production" || owner != "ops@example.com" {
		t.Errorf("x = %s / %s, want production / ops@example.com", env, owner)
	}
	var foreignEnv string
	if err := f.raw.QueryRow(`SELECT environment::text FROM assets WHERE id = $1`, foreign).Scan(&foreignEnv); err != nil || foreignEnv != "staging" {
		t.Errorf("another tenant's asset environment = %q (%v), want staging untouched", foreignEnv, err)
	}
	for id, want := range map[uuid.UUID]int{x: 1, y: 1, same: 0} {
		if got := f.historyCount(t, id, "updated"); got != want {
			t.Errorf("asset %s: %d `updated` history rows by the actor, want %d", id, got, want)
		}
	}

	// "" clears a field.
	if _, err := svc.BulkUpdateAssets(f.tenant, []uuid.UUID{x}, BulkAssetChanges{Environment: strp("")}, f.actor); err != nil {
		t.Fatalf("clear: %v", err)
	}
	var cleared sql.NullString
	if err := f.raw.QueryRow(`SELECT environment::text FROM assets WHERE id = $1`, x).Scan(&cleared); err != nil || cleared.Valid {
		t.Errorf("environment after clear = %v (%v), want NULL", cleared, err)
	}

	for name, ch := range map[string]BulkAssetChanges{
		"nothing to change":   {},
		"unknown environment": {Environment: strp("prod")},
		"not an email":        {OwnerEmail: strp("ops")},
		"nameless tag":        {AddTags: map[string]string{" ": "x"}},
	} {
		if _, err := svc.BulkUpdateAssets(f.tenant, []uuid.UUID{x}, ch, f.actor); !errors.Is(err, ErrBulkChangesInvalid) {
			t.Errorf("%s: err = %v, want ErrBulkChangesInvalid", name, err)
		}
	}
}

func TestIntegration_BulkLifecycle_ArchiveRestoreDeleteCountWhatTheyChange(t *testing.T) {
	f := newBulkFixture(t)
	a := f.asset(t, f.tenant, "monitoring", "", false, "")
	already := f.asset(t, f.tenant, "monitoring", "", false, "")
	if _, err := f.raw.Exec(`UPDATE assets SET stale_status = 'archived' WHERE id = $1`, already); err != nil {
		t.Fatal(err)
	}
	foreign := f.asset(t, f.other, "monitoring", "", false, "")
	lc := &AssetLifecycleService{db: f.db}
	svc := &AssetService{db: f.db}

	n, err := lc.ArchiveAssets(f.tenant, []uuid.UUID{a, already, foreign}, f.actor)
	if err != nil || n != 1 {
		t.Fatalf("archive: %d, %v; want 1 (one was archived already, one is another tenant's)", n, err)
	}
	if got := f.historyCount(t, a, "archived"); got != 1 {
		t.Errorf("archived asset has %d `archived` rows, want 1", got)
	}
	if got := f.historyCount(t, already, "archived"); got != 0 {
		t.Errorf("an already-archived asset got %d new `archived` rows, want 0", got)
	}

	n, err = lc.UnarchiveAssets(f.tenant, []uuid.UUID{a, already, foreign}, f.actor)
	if err != nil || n != 2 {
		t.Fatalf("restore: %d, %v; want 2", n, err)
	}
	var stale string
	if err := f.raw.QueryRow(`SELECT stale_status FROM assets WHERE id = $1`, already).Scan(&stale); err != nil || stale != "active" {
		t.Errorf("restored stale_status = %q (%v), want active", stale, err)
	}
	if got := f.historyCount(t, already, "updated"); got != 1 {
		t.Errorf("restored asset has %d `updated` rows by the actor, want 1", got)
	}

	n, err = svc.DeleteAssets(f.tenant, []uuid.UUID{a, foreign})
	if err != nil || n != 1 {
		t.Fatalf("delete: %d, %v; want 1", n, err)
	}
	var deleted, foreignDeleted bool
	_ = f.raw.QueryRow(`SELECT deleted_at IS NOT NULL FROM assets WHERE id = $1`, a).Scan(&deleted)
	_ = f.raw.QueryRow(`SELECT deleted_at IS NOT NULL FROM assets WHERE id = $1`, foreign).Scan(&foreignDeleted)
	if !deleted || foreignDeleted {
		t.Errorf("deleted = %v, foreign deleted = %v; want true, false", deleted, foreignDeleted)
	}
	if n, err := svc.DeleteAssets(f.tenant, []uuid.UUID{a}); err != nil || n != 0 {
		t.Errorf("second delete: %d, %v; want 0, nil", n, err)
	}
}
