package services

// DB-integration tests for the automatic end-of-life catalogue match. Skipped
// unless TEST_DATABASE_URL is set; run with make test-integration-db.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func eolMatchEntry(t *testing.T, owner *sql.DB, kind, vendor, product, cycle string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := owner.QueryRow(`INSERT INTO eol_catalogue (product_kind, vendor, product, cycle, eol_date)
		VALUES ($1, $2, $3, $4, '2030-01-31') RETURNING id`, kind, vendor, product, cycle).Scan(&id); err != nil {
		t.Fatalf("seed eol_catalogue: %v", err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(`DELETE FROM eol_catalogue WHERE id = $1`, id) })
	return id
}

func eolMatchMfr(t *testing.T, owner *sql.DB, tenant uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := owner.QueryRow(`INSERT INTO manufacturers (tenant_id, name, slug) VALUES ($1, $2, $3) RETURNING id`,
		tenant, name, Slugify(name)).Scan(&id); err != nil {
		t.Fatalf("seed manufacturer: %v", err)
	}
	return id
}

func eolMatchType(t *testing.T, owner *sql.DB, tenant, mfr uuid.UUID, model string, link *uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := owner.QueryRow(`INSERT INTO device_types (tenant_id, manufacturer_id, model, slug, eol_catalogue_id)
		VALUES ($1, $2, $3, $4, $5) RETURNING id`, tenant, mfr, model, Slugify(model)+"-"+uuid.NewString()[:6], link).Scan(&id); err != nil {
		t.Fatalf("seed device type: %v", err)
	}
	return id
}

func eolMatchLinkOf(t *testing.T, owner *sql.DB, table string, id uuid.UUID) *uuid.UUID {
	t.Helper()
	var l *uuid.UUID
	if err := owner.QueryRow(fmt.Sprintf(`SELECT eol_catalogue_id FROM %s WHERE id = $1`, table), id).Scan(&l); err != nil {
		t.Fatalf("read link: %v", err)
	}
	return l
}

func eolMatchListSource(t *testing.T, svc *CatalogueService, tenant uuid.UUID, route string, id uuid.UUID) any {
	t.Helper()
	rows, _, err := svc.List(ifaceActorCtx(), tenant, route, IPAMListParams{Limit: 200})
	if err != nil {
		t.Fatalf("list %s: %v", route, err)
	}
	for _, r := range rows {
		var m map[string]any
		if err := json.Unmarshal(r, &m); err != nil {
			t.Fatal(err)
		}
		if m["id"] == id.String() {
			return m["eol_link_source"]
		}
	}
	t.Fatalf("%s %s not listed", route, id)
	return nil
}

// One unambiguous match links; two candidates (two release cycles) do not; a
// person's link stays; a row a person unlinked is not relinked; a platform
// matches by name. The link is recorded as an automatic change.
//
// Mutation: drop the `eol_catalogue_id IS NULL` guard in linkEOLEntry /
// eolUnlinkedSQL → the declared link is replaced; drop the `single` count
// check → the ambiguous type is linked to a guess; drop the NOT EXISTS in
// eolUnlinkedSQL → the person-unlinked type is relinked.
func TestIntegration_EOLMatch_LinksOnlyTheUnambiguousAndNeverReplacesAPersonsLink(t *testing.T) {
	owner, app, tenant, svc := catFixture(t)
	_ = app
	sfx := uuid.NewString()[:8]
	vendor := "Acme-" + sfx
	mfr := eolMatchMfr(t, owner, tenant, vendor)

	one := eolMatchEntry(t, owner, "hardware", vendor, "Switch-1-"+sfx, "1")
	eolMatchEntry(t, owner, "hardware", vendor, "Switch-2-"+sfx, "1")
	eolMatchEntry(t, owner, "hardware", vendor, "Switch-2-"+sfx, "2")
	declared := eolMatchEntry(t, owner, "hardware", vendor, "Declared-Other-"+sfx, "1")
	eolMatchEntry(t, owner, "hardware", vendor, "Unlinked-"+sfx, "1")

	matched := eolMatchType(t, owner, tenant, mfr, " switch-1-"+sfx+" ", nil)
	ambiguous := eolMatchType(t, owner, tenant, mfr, "Switch-2-"+sfx, nil)
	kept := eolMatchType(t, owner, tenant, mfr, "Switch-1-"+sfx+"-b", &declared) // would prefix-match `one`
	unlinked := eolMatchType(t, owner, tenant, mfr, "Unlinked-"+sfx, nil)
	// A person took a link off `unlinked` earlier.
	if _, err := owner.Exec(`INSERT INTO object_changes (tenant_id, object_kind, object_id, action, prechange_data, postchange_data, changed_fields, user_id, source)
		VALUES ($1, 'device_type', $2, 'update', jsonb_build_object('eol_catalogue_id', $3::text), jsonb_build_object('eol_catalogue_id', NULL), ARRAY['eol_catalogue_id'], $4, 'ui')`,
		tenant, unlinked, one.String(), uuid.New()); err != nil {
		t.Fatalf("seed unlink change: %v", err)
	}

	osVendor := "OsVendor-" + sfx
	osOne := eolMatchEntry(t, owner, "os", osVendor, "AcmeOS-"+sfx, "9")
	var plat uuid.UUID
	if err := owner.QueryRow(`INSERT INTO platforms (tenant_id, name, slug) VALUES ($1, $2, $3) RETURNING id`,
		tenant, "AcmeOS-"+sfx, "acmeos-"+sfx).Scan(&plat); err != nil {
		t.Fatalf("seed platform: %v", err)
	}

	ctx := ifaceActorCtx()
	counts, err := svc.MatchEOLCatalogue(ctx, tenant)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if counts.Linked != 2 || counts.Ambiguous != 1 {
		t.Errorf("counts = %+v, want 2 linked (type + platform), 1 ambiguous", counts)
	}
	if l := eolMatchLinkOf(t, owner, "device_types", matched); l == nil || *l != one {
		t.Errorf("unambiguous type not linked to its entry: %v", l)
	}
	if l := eolMatchLinkOf(t, owner, "device_types", ambiguous); l != nil {
		t.Errorf("ambiguous type was linked to a guess: %v", *l)
	}
	if l := eolMatchLinkOf(t, owner, "device_types", kept); l == nil || *l != declared {
		t.Errorf("a person's link was replaced: %v", l)
	}
	if l := eolMatchLinkOf(t, owner, "device_types", unlinked); l != nil {
		t.Errorf("a type a person unlinked was relinked: %v", *l)
	}
	if l := eolMatchLinkOf(t, owner, "platforms", plat); l == nil || *l != osOne {
		t.Errorf("platform not linked: %v", l)
	}

	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_id = ANY($2) AND source = 'intake:eol-match'
		AND 'eol_catalogue_id' = ANY(changed_fields)`, tenant, "{"+matched.String()+","+plat.String()+"}").Scan(&n); err != nil || n != 2 {
		t.Errorf("recorded automatic changes = %d (%v), want 2", n, err)
	}

	// The list says which links were made automatically.
	if got := eolMatchListSource(t, svc, tenant, "device-types", matched); got != "automatic" {
		t.Errorf("matched type eol_link_source = %v", got)
	}
	if got := eolMatchListSource(t, svc, tenant, "device-types", kept); got != "manual" {
		t.Errorf("declared type eol_link_source = %v", got)
	}
	if got := eolMatchListSource(t, svc, tenant, "device-types", ambiguous); got != nil {
		t.Errorf("unlinked type eol_link_source = %v, want null", got)
	}
	if got := eolMatchListSource(t, svc, tenant, "platforms", plat); got != "automatic" {
		t.Errorf("platform eol_link_source = %v", got)
	}

	// A second pass changes nothing.
	again, err := svc.MatchEOLCatalogue(ctx, tenant)
	if err != nil || again.Linked != 0 {
		t.Errorf("second pass = %+v, %v; want nothing linked", again, err)
	}
}

// Creating a device type or platform runs the same match in the writing
// transaction; a person-supplied link on create is kept.
//
// Mutation: drop `AfterWrite: matchEOLAfterWrite(...)` from the device-types
// or platforms spec → the created row has no link.
func TestIntegration_EOLMatch_RunsOnCreate(t *testing.T) {
	owner, _, tenant, svc := catFixture(t)
	sfx := uuid.NewString()[:8]
	vendor := "Beta-" + sfx
	mfr := eolMatchMfr(t, owner, tenant, vendor)
	entry := eolMatchEntry(t, owner, "hardware", vendor, "Box-"+sfx, "1")
	osEntry := eolMatchEntry(t, owner, "os", "BetaOS Inc", "BetaOS-"+sfx, "3")
	other := eolMatchEntry(t, owner, "hardware", vendor, "Elsewhere-"+sfx, "1")
	ctx := ifaceActorCtx()

	raw, err := svc.Create(ctx, tenant, "device-types", []byte(fmt.Sprintf(`{"manufacturer_id":%q,"model":"Box-%s"}`, mfr, sfx)))
	if err != nil {
		t.Fatalf("create device type: %v", err)
	}
	if l := eolMatchLinkOf(t, owner, "device_types", catID(t, raw)); l == nil || *l != entry {
		t.Errorf("created device type not matched: %v", l)
	}
	// A link supplied on create is kept, though "Box-<sfx>-x" would otherwise
	// prefix-match the Box entry.
	raw, err = svc.Create(ctx, tenant, "device-types", []byte(fmt.Sprintf(`{"manufacturer_id":%q,"model":"Box-%s-x","eol_catalogue_id":%q}`, mfr, sfx, other)))
	if err != nil {
		t.Fatalf("create device type with a link: %v", err)
	}
	if l := eolMatchLinkOf(t, owner, "device_types", catID(t, raw)); l == nil || *l != other {
		t.Errorf("supplied link replaced on create: %v", l)
	}
	raw, err = svc.Create(ctx, tenant, "platforms", []byte(fmt.Sprintf(`{"name":"BetaOS-%s"}`, sfx)))
	if err != nil {
		t.Fatalf("create platform: %v", err)
	}
	if l := eolMatchLinkOf(t, owner, "platforms", catID(t, raw)); l == nil || *l != osEntry {
		t.Errorf("created platform not matched: %v", l)
	}
	if got := eolMatchListSource(t, svc, tenant, "platforms", catID(t, raw)); got != "automatic" {
		t.Errorf("created platform eol_link_source = %v", got)
	}
}
