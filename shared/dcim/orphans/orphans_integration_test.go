package orphans_test

// DB-integration test for Sweep: it skips unless TEST_DATABASE_URL is set
// (`make test-integration-db`).

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim/orphans"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type fixture struct {
	t             *testing.T
	owner         *sql.DB
	tenant        uuid.UUID
	tag           uuid.UUID
	contact, role uuid.UUID
}

func (f *fixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.owner.Exec(q, args...); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
}

func (f *fixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.owner.QueryRow(q, args...).Scan(&n); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	return n
}

// site inserts a site and hangs one of each kind of reference on it.
func (f *fixture) site(name string) (uuid.UUID, string) {
	id, ref := uuid.New(), "img/"+name
	f.exec(`INSERT INTO sites (id, tenant_id, name, slug) VALUES ($1, $2, $3, $3)`, id, f.tenant, name)
	f.exec(`INSERT INTO object_tags (tenant_id, object_kind, object_id, tag_id) VALUES ($1, 'site', $2, $3)`, f.tenant, id, f.tag)
	f.exec(`INSERT INTO journal_entries (tenant_id, object_kind, object_id, comments) VALUES ($1, 'site', $2, 'note')`, f.tenant, id)
	f.exec(`INSERT INTO contact_assignments (tenant_id, object_kind, object_id, contact_id, role_id) VALUES ($1, 'site', $2, $3, $4)`, f.tenant, id, f.contact, f.role)
	f.exec(`INSERT INTO image_attachments (tenant_id, object_kind, object_id, storage_ref, width, height, size_bytes) VALUES ($1, 'site', $2, $3, 1, 1, 1)`, f.tenant, id, ref)
	f.exec(`INSERT INTO prefixes (tenant_id, prefix, scope_kind, scope_id) VALUES ($1, $2::cidr, 'site', $3)`, f.tenant, "10."+string(rune('0'+len(name)))+".0.0/16", id)
	f.exec(`INSERT INTO vlan_groups (tenant_id, name, slug, scope_kind, scope_id) VALUES ($1, $2, $2, 'site', $3)`, f.tenant, name, id)
	return id, ref
}

func newFixture(t *testing.T, owner *sql.DB) *fixture {
	f := &fixture{t: t, owner: owner, tenant: testdb.NewTenant(t, owner), tag: uuid.New(), contact: uuid.New()}
	f.exec(`INSERT INTO tags (id, tenant_id, name, slug) VALUES ($1, $2, 'ops', 'ops')`, f.tag, f.tenant)
	f.exec(`INSERT INTO contacts (id, tenant_id, name) VALUES ($1, $2, 'Pat')`, f.contact, f.tenant)
	if err := owner.QueryRow(`SELECT id FROM contact_roles WHERE tenant_id IS NULL LIMIT 1`).Scan(&f.role); err != nil {
		t.Fatalf("a seeded contact role: %v", err)
	}
	return f
}

// Deleting an object leaves its tags, journal entries, contact assignments and
// images (Delete) and its scope pointers (Null) behind. A dry run counts them;
// a sweep removes them, keeps the rows that stood on their own, hands back the
// image's storage ref, never touches the object that still exists, and never
// touches another tenant. Mutation: make Sweep skip the NOT EXISTS predicate and
// the surviving site's rows go too.
func TestIntegration_Sweep_RemovesWhatPointsAtADeletedObject(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)

	a, other := newFixture(t, owner), newFixture(t, owner)
	keep, _ := a.site("keep")
	gone, goneRef := a.site("goneee")
	otherGone, _ := other.site("elsewhere")
	a.exec(`DELETE FROM sites WHERE id = $1`, gone)
	other.exec(`DELETE FROM sites WHERE id = $1`, otherGone)

	run := func(dry bool) orphans.Report {
		t.Helper()
		var rep orphans.Report
		err := database.WithTenantTx(context.Background(), app, a.tenant, func(tx *sql.Tx) error {
			var err error
			rep, err = orphans.Sweep(context.Background(), tx, a.tenant, dry)
			return err
		})
		if err != nil {
			t.Fatalf("sweep (dry=%v): %v", dry, err)
		}
		return rep
	}

	dry := run(true)
	for _, key := range []string{"object_tags.object_kind", "journal_entries.object_kind", "contact_assignments.object_kind",
		"image_attachments.object_kind", "prefixes.scope_kind", "vlan_groups.scope_kind"} {
		if dry.Rows[key] != 1 {
			t.Errorf("dry run: %s = %d, want 1 (report %v)", key, dry.Rows[key], dry.Rows)
		}
	}
	if a.count(`SELECT count(*) FROM object_tags WHERE object_id = $1`, gone) != 1 {
		t.Fatal("a dry run removed a row")
	}

	rep := run(false)
	if rep.Total() != 6 {
		t.Errorf("swept %d rows, want 6: %v", rep.Total(), rep.Rows)
	}
	if len(rep.ImageRefs) != 1 || rep.ImageRefs[0] != goneRef {
		t.Errorf("image refs = %v, want [%s]", rep.ImageRefs, goneRef)
	}
	for _, tbl := range []string{"object_tags", "journal_entries", "contact_assignments", "image_attachments"} {
		if n := a.count(`SELECT count(*) FROM `+tbl+` WHERE object_id = $1`, gone); n != 0 {
			t.Errorf("%s still has %d row(s) for the deleted site", tbl, n)
		}
		if n := a.count(`SELECT count(*) FROM `+tbl+` WHERE object_id = $1`, keep); n != 1 {
			t.Errorf("%s has %d row(s) for the surviving site, want 1", tbl, n)
		}
	}
	// A prefix and a VLAN group stand on their own: the row stays, the dead scope goes.
	if n := a.count(`SELECT count(*) FROM prefixes WHERE tenant_id = $1 AND scope_kind IS NULL AND scope_id IS NULL`, a.tenant); n != 1 {
		t.Errorf("%d prefix(es) with the scope cleared, want 1", n)
	}
	if n := a.count(`SELECT count(*) FROM prefixes WHERE tenant_id = $1`, a.tenant); n != 2 {
		t.Errorf("%d prefixes remain, want both (Null keeps the row)", n)
	}
	if n := a.count(`SELECT count(*) FROM vlan_groups WHERE tenant_id = $1 AND scope_id = $2`, a.tenant, keep); n != 1 {
		t.Errorf("the surviving site lost its VLAN group scope")
	}
	// Another tenant's orphans are theirs to sweep.
	if n := other.count(`SELECT count(*) FROM object_tags WHERE object_id = $1`, otherGone); n != 1 {
		t.Errorf("tenant A's sweep touched tenant B's rows")
	}

	if again := run(false); again.Total() != 0 {
		t.Errorf("a second sweep found %d rows: %v", again.Total(), again.Rows)
	}
}
