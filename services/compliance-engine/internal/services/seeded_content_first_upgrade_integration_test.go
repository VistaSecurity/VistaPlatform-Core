package services

// Seeded content, continued (decision 4, RC-12; review of):
//
//   - the FIRST upgrade onto the ownership marker, where every shipped row is
//     unmarked and the guard must compare it with the WHOLE row the seed ships,
//     not just the columns an ON CONFLICT SET list happens to write;
//   - measurement rules, which the seed never upserts, classified without
//     calling an admin's rule Vista's;
//   - re-keying a shipped row, which must tombstone the shipped key;
//   - deleting a whole shipped framework, which must count as accounted for;
//   - a seed correction that matches a row an admin created, which must leave
//     it alone.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// asPreMarkerInstall turns the fixture's freshly seeded database into what an
// install from BEFORE the ownership marker looks like — every seeded row
// unmarked, no tombstones — and then makes the given admin edits the way that
// release's console made them: with no guard trigger to notice. Triggers are
// off for the whole transaction (session_replication_role = replica), so
// created_at/updated_at are exactly what the statements write.
func (f *seededFixture) asPreMarkerInstall(t *testing.T, edits ...string) {
	t.Helper()
	tx, err := f.raw.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{
		`SET LOCAL session_replication_role = replica`,
		`UPDATE platform_frameworks SET content_origin = NULL, admin_modified_at = NULL, seed_shipped = NULL, seed_offer = NULL`,
		`UPDATE platform_framework_controls SET content_origin = NULL, admin_modified_at = NULL, seed_shipped = NULL, seed_offer = NULL`,
		`UPDATE control_measurements SET content_origin = NULL, admin_modified_at = NULL, seed_shipped = NULL, seed_offer = NULL`,
		`UPDATE classification_rules SET content_origin = NULL, admin_modified_at = NULL, seed_shipped = NULL, seed_offer = NULL`,
		`DELETE FROM seeded_content_tombstones`,
	} {
		if _, err := tx.Exec(q); err != nil {
			t.Fatalf("pre-marker install: %s: %v", q, err)
		}
	}
	for _, q := range edits {
		res, err := tx.Exec(q)
		if err != nil {
			t.Fatalf("pre-marker admin edit: %s: %v", q, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("pre-marker admin edit matched %d rows, want 1: %s", n, q)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

type ownership struct {
	origin   string
	modified bool
	offer    string
}

func (f *seededFixture) ownershipOf(t *testing.T, q string) ownership {
	t.Helper()
	var o ownership
	if err := f.raw.QueryRow(`SELECT coalesce(content_origin, ''), admin_modified_at IS NOT NULL, coalesce(seed_offer::text, '') FROM (`+q+`) r`).
		Scan(&o.origin, &o.modified, &o.offer); err != nil {
		t.Fatalf("ownership of %s: %v", q, err)
	}
	return o
}

const (
	bpFramework = `SELECT * FROM platform_frameworks WHERE code = 'best-practices'`
	adminRule   = `SELECT cm.* FROM control_measurements cm
		JOIN platform_framework_controls c ON c.id = cm.control_id
		JOIN measurement_types mt ON mt.id = cm.measurement_type_id
		WHERE c.control_id = 'BP-003' AND mt.code = 'key_size' AND cm.framework_type = 'platform'`
)

func controlRow(id string) string {
	return `SELECT * FROM platform_framework_controls WHERE control_id = '` + id + `'`
}

func ruleOf(control string) string {
	return `SELECT cm.* FROM control_measurements cm
		JOIN platform_framework_controls c ON c.id = cm.control_id
		WHERE c.control_id = '` + control + `' AND cm.framework_type = 'platform'`
}

// The review's reproduction. On the first upgrade onto the marker, an admin's
// edit to a column the seed's SET list never writes — a framework's name, a
// control's crypto_relevant — must be kept and flagged as the admin's, with
// the shipped value offered; an admin-created measurement rule under a shipped
// control must NOT be claimed as Vista's. A row that is exactly what ships is
// marked pristine. And the second upgrade changes nothing.
func TestIntegration_SeededContent_FirstUpgradeComparesTheWholeShippedRow(t *testing.T) {
	f := newSeededFixture(t)
	f.asPreMarkerInstall(t,
		// Columns the Core upserts do NOT write.
		`UPDATE platform_frameworks SET name = 'Admin BP name' WHERE code = 'best-practices'`,
		`UPDATE platform_framework_controls SET crypto_relevant = false WHERE control_id = 'BP-001'`,
		// A column the control upsert DOES write (the case that already worked).
		`UPDATE platform_framework_controls SET title = 'Admin BP-002 title' WHERE control_id = 'BP-002'`,
		// An edited shipped measurement rule, and one the admin added.
		`UPDATE control_measurements cm SET predicate = '{"operator": ">=", "value": 14}', updated_at = clock_timestamp()
		   FROM platform_framework_controls c WHERE c.id = cm.control_id AND c.control_id = 'BP-002' AND cm.framework_type = 'platform'`,
		`INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
		 SELECT c.id, 'platform', mt.id, 'threshold', '{"operator": ">=", "value": 3072}', 'high', 5, clock_timestamp(), clock_timestamp()
		   FROM platform_framework_controls c, measurement_types mt WHERE c.control_id = 'BP-003' AND mt.code = 'key_size'`,
	)

	for pass := 1; pass <= 2; pass++ {
		testdb.ForceApplySeed(t, f.raw)

		if got := f.str(t, `SELECT name FROM platform_frameworks WHERE code = 'best-practices'`); got != "Admin BP name" {
			t.Errorf("pass %d: best-practices name = %q, want the admin's", pass, got)
		}
		if got := f.ownershipOf(t, bpFramework); got != (ownership{"seed", true, `{"name": "Security Best Practices"}`}) {
			t.Errorf("pass %d: best-practices ownership = %+v; want shipped, admin-modified, the shipped name offered", pass, got)
		}
		if got := f.str(t, `SELECT crypto_relevant::text FROM platform_framework_controls WHERE control_id = 'BP-001'`); got != "false" {
			t.Errorf("pass %d: BP-001 crypto_relevant = %s, want the admin's false", pass, got)
		}
		if got := f.ownershipOf(t, controlRow("BP-001")); got != (ownership{"seed", true, `{"crypto_relevant": true}`}) {
			t.Errorf("pass %d: BP-001 ownership = %+v; want shipped, admin-modified, crypto_relevant=true offered", pass, got)
		}
		if got := f.ownershipOf(t, controlRow("BP-002")); got != (ownership{"seed", true, `{"title": "Certificate Expiration Monitoring"}`}) {
			t.Errorf("pass %d: BP-002 ownership = %+v; want shipped, admin-modified, the shipped title offered", pass, got)
		}
		if got := f.ownershipOf(t, controlRow("BP-005")); got != (ownership{"seed", false, ""}) {
			t.Errorf("pass %d: untouched BP-005 ownership = %+v; want pristine shipped content", pass, got)
		}
		if got := f.ownershipOf(t, adminRule); got.origin == "seed" {
			t.Errorf("pass %d: the admin's own rule under BP-003 was claimed as Vista content: %+v", pass, got)
		}
		if got := f.ownershipOf(t, ruleOf("BP-002")); got != (ownership{"seed", true, ""}) {
			t.Errorf("pass %d: BP-002's edited rule ownership = %+v; want shipped and admin-modified", pass, got)
		}
		if got := f.ownershipOf(t, ruleOf("BP-001")); got != (ownership{"seed", false, ""}) {
			t.Errorf("pass %d: BP-001's untouched rule ownership = %+v; want pristine shipped content", pass, got)
		}

		// Exactly the rows the admin touched are the admin's; everything the seed
		// ships and nobody touched is marked pristine.
		for _, c := range []struct {
			table string
			where string
			want  int
		}{
			{"platform_frameworks", "admin_modified_at IS NOT NULL", 1},
			{"platform_frameworks", "content_origin IS NULL", 0},
			{"platform_framework_controls", "admin_modified_at IS NOT NULL", 2},
			{"platform_framework_controls", "content_origin IS NULL", 0},
			{"control_measurements", "framework_type = 'platform' AND admin_modified_at IS NOT NULL", 1},
			{"control_measurements", "framework_type = 'platform' AND content_origin IS NULL", 1},
			{"classification_rules", "content_origin IS DISTINCT FROM 'seed' OR admin_modified_at IS NOT NULL", 0},
		} {
			if got := f.count(t, `SELECT count(*) FROM `+c.table+` WHERE `+c.where); got != c.want {
				t.Errorf("pass %d: %s WHERE %s: %d rows, want %d", pass, c.table, c.where, got, c.want)
			}
		}
	}

	// The offer is real: accepting it restores the shipped name.
	fwID := f.str(t, `SELECT id::text FROM platform_frameworks WHERE code = 'best-practices'`)
	if got := f.str(t, `SELECT public.accept_seeded_content_update('framework', $1::uuid)::text`, fwID); got != "true" {
		t.Fatalf("accept on best-practices returned %s", got)
	}
	if got := f.str(t, `SELECT name FROM platform_frameworks WHERE code = 'best-practices'`); got != "Security Best Practices" {
		t.Errorf("after accept, best-practices name = %q, want the shipped name", got)
	}
}

// Changing a shipped row's natural key (a control's control_id, a
// classification rule's pattern) must tombstone the OLD key, or the next
// upgrade puts the shipped original back beside the admin's re-keyed copy.
// Polarity: re-keying a row the admin created tombstones nothing.
func TestIntegration_SeededContent_RekeyTombstonesTheShippedKey(t *testing.T) {
	f := newSeededFixture(t)

	f.exec(t, `UPDATE classification_rules SET pattern = 'AD0039' WHERE rule_kind = 'oui' AND pattern = '000039'`)
	f.exec(t, `UPDATE platform_framework_controls SET control_id = 'BP-004-OURS' WHERE control_id = 'BP-004'`)
	f.exec(t, `INSERT INTO classification_rules (rule_kind, pattern, class_key, vendor, confidence)
		VALUES ('oui', 'AD0001', NULL, 'Ours', 0.5)`)
	f.exec(t, `UPDATE classification_rules SET pattern = 'AD0002' WHERE rule_kind = 'oui' AND pattern = 'AD0001'`)

	for _, want := range []struct{ entity, key string }{
		{"classification_rule", `["oui", "000039"]`},
		{"control", `["best-practices", "1.0", "BP-004"]`},
	} {
		if got := f.count(t, `SELECT count(*) FROM seeded_content_tombstones WHERE entity = $1 AND natural_key = $2`, want.entity, want.key); got != 1 {
			t.Errorf("re-keying the shipped %s %s wrote no tombstone for the old key", want.entity, want.key)
		}
	}
	if got := f.count(t, `SELECT count(*) FROM seeded_content_tombstones`); got != 2 {
		t.Errorf("%d tombstones, want exactly 2 (the two shipped keys; re-keying an admin-created rule tombstones nothing)", got)
	}

	testdb.ForceApplySeed(t, f.raw)
	testdb.ForceApplySeed(t, f.raw)

	for q, want := range map[string]int{
		`SELECT count(*) FROM classification_rules WHERE rule_kind = 'oui' AND pattern = '000039'`: 0,
		`SELECT count(*) FROM classification_rules WHERE rule_kind = 'oui' AND pattern = 'AD0039'`: 1,
		`SELECT count(*) FROM platform_framework_controls WHERE control_id = 'BP-004'`:             0,
		`SELECT count(*) FROM platform_framework_controls WHERE control_id = 'BP-004-OURS'`:        1,
	} {
		if got := f.count(t, q); got != want {
			t.Errorf("after re-seeding: %s = %d, want %d (a re-keyed shipped row's original came back)", q, got, want)
		}
	}
}

// Deleting a whole shipped framework is an admin decision the seed-data Job
// must accept: seeded_frameworks_unaccounted() counts it as accounted for (via
// its tombstone), and re-seeding neither recreates it nor its controls.
func TestIntegration_SeededContent_DeletedFrameworkIsAccountedFor(t *testing.T) {
	f := newSeededFixture(t)
	controls := f.count(t, `SELECT count(*) FROM platform_framework_controls c JOIN platform_frameworks fw ON fw.id = c.framework_id WHERE fw.code = 'lifecycle'`)
	if controls == 0 {
		t.Fatal("fixture: the lifecycle framework has no controls")
	}
	if n := f.exec(t, `DELETE FROM platform_frameworks WHERE code = 'lifecycle'`); n != 1 {
		t.Fatalf("delete lifecycle: %d rows", n)
	}
	unaccounted := func(codes string) string {
		return f.str(t, `SELECT public.seeded_frameworks_unaccounted(`+codes+`)::text`)
	}
	if got := unaccounted(`ARRAY['lifecycle']`); got != "0" {
		t.Errorf("seeded_frameworks_unaccounted(lifecycle) = %s after an admin deleted it, want 0", got)
	}

	testdb.ForceApplySeed(t, f.raw)
	if got := f.count(t, `SELECT count(*) FROM platform_frameworks WHERE code = 'lifecycle'`); got != 0 {
		t.Errorf("re-seeding recreated the framework an admin deleted")
	}
	if got := f.count(t, `SELECT count(*) FROM platform_framework_controls c JOIN platform_frameworks fw ON fw.id = c.framework_id WHERE fw.code = 'lifecycle'`); got != 0 {
		t.Errorf("re-seeding recreated %d controls of the deleted framework", got)
	}
	if got := unaccounted(`ARRAY['lifecycle']`); got != "0" {
		t.Errorf("seeded_frameworks_unaccounted(lifecycle) = %s after re-seed, want 0", got)
	}

	// Polarity: a framework missing for any other reason is unaccounted.
	if got := unaccounted(`ARRAY['lifecycle', 'no-such-framework']`); got != "1" {
		t.Errorf("seeded_frameworks_unaccounted with an unknown code = %s, want 1", got)
	}
	f.exec(t, `DELETE FROM seeded_content_tombstones WHERE entity = 'framework'`)
	if got := unaccounted(`ARRAY['lifecycle']`); got != "1" {
		t.Errorf("seeded_frameworks_unaccounted(lifecycle) = %s with no tombstone, want 1", got)
	}
}

// A row an admin created belongs to the admin outright. A seed correction
// whose WHERE happens to match it — here the CMP-3 repair of the old weak-cipher
// pattern — must neither rewrite it nor put an "update available" offer on it.
func TestIntegration_SeededContent_SeedCorrectionLeavesAdminCreatedRowsAlone(t *testing.T) {
	f := newSeededFixture(t)
	const oldPattern = `{"flags": "i", "pattern": "^(3DES|DES|RC4|RC4-.*)$", "match_means_violation": true}`
	f.exec(t, `INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight)
		SELECT c.id, 'platform', mt.id, 'pattern', $1::jsonb, 'low', 2
		  FROM platform_framework_controls c, measurement_types mt WHERE c.control_id = 'BP-005' AND mt.code = 'symmetric_encryption'`, oldPattern)
	q := `SELECT cm.* FROM control_measurements cm JOIN platform_framework_controls c ON c.id = cm.control_id
		WHERE c.control_id = 'BP-005' AND cm.weight = 2 AND cm.severity_override = 'low'`
	if got := f.ownershipOf(t, q); got != (ownership{"admin", false, ""}) {
		t.Fatalf("admin-created rule ownership = %+v, want admin", got)
	}

	testdb.ForceApplySeed(t, f.raw)

	if got := f.str(t, `SELECT r.predicate::text FROM (`+q+`) r`); got != oldPattern {
		t.Errorf("the seed's correction rewrote an admin-created rule: predicate = %s", got)
	}
	if got := f.ownershipOf(t, q); got != (ownership{"admin", false, ""}) {
		t.Errorf("admin-created rule after re-seed = %+v; want admin, unmodified, no offer", got)
	}
}

// Only an upsert's own INSERT can vouch for a whole row. A seed statement that
// is not an upsert — a correction UPDATE — must never mark a row that predates
// the marker as pristine, and must never borrow the row an EARLIER insert in
// the same transaction proposed (the shipped-row hand-off is keyed to its own
// row). Driven statement by statement in one seed-pass transaction, which is
// how the harness (one Exec) and a DO block run the seed.
func TestIntegration_SeededContent_SeedStatementsWithoutAWholeRowNeverStampPristine(t *testing.T) {
	f := newSeededFixture(t)
	f.asPreMarkerInstall(t)

	tx, err := f.raw.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{
		`SELECT set_config('vista.seed_apply', 'on', true)`,
		// A seed statement that touches no tracked column of a pre-marker row.
		`UPDATE platform_framework_controls SET updated_at = now() WHERE control_id = 'BP-001'`,
		// A seed INSERT that really inserts (no conflict) — its shipped row is
		// handed off — followed by a correction to a DIFFERENT pre-marker row.
		`INSERT INTO classification_rules (rule_kind, pattern, class_key, vendor, confidence) VALUES ('oui', 'ADFFFF', 'ot_device', 'Shipped later', 0.60)`,
		`UPDATE classification_rules SET confidence = 0.66 WHERE rule_kind = 'oui' AND pattern = '00000A'`,
	} {
		if _, err := tx.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if got := f.ownershipOf(t, controlRow("BP-001")); got != (ownership{"", false, ""}) {
		t.Errorf("BP-001 after a non-upsert seed statement = %+v; want it left unmarked (nothing vouched for the whole row)", got)
	}
	if got := f.count(t, `SELECT count(*) FROM platform_framework_controls WHERE control_id = 'BP-001' AND seed_shipped IS NOT NULL`); got != 0 {
		t.Error("BP-001: a non-upsert seed statement recorded the row's own values as 'what Vista shipped'")
	}
	if got := f.str(t, `SELECT confidence::text FROM classification_rules WHERE rule_kind = 'oui' AND pattern = '00000A'`); got != "0.70" {
		t.Errorf("00000A confidence = %s: a correction overwrote a pre-marker row it could not vouch for", got)
	}
	if got := f.ownershipOf(t, `SELECT * FROM classification_rules WHERE rule_kind = 'oui' AND pattern = '00000A'`); got != (ownership{"seed", true, `{"confidence": 0.66}`}) {
		t.Errorf("00000A ownership = %+v; want kept, with exactly the correction on offer (not the other rule's shipped row)", got)
	}
}

// classify_seeded_measurements() runs its UPDATE in 'classify' mode, which may
// set the ownership of an UNMARKED row and nothing else: it leaves a marked
// row — here one the admin created — exactly as it is, and never moves
// updated_at.
func TestIntegration_SeededContent_ClassifyModeOnlyMarksUnmarkedRows(t *testing.T) {
	f := newSeededFixture(t)
	f.exec(t, `INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight)
		SELECT c.id, 'platform', mt.id, 'threshold', '{"operator": ">=", "value": 4096}', 'low', 3
		  FROM platform_framework_controls c, measurement_types mt WHERE c.control_id = 'BP-005' AND mt.code = 'key_size'`)
	admin := `SELECT * FROM control_measurements WHERE weight = 3 AND severity_override = 'low' AND predicate ->> 'value' = '4096'`
	before := f.str(t, `SELECT updated_at::text FROM (`+admin+`) r`)

	tx, err := f.raw.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{
		`SELECT set_config('vista.seed_apply', 'classify', true)`,
		`UPDATE control_measurements SET content_origin = 'seed', admin_modified_at = NULL, weight = 9
		  WHERE weight = 3 AND severity_override = 'low' AND predicate ->> 'value' = '4096'`,
	} {
		if _, err := tx.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := f.ownershipOf(t, admin); got != (ownership{"admin", false, ""}) {
		t.Errorf("classify mode rewrote a marked row's ownership: %+v", got)
	}
	if got := f.str(t, `SELECT updated_at::text FROM (`+admin+`) r`); got != before {
		t.Errorf("classify mode moved updated_at %s → %s", before, got)
	}

	// And on the rows it may mark, it changes nothing but ownership. (Only the
	// rules are unmarked: classification needs their controls marked, as the
	// seed has done by the time seed.sql calls it.)
	f.exec(t, `BEGIN;
		SET LOCAL session_replication_role = replica;
		UPDATE control_measurements SET content_origin = NULL, admin_modified_at = NULL, seed_shipped = NULL, seed_offer = NULL
		 WHERE content_origin = 'seed';
		COMMIT`)
	contentBefore := f.str(t, `SELECT string_agg(md5(row(cm.id, cm.predicate, cm.weight, cm.updated_at)::text), ',' ORDER BY cm.id) FROM control_measurements cm WHERE framework_type = 'platform'`)
	if got := f.str(t, `SELECT public.classify_seeded_measurements()::text`); got == "0" {
		t.Fatal("classify_seeded_measurements() marked nothing on a pre-marker install")
	}
	if got := f.str(t, `SELECT string_agg(md5(row(cm.id, cm.predicate, cm.weight, cm.updated_at)::text), ',' ORDER BY cm.id) FROM control_measurements cm WHERE framework_type = 'platform'`); got != contentBefore {
		t.Error("classify_seeded_measurements() changed rule content or updated_at")
	}
}
