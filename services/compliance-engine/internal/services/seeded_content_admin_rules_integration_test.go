package services

// Seeded content, second review of (decision 4, RC-12):
//
//   - seed.sql's one-time de-duplication of platform measurement rules used to
//     keep ONE rule per (control, measurement type) and delete the rest, which
//     removed every rule a platform admin added with a type the control already
//     used — under a shipped control and under the admin's own — on every
//     upgrade, and moved or cascaded the tenant overrides on them;
//   - a seed correction that meets an untouched pre-marker rule before
//     classify_seeded_measurements() has placed it must apply the fix, not
//     turn it into an offer;
//   - deleting a row an admin created is not deleting shipped content, and
//     must leave no tombstone.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const (
	// The pre- weak-cipher pattern seed.sql's CMP-3 correction repairs.
	oldWeakCipherPredicate = `{"flags": "i", "pattern": "^(3DES|DES|RC4|RC4-.*)$", "match_means_violation": true}`
	newWeakCipherPattern   = `^(3DES|DES|RC4)(-[A-Z0-9]+)*$`
)

// ruleWhere selects one platform rule by its control's code and a predicate
// fragment, for ownershipOf and friends.
func ruleWhere(control, predicateFragment string) string {
	return `SELECT cm.* FROM control_measurements cm
		JOIN platform_framework_controls c ON c.id = cm.control_id
		WHERE c.control_id = '` + control + `' AND cm.framework_type = 'platform'
		  AND cm.predicate::text LIKE '%` + predicateFragment + `%'`
}

// insertOverride writes a tenant override on a rule directly. FKs are off for
// the insert (replica role): the tenant and author are not what is under test,
// only which rule the override points at after a re-seed.
func (f *seededFixture) insertOverride(t *testing.T, ruleQuery string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	tx, err := f.raw.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	res, err := tx.Exec(`INSERT INTO tenant_measurement_overrides (id, tenant_id, control_measurement_id, predicate_override, rationale, created_by)
		SELECT $1, gen_random_uuid(), r.id, '{"exists": true}', 'it', gen_random_uuid() FROM (`+ruleQuery+`) r`, id)
	if err != nil {
		t.Fatalf("insert override: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("override target matched %d rules, want 1", n)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return id
}

// The review's reproduction. An admin adds a second tls_version rule under the
// shipped BP-001 (before the marker existed, and after), and a control of
// their own with two key_size rules. Re-seeding — twice, as two upgrades —
// must keep all of them, and leave a tenant override on the admin's rule where
// it is. Polarity: an EXACT copy of a shipped rule, which is what the old bare
// re-seed INSERTs left behind and what the de-duplication exists for, is still
// collapsed onto the shipped rule, with its override moved across.
func TestIntegration_SeededContent_ReseedKeepsAdminRulesOfAShippedType(t *testing.T) {
	f := newSeededFixture(t)
	f.asPreMarkerInstall(t,
		// A re-seed copy of BP-001's shipped rule, as a pre-dedup release left it.
		`INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
		 SELECT control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, clock_timestamp(), clock_timestamp()
		   FROM control_measurements cm WHERE cm.control_id = (SELECT id FROM platform_framework_controls WHERE control_id = 'BP-001')`,
		// The admin's own tls_version rule under BP-001, before the marker.
		`INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate, weight, created_at, updated_at)
		 SELECT c.id, 'platform', mt.id, 'pattern', '{"pattern": "^PRE-MARKER.*$", "match_means_violation": true}', 4, clock_timestamp(), clock_timestamp()
		   FROM platform_framework_controls c, measurement_types mt WHERE c.control_id = 'BP-001' AND mt.code = 'tls_version'`,
	)
	// The first upgrade onto the marker has run; now the console, after it.
	testdb.ForceApplySeed(t, f.raw)
	f.exec(t, `INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate, weight)
		SELECT c.id, 'platform', mt.id, 'pattern', '{"pattern": "^ADMIN-SSL.*$", "match_means_violation": true}', 1
		  FROM platform_framework_controls c, measurement_types mt WHERE c.control_id = 'BP-001' AND mt.code = 'tls_version'`)
	f.exec(t, `INSERT INTO platform_framework_controls (framework_id, control_id, title, baseline_severity)
		SELECT id, 'ADM-1', 'Our key size policy', 'medium' FROM platform_frameworks WHERE code = 'best-practices'`)
	f.exec(t, `INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate, weight)
		SELECT c.id, 'platform', mt.id, 'threshold', v::jsonb, 1
		  FROM platform_framework_controls c, measurement_types mt,
		       (VALUES ('{"operator": ">=", "value": 2048}'), ('{"operator": "<=", "value": 8192}')) AS x(v)
		 WHERE c.control_id = 'ADM-1' AND mt.code = 'key_size'`)

	// The admin also enters a rule identical to BP-001's shipped one. Byte for
	// byte a copy of it, but the admin's row: not a re-seed leftover to
	// collapse, and a tenant override on it stays on it.
	f.exec(t, `INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight)
		SELECT control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight
		  FROM control_measurements WHERE content_origin = 'seed'
		   AND control_id = (SELECT id FROM platform_framework_controls WHERE control_id = 'BP-001')`)
	adminCopy := `SELECT * FROM control_measurements WHERE content_origin = 'admin'
		AND control_id = (SELECT id FROM platform_framework_controls WHERE control_id = 'BP-001')
		AND predicate::text LIKE '%Unknown-0x0300%'`
	onAdminCopy := f.insertOverride(t, adminCopy)

	onAdminRule := f.insertOverride(t, ruleWhere("BP-001", "ADMIN-SSL"))
	onPreMarkerRule := f.insertOverride(t, ruleWhere("BP-001", "PRE-MARKER"))

	// A second re-seed copy of the shipped rule, with an override on it (the
	// polarity half). Written with triggers off, as a pre-marker release would
	// have; content_origin stays NULL.
	tx, err := f.raw.Begin()
	if err != nil {
		t.Fatal(err)
	}
	copyID := uuid.New()
	for _, q := range []string{
		`SET LOCAL session_replication_role = replica`,
		`INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
		 SELECT '` + copyID.String() + `', control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, clock_timestamp(), clock_timestamp()
		   FROM control_measurements WHERE content_origin = 'seed'
		    AND control_id = (SELECT id FROM platform_framework_controls WHERE control_id = 'BP-001')`,
	} {
		if _, err := tx.Exec(q); err != nil {
			_ = tx.Rollback()
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	onCopy := f.insertOverride(t, `SELECT * FROM control_measurements WHERE id = '`+copyID.String()+`'`)
	shippedID := f.str(t, `SELECT r.id::text FROM (`+ruleWhere("BP-001", "Unknown-0x0300")+`) r WHERE r.content_origin = 'seed'`)

	testdb.ForceApplySeed(t, f.raw)
	testdb.ForceApplySeed(t, f.raw)

	// Every rule the admin wrote is still there.
	for _, c := range []struct {
		what, q string
		want    int
	}{
		{"the admin's pre-marker rule under BP-001", ruleWhere("BP-001", "PRE-MARKER"), 1},
		{"the admin's rule under BP-001", ruleWhere("BP-001", "ADMIN-SSL"), 1},
		{"the admin's rules under their own ADM-1", ruleOf("ADM-1"), 2},
		{"the admin's copy of BP-001's shipped rule", adminCopy, 1},
		// ...and of the shipped rule and its re-seed copies, exactly one survives.
		{"BP-001's shipped rule and its re-seed copies", ruleWhere("BP-001", "Unknown-0x0300") + ` AND cm.content_origin IS DISTINCT FROM 'admin'`, 1},
	} {
		if got := f.count(t, `SELECT count(*) FROM (`+c.q+`) r`); got != c.want {
			t.Errorf("after re-seeding: %s: %d rows, want %d", c.what, got, c.want)
		}
	}
	if got := f.ownershipOf(t, ruleWhere("BP-001", "ADMIN-SSL")); got != (ownership{"admin", false, ""}) {
		t.Errorf("the admin's rule under BP-001 after re-seed = %+v, want admin-owned and untouched", got)
	}
	if got := f.ownershipOf(t, ruleWhere("BP-001", "PRE-MARKER")); got.origin == "seed" {
		t.Errorf("the admin's pre-marker rule was claimed as shipped content: %+v", got)
	}

	// The overrides on the admin's rules stay on them; the one on the copy
	// moved to the shipped rule it duplicated.
	pointsAt := func(override uuid.UUID) string {
		return f.str(t, `SELECT control_measurement_id::text FROM tenant_measurement_overrides WHERE id = $1`, override)
	}
	if got, want := pointsAt(onAdminRule), f.str(t, `SELECT r.id::text FROM (`+ruleWhere("BP-001", "ADMIN-SSL")+`) r`); got != want {
		t.Errorf("the tenant override on the admin's rule now points at %q, want %q (its own rule)", got, want)
	}
	if got, want := pointsAt(onPreMarkerRule), f.str(t, `SELECT r.id::text FROM (`+ruleWhere("BP-001", "PRE-MARKER")+`) r`); got != want {
		t.Errorf("the tenant override on the admin's pre-marker rule now points at %q, want %q", got, want)
	}
	if got, want := pointsAt(onAdminCopy), f.str(t, `SELECT r.id::text FROM (`+adminCopy+`) r`); got != want {
		t.Errorf("the tenant override on the admin's copy of the shipped rule now points at %q, want %q", got, want)
	}
	if got := pointsAt(onCopy); got != shippedID {
		t.Errorf("the override on a re-seed copy points at %q, want the surviving shipped rule %q", got, shippedID)
	}
}

// A seed correction meeting an UNTOUCHED shipped rule that predates the marker
// applies the fix — the rule's created_at equals its control's and it was never
// updated, so it is Vista's content, not an admin's. The same broken value on a
// rule that WAS updated since cannot be told from an admin's edit, so that one
// is kept and the fix offered. seed.sql runs its corrections before
// classify_seeded_measurements(), which is why the guard classifies inline.
func TestIntegration_SeededContent_FirstUpgradeCorrectionReachesUntouchedRule(t *testing.T) {
	f := newSeededFixture(t)
	f.asPreMarkerInstall(t,
		// Untouched: the old pattern, updated_at still equal to created_at.
		`UPDATE control_measurements cm SET predicate = '`+oldWeakCipherPredicate+`'
		   FROM platform_framework_controls c WHERE c.id = cm.control_id AND c.control_id = 'BP-003' AND cm.framework_type = 'platform'`,
		// Updated since: the same old pattern, but updated_at moved.
		`UPDATE control_measurements cm SET predicate = '`+oldWeakCipherPredicate+`', updated_at = clock_timestamp()
		   FROM platform_framework_controls c WHERE c.id = cm.control_id AND c.control_id = 'BP-010' AND cm.framework_type = 'platform'`,
	)

	for pass := 1; pass <= 2; pass++ {
		testdb.ForceApplySeed(t, f.raw)

		if got := f.str(t, `SELECT r.predicate ->> 'pattern' FROM (`+ruleOf("BP-003")+`) r`); got != newWeakCipherPattern {
			t.Errorf("pass %d: untouched BP-003 rule pattern = %q, want the corrected %q", pass, got, newWeakCipherPattern)
		}
		if got := f.ownershipOf(t, ruleOf("BP-003")); got != (ownership{"seed", false, ""}) {
			t.Errorf("pass %d: untouched BP-003 rule ownership = %+v, want pristine shipped content with nothing offered", pass, got)
		}
		if got := f.str(t, `SELECT r.predicate ->> 'pattern' FROM (`+ruleOf("BP-010")+`) r`); got != "^(3DES|DES|RC4|RC4-.*)$" {
			t.Errorf("pass %d: updated BP-010 rule pattern = %q; a rule that may carry an admin's edit must be kept", pass, got)
		}
		if got := f.ownershipOf(t, ruleOf("BP-010")); got.origin != "seed" || !got.modified || got.offer == "" {
			t.Errorf("pass %d: updated BP-010 rule ownership = %+v, want kept as the admin's with the correction offered", pass, got)
		}
	}
}

// Deleting a row a platform admin CREATED removes the admin's own content; it
// is not a shipped row to keep out, and must write no tombstone — on any of the
// four tables. Polarity: deleting a shipped row does write one.
func TestIntegration_SeededContent_DeletingAdminCreatedRowsLeavesNoTombstone(t *testing.T) {
	f := newSeededFixture(t)
	f.exec(t, `INSERT INTO platform_frameworks (code, name, version, created_by)
		SELECT 'it-admin-fw', 'Admin framework', '1.0', id FROM platform_users ORDER BY created_at LIMIT 1`)
	f.exec(t, `INSERT INTO platform_framework_controls (framework_id, control_id, title, baseline_severity)
		SELECT id, 'ADM-DEL', 'Admin control', 'low' FROM platform_frameworks WHERE code = 'best-practices'`)
	f.exec(t, `INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate, weight)
		SELECT c.id, 'platform', mt.id, 'pattern', '{"pattern": "^ADMIN-DEL$", "match_means_violation": true}', 1
		  FROM platform_framework_controls c, measurement_types mt WHERE c.control_id = 'BP-001' AND mt.code = 'tls_version'`)
	f.exec(t, `INSERT INTO classification_rules (rule_kind, pattern, vendor, confidence) VALUES ('oui', 'ADDE11', 'Ours', 0.5)`)

	for _, q := range []string{
		`DELETE FROM control_measurements WHERE predicate ->> 'pattern' = '^ADMIN-DEL$'`,
		`DELETE FROM platform_framework_controls WHERE control_id = 'ADM-DEL'`,
		`DELETE FROM platform_frameworks WHERE code = 'it-admin-fw'`,
		`DELETE FROM classification_rules WHERE rule_kind = 'oui' AND pattern = 'ADDE11'`,
	} {
		if n := f.exec(t, q); n != 1 {
			t.Fatalf("%s: %d rows, want 1", q, n)
		}
	}
	if got := f.count(t, `SELECT count(*) FROM seeded_content_tombstones`); got != 0 {
		t.Errorf("deleting four admin-created rows wrote %d tombstones, want 0", got)
	}

	f.exec(t, `DELETE FROM classification_rules WHERE rule_kind = 'oui' AND pattern = '000001'`)
	if got := f.count(t, `SELECT count(*) FROM seeded_content_tombstones WHERE entity = 'classification_rule' AND natural_key = '["oui", "000001"]'`); got != 1 {
		t.Errorf("deleting a shipped classification rule wrote %d tombstones, want 1", got)
	}
}
