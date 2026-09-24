package services

// The upgrade-path test's seeded-content leg (decision 4, RC-12).
//
// A release before the seeded-content marker let an upgrade overwrite a
// platform admin's edits to shipped frameworks and controls. The FIRST upgrade
// onto the marker is the one that matters most: every row is unmarked, and the
// guard has to decide, once and for good, which rows are untouched Vista
// content (and so follow later releases) and which are the admin's (kept, later
// changes offered). These helpers make admin edits on the prior release's
// database and assert the upgrade — current schema.sql, then the current
// seed.sql, exactly as the chart runs them — kept them AND classified them as
// the admin's.
//
// The edits deliberately include columns the seed's ON CONFLICT SET lists do
// NOT write (a framework's name, a control's crypto_relevant) and a measurement
// rule the admin added under a shipped control, which the seed never upserts.
// Those were the rows the first cut of the guard stamped as pristine Vista
// content, because the UPDATE arm alone could not see the difference.

import (
	"database/sql"
	"testing"
)

func editSeededContentBeforeUpgrade(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, q := range []string{
		`UPDATE platform_frameworks SET status = 'archived' WHERE code = 'lifecycle'`,
		`UPDATE platform_frameworks SET name = 'Upgrade-path admin name' WHERE code = 'best-practices'`,
		`UPDATE platform_framework_controls SET title = 'Upgrade-path admin title' WHERE control_id = 'BP-001'`,
		`UPDATE platform_framework_controls SET crypto_relevant = NOT crypto_relevant WHERE control_id = 'BP-002'`,
		`INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight)
		 SELECT c.id, 'platform', mt.id, 'threshold', '{"operator": ">=", "value": 3072}', 'high', 7
		   FROM platform_framework_controls c, measurement_types mt WHERE c.control_id = 'BP-003' AND mt.code = 'key_size'`,
		// A second rule of a measurement type the shipped control already
		// uses, and a control of the admin's own with two rules of one type.
		// seed.sql's one-time de-duplication used to keep one rule per
		// (control, type) and delete these on every upgrade.
		`INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate, weight)
		 SELECT c.id, 'platform', mt.id, 'pattern', '{"pattern": "^UPGRADE-ADMIN.*$", "match_means_violation": true}', 3
		   FROM platform_framework_controls c, measurement_types mt WHERE c.control_id = 'BP-001' AND mt.code = 'tls_version'`,
		`INSERT INTO platform_framework_controls (framework_id, control_id, title, baseline_severity)
		 SELECT id, 'UPGRADE-ADM-1', 'Upgrade-path admin control', 'medium' FROM platform_frameworks WHERE code = 'best-practices'`,
		`INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate, weight)
		 SELECT c.id, 'platform', mt.id, 'threshold', '{"operator": ">=", "value": 2048}', 1
		   FROM platform_framework_controls c, measurement_types mt WHERE c.control_id = 'UPGRADE-ADM-1' AND mt.code = 'key_size'`,
		`INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate, weight)
		 SELECT c.id, 'platform', mt.id, 'threshold', '{"operator": "<=", "value": 8192}', 1
		   FROM platform_framework_controls c, measurement_types mt WHERE c.control_id = 'UPGRADE-ADM-1' AND mt.code = 'key_size'`,
	} {
		res, err := db.Exec(q)
		if err != nil {
			t.Fatalf("admin edit on the prior release: %v", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("admin edit on the prior release matched %d rows, want 1: %s", n, q)
		}
	}
}

func assertSeededContentEditsSurvived(t *testing.T, db *sql.DB, tag string) {
	t.Helper()
	var status string
	if err := db.QueryRow(`SELECT status FROM platform_frameworks WHERE code = 'lifecycle'`).Scan(&status); err != nil {
		t.Fatalf("read lifecycle after upgrading from %s: %v", tag, err)
	}
	if status != "archived" {
		t.Errorf("upgrading from %s republished the framework an admin archived (status %q)", tag, status)
	}

	// Each edited row keeps the admin's value and is marked as shipped content
	// the admin modified — never as pristine, which would let a later release
	// overwrite it.
	for _, c := range []struct {
		what, q, want string
	}{
		{"best-practices name", `SELECT name, coalesce(content_origin, ''), admin_modified_at IS NOT NULL FROM platform_frameworks WHERE code = 'best-practices'`, "Upgrade-path admin name"},
		{"BP-001 title", `SELECT title, coalesce(content_origin, ''), admin_modified_at IS NOT NULL FROM platform_framework_controls WHERE control_id = 'BP-001'`, "Upgrade-path admin title"},
		{"BP-002 (crypto_relevant flipped)", `SELECT title, coalesce(content_origin, ''), admin_modified_at IS NOT NULL FROM platform_framework_controls WHERE control_id = 'BP-002'`, ""},
	} {
		var value, origin string
		var modified bool
		if err := db.QueryRow(c.q).Scan(&value, &origin, &modified); err != nil {
			t.Fatalf("read %s after upgrading from %s: %v", c.what, tag, err)
		}
		if (c.want != "" && value != c.want) || origin != "seed" || !modified {
			t.Errorf("%s after upgrading from %s: value=%q origin=%q admin_modified=%t; want the admin's value, marked as shipped content the admin modified",
				c.what, tag, value, origin, modified)
		}
	}

	// The rule the admin added under a shipped control is not Vista's.
	var ruleOrigin string
	if err := db.QueryRow(`SELECT coalesce(cm.content_origin, '') FROM control_measurements cm
		JOIN platform_framework_controls c ON c.id = cm.control_id
		JOIN measurement_types mt ON mt.id = cm.measurement_type_id
		WHERE c.control_id = 'BP-003' AND mt.code = 'key_size' AND cm.weight = 7`).Scan(&ruleOrigin); err != nil {
		t.Fatalf("read the admin's rule after upgrading from %s: %v", tag, err)
	}
	if ruleOrigin == "seed" {
		t.Errorf("upgrading from %s claimed the admin's own measurement rule as shipped Vista content", tag)
	}

	// Rules of a type the control already uses survive: the admin's second
	// tls_version rule under BP-001, and both key_size rules of their own control.
	for _, c := range []struct {
		what, q string
		want    int
	}{
		{"the admin's second tls_version rule under BP-001", `SELECT count(*) FROM control_measurements cm
			JOIN platform_framework_controls c ON c.id = cm.control_id
			WHERE c.control_id = 'BP-001' AND cm.predicate ->> 'pattern' = '^UPGRADE-ADMIN.*$'`, 1},
		{"the admin's two key_size rules under UPGRADE-ADM-1", `SELECT count(*) FROM control_measurements cm
			JOIN platform_framework_controls c ON c.id = cm.control_id
			WHERE c.control_id = 'UPGRADE-ADM-1'`, 2},
	} {
		var n int
		if err := db.QueryRow(c.q).Scan(&n); err != nil {
			t.Fatalf("count %s after upgrading from %s: %v", c.what, tag, err)
		}
		if n != c.want {
			t.Errorf("upgrading from %s left %d of %s, want %d (the upgrade deleted the admin's rules)", tag, n, c.what, c.want)
		}
	}

	var unmarked int
	if err := db.QueryRow(`SELECT count(*) FROM platform_frameworks WHERE content_origin IS NULL`).Scan(&unmarked); err != nil {
		t.Fatal(err)
	}
	if unmarked != 0 {
		t.Errorf("%d shipped frameworks are still unmarked after upgrading from %s", unmarked, tag)
	}
}
