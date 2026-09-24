package services

// Seeded content: admin edits win (decision 4, RC-12 — catalog-3, catalog-7)
// and the PQC recommendations are added once (catalog-9).
//
// seed.sql re-runs on every helm upgrade. These tests apply it again, and again,
// over a database a platform admin has changed, and assert the admin's changes
// are still there: an archived framework stays archived, an edited control or
// classification rule keeps its text, and a deleted control, measurement rule
// or classification rule stays deleted. Then they apply a "next release" seed
// that ships new content, and assert it arrives as an offer on the admin's row
// (and as a plain update on rows nobody touched), and that accepting the offer
// applies it.
//
// Every test runs on its OWN scratch database: the rows under test are global
// (one catalogue for every tenant), and archiving Best Practices' neighbours or
// leaving a tombstone on the shared database would change what every other
// test binary sees.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type seededFixture struct {
	raw *sql.DB
	db  *sqlx.DB
}

func newSeededFixture(t *testing.T) *seededFixture {
	t.Helper()
	raw := testdb.ScratchDatabase(t)
	return &seededFixture{raw: raw, db: sqlx.NewDb(raw, "postgres")}
}

func (f *seededFixture) exec(t *testing.T, q string, args ...interface{}) int64 {
	t.Helper()
	res, err := f.raw.Exec(q, args...)
	if err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
	n, _ := res.RowsAffected()
	return n
}

func (f *seededFixture) str(t *testing.T, q string, args ...interface{}) string {
	t.Helper()
	var s sql.NullString
	if err := f.raw.QueryRow(q, args...).Scan(&s); err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return s.String
}

func (f *seededFixture) count(t *testing.T, q string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := f.raw.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", q, err)
	}
	return n
}

// ids of a seeded control and its framework.
func (f *seededFixture) control(t *testing.T, framework, control string) (frameworkID, controlID uuid.UUID) {
	t.Helper()
	if err := f.raw.QueryRow(`
		SELECT f.id, c.id FROM platform_framework_controls c
		JOIN platform_frameworks f ON f.id = c.framework_id
		WHERE f.code = $1 AND c.control_id = $2`, framework, control).Scan(&frameworkID, &controlID); err != nil {
		t.Fatalf("seeded control %s/%s: %v", framework, control, err)
	}
	return frameworkID, controlID
}

// applySeedText applies a seed.sql body the way the harness does. Used for the
// "next release" variant, which is this release's seed with shipped content
// changed.
func (f *seededFixture) applySeedText(t *testing.T, body string) {
	t.Helper()
	if _, err := f.raw.Exec(body); err != nil {
		t.Fatalf("apply seed: %v", err)
	}
}

// nextReleaseSeed is seed.sql with three pieces of shipped content changed, as
// a later release would change them. Every replacement is asserted to have
// matched: a replace that matches nothing returns its input, and the test
// would then "prove" that an unchanged seed offers nothing.
func nextReleaseSeed(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(testdb.RepoRoot(t), "scripts", "database", "seed.sql"))
	if err != nil {
		t.Fatalf("read seed.sql: %v", err)
	}
	s := string(body)
	for _, r := range [][2]string{
		// Best Practices BP-001's title (the admin edits this one).
		{"'TLS Version Requirements',", "'TLS Version Requirements (v2)',"},
		// Cisco's OUI confidence (the admin edits this one).
		{"('oui', '00000C', 'network_device', 'Cisco Systems', NULL, 0.70,", "('oui', '00000C', 'network_device', 'Cisco Systems', NULL, 0.75,"},
		// Omron's OUI confidence (nobody touches this one).
		{"('oui', '00000A', 'ot_device', 'Omron', NULL, 0.70,", "('oui', '00000A', 'ot_device', 'Omron', NULL, 0.72,"},
	} {
		if strings.Count(s, r[0]) != 1 {
			t.Fatalf("next-release fixture: %q occurs %d times in seed.sql, want exactly 1 — the fixture no longer matches the seed", r[0], strings.Count(s, r[0]))
		}
		s = strings.Replace(s, r[0], r[1], 1)
	}
	return s
}

// The admin's changes, made the way the console makes them: plain writes on a
// session that is not a seed pass.
func (f *seededFixture) adminEdits(t *testing.T) {
	t.Helper()
	if n := f.exec(t, `UPDATE platform_frameworks SET status = 'archived' WHERE code = 'lifecycle'`); n != 1 {
		t.Fatalf("archive lifecycle: %d rows", n)
	}
	if n := f.exec(t, `UPDATE platform_framework_controls SET title = 'TLS 1.2+ only (our policy)' WHERE control_id = 'BP-001'`); n != 1 {
		t.Fatalf("edit BP-001: %d rows", n)
	}
	if n := f.exec(t, `DELETE FROM platform_framework_controls WHERE control_id = 'PQC-002'`); n != 1 {
		t.Fatalf("delete PQC-002: %d rows", n)
	}
	if n := f.exec(t, `DELETE FROM control_measurements cm USING platform_framework_controls c
		WHERE c.id = cm.control_id AND c.control_id = 'BP-002' AND cm.framework_type = 'platform'`); n < 1 {
		t.Fatalf("delete BP-002's rule: %d rows", n)
	}
	if n := f.exec(t, `UPDATE classification_rules SET confidence = 0.55 WHERE rule_kind = 'oui' AND pattern = '00000C'`); n != 1 {
		t.Fatalf("edit 00000C: %d rows", n)
	}
	if n := f.exec(t, `DELETE FROM classification_rules WHERE rule_kind = 'oui' AND pattern = '000001'`); n != 1 {
		t.Fatalf("delete 000001: %d rows", n)
	}
}

// Re-seeding — twice, as two upgrades would — leaves every admin change in
// place, and offers nothing: the seed shipped nothing new, and a row that
// differs from the seed only because the admin changed it has no "update".
func TestIntegration_SeededContent_ReseedKeepsAdminEditsAndDeletions(t *testing.T) {
	f := newSeededFixture(t)

	frameworksBefore := f.count(t, `SELECT count(*) FROM platform_frameworks`)
	controlsBefore := f.count(t, `SELECT count(*) FROM platform_framework_controls`)
	if got := f.count(t, `SELECT count(*) FROM platform_frameworks WHERE content_origin IS DISTINCT FROM 'seed'`); got != 0 {
		t.Fatalf("%d seeded frameworks are not marked content_origin='seed' after the seed", got)
	}

	f.adminEdits(t)
	testdb.ForceApplySeed(t, f.raw)
	testdb.ForceApplySeed(t, f.raw)

	if got := f.str(t, `SELECT status FROM platform_frameworks WHERE code = 'lifecycle'`); got != "archived" {
		t.Errorf("lifecycle status after re-seed = %q, want archived (the seed republished what the admin archived)", got)
	}
	if got := f.str(t, `SELECT title FROM platform_framework_controls WHERE control_id = 'BP-001'`); got != "TLS 1.2+ only (our policy)" {
		t.Errorf("BP-001 title after re-seed = %q, want the admin's", got)
	}
	if got := f.count(t, `SELECT count(*) FROM platform_framework_controls WHERE control_id = 'PQC-002'`); got != 0 {
		t.Errorf("deleted control PQC-002 is back after re-seed (%d rows)", got)
	}
	if got := f.count(t, `SELECT count(*) FROM control_measurements cm JOIN platform_framework_controls c ON c.id = cm.control_id
		WHERE c.control_id = 'BP-002' AND cm.framework_type = 'platform'`); got != 0 {
		t.Errorf("deleted measurement rule of BP-002 is back after re-seed (%d rows)", got)
	}
	if got := f.str(t, `SELECT confidence::text FROM classification_rules WHERE rule_kind = 'oui' AND pattern = '00000C'`); got != "0.55" {
		t.Errorf("00000C confidence after re-seed = %s, want the admin's 0.55", got)
	}
	if got := f.count(t, `SELECT count(*) FROM classification_rules WHERE rule_kind = 'oui' AND pattern = '000001'`); got != 0 {
		t.Errorf("deleted classification rule 000001 is back after re-seed")
	}

	// Nothing new shipped, so nothing is on offer — on any seeded table.
	for _, table := range []string{"platform_frameworks", "platform_framework_controls", "control_measurements", "classification_rules"} {
		if got := f.count(t, `SELECT count(*) FROM `+table+` WHERE seed_offer IS NOT NULL`); got != 0 {
			t.Errorf("%s: %d rows show an update after re-applying the SAME seed", table, got)
		}
	}
	// Only the rows the admin changed are the admin's.
	if got := f.count(t, `SELECT count(*) FROM platform_framework_controls WHERE admin_modified_at IS NOT NULL`); got != 1 {
		t.Errorf("%d controls marked admin-modified, want 1 (BP-001)", got)
	}
	if got := f.count(t, `SELECT count(*) FROM platform_frameworks`); got != frameworksBefore {
		t.Errorf("framework count %d → %d across re-seeds", frameworksBefore, got)
	}
	if got := f.count(t, `SELECT count(*) FROM platform_framework_controls`); got != controlsBefore-1 {
		t.Errorf("control count %d → %d across re-seeds, want exactly one fewer (the deleted one)", controlsBefore, got)
	}
}

// A later release ships new content. The row nobody touched takes it; the
// admin's row keeps the admin's value and shows the shipped one as an offer;
// re-applying the same release does not stack offers; accepting applies it.
func TestIntegration_SeededContent_NewShippedVersionIsOfferedAndAcceptApplies(t *testing.T) {
	f := newSeededFixture(t)
	f.adminEdits(t)
	next := nextReleaseSeed(t)
	f.applySeedText(t, next)
	f.applySeedText(t, next)

	fwID, bp001 := f.control(t, "best-practices", "BP-001")
	if got := f.str(t, `SELECT title FROM platform_framework_controls WHERE id = $1`, bp001); got != "TLS 1.2+ only (our policy)" {
		t.Fatalf("BP-001 title = %q: the next release overwrote the admin's edit", got)
	}
	if got := f.str(t, `SELECT seed_offer::text FROM platform_framework_controls WHERE id = $1`, bp001); got != `{"title": "TLS Version Requirements (v2)"}` {
		t.Errorf("BP-001 offer = %s, want exactly the new shipped title", got)
	}
	if got := f.str(t, `SELECT confidence::text FROM classification_rules WHERE rule_kind = 'oui' AND pattern = '00000A'`); got != "0.72" {
		t.Errorf("untouched rule 00000A confidence = %s, want the new shipped 0.72 (pristine rows follow the seed)", got)
	}
	if got := f.str(t, `SELECT seed_offer::text FROM classification_rules WHERE rule_kind = 'oui' AND pattern = '00000A'`); got != "" {
		t.Errorf("untouched rule 00000A has an offer %s; it should simply have been updated", got)
	}
	if got := f.str(t, `SELECT confidence::text || ' ' || seed_offer::text FROM classification_rules WHERE rule_kind = 'oui' AND pattern = '00000C'`); got != `0.55 {"confidence": 0.75}` {
		t.Errorf("edited rule 00000C = %s, want the admin's 0.55 with 0.75 on offer", got)
	}
	// Other offers: none. BP-001 and 00000C are the only admin rows the next
	// release changed.
	if got := f.count(t, `SELECT (SELECT count(*) FROM platform_framework_controls WHERE seed_offer IS NOT NULL)
		+ (SELECT count(*) FROM classification_rules WHERE seed_offer IS NOT NULL)
		+ (SELECT count(*) FROM platform_frameworks WHERE seed_offer IS NOT NULL)`); got != 2 {
		t.Errorf("%d offers, want 2", got)
	}

	svc := NewPlatformFrameworkService(f.db)

	// The catalogue read reports it.
	fw, err := svc.GetFramework(fwID)
	if err != nil {
		t.Fatalf("GetFramework: %v", err)
	}
	if fw.ContentOrigin != "vista" {
		t.Errorf("Best Practices content_origin = %q, want vista", fw.ContentOrigin)
	}
	var found bool
	for _, c := range fw.Controls {
		if c.ID != bp001 {
			continue
		}
		found = true
		if !c.AdminModified || !c.UpdateAvailable || c.OfferedUpdate["title"] != "TLS Version Requirements (v2)" {
			t.Errorf("BP-001 in the catalogue read: admin_modified=%t update_available=%t offered=%v", c.AdminModified, c.UpdateAvailable, c.OfferedUpdate)
		}
	}
	if !found {
		t.Fatal("BP-001 missing from GetFramework's controls")
	}

	// Scoped to its parent: the wrong framework finds nothing.
	if _, err := svc.AcceptSeededUpdate(SeededControl, bp001, uuid.New()); !errors.Is(err, ErrSeededContentNotFound) {
		t.Errorf("accept under the wrong framework: err = %v, want ErrSeededContentNotFound", err)
	}
	// A row with nothing on offer is a 409, not a silent no-op.
	_, bp003 := f.control(t, "best-practices", "BP-003")
	if _, err := svc.AcceptSeededUpdate(SeededControl, bp003, fwID); !errors.Is(err, ErrNoSeededUpdate) {
		t.Errorf("accept with nothing on offer: err = %v, want ErrNoSeededUpdate", err)
	}

	accepted, err := svc.AcceptSeededUpdate(SeededControl, bp001, fwID)
	if err != nil {
		t.Fatalf("AcceptSeededUpdate: %v", err)
	}
	if accepted.Before["title"] != "TLS 1.2+ only (our policy)" || accepted.After["title"] != "TLS Version Requirements (v2)" {
		t.Errorf("accept before/after = %v / %v", accepted.Before, accepted.After)
	}
	control, err := svc.GetPlatformControl(bp001)
	if err != nil {
		t.Fatalf("GetPlatformControl: %v", err)
	}
	if control.Title != "TLS Version Requirements (v2)" || control.UpdateAvailable || !control.AdminModified {
		t.Errorf("after accept: title=%q update_available=%t admin_modified=%t, want the shipped title, no offer, still the admin's",
			control.Title, control.UpdateAvailable, control.AdminModified)
	}
	if _, err := svc.AcceptSeededUpdate(SeededControl, bp001, fwID); !errors.Is(err, ErrNoSeededUpdate) {
		t.Errorf("second accept: err = %v, want ErrNoSeededUpdate", err)
	}
	// The accept's transaction-local mode did not leak into the pool.
	if got := f.str(t, `SELECT current_setting('vista.seed_apply', true)`); got == "accept" || got == "on" {
		t.Errorf("vista.seed_apply = %q on a pooled connection after accept", got)
	}

	// The same release again offers nothing new: the accepted value is what ships.
	f.applySeedText(t, next)
	if got := f.str(t, `SELECT seed_offer::text FROM platform_framework_controls WHERE id = $1`, bp001); got != "" {
		t.Errorf("re-seeding after accept re-offered %s", got)
	}

	// The classification rule's offer is accepted by the same database action
	// admin-service calls.
	var ruleID uuid.UUID
	if err := f.raw.QueryRow(`SELECT id FROM classification_rules WHERE rule_kind = 'oui' AND pattern = '00000C'`).Scan(&ruleID); err != nil {
		t.Fatal(err)
	}
	var ok bool
	if err := f.raw.QueryRow(`SELECT public.accept_seeded_content_update('classification_rule', $1)`, ruleID).Scan(&ok); err != nil || !ok {
		t.Fatalf("accept classification rule: ok=%t err=%v", ok, err)
	}
	if got := f.str(t, `SELECT confidence::text || ' ' || coalesce(seed_offer::text, 'none') FROM classification_rules WHERE id = $1`, ruleID); got != "0.75 none" {
		t.Errorf("classification rule after accept = %s, want 0.75 none", got)
	}
}

// A framework the admin created is "custom", and one the admin archived is
// held back without an offer: "Vista ships it published" is not an update.
func TestIntegration_SeededContent_OriginOfAdminCreatedAndArchivedFrameworks(t *testing.T) {
	f := newSeededFixture(t)
	svc := NewPlatformFrameworkService(f.db)

	var adminID uuid.UUID
	if err := f.raw.QueryRow(`SELECT id FROM platform_users ORDER BY created_at LIMIT 1`).Scan(&adminID); err != nil {
		t.Fatalf("seeded platform user: %v", err)
	}
	custom, err := svc.CreateFramework(&models.PlatformFrameworkInput{
		Code: "it-custom-" + uuid.NewString()[:8], Name: "Our own policy", Version: "1.0",
	}, adminID)
	if err != nil {
		t.Fatalf("CreateFramework: %v", err)
	}
	f.exec(t, `UPDATE platform_frameworks SET status = 'archived' WHERE code = 'cert-hygiene'`)
	testdb.ForceApplySeed(t, f.raw)

	all, err := svc.ListFrameworks("")
	if err != nil {
		t.Fatalf("ListFrameworks: %v", err)
	}
	seen := 0
	for _, fw := range all {
		switch fw.Code {
		case custom.Code:
			seen++
			if fw.ContentOrigin != "custom" || fw.AdminModified || fw.UpdateAvailable {
				t.Errorf("admin-created framework: origin=%q admin_modified=%t update_available=%t", fw.ContentOrigin, fw.AdminModified, fw.UpdateAvailable)
			}
		case "cert-hygiene":
			seen++
			if fw.Status != "archived" || fw.ContentOrigin != "vista" || !fw.AdminModified || fw.UpdateAvailable {
				t.Errorf("archived shipped framework: status=%q origin=%q admin_modified=%t update_available=%t",
					fw.Status, fw.ContentOrigin, fw.AdminModified, fw.UpdateAvailable)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("ListFrameworks returned %d of the 2 frameworks under test", seen)
	}
}

// The console writes on crypto_app. Its delete of a shipped control must be
// able to write the tombstone (the table must be covered by the grants), and
// its edit must be able to mark the row — or the protection exists only for
// the superuser the tests usually run as.
func TestIntegration_SeededContent_AppRoleEditsAreTracked(t *testing.T) {
	f := newSeededFixture(t)
	app := testdb.ConnectScratchAsAppRole(t, f.raw)

	if _, err := app.Exec(`UPDATE platform_framework_controls SET title = 'app role edit' WHERE control_id = 'BP-003'`); err != nil {
		t.Fatalf("edit as crypto_app: %v", err)
	}
	if _, err := app.Exec(`DELETE FROM platform_framework_controls WHERE control_id = 'BP-004'`); err != nil {
		t.Fatalf("delete as crypto_app: %v", err)
	}
	if _, err := app.Exec(`UPDATE platform_framework_controls SET content_origin = 'admin', admin_modified_at = NULL, seed_offer = '{"title":"x"}' WHERE control_id = 'BP-005'`); err != nil {
		t.Fatalf("forge ownership as crypto_app: %v", err)
	}
	if got := f.count(t, `SELECT count(*) FROM platform_framework_controls WHERE control_id = 'BP-003' AND admin_modified_at IS NOT NULL`); got != 1 {
		t.Errorf("crypto_app's edit did not mark BP-003 admin-modified")
	}
	if got := f.count(t, `SELECT count(*) FROM seeded_content_tombstones WHERE entity = 'control' AND natural_key = '["best-practices", "1.0", "BP-004"]'`); got != 1 {
		t.Errorf("crypto_app's delete wrote no tombstone for BP-004")
	}
	if got := f.str(t, `SELECT content_origin || ' ' || coalesce(seed_offer::text, 'none') FROM platform_framework_controls WHERE control_id = 'BP-005'`); got != "seed none" {
		t.Errorf("the application rewrote BP-005's ownership columns: %s", got)
	}
	testdb.ForceApplySeed(t, f.raw)
	if got := f.count(t, `SELECT count(*) FROM platform_framework_controls WHERE control_id = 'BP-004'`); got != 0 {
		t.Errorf("control deleted by crypto_app came back on re-seed")
	}
}

// catalog-9: the two PQC recommendation UPDATEs prepended their alternatives
// and appended their paragraph on EVERY run. Re-seeding must now leave one of
// each, repair a row an earlier release had already duplicated, and not put
// back what an admin removed.
func TestIntegration_Seed_PQCRecommendationsAreAddedOnce(t *testing.T) {
	f := newSeededFixture(t)
	const para = "PQC Migration: This algorithm is not quantum-resistant"
	occurrences := func(code string) (alts, paras int) {
		t.Helper()
		if err := f.raw.QueryRow(`
			SELECT (SELECT count(*) FROM unnest(recommended_alternatives) a WHERE a = 'ML-KEM-768'),
			       (length(coalesce(migration_guidance, '')) - length(replace(coalesce(migration_guidance, ''), $2, ''))) / length($2)
			  FROM algorithms WHERE code = $1`, code, para).Scan(&alts, &paras); err != nil {
			t.Fatalf("read %s: %v", code, err)
		}
		return alts, paras
	}

	testdb.ForceApplySeed(t, f.raw)
	testdb.ForceApplySeed(t, f.raw)
	if alts, paras := occurrences("RSA-2048"); alts != 1 || paras != 1 {
		t.Errorf("RSA-2048 after three seed passes: ML-KEM-768 ×%d, paragraph ×%d; want 1 and 1", alts, paras)
	}

	// An install that ran the old seed four times.
	f.exec(t, `UPDATE algorithms SET
		recommended_alternatives = ARRAY['ML-KEM-768','ML-KEM-1024','ML-KEM-768','ML-KEM-1024','ML-KEM-768','ML-KEM-1024'],
		migration_guidance = 'Base guidance.' || repeat(E'\n\nPQC Migration: This algorithm is not quantum-resistant. Consider migrating to ML-KEM (formerly CRYSTALS-Kyber) for key exchange or ML-DSA (formerly CRYSTALS-Dilithium) for signatures per NIST PQC standards.', 3)
		WHERE code = 'RSA-2048'`)
	testdb.ForceApplySeed(t, f.raw)
	if alts, paras := occurrences("RSA-2048"); alts != 1 || paras != 1 {
		t.Errorf("RSA-2048 after repair: ML-KEM-768 ×%d, paragraph ×%d; want 1 and 1", alts, paras)
	}
	if got := f.str(t, `SELECT array_to_string(recommended_alternatives, ',') FROM algorithms WHERE code = 'RSA-2048'`); got != "ML-KEM-768,ML-KEM-1024" {
		t.Errorf("RSA-2048 alternatives after repair = %s, want first-occurrence order ML-KEM-768,ML-KEM-1024", got)
	}
	if got := f.str(t, `SELECT left(migration_guidance, 14) FROM algorithms WHERE code = 'RSA-2048'`); got != "Base guidance." {
		t.Errorf("repair lost the text before the paragraph: %q", got)
	}

	// An admin removed the PQC paragraph from DHE's guidance and kept the
	// alternatives. Re-seeding must not put half of the advice back. (An admin
	// who removes BOTH halves is indistinguishable from a row the addition never
	// reached, and gets it again — the limit of guarding without a marker.)
	f.exec(t, `UPDATE algorithms SET migration_guidance = 'Admin text.' WHERE code = 'DHE'`)
	testdb.ForceApplySeed(t, f.raw)
	if got := f.str(t, `SELECT migration_guidance FROM algorithms WHERE code = 'DHE'`); got != "Admin text." {
		t.Errorf("re-seed rewrote DHE's admin-edited guidance: %q", got)
	}
}
