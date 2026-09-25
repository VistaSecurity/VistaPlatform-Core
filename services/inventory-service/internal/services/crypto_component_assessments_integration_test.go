package services

// Proof that the risk explanation the drawer shows is the SAME assessment the
// score was computed from, read live from the catalogue.
//
// catalogue_risk_integration_test.go proves the SCORE follows the catalogue.
// This file proves the EXPLANATION does too — which is the whole reason it is
// recomputed on read instead of stored: a stored copy would keep citing a
// catalogue row that has since been corrected, and the stale copy is the one on
// the screen.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// componentsOf runs the production read path against the fixture's tenant.
func (f catRiskFixture) componentsOf(t *testing.T, implID uuid.UUID) []models.CryptoComponentAssessment {
	t.Helper()
	svc := NewCryptoImplementationService(f.db)
	got, err := svc.GetCryptoImplementationComponents(f.tenant, implID)
	if err != nil {
		t.Fatalf("GetCryptoImplementationComponents: %v", err)
	}
	return got
}

// linkInferred links one algorithm under a role with an explicit is_inferred
// value, so the observed/offered split can be exercised end to end.
func (f catRiskFixture) linkInferred(t *testing.T, implID uuid.UUID, role, code string, inferred bool) {
	t.Helper()
	var algID uuid.UUID
	if err := f.db.QueryRow(`SELECT id FROM algorithms WHERE code = $1`, code).Scan(&algID); err != nil {
		t.Fatalf("catalogue lookup %q: %v", code, err)
	}
	if _, err := f.db.Exec(`
		INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type, is_inferred)
		VALUES ($1,$2,$3,$4)`, implID, algID, role, inferred); err != nil {
		t.Fatalf("link %s=%s: %v", role, code, err)
	}
}

// The explanation must be ordered worst-first and mark exactly one score-setter
// — the component the drawer names as the cause of the score. RC4 is catalogue
// risk 90, SHA256 is low.
func TestIntegration_CryptoComponents_WorstFirstAndSetsScore(t *testing.T) {
	f := newCatRiskFixture(t)
	impl := f.implWith(t, map[string]string{"symmetric": "RC4", "hash": "SHA256"})

	got := f.componentsOf(t, impl)
	if len(got) != 2 {
		t.Fatalf("got %d components, want 2", len(got))
	}
	if got[0].Code != "RC4" {
		t.Errorf("first component = %q, want RC4 (worst first)", got[0].Code)
	}
	if !got[0].SetsScore {
		t.Error("the worst component must be marked sets_score")
	}
	if got[1].SetsScore {
		t.Error("only ONE component may be marked sets_score")
	}
	// Banding is server-side and must match the canonical ladder exactly.
	if got[0].RiskScore == nil || got[0].RiskLevel == nil {
		t.Fatalf("worst component lost numeric assessment: %+v", got[0])
	}
	if want := models.GetRiskLevel(*got[0].RiskScore); *got[0].RiskLevel != want {
		t.Errorf("risk_level = %q, want %q (models.RiskBands)", *got[0].RiskLevel, want)
	}
	// And it must agree with the score the ingest path computes, or the drawer
	// would be explaining a different number than it displays.
	score, _, ok := f.score(t, impl)
	if !ok || score != *got[0].RiskScore {
		t.Errorf("worst component risk %d != ingest score %d (ok=%v) — explanation and score disagree",
			*got[0].RiskScore, score, ok)
	}
}

// Each component carries its catalogue row's curated remediation guidance —
// the "How to fix" the drawer shows — and a row that records none carries
// none. Compared against the row itself rather than a hardcoded string, so a
// seed edit to RC4's advice does not break the test while a read path that
// dropped or invented guidance does.
func TestIntegration_CryptoComponents_CarryCatalogueRemediationGuidance(t *testing.T) {
	f := newCatRiskFixture(t)
	impl := f.implWith(t, map[string]string{"symmetric": "RC4", "hash": "SHA256"})

	catalogue := func(code string) *models.ComponentRemediationGuidance {
		t.Helper()
		var raw []byte
		if err := f.db.QueryRow(`SELECT remediation_guidance FROM algorithms WHERE code = $1`, code).Scan(&raw); err != nil {
			t.Fatalf("catalogue %s: %v", code, err)
		}
		return models.ParseComponentRemediationGuidance(raw)
	}
	wantRC4 := catalogue("RC4")
	if wantRC4 == nil || len(wantRC4.Steps) == 0 {
		t.Fatalf("fixture: the seeded RC4 row records no remediation steps — the case would prove nothing: %+v", wantRC4)
	}
	if catalogue("SHA256") != nil {
		t.Fatal("fixture: SHA256 now records remediation guidance — pick a row that does not")
	}

	byCode := map[string]models.CryptoComponentAssessment{}
	for _, c := range f.componentsOf(t, impl) {
		byCode[c.Code] = c
	}
	if !reflect.DeepEqual(byCode["RC4"].RemediationGuidance, wantRC4) {
		t.Errorf("RC4 guidance = %+v, want the catalogue row's %+v", byCode["RC4"].RemediationGuidance, wantRC4)
	}
	if g := byCode["SHA256"].RemediationGuidance; g != nil {
		t.Errorf("SHA256 records no guidance but the read invented %+v", g)
	}
}

// The observed/offered distinction must survive the read. It is the difference
// between "this server negotiated 3DES" and "this server would accept 3DES if
// asked", and it exists nowhere else in the response.
func TestIntegration_CryptoComponents_InferredRoundTrips(t *testing.T) {
	f := newCatRiskFixture(t)
	impl := f.implWith(t, nil)
	f.linkInferred(t, impl, "symmetric", "RC4", true)
	f.linkInferred(t, impl, "hash", "SHA256", false)

	byCode := map[string]models.CryptoComponentAssessment{}
	for _, c := range f.componentsOf(t, impl) {
		byCode[c.Code] = c
	}
	if !byCode["RC4"].IsInferred {
		t.Error("RC4 was linked as inferred (offered only) and came back as observed")
	}
	if byCode["SHA256"].IsInferred {
		t.Error("SHA256 was linked as observed and came back as inferred")
	}
}

// Nothing linked means NOT ASSESSED. The read must return an EMPTY, non-nil
// slice — never nil, which serializes to `null` and invites a consumer to skip
// the not-assessed branch entirely.
func TestIntegration_CryptoComponents_UnlinkedIsEmptyNotNull(t *testing.T) {
	f := newCatRiskFixture(t)
	impl := f.implWith(t, nil)

	got := f.componentsOf(t, impl)
	if got == nil {
		t.Fatal("components must be an empty slice, never nil")
	}
	if len(got) != 0 {
		t.Fatalf("got %d components for an unlinked implementation, want 0", len(got))
	}
}

// Editing the catalogue must move the explanation — the recompute property that
// justifies not storing a risk_factors column.
//
// NOTE ON ISOLATION: `algorithms` is global reference data, not tenant-scoped,
// so testdb.NewTenant's CASCADE cleanup does not undo an edit to it — a sibling
// test in this package (TestIntegration_CatalogueRisk_ScoreFollowsTheCatalogue)
// edits AES256 and leaves it edited, which made an assertion against a
// hardcoded baseline here fail purely on test ORDER. This test therefore
// asserts MOVEMENT from whatever the row currently says, and restores the row
// afterwards rather than inflicting the same surprise on the next test.
func TestIntegration_CryptoComponents_FollowTheCatalogue(t *testing.T) {
	f := newCatRiskFixture(t)
	impl := f.implWith(t, map[string]string{"symmetric": "AES256"})

	before := f.componentsOf(t, impl)
	if len(before) != 1 {
		t.Fatalf("baseline = %+v, want a single AES256 component", before)
	}
	if before[0].RiskScore == nil || before[0].RiskLevel == nil {
		t.Fatalf("baseline lost numeric assessment: %+v", before[0])
	}
	if want := models.GetRiskLevel(*before[0].RiskScore); *before[0].RiskLevel != want {
		t.Fatalf("baseline band = %q, want %q for score %d", *before[0].RiskLevel, want, *before[0].RiskScore)
	}
	// Move to a score in a DIFFERENT band from wherever the row currently sits,
	// so the assertion proves movement rather than coincidence — and so the test
	// passes regardless of what an earlier test left behind.
	target, targetBand := 88, "High"
	if *before[0].RiskScore >= 70 {
		target, targetBand = 15, "Low"
	}

	baseline := before[0]
	var baselineGuidance []byte
	if err := f.db.QueryRow(`SELECT remediation_guidance FROM algorithms WHERE code = 'AES256'`).Scan(&baselineGuidance); err != nil {
		t.Fatalf("read baseline remediation_guidance: %v", err)
	}
	t.Cleanup(func() {
		if _, err := f.db.Exec(
			`UPDATE algorithms SET risk_score = $1, strength = $2, deprecation_status = $3, remediation_guidance = $4 WHERE code = 'AES256'`,
			*baseline.RiskScore, baseline.Strength, baseline.DeprecationStatus, baselineGuidance,
		); err != nil {
			t.Errorf("restore catalogue row: %v", err)
		}
	})

	// A reviewer re-assesses AES256 and records guidance.
	if _, err := f.db.Exec(`
		UPDATE algorithms
		   SET risk_score = $1, strength = 'weak', deprecation_status = 'deprecated',
		       migration_guidance = 'Move to AES-256-GCM with a rotated key.',
		       recommended_alternatives = ARRAY['AES256-GCM'],
		       remediation_guidance = '{"summary":"Re-key onto AES-256-GCM.","steps":["Rotate the key"]}'::jsonb
		 WHERE code = 'AES256'`, target); err != nil {
		t.Fatalf("update catalogue: %v", err)
	}

	after := f.componentsOf(t, impl)
	if len(after) != 1 {
		t.Fatalf("got %d components, want 1", len(after))
	}
	if after[0].RiskScore == nil || after[0].RiskLevel == nil || *after[0].RiskScore != target || *after[0].RiskLevel != targetBand {
		t.Errorf("after re-assessment: score=%v level=%v, want %d/%s — the explanation is not reading the catalogue",
			after[0].RiskScore, after[0].RiskLevel, target, targetBand)
	}
	if after[0].Strength != "weak" || after[0].DeprecationStatus != "deprecated" {
		t.Errorf("strength/deprecation = %q/%q, want weak/deprecated", after[0].Strength, after[0].DeprecationStatus)
	}
	if after[0].MigrationGuidance == nil || *after[0].MigrationGuidance == "" {
		t.Error("migration guidance from the catalogue did not reach the response")
	}
	if len(after[0].RecommendedAlternatives) != 1 {
		t.Errorf("recommended_alternatives = %v, want the catalogue's single entry", after[0].RecommendedAlternatives)
	}
	if g := after[0].RemediationGuidance; g == nil || g.Summary != "Re-key onto AES-256-GCM." || !reflect.DeepEqual(g.Steps, []string{"Rotate the key"}) {
		t.Errorf("remediation guidance = %+v, want the edited catalogue row's", g)
	}
}

func TestIntegration_CryptoComponents_NullAndExplicitZeroStayDistinct(t *testing.T) {
	f := newCatRiskFixture(t)
	impl := f.implWith(t, map[string]string{"symmetric": "AES256"})

	var original int
	var originalStrength string
	if err := f.db.QueryRow(`SELECT risk_score, strength FROM algorithms WHERE code = 'AES256'`).Scan(&original, &originalStrength); err != nil {
		t.Fatalf("read baseline AES256 score: %v", err)
	}
	t.Cleanup(func() {
		if _, err := f.db.Exec(`UPDATE algorithms SET risk_score = $1, strength = $2 WHERE code = 'AES256'`, original, originalStrength); err != nil {
			t.Errorf("restore AES256 score and strength: %v", err)
		}
	})

	assertRead := func(wantAssessed bool, wantScore *int) {
		t.Helper()
		rows, err := (&AssetService{db: f.db}).GetCryptoImplementations(f.tenant, f.asset)
		if err != nil || len(rows) != 1 {
			t.Fatalf("read asset configurations: rows=%+v err=%v", rows, err)
		}
		if rows[0].RiskScoreAssessed != wantAssessed {
			t.Fatalf("risk_score_assessed=%v want %v", rows[0].RiskScoreAssessed, wantAssessed)
		}
		if (rows[0].RiskScore == nil) != (wantScore == nil) || (wantScore != nil && *rows[0].RiskScore != *wantScore) {
			t.Fatalf("risk_score=%v want %v", rows[0].RiskScore, wantScore)
		}
	}
	assertInformationalFilter := func(want int) {
		t.Helper()
		rows, total, err := (&CryptoImplementationService{db: f.db}).GetCryptoImplementations(f.tenant, models.CryptoImplementationFilters{
			AssetID: &f.asset, RiskLevel: []string{"Informational"}, Page: 1, PageSize: 20,
		})
		if err != nil || total != want || len(rows) != want {
			t.Fatalf("Informational filter rows=%d total=%d err=%v, want %d", len(rows), total, err, want)
		}
	}

	if _, err := f.db.Exec(`UPDATE crypto_implementations SET risk_score = NULL WHERE id = $1`, impl); err != nil {
		t.Fatalf("set stored score null: %v", err)
	}
	assertRead(false, nil)
	assertInformationalFilter(0)

	if _, err := f.db.Exec(`UPDATE crypto_implementations SET risk_score = 0 WHERE id = $1`, impl); err != nil {
		t.Fatalf("store explicit zero: %v", err)
	}
	// The existing non-zero AES256 catalogue assessment cannot prove that a
	// legacy stored zero is deliberate; the two numbers contradict each other.
	assertRead(false, nil)
	assertInformationalFilter(0)

	if _, err := f.db.Exec(`UPDATE algorithms SET risk_score = 0 WHERE code = 'AES256'`); err != nil {
		t.Fatalf("set explicit zero: %v", err)
	}
	assertRead(true, producerIntPtrForService(0))
	assertInformationalFilter(1)

	if _, err := f.db.Exec(`UPDATE algorithms SET risk_score = NULL, strength = 'weak' WHERE code = 'AES256'`); err != nil {
		t.Fatalf("set qualitative-only judgment: %v", err)
	}
	assertRead(false, nil)
	assertInformationalFilter(0)
	components := f.componentsOf(t, impl)
	if len(components) != 1 || components[0].Strength != "weak" || components[0].RiskScore != nil || components[0].RiskLevel != nil || components[0].SetsScore {
		t.Fatalf("qualitative-only component fabricated a numeric assessment: %+v", components)
	}
}

func producerIntPtrForService(value int) *int { return &value }

// Tenant isolation: the junction carries no tenant_id, so the join through
// crypto_implementations is the ONLY thing keeping this read from being
// cross-tenant. Asking for another tenant's configuration must return nothing.
func TestIntegration_CryptoComponents_TenantIsolation(t *testing.T) {
	f := newCatRiskFixture(t)
	impl := f.implWith(t, map[string]string{"symmetric": "RC4"})

	// Sanity: the owning tenant does see it.
	if len(f.componentsOf(t, impl)) == 0 {
		t.Fatal("owning tenant sees no components — fixture is wrong")
	}

	raw := testdb.Connect(t)
	other := testdb.NewTenant(t, raw)
	svc := NewCryptoImplementationService(f.db)
	got, err := svc.GetCryptoImplementationComponents(other, impl)
	if err != nil {
		t.Fatalf("cross-tenant read errored (it should simply return nothing): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("tenant %s read %d components off tenant %s's configuration", other, len(got), f.tenant)
	}
}

// The read must not leak soft-deleted configurations.
func TestIntegration_CryptoComponents_SkipsDeleted(t *testing.T) {
	f := newCatRiskFixture(t)
	impl := f.implWith(t, map[string]string{"symmetric": "RC4"})

	if err := database.WithTenantTx(t.Context(), f.db, f.tenant, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`UPDATE crypto_implementations SET deleted_at = NOW() WHERE id = $1`, impl)
		return e
	}); err != nil {
		t.Fatalf("soft delete: %v", err)
	}

	if got := f.componentsOf(t, impl); len(got) != 0 {
		t.Fatalf("got %d components for a soft-deleted configuration, want 0", len(got))
	}
}
