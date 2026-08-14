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
	if want := models.GetRiskLevel(got[0].RiskScore); got[0].RiskLevel != want {
		t.Errorf("risk_level = %q, want %q (models.RiskBands)", got[0].RiskLevel, want)
	}
	// And it must agree with the score the ingest path computes, or the drawer
	// would be explaining a different number than it displays.
	score, _, ok := f.score(t, impl)
	if !ok || score != got[0].RiskScore {
		t.Errorf("worst component risk %d != ingest score %d (ok=%v) — explanation and score disagree",
			got[0].RiskScore, score, ok)
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
	if want := models.GetRiskLevel(before[0].RiskScore); before[0].RiskLevel != want {
		t.Fatalf("baseline band = %q, want %q for score %d", before[0].RiskLevel, want, before[0].RiskScore)
	}
	// Move to a score in a DIFFERENT band from wherever the row currently sits,
	// so the assertion proves movement rather than coincidence — and so the test
	// passes regardless of what an earlier test left behind.
	target, targetBand := 88, "High"
	if before[0].RiskScore >= 70 {
		target, targetBand = 15, "Low"
	}

	baseline := before[0]
	t.Cleanup(func() {
		if _, err := f.db.Exec(
			`UPDATE algorithms SET risk_score = $1, strength = $2, deprecation_status = $3 WHERE code = 'AES256'`,
			baseline.RiskScore, baseline.Strength, baseline.DeprecationStatus,
		); err != nil {
			t.Errorf("restore catalogue row: %v", err)
		}
	})

	// A reviewer re-assesses AES256 and records guidance.
	if _, err := f.db.Exec(`
		UPDATE algorithms
		   SET risk_score = $1, strength = 'weak', deprecation_status = 'deprecated',
		       migration_guidance = 'Move to AES-256-GCM with a rotated key.',
		       recommended_alternatives = ARRAY['AES256-GCM']
		 WHERE code = 'AES256'`, target); err != nil {
		t.Fatalf("update catalogue: %v", err)
	}

	after := f.componentsOf(t, impl)
	if len(after) != 1 {
		t.Fatalf("got %d components, want 1", len(after))
	}
	if after[0].RiskScore != target || after[0].RiskLevel != targetBand {
		t.Errorf("after re-assessment: score=%d level=%q, want %d/%s — the explanation is not reading the catalogue",
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
}

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
