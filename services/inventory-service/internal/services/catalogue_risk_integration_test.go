package services

// Proof that the algorithm catalogue drives risk scoring.
//
// The `algorithms` table is documented as the authoritative source for every
// cryptographic assessment, but its risk_score used to appear only in ORDER BY
// clauses: the score the product displayed came from hardcoded string matching
// in weak_crypto_detector.go. Two parallel opinions, and the uncited one won.
//
// The decisive test here is TestIntegration_CatalogueRisk_ScoreFollowsTheCatalogue:
// it edits a catalogue row and asserts the implementation's score moves with it.
// That is the property that makes a score defensible — it traces to an
// assessment a reviewer can read and correct, not to a literal in code.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type catRiskFixture struct {
	db     *database.DB
	tenant uuid.UUID
	asset  uuid.UUID
}

func newCatRiskFixture(t *testing.T) catRiskFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	asset := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'catrisk.example.test','server','monitoring',NOW(),NOW(),NOW(),NOW())`, asset, tenant); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	return catRiskFixture{db: db, tenant: tenant, asset: asset}
}

// implWith links the given algorithm codes under the given roles and returns
// the implementation id.
func (f catRiskFixture) implWith(t *testing.T, components map[string]string) uuid.UUID {
	t.Helper()
	implID := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, created_at, updated_at)
		VALUES ($1,$2,$3,'TLS','passive',NOW(),NOW())`, implID, f.tenant, f.asset); err != nil {
		t.Fatalf("insert implementation: %v", err)
	}
	for role, code := range components {
		var algID uuid.UUID
		if err := f.db.QueryRow(`SELECT id FROM algorithms WHERE code = $1`, code).Scan(&algID); err != nil {
			t.Fatalf("catalogue lookup %q: %v", code, err)
		}
		if _, err := f.db.Exec(`
			INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type, is_inferred)
			VALUES ($1,$2,$3,false)`, implID, algID, role); err != nil {
			t.Fatalf("link %s=%s: %v", role, code, err)
		}
	}
	return implID
}

// score runs the catalogue scorer the ingest path uses.
func (f catRiskFixture) score(t *testing.T, implID uuid.UUID) (int, []string, bool) {
	t.Helper()
	var s int
	var factors []string
	var ok bool
	err := database.WithTenantTx(t.Context(), f.db, f.tenant, func(tx *sqlx.Tx) error {
		worst, all, found, e := catalogueRiskForImplementation(tx, implID)
		if e != nil {
			return e
		}
		s, factors, ok = worst.RiskScore, catalogueRiskFactors(all), found
		return nil
	})
	if err != nil {
		t.Fatalf("catalogue risk: %v", err)
	}
	return s, factors, ok
}

// The worst component sets the score: an AES-256 cipher must not offset an RC4
// fallback. RC4 is catalogue risk 90 (weak/obsolete); AES256 is 15.
func TestIntegration_CatalogueRisk_WorstComponentWins(t *testing.T) {
	f := newCatRiskFixture(t)
	impl := f.implWith(t, map[string]string{"symmetric": "RC4", "hash": "SHA256"})

	got, factors, ok := f.score(t, impl)
	if !ok {
		t.Fatal("expected a catalogue assessment")
	}
	if got != 90 {
		t.Errorf("score = %d, want 90 (RC4, weak/obsolete) — the strong SHA256 component must not lower it", got)
	}
	if len(factors) != 2 {
		t.Errorf("got %d risk factors, want 2 (one per linked component)", len(factors))
	}
	// The explanation must name the catalogue row, not a hardcoded rule.
	if len(factors) > 0 && !strings.Contains(factors[0], "RC4") {
		t.Errorf("worst factor = %q, want it to name RC4", factors[0])
	}
}

// An obsolete protocol version is a first-class risk signal, so container rows
// count here even though the PQC classifier ignores them. TLS1.0 is 75.
func TestIntegration_CatalogueRisk_ProtocolVersionCounts(t *testing.T) {
	f := newCatRiskFixture(t)
	impl := f.implWith(t, map[string]string{"protocol_version": "TLS1.0", "symmetric": "AES256"})

	got, _, ok := f.score(t, impl)
	if !ok {
		t.Fatal("expected a catalogue assessment")
	}
	if got != 75 {
		t.Errorf("score = %d, want 75 (TLS1.0 is weak/deprecated; RFC 8996 says MUST NOT use)", got)
	}
}

// THE test: change the catalogue, and the score must follow. This is what makes
// the number defensible — it is derived from a reviewable assessment.
func TestIntegration_CatalogueRisk_ScoreFollowsTheCatalogue(t *testing.T) {
	f := newCatRiskFixture(t)
	impl := f.implWith(t, map[string]string{"symmetric": "AES256"})

	before, _, ok := f.score(t, impl)
	if !ok {
		t.Fatal("expected a catalogue assessment")
	}
	if before != 15 {
		t.Fatalf("baseline score = %d, want 15 (AES256 strong/current)", before)
	}

	// `algorithms` is GLOBAL reference data — testdb.NewTenant's CASCADE cleanup
	// does not undo an edit to it, so this test used to leave AES256 permanently
	// re-assessed for every later test in the package. Restore it.
	t.Cleanup(func() {
		if _, err := f.db.Exec(`UPDATE algorithms SET risk_score = 15, strength = 'strong', deprecation_status = 'current' WHERE code = 'AES256'`); err != nil {
			t.Errorf("restore catalogue row: %v", err)
		}
	})

	// A reviewer re-assesses AES256 in the catalogue.
	if _, err := f.db.Exec(`UPDATE algorithms SET risk_score = 88, strength = 'weak', deprecation_status = 'deprecated' WHERE code = 'AES256'`); err != nil {
		t.Fatalf("update catalogue: %v", err)
	}

	after, factors, _ := f.score(t, impl)
	if after != 88 {
		t.Errorf("score = %d after re-assessing the catalogue row, want 88 — "+
			"the risk engine is not actually reading the catalogue", after)
	}
	if len(factors) == 0 || !strings.Contains(factors[0], "weak") || !strings.Contains(factors[0], "deprecated") {
		t.Errorf("factor = %v, want it to carry the catalogue's strength/deprecation wording", factors)
	}
}

// Nothing linked means NOT ASSESSED, which must stay distinct from "assessed as
// safe" — the ingest path leaves the score at 0 so the Informational band keeps
// meaning unassessed.
func TestIntegration_CatalogueRisk_UnlinkedIsNotAssessed(t *testing.T) {
	f := newCatRiskFixture(t)
	impl := f.implWith(t, nil)

	got, factors, ok := f.score(t, impl)
	if ok {
		t.Errorf("expected no assessment for an implementation with no linked algorithms, got score %d", got)
	}
	if len(factors) != 0 {
		t.Errorf("expected no risk factors, got %v", factors)
	}
}
