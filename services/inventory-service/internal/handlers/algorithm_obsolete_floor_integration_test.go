package handlers

// Decision 12 (admin-ui data review RC-38): Catalog → Ratings → Deprecate says
// the algorithm "will grade as Critical". This drives that claim through the
// REAL UpdateAlgorithm handler, the REAL AlgorithmService and a real Postgres,
// with a real audit middleware on the wire:
//
//   - PUT {deprecation_status: obsolete} raises risk_score to the bottom of the
//     Critical band and remembers the score it replaced;
//   - while obsolete, a score below the floor is refused (400) and nothing moves;
//   - PUT {deprecation_status: current} restores the remembered score;
//   - both writes are audited with the transition and the remembered score.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).
//
// Mutation checks run for this PR: dropping `WriteRisk: true` from the
// entering branch of planObsoleteRisk leaves risk at 30 and the first
// assertion fails; making the restore branch return the plan without Risk
// leaves the score at the floor and the restore assertion fails; deleting the
// metadata block in UpdateAlgorithm fails the audit assertions; disabling the
// below-floor refusal lets `{"risk_score":50}` through with a 200.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/riskbands"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Deprecate_GradesCriticalAndRestoresOnReactivate(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := services.NewAlgorithmService(db)

	code := "RC38-" + uuid.NewString()
	t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM algorithms WHERE code = $1`, code) })
	if _, err := svc.CreateAlgorithm(services.AlgorithmCreate{
		Code: code, Name: "RC-38 fixture", Category: "hash", RiskScore: intPtr(30),
	}); err != nil {
		t.Fatalf("create fixture algorithm: %v", err)
	}

	spy, entries := newAuditSpy(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	api := r.Group("/api/v1")
	api.Use(spy)
	h := NewAlgorithmHandler(svc)
	api.PUT("/inventory-service/admin/algorithms/:code", h.UpdateAlgorithm)
	path := "/api/v1/inventory-service/admin/algorithms/" + code

	floor := services.ObsoleteRiskFloor()

	// 1. Deprecate — the exact body the console's Deprecate dialog sends.
	w := do(r, http.MethodPut, path, strings.NewReader(`{"deprecation_status":"obsolete"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("deprecate: status %d, body %s", w.Code, w.Body.String())
	}
	got := responseRisk(t, w.Body.Bytes())
	if got == nil || *got != floor {
		t.Fatalf("after deprecate risk_score = %v, want the Critical floor %d", riskText(got), floor)
	}
	if riskbands.GetRiskLevel(*got) != "Critical" {
		t.Fatalf("an obsoleted algorithm grades %s, the dialog promises Critical", riskbands.GetRiskLevel(*got))
	}
	prior, floorSet := storedObsoleteMemory(t, raw, code)
	if !floorSet || !prior.Valid || prior.Int64 != 30 {
		t.Fatalf("remembered score = %+v (floor set %v), want 30", prior, floorSet)
	}
	e := awaitEntry(t, entries, "configuration.algorithm.updated")
	if e.Metadata["obsolete_transition"] != services.ObsoleteTransitionEntered {
		t.Fatalf("audit obsolete_transition = %v, want %q", e.Metadata["obsolete_transition"], services.ObsoleteTransitionEntered)
	}
	if e.Metadata["remembered_risk_score"] != float64(30) {
		t.Fatalf("audit remembered_risk_score = %v, want 30", e.Metadata["remembered_risk_score"])
	}
	if e.OldValues["risk_score"] != float64(30) || e.NewValues["risk_score"] != float64(floor) {
		t.Fatalf("audit risk_score %v → %v, want 30 → %d", e.OldValues["risk_score"], e.NewValues["risk_score"], floor)
	}

	// 2. While obsolete, a score below the floor is refused and nothing moves.
	w = do(r, http.MethodPut, path, strings.NewReader(`{"risk_score":50}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("below-floor edit while obsolete: status %d, want 400; body %s", w.Code, w.Body.String())
	}
	var stillRisk int
	if err := raw.QueryRow(`SELECT risk_score FROM algorithms WHERE code = $1`, code).Scan(&stillRisk); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stillRisk != floor {
		t.Fatalf("a refused edit changed risk_score to %d", stillRisk)
	}

	// 3. Re-activate: the remembered score comes back and the memory is spent.
	w = do(r, http.MethodPut, path, strings.NewReader(`{"deprecation_status":"current"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("reactivate: status %d, body %s", w.Code, w.Body.String())
	}
	if got := responseRisk(t, w.Body.Bytes()); got == nil || *got != 30 {
		t.Fatalf("after reactivate risk_score = %v, want the remembered 30", riskText(got))
	}
	if _, floorSet := storedObsoleteMemory(t, raw, code); floorSet {
		t.Fatal("the remembered score must be cleared once restored")
	}
	e = awaitEntry(t, entries, "configuration.algorithm.updated")
	if e.Metadata["obsolete_transition"] != services.ObsoleteTransitionRestored {
		t.Fatalf("audit obsolete_transition = %v, want %q", e.Metadata["obsolete_transition"], services.ObsoleteTransitionRestored)
	}
}

func responseRisk(t *testing.T, body []byte) *int {
	t.Helper()
	var resp struct {
		Algorithm struct {
			RiskScore *int `json:"risk_score"`
		} `json:"algorithm"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode response: %v (%s)", err, body)
	}
	return resp.Algorithm.RiskScore
}

func riskText(p *int) any {
	if p == nil {
		return "NULL"
	}
	return *p
}

func storedObsoleteMemory(t *testing.T, raw *sql.DB, code string) (sql.NullInt64, bool) {
	t.Helper()
	var prior sql.NullInt64
	var set bool
	if err := raw.QueryRow(`
		SELECT pre_obsolete_risk_score, obsolete_risk_floor_at IS NOT NULL
		FROM algorithms WHERE code = $1`, code).Scan(&prior, &set); err != nil {
		t.Fatalf("read obsolete memory: %v", err)
	}
	return prior, set
}
