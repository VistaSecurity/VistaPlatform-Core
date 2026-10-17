package services

// Upgrade regression guard for ADR-0016's removal of the fabricated
// algorithms.risk_score default. Runs only with TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_CreateAlgorithmPreservesExplicitZero(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	service := NewAlgorithmService(&database.DB{DB: sqlx.NewDb(raw, "postgres")})
	code := "ADR16-ZERO-" + uuid.NewString()
	t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM algorithms WHERE code = $1`, code) })

	created, err := service.CreateAlgorithm(AlgorithmCreate{
		Code: code, Name: "Explicit zero assessment", Category: "hash", RiskScore: algorithmServiceIntPtr(0),
	})
	if err != nil {
		t.Fatalf("CreateAlgorithm(explicit zero): %v", err)
	}
	if created.RiskScore == nil || *created.RiskScore != 0 {
		t.Fatalf("created risk_score = %v, want explicit 0", created.RiskScore)
	}
}

// TestIntegration_Schema_AlgorithmRiskScoreHasNoDefault: the 5.0.0 baseline
// (asset-inventory ADR-0010 D11) declares algorithms.risk_score with no
// default — a default of 50 looked like an assessment nobody made (ADR-0016) —
// and refuses an INSERT that omits it, while a row whose score is NULL stays
// editable. (The upgrade half of this guard, which rewound a 4.x shape and
// re-applied the file, retired with the migration block.)
func TestIntegration_Schema_AlgorithmRiskScoreHasNoDefault(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire connection: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var columnDefault sql.NullString
	if err := conn.QueryRowContext(ctx, `
		SELECT column_default
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'algorithms' AND column_name = 'risk_score'`).Scan(&columnDefault); err != nil {
		t.Fatalf("read algorithms.risk_score default: %v", err)
	}
	if columnDefault.Valid {
		t.Fatalf("algorithms.risk_score default = %q, want NULL", columnDefault.String)
	}

	prefix := "ADR16-" + uuid.NewString()
	defer func() { _, _ = conn.ExecContext(ctx, `DELETE FROM algorithms WHERE code LIKE $1`, prefix+"%") }()
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO algorithms (code, category, name) VALUES ($1, 'hash', 'missing assessment')`, prefix+"-NEW"); err == nil {
		t.Fatal("a new algorithm without risk_score was accepted; algorithms_risk_score_required_on_insert must refuse it")
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO algorithms (code, category, name, risk_score) VALUES ($1, 'hash', 'scored', 73)`, prefix+"-SCORED"); err != nil {
		t.Fatalf("a scored algorithm was refused: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`UPDATE algorithms SET risk_score = NULL WHERE code = $1`, prefix+"-SCORED"); err != nil {
		t.Fatalf("clearing a score on UPDATE was refused: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`UPDATE algorithms SET description = 'still editable while unassessed' WHERE code = $1`, prefix+"-SCORED"); err != nil {
		t.Fatalf("an unrelated update of a NULL-scored row was refused: %v", err)
	}
}
