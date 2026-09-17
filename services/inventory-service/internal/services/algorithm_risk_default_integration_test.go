package services

// Upgrade regression guard for ADR-0016's removal of the fabricated
// algorithms.risk_score default. Runs only with TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
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

func TestIntegration_Schema_RemovesAlgorithmRiskDefaultWithoutRegradingRows(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	schemaPath := filepath.Join(testdb.RepoRoot(t), "scripts", "database", "schema.sql")
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}

	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire connection: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(889)`); err != nil {
		t.Fatalf("pg_advisory_lock: %v", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock(889)`) }()

	// Reconstruct the old column shape and rows that could exist on an upgrade:
	// a deliberate score, an explicitly unknown score, and a write that received
	// the old default. Applying the current schema must remove only the default.
	if _, err := conn.ExecContext(ctx, `DROP TRIGGER IF EXISTS algorithms_risk_score_required_on_insert ON algorithms`); err != nil {
		t.Fatalf("remove current required-score trigger: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `ALTER TABLE algorithms ALTER COLUMN risk_score SET DEFAULT 50`); err != nil {
		t.Fatalf("restore legacy default: %v", err)
	}
	prefix := "ADR16-" + uuid.NewString()
	defer func() { _, _ = conn.ExecContext(ctx, `DELETE FROM algorithms WHERE code LIKE $1`, prefix+"%") }()
	if _, err := conn.ExecContext(ctx, `
		INSERT INTO algorithms (code, category, name, risk_score) VALUES
			($1, 'hash', 'deliberately scored', 73),
			($2, 'hash', 'historically unassessed', NULL)`, prefix+"-SCORED", prefix+"-NULL"); err != nil {
		t.Fatalf("insert existing assessed/unknown rows: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO algorithms (code, category, name) VALUES ($1, 'hash', 'legacy defaulted')`, prefix+"-DEFAULTED"); err != nil {
		t.Fatalf("insert legacy-defaulted row: %v", err)
	}

	for pass := 1; pass <= 2; pass++ {
		if _, err := conn.ExecContext(ctx, string(schema)); err != nil {
			t.Fatalf("schema apply %d: %v", pass, err)
		}
		assertAlgorithmRiskDefaultAndRows(t, conn, ctx, prefix)
	}
}

func assertAlgorithmRiskDefaultAndRows(t *testing.T, conn *sql.Conn, ctx context.Context, prefix string) {
	t.Helper()
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
	var requiredGuard bool
	if err := conn.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_trigger
			WHERE tgrelid = 'public.algorithms'::regclass
			  AND tgname = 'algorithms_risk_score_required_on_insert'
			  AND NOT tgisinternal
		)`).Scan(&requiredGuard); err != nil {
		t.Fatalf("read required-score trigger: %v", err)
	}
	if !requiredGuard {
		t.Fatal("algorithms_risk_score_required_on_insert trigger is missing")
	}

	type row struct {
		code  string
		score sql.NullInt64
	}
	rows, err := conn.QueryContext(ctx,
		`SELECT code, risk_score FROM algorithms WHERE code LIKE $1 ORDER BY code`, prefix+"%")
	if err != nil {
		t.Fatalf("read preserved rows: %v", err)
	}
	got := make(map[string]sql.NullInt64)
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.code, &r.score); err != nil {
			t.Fatalf("scan preserved row: %v", err)
		}
		got[r.code] = r.score
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate preserved rows: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close preserved rows: %v", err)
	}

	if score := got[prefix+"-SCORED"]; !score.Valid || score.Int64 != 73 {
		t.Errorf("deliberate score after migration = %v, want 73", score)
	}
	if score := got[prefix+"-DEFAULTED"]; !score.Valid || score.Int64 != 50 {
		t.Errorf("legacy defaulted score after migration = %v, want preserved 50", score)
	}
	if score, ok := got[prefix+"-NULL"]; !ok || score.Valid {
		t.Errorf("historically unassessed score after migration = %v (present=%t), want preserved NULL", score, ok)
	}
	if _, err := conn.ExecContext(ctx,
		`UPDATE algorithms SET description = 'still editable while unassessed' WHERE code = $1`, prefix+"-NULL"); err != nil {
		t.Fatalf("unrelated update of historical NULL risk_score was blocked: %v", err)
	}

	if _, err := conn.ExecContext(ctx,
		`INSERT INTO algorithms (code, category, name) VALUES ($1, 'hash', 'missing new assessment')`, prefix+"-NEW"); err == nil {
		t.Fatal("new algorithm without risk_score succeeded after migration")
	}
}
