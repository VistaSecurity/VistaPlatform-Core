package xbom

import (
	"context"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_XBOMSource_ReadsRiskAssessment.
//
// `assets.risk_score` is NOT NULL DEFAULT 0, so the column alone cannot tell a
// never-assessed asset from an assessed-clean one; `risk_assessed_by` can. The
// SQL is the half a hand-built Snapshot cannot prove: delete the assessment
// expression from loadAssets and every asset reads unassessed (or, worse, every
// asset reads assessed and the exporter asserts a 0 nobody measured).
func TestIntegration_XBOMSource_ReadsRiskAssessment(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)

	insert := func(name string, score int, assessedBy string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := owner.Exec(`
			INSERT INTO public.assets
				(id, tenant_id, class_key, class_path, display_name,
				 asset_status, asset_ownership, environment, risk_score, risk_assessed_by)
			VALUES ($1, $2, 'server', 'hardware.computer.server', $3,
			        'monitoring', 'internal', 'production', $4, $5::text[])
		`, id, tenant, name, score, assessedBy); err != nil {
			t.Fatalf("seed asset %s: %v", name, err)
		}
		return id
	}
	unassessed := insert("never-assessed", 0, "{}")
	clean := insert("assessed-clean", 0, "{crypto}")
	scored := insert("assessed-55", 55, "{crypto}")

	snap, err := NewSource(app).Load(context.Background(), tenant, []uuid.UUID{unassessed, clean, scored})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	byID := map[uuid.UUID]Asset{}
	for _, a := range snap.Assets {
		byID[a.ID] = a
	}
	for _, c := range []struct {
		name     string
		id       uuid.UUID
		score    int
		assessed bool
	}{
		{"never assessed (0, no producer)", unassessed, 0, false},
		{"assessed clean (0, producer present)", clean, 0, true},
		{"assessed 55", scored, 55, true},
	} {
		got := byID[c.id]
		if got.RiskScore != c.score || got.RiskAssessed != c.assessed {
			t.Errorf("%s: RiskScore=%d RiskAssessed=%v, want %d / %v", c.name, got.RiskScore, got.RiskAssessed, c.score, c.assessed)
		}
	}
}
