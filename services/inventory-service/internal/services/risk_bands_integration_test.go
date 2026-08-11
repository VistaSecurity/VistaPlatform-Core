package services

// Guards for the risk-band ladder (models.RiskBands).
//
// The bands used to be hand-copied into eight SQL queries and one Go function,
// and they drifted: badges banded High at >= 60 while the summary and facet
// counters banded it at >= 70, so a 60–69 asset rendered "High", was counted
// "Medium", and was dropped by the "High" facet filter. These tests pin the Go
// ladder, the generated SQL ladder, and the CVSS convention they are anchored
// to against each other, so the three can never disagree again.
//
// The SQL half needs a real Postgres and skips without TEST_DATABASE_URL
// (nightly test-backend / make test-integration-db); the pure-Go halves always
// run.

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// cvssBand is the published CVSS v3.1/v4.0 qualitative severity rating for a
// score, scaled x10. Written out longhand ON PURPOSE: if it derived from
// models.RiskBands it would agree with any drift, which is the bug this guards.
// "Informational" is the product's label for the CVSS "None" band.
func cvssBand(score int) string {
	switch {
	case score >= 90: // CVSS Critical 9.0-10.0
		return "Critical"
	case score >= 70: // CVSS High 7.0-8.9
		return "High"
	case score >= 40: // CVSS Medium 4.0-6.9
		return "Medium"
	case score >= 1: // CVSS Low 0.1-3.9
		return "Low"
	default: // CVSS None 0.0
		return "Informational"
	}
}

func TestRiskBands_MatchCVSSSeverityRatings(t *testing.T) {
	for score := 0; score <= 100; score++ {
		if got, want := models.GetRiskLevel(score), cvssBand(score); got != want {
			t.Errorf("GetRiskLevel(%d) = %q, want %q (CVSS qualitative severity)", score, got, want)
		}
	}
}

// The bands must tile 0..100 with no gap and no overlap, or assets fall out of
// the distribution (or get counted twice).
func TestRiskBands_PartitionTheScoreRange(t *testing.T) {
	for score := 0; score <= 100; score++ {
		matches := 0
		for _, b := range models.RiskBands {
			cond, ok := models.RiskBandSQL("x", b.Label)
			if !ok {
				t.Fatalf("RiskBandSQL missing band %q", b.Label)
			}
			_ = cond
			// Evaluate the band interval in Go: [Min, next-higher Min).
			upper := 1 << 30
			for _, other := range models.RiskBands {
				if other.Min > b.Min && other.Min < upper {
					upper = other.Min
				}
			}
			if score >= b.Min && score < upper {
				matches++
			}
		}
		if matches != 1 {
			t.Errorf("score %d matched %d bands, want exactly 1", score, matches)
		}
	}
}

// The generated SQL ladder must return exactly what the Go ladder returns, for
// every score. This is the check that would have caught the original drift.
func TestIntegration_RiskBands_SQLMatchesGo(t *testing.T) {
	raw := testdb.Connect(t)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}

	caseSQL := models.RiskLevelCaseSQL("s.score")
	q := fmt.Sprintf(`SELECT s.score, %s FROM generate_series(0, 100) AS s(score) ORDER BY s.score`, caseSQL)

	rows, err := db.Query(q)
	if err != nil {
		t.Fatalf("run generated ladder: %v\nSQL: %s", err, q)
	}
	defer func() { _ = rows.Close() }()

	seen := 0
	for rows.Next() {
		var score int
		var sqlLabel string
		if err := rows.Scan(&score, &sqlLabel); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if goLabel := models.GetRiskLevel(score); sqlLabel != goLabel {
			t.Errorf("score %d: SQL ladder = %q, Go GetRiskLevel = %q", score, sqlLabel, goLabel)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != 101 {
		t.Fatalf("checked %d scores, want 101", seen)
	}
}

// GetRiskSummary must bucket each asset exactly once — by its own worst score.
// Pre-fix, an asset with implementations in two different bands was counted in
// both, so the buckets summed past total_assets.
func TestIntegration_RiskSummary_BucketsAreExclusiveAndExhaustive(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &AssetService{db: db}

	// One asset per scenario, including the mixed-band asset that exposed the bug.
	scenarios := []struct {
		name     string
		scores   []int
		wantBand string
	}{
		{"critical-and-low", []int{90, 20}, "Critical"},
		{"high-and-low", []int{75, 30}, "High"},
		{"medium-only", []int{50}, "Medium"},
		{"low-only", []int{20}, "Low"},
		{"zero-only", []int{0}, "Informational"},
		{"no-implementations", nil, "Informational"},
	}
	for _, sc := range scenarios {
		// The band each asset SHOULD land in, per its own worst score.
		worst := 0
		for _, s := range sc.scores {
			if s > worst {
				worst = s
			}
		}
		if got := models.GetRiskLevel(worst); got != sc.wantBand {
			t.Fatalf("%s: GetRiskLevel(max=%d) = %q, want %q", sc.name, worst, got, sc.wantBand)
		}

		assetID := uuid.New()
		if _, err := db.Exec(`
			INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1,$2,$3,'server','monitoring',NOW(),NOW(),NOW(),NOW())`,
			assetID, tenant, sc.name+".example.test"); err != nil {
			t.Fatalf("insert asset %s: %v", sc.name, err)
		}
		for _, score := range sc.scores {
			if _, err := db.Exec(`
				INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, risk_score, created_at, updated_at)
				VALUES ($1,$2,$3,'TLS','passive',$4,NOW(),NOW())`,
				uuid.New(), tenant, assetID, score); err != nil {
				t.Fatalf("insert impl %d for %s: %v", score, sc.name, err)
			}
		}
	}

	got, err := svc.GetRiskSummary(tenant)
	if err != nil {
		t.Fatalf("GetRiskSummary: %v", err)
	}

	sum := got.HighRisk + got.MediumRisk + got.LowRisk + got.UnknownRisk
	if sum != got.TotalAssets {
		t.Errorf("buckets sum to %d but total_assets = %d (high=%d medium=%d low=%d unknown=%d) — "+
			"an asset is being counted in more than one band",
			sum, got.TotalAssets, got.HighRisk, got.MediumRisk, got.LowRisk, got.UnknownRisk)
	}
	if got.TotalAssets != len(scenarios) {
		t.Fatalf("total_assets = %d, want %d", got.TotalAssets, len(scenarios))
	}

	// Each asset must land in the bucket its OWN MAX score implies.
	// critical-and-low (90) and high-and-low (75) both roll up into "high and above".
	if got.HighRisk != 2 {
		t.Errorf("high_risk = %d, want 2 (the 90-max and 75-max assets)", got.HighRisk)
	}
	if got.MediumRisk != 1 {
		t.Errorf("medium_risk = %d, want 1 (only the 50-max asset; the 75/30 asset must NOT appear here)", got.MediumRisk)
	}
	if got.LowRisk != 1 {
		t.Errorf("low_risk = %d, want 1 (only the 20-max asset; mixed-band assets must NOT appear here)", got.LowRisk)
	}
	if got.UnknownRisk != 2 {
		t.Errorf("unknown_risk = %d, want 2 (zero-scored and no-implementation assets)", got.UnknownRisk)
	}

	// critical_findings is implementation-scoped, not asset-scoped: exactly the
	// one 90-scoring implementation.
	if got.CriticalFindings != 1 {
		t.Errorf("critical_findings = %d, want 1 (the single >=90 implementation)", got.CriticalFindings)
	}
}

// Every severity the weak-crypto detector can emit must band as the severity it
// claims to be. Pre-fix, SeverityInformational scored 20, which bands as "Low" —
// a finding labelled informational would have rendered a Low badge. This also
// holds the risk engine honest when its scores stop being a fixed set.
func TestRiskBands_DetectorSeveritiesRoundTrip(t *testing.T) {
	d := &WeakCryptoDetector{}
	for _, tc := range []struct {
		severity  WeakCryptoSeverity
		wantLabel string
	}{
		{SeverityCritical, "Critical"},
		{SeverityHigh, "High"},
		{SeverityMedium, "Medium"},
		{SeverityLow, "Low"},
	} {
		score := d.CalculateRiskScore([]WeakCryptoIssue{{Severity: tc.severity}})
		if got := models.GetRiskLevel(score); got != tc.wantLabel {
			t.Errorf("severity %q scores %d, which bands as %q — want %q",
				tc.severity, score, got, tc.wantLabel)
		}
	}
}
