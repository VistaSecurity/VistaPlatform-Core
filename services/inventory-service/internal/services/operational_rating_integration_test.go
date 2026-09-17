package services

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/riskbands"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"testing"
)

// Static materialized-view DDL cannot import Go. Exercise the actual scoped
// service query across every score so its persisted CASE and eligibility floor
// cannot silently disagree with the shared risk owner or ordering.
func TestIntegration_OperationalQueueRatingParity(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	scores := map[uuid.UUID]int{}
	testdb.WithSchemaShareLock(t, owner, func() {
		asset := uuid.New()
		if _, err := owner.Exec(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status) VALUES($1,$2,'rating-queue','server','hardware.computer.server','monitoring')`, asset, tenant); err != nil {
			t.Fatal(err)
		}
		for score := 0; score <= 100; score++ {
			id := uuid.New()
			scores[id] = score
			if _, err := owner.Exec(`INSERT INTO crypto_implementations(id,tenant_id,asset_id,protocol,discovery_method,risk_score,created_at) VALUES($1,$2,$3,'TLS','passive',$4,NOW()+$5::interval)`, id, tenant, asset, score, fmt.Sprintf("%d seconds", 100-score)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := owner.Exec(`SELECT refresh_operational_views()`); err != nil {
			t.Fatal(err)
		}
		service := NewOperationalService(&database.DB{DB: sqlx.NewDb(app, "postgres")})
		kind := "weak_cipher"
		rows, total, err := service.GetRemediationQueue(tenant, models.RemediationQueueFilters{FindingType: &kind, PageSize: 150})
		if err != nil {
			t.Fatal(err)
		}
		minScore, _ := riskbands.RiskBandMin("Medium")
		if total != 101-minScore || len(rows) != total {
			t.Fatalf("rows=%d total=%d minimum=%d", len(rows), total, minScore)
		}
		lastRank := 100
		for _, row := range rows {
			score := scores[*row.CryptoImplementationID]
			expected := string(riskbands.Severity(score))
			if row.Severity != expected {
				t.Errorf("score%d got%s want%s", score, row.Severity, expected)
			}
			bandMin, _ := riskbands.RiskBandMin(riskbands.GetRiskLevel(score))
			if bandMin > lastRank {
				t.Fatalf("severity order reversed at score%d", score)
			}
			lastRank = bandMin
		}
		high := "high"
		filtered, count, err := service.GetRemediationQueue(tenant, models.RemediationQueueFilters{FindingType: &kind, Severity: &high, PageSize: 150})
		if err != nil {
			t.Fatal(err)
		}
		if count != 20 || len(filtered) != 20 {
			t.Fatalf("high filter rows=%d count=%d", len(filtered), count)
		}
		for _, row := range filtered {
			if row.Severity != "high" {
				t.Fatal(row.Severity)
			}
		}
	})
}
