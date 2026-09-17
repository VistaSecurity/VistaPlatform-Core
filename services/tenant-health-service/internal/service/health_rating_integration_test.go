package service

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/models"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/repository"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/scoring"
	"github.com/vistasecurity/vistaplatform/shared/healthbands"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_HealthTrendUsesScorerBand(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	repo := repository.NewHealthRepository(db, db)
	svc := NewHealthService(repo)
	// Vary historical inputs: exercise recomputation across the canonical bands.
	for i := 0; i <= 10; i++ {
		metrics := models.HealthMetrics{TenantID: tenant, Timestamp: time.Now().Add(-time.Duration(i+1) * time.Hour), CPUUtilization: float64(i * 10), MemoryUtilization: float64(i * 10), StorageUtilization: float64(i * 10), NetworkUtilization: float64(i * 10), Uptime: float64(100 - i*10), ComplianceScore: float64(i * 10), LastSecurityUpdate: time.Now(), FeatureUsage: map[string]int{}, UserEngagement: float64(i * 10), CostEfficiency: float64(i * 10)}
		if err := repo.SaveHealthMetrics(context.Background(), &metrics); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := repo.GetHealthMetrics(context.Background(), tenant, time.Now().Add(-24*time.Hour), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := svc.generateTrendsFromHistory(tenant, 0, healthbands.Unknown)
	if len(got.ScoreHistory) != len(stored)+1 {
		t.Fatal(len(got.ScoreHistory), len(stored))
	}
	if got.ScoreHistory[0].Status != healthbands.Unknown {
		t.Fatal("current unknown received band")
	}
	for i, metric := range stored {
		assessment := scoring.NewHealthScorer().CalculateHealthScore(metric)
		point := got.ScoreHistory[i+1]
		if point.Score != assessment.OverallScore || point.Status != assessment.HealthStatus {
			t.Fatalf("trend %+v differs from scorer %+v", point, assessment)
		}
	}
}

func TestIntegration_HealthAlertsKeepSeveritySeparate(t *testing.T) {
	db := testdb.Connect(t)
	for _, tc := range []struct {
		status   string
		score    float64
		severity string
	}{{"failing", 39.9, "critical"}, {"poor", 40, "high"}, {"fair", 60, ""}, {"unknown", 0, ""}} {
		tenant := testdb.NewTenant(t, db)
		svc := NewHealthService(repository.NewHealthRepository(db, db))
		if err := svc.generateHealthAlerts(&models.TenantHealth{TenantID: tenant, HealthStatus: tc.status, OverallScore: tc.score}); err != nil {
			t.Fatal(err)
		}

		var count int
		var value string
		if err := db.QueryRow("SELECT count(*),coalesce(max(severity),'') FROM health_alerts WHERE tenant_id=$1", tenant).Scan(&count, &value); err != nil {
			t.Fatal(err)
		}
		if value != tc.severity || (tc.severity == "" && count != 0) || (tc.severity != "" && count != 1) {
			t.Fatal(tc, count, value)
		}

	}
}

func TestIntegration_CalculateHealthPersistsCanonicalStatusAndUnknown(t *testing.T) {
	db := testdb.Connect(t)
	for _, unknown := range []bool{false, true} {
		tenant := testdb.NewTenant(t, db)
		repo := repository.NewHealthRepository(db, db)
		svc := NewHealthService(repo)
		metrics := models.HealthMetrics{TenantID: tenant, Timestamp: time.Now(), LastSecurityUpdate: time.Now().Add(-365 * 24 * time.Hour), FeatureUsage: map[string]int{}, CPUUtilization: 100, MemoryUtilization: 100, StorageUtilization: 100, NetworkUtilization: 100, ErrorRate: 1, FailedLogins: 100, SecurityAlerts: 100, ResourceCost: 1000, CostPerUser: 10000}
		if unknown {
			metrics.UnavailableSources = []string{models.SourceMonitoring, models.SourceAuth, models.SourceInventory, models.SourceResourceTracker}
		}
		want := scoring.NewHealthScorer().CalculateHealthScore(metrics)
		response, err := svc.CalculateTenantHealth(&models.HealthScoreRequest{TenantID: tenant, Metrics: metrics})
		if err != nil {
			t.Fatal(err)
		}
		if response.HealthStatus != want.HealthStatus || response.OverallScore != want.OverallScore {
			t.Fatal(response, want)
		}
		var status string
		var score float64
		if err := db.QueryRow("SELECT health_status,overall_score FROM tenant_health WHERE tenant_id=$1", tenant).Scan(&status, &score); err != nil {
			t.Fatal(err)
		}
		if status != want.HealthStatus || math.Abs(score-want.OverallScore) > 0.01 {
			t.Fatalf("stored %s/%v want %s/%v", status, score, want.HealthStatus, want.OverallScore)
		}
		if unknown && status != healthbands.Unknown {
			t.Fatal("missing sources received band", status)
		}
		if !unknown && status != string(healthbands.Failing) {
			t.Fatal("failing current health used legacy or wrong band", status)
		}
	}
}
