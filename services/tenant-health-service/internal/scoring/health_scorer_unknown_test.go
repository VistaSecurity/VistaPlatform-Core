package scoring

import (
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/models"
)

// These tests pin B-12's contract: a peer that could not be reached produces
// an UNKNOWN factor, never a number. Before the fix every unreachable peer was
// replaced by a hardcoded constant (Uptime 99.9, ErrorRate 0.005, CPU 50,
// Memory 60, ComplianceScore 85), so every tenant on a mesh-enabled deployment
// scored identically off invented data.

func measuredMetrics() models.HealthMetrics {
	return models.HealthMetrics{
		TenantID:           uuid.New(),
		Timestamp:          time.Now(),
		CPUUtilization:     65,
		MemoryUtilization:  75,
		StorageUtilization: 80,
		NetworkUtilization: 55,
		AvgResponseTime:    120,
		ErrorRate:          0.001,
		Throughput:         200,
		Uptime:             99.95,
		FailedLogins:       1,
		SecurityAlerts:     0,
		ComplianceScore:    90,
		LastSecurityUpdate: time.Now(),
		ActiveUsers:        20,
		APICalls:           5000,
		FeatureUsage:       map[string]int{"assets": 3},
		UserEngagement:     70,
		ResourceCost:       12,
		CostPerUser:        0.6,
		CostEfficiency:     80,
	}
}

func TestCalculateHealthScore_AllSourcesUnavailable_IsUnknownNotZeroScore(t *testing.T) {
	m := measuredMetrics()
	m.UnavailableSources = []string{
		models.SourceMonitoring, models.SourceAuth,
		models.SourceInventory, models.SourceResourceTracker,
	}

	got := NewHealthScorer().CalculateHealthScore(m)

	if got.HealthStatus != models.HealthStatusUnknown {
		t.Fatalf("health status = %q, want %q — an unmeasured tenant must not be given a score band",
			got.HealthStatus, models.HealthStatusUnknown)
	}
	b := got.ScoreBreakdown
	for name, v := range map[string]*float64{
		"resource_efficiency": b.ResourceEfficiency,
		"performance_metrics": b.PerformanceMetrics,
		"security_posture":    b.SecurityPosture,
		"business_activity":   b.BusinessActivity,
		"cost_optimization":   b.CostOptimization,
	} {
		if v != nil {
			t.Errorf("factor %s = %v, want nil (unknown) when its source peer was unreachable", name, *v)
		}
	}
	if b.DataCompleteness != 0 {
		t.Errorf("data_completeness = %v, want 0", b.DataCompleteness)
	}
	if len(b.UnavailableSources) != 4 {
		t.Errorf("unavailable_sources = %v, want all four peers named", b.UnavailableSources)
	}
}

func TestCalculateHealthScore_PartialAvailability_RenormalisesAndReportsGap(t *testing.T) {
	m := measuredMetrics()
	// resource-tracker-service feeds TWO factors (resource efficiency 0.25 +
	// cost optimization 0.15 = 0.40 of the total weight).
	m.UnavailableSources = []string{models.SourceResourceTracker}

	hs := NewHealthScorer()
	got := hs.CalculateHealthScore(m)

	b := got.ScoreBreakdown
	if b.ResourceEfficiency != nil || b.CostOptimization != nil {
		t.Fatalf("resource-tracker's factors must be nil, got %v / %v", b.ResourceEfficiency, b.CostOptimization)
	}
	if b.PerformanceMetrics == nil || b.SecurityPosture == nil || b.BusinessActivity == nil {
		t.Fatal("factors from reachable peers must still be scored")
	}
	if math.Abs(b.DataCompleteness-0.60) > 1e-9 {
		t.Errorf("data_completeness = %v, want 0.60 (0.25+0.20+0.15 of 1.0)", b.DataCompleteness)
	}

	// Overall must be the weighted average over the MEASURED factors only,
	// renormalised — not a total that silently counts missing factors as 0.
	want := (*b.PerformanceMetrics*0.25 + *b.SecurityPosture*0.20 + *b.BusinessActivity*0.15) / 0.60
	if math.Abs(got.OverallScore-want) > 1e-9 {
		t.Errorf("overall_score = %v, want %v (renormalised over measured weight)", got.OverallScore, want)
	}
	if got.HealthStatus == models.HealthStatusUnknown {
		t.Error("partial data still yields a real score; status must not be unknown")
	}
}

func TestCalculateHealthScore_EverythingMeasured_UsesFullWeighting(t *testing.T) {
	m := measuredMetrics()
	hs := NewHealthScorer()
	got := hs.CalculateHealthScore(m)

	b := got.ScoreBreakdown
	if b.ResourceEfficiency == nil || b.PerformanceMetrics == nil || b.SecurityPosture == nil ||
		b.BusinessActivity == nil || b.CostOptimization == nil {
		t.Fatal("no source was unavailable; every factor must be scored")
	}
	if b.DataCompleteness != 1 {
		t.Errorf("data_completeness = %v, want 1", b.DataCompleteness)
	}
	if len(b.UnavailableSources) != 0 {
		t.Errorf("unavailable_sources = %v, want empty", b.UnavailableSources)
	}

	want := *b.ResourceEfficiency*0.25 + *b.PerformanceMetrics*0.25 + *b.SecurityPosture*0.20 +
		*b.BusinessActivity*0.15 + *b.CostOptimization*0.15
	if math.Abs(got.OverallScore-want) > 1e-9 {
		t.Errorf("overall_score = %v, want %v (unchanged full-weight formula)", got.OverallScore, want)
	}
}

func TestCalculateHealthScore_UnmeasuredFactorsProduceNoRecommendations(t *testing.T) {
	m := measuredMetrics()
	// Values that WOULD trip the resource recommendations if the factor were
	// scored — the point is that an unreachable peer must not produce advice.
	m.CPUUtilization = 99
	m.MemoryUtilization = 99
	m.UnavailableSources = []string{models.SourceResourceTracker}

	got := NewHealthScorer().CalculateHealthScore(m)
	for _, rec := range got.Recommendations {
		if rec.Category == "resource" || rec.Category == "cost" {
			t.Errorf("recommendation %q drawn from an unmeasured factor", rec.Title)
		}
	}
}
