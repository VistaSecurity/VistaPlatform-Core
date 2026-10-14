package scoring

import (
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/healthbands"
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
		models.SourceMonitoring, models.SourceAuth, models.SourceInventory,
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
	// All three peers, plus the two producers that never exist.
	if len(b.UnavailableSources) != 5 {
		t.Errorf("unavailable_sources = %v, want all three peers plus %s and %s named",
			b.UnavailableSources, models.SourceResourceMetering, models.SourceCostMetering)
	}
}

func TestCalculateHealthScore_PartialAvailability_RenormalisesAndReportsGap(t *testing.T) {
	m := measuredMetrics()
	// monitoring-service feeds ONE factor: performance, 25 of the 60 points
	// that remain once resource efficiency and cost optimization are dropped.
	m.UnavailableSources = []string{models.SourceMonitoring}

	hs := NewHealthScorer()
	got := hs.CalculateHealthScore(m)

	b := got.ScoreBreakdown
	if b.ResourceEfficiency != nil || b.CostOptimization != nil {
		t.Fatalf("resource efficiency and cost optimization must be nil, got %v / %v", b.ResourceEfficiency, b.CostOptimization)
	}
	if b.PerformanceMetrics != nil {
		t.Fatalf("performance = %v, want nil — monitoring-service was unreachable", *b.PerformanceMetrics)
	}
	if b.SecurityPosture == nil || b.BusinessActivity == nil {
		t.Fatal("factors from reachable peers must still be scored")
	}
	if math.Abs(b.DataCompleteness-35.0/60.0) > 1e-9 {
		t.Errorf("data_completeness = %v, want (20+15)/60", b.DataCompleteness)
	}

	// Overall must be the weighted average over the MEASURED factors only,
	// renormalised — not a total that silently counts missing factors as 0.
	want := (*b.SecurityPosture*20 + *b.BusinessActivity*15) / 35
	if math.Abs(got.OverallScore-want) > 1e-9 {
		t.Errorf("overall_score = %v, want %v (renormalised over measured weight)", got.OverallScore, want)
	}
	if got.HealthStatus == models.HealthStatusUnknown {
		t.Error("partial data still yields a real score; status must not be unknown")
	}
}

// Decision 8 (RC-14) dropped resource efficiency; the resource-tracker
// retirement dropped cost optimization the same way. The three factors
// left keep their 25/20/15 proportions, and everything measured means
// completeness 1 — the missing factors are by design, not a gap.
func TestCalculateHealthScore_EverythingMeasured_UsesReweightedIndex(t *testing.T) {
	m := measuredMetrics()
	hs := NewHealthScorer()
	got := hs.CalculateHealthScore(m)

	b := got.ScoreBreakdown
	if b.PerformanceMetrics == nil || b.SecurityPosture == nil || b.BusinessActivity == nil {
		t.Fatal("no peer was unavailable; every measured factor must be scored")
	}
	if b.ResourceEfficiency != nil {
		t.Fatalf("resource_efficiency = %v, want nil — nothing measures it", *b.ResourceEfficiency)
	}
	if b.CostOptimization != nil {
		t.Fatalf("cost_optimization = %v, want nil — nothing prices a tenant's usage", *b.CostOptimization)
	}
	if b.DataCompleteness != 1 {
		t.Errorf("data_completeness = %v, want 1 (the unmeasured factors carry no weight)", b.DataCompleteness)
	}
	if len(b.UnavailableSources) != 2 || b.UnavailableSources[0] != models.SourceResourceMetering || b.UnavailableSources[1] != models.SourceCostMetering {
		t.Errorf("unavailable_sources = %v, want exactly [%s %s]", b.UnavailableSources, models.SourceResourceMetering, models.SourceCostMetering)
	}

	want := (*b.PerformanceMetrics*25 + *b.SecurityPosture*20 + *b.BusinessActivity*15) / 60
	if math.Abs(got.OverallScore-want) > 1e-9 {
		t.Errorf("overall_score = %v, want %v (25/20/15 over 60)", got.OverallScore, want)
	}

	w := hs.weights
	if sum := w.PerformanceMetrics + w.SecurityPosture + w.BusinessActivity; math.Abs(sum-1) > 1e-9 {
		t.Errorf("weights sum to %v, want 1", sum)
	}
}

// The resource inputs no longer move the index at all: the CPU, memory,
// storage and network fields are not measured, so no value in them may change
// the score (they used to carry 25% of it, from constants).
func TestCalculateHealthScore_ResourceInputsDoNotMoveTheIndex(t *testing.T) {
	hs := NewHealthScorer()
	base := hs.CalculateHealthScore(measuredMetrics())
	m := measuredMetrics()
	m.CPUUtilization, m.MemoryUtilization, m.StorageUtilization, m.NetworkUtilization = 0, 0, 50, 60
	if got := hs.CalculateHealthScore(m); got.OverallScore != base.OverallScore {
		t.Fatalf("overall_score moved %v -> %v on resource inputs nothing measures", base.OverallScore, got.OverallScore)
	}
}

func TestCalculateHealthScore_UnmeasuredFactorsProduceNoRecommendations(t *testing.T) {
	m := measuredMetrics()
	// Values that WOULD trip the resource and cost recommendations if those
	// factors were scored — the point is that an unmeasured factor must not
	// produce advice. Neither factor is ever measured (see
	// models.SourceResourceMetering / models.SourceCostMetering).
	m.CPUUtilization = 99
	m.MemoryUtilization = 99
	m.CostPerUser = 1000
	m.ResourceCost = 100000

	got := NewHealthScorer().CalculateHealthScore(m)
	for _, rec := range got.Recommendations {
		if rec.Category == "resource" || rec.Category == "cost" {
			t.Errorf("recommendation %q drawn from an unmeasured factor", rec.Title)
		}
	}
}

func TestCalculateHealthScoreCanonicalBands(t *testing.T) {
	hs := NewHealthScorer()
	for _, tc := range []struct {
		score  float64
		status string
	}{{0, "failing"}, {39.99, "failing"}, {40, "poor"}, {59.99, "poor"}, {60, "fair"}, {74.99, "fair"}, {75, "good"}, {89.99, "good"}, {90, "excellent"}, {100, "excellent"}} {
		if got := hs.determineHealthStatus(tc.score); got != tc.status {
			t.Fatalf("%v=%s want %s", tc.score, got, tc.status)
		}
	}
	// Check the actual scorer is wired to the canonical classifier too.
	for i := 0; i <= 10; i++ {
		m := measuredMetrics()
		m.CPUUtilization = float64(i * 10)
		m.MemoryUtilization = float64(i * 10)
		m.ComplianceScore = float64(i * 10)
		got := hs.CalculateHealthScore(m)
		if got.HealthStatus != healthbands.Status(&got.OverallScore) {
			t.Fatalf("scorer %v=%s", got.OverallScore, got.HealthStatus)
		}
	}
}
