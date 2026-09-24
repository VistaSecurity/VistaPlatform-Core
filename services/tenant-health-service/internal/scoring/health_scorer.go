package scoring

import (
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/healthbands"
)

// HealthScorer handles the calculation of tenant health scores
type HealthScorer struct {
	weights HealthWeights
}

// HealthWeights defines the relative importance of each health factor.
//
// There is no resource-efficiency weight. That factor was 25% of the index and
// was built from hard-coded storage 50 / network 60 plus CPU and memory
// columns nothing writes, so every tenant carried the same invented
// contribution. Owner decision 8 (ADMIN_UI_DATA_REVIEW_2026-09, RC-14) dropped
// it and re-weighted the rest PROPORTIONALLY: the old 25/20/15/15 split is
// kept, each divided by the 75% that remains.
type HealthWeights struct {
	PerformanceMetrics float64 // 25/75
	SecurityPosture    float64 // 20/75
	BusinessActivity   float64 // 15/75
	CostOptimization   float64 // 15/75
}

// NewHealthScorer creates a new health scorer with default weights
func NewHealthScorer() *HealthScorer {
	return &HealthScorer{
		weights: HealthWeights{
			PerformanceMetrics: 25.0 / 75.0,
			SecurityPosture:    20.0 / 75.0,
			BusinessActivity:   15.0 / 75.0,
			CostOptimization:   15.0 / 75.0,
		},
	}
}

// unavailableFactors returns the set of factor names that cannot be scored
// because the source feeding them was unreachable (or, for
// SourceResourceMetering, does not exist).
func unavailableFactors(sources []string) map[string]bool {
	out := make(map[string]bool)
	for _, src := range sources {
		for _, factor := range models.SourceFactors[src] {
			out[factor] = true
		}
	}
	return out
}

// reportedSources is the breakdown's unavailable_sources: the peers that
// failed during collection, plus SourceResourceMetering, which is always
// absent (no producer exists). Deduplicated, collection order preserved.
func reportedSources(collected []string) []string {
	all := append(append(make([]string, 0, len(collected)+1), collected...), models.SourceResourceMetering)
	out := make([]string, 0, len(all))
	seen := make(map[string]bool, len(all))
	for _, s := range all {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// CalculateHealthScore calculates the overall health score for a tenant.
//
// Factors whose source peer was unreachable are scored as UNKNOWN (nil in the
// breakdown) and excluded from the weighted average, whose remaining weights
// are renormalised. When NOTHING could be measured the result is score 0 with
// status models.HealthStatusUnknown — deliberately distinguishable from a
// genuine score of 0, which is what a fabricated placeholder could never be.
//
// Resource efficiency is never scored: it is always nil in the breakdown and
// SourceResourceMetering is always listed in unavailable_sources.
func (hs *HealthScorer) CalculateHealthScore(metrics models.HealthMetrics) models.HealthScoreResponse {
	sources := reportedSources(metrics.UnavailableSources)
	missing := unavailableFactors(sources)

	// score returns a pointer to the computed factor score, or nil when the
	// factor's source peer never answered.
	score := func(factor string, compute func(models.HealthMetrics) float64) *float64 {
		if missing[factor] {
			return nil
		}
		v := compute(metrics)
		return &v
	}

	performanceScore := score(models.FactorPerformanceMetrics, hs.calculatePerformanceMetrics)
	securityScore := score(models.FactorSecurityPosture, hs.calculateSecurityPosture)
	businessScore := score(models.FactorBusinessActivity, hs.calculateBusinessActivity)
	costScore := score(models.FactorCostOptimization, hs.calculateCostOptimization)

	// Weighted overall score over the MEASURED factors only, renormalised by
	// the weight actually present. Treating an unmeasured factor as 0 would
	// invent a bad score; treating it as 100 would invent a good one.
	var weighted, totalWeight float64
	accumulate := func(v *float64, weight float64) {
		if v == nil {
			return
		}
		weighted += *v * weight
		totalWeight += weight
	}
	accumulate(performanceScore, hs.weights.PerformanceMetrics)
	accumulate(securityScore, hs.weights.SecurityPosture)
	accumulate(businessScore, hs.weights.BusinessActivity)
	accumulate(costScore, hs.weights.CostOptimization)

	allWeight := hs.weights.PerformanceMetrics + hs.weights.SecurityPosture + hs.weights.BusinessActivity + hs.weights.CostOptimization

	var overallScore, completeness float64
	healthStatus := models.HealthStatusUnknown
	if totalWeight > 0 {
		overallScore = weighted / totalWeight
		healthStatus = hs.determineHealthStatus(overallScore)
	}
	if allWeight > 0 {
		completeness = totalWeight / allWeight
	}

	breakdown := models.HealthBreakdown{
		ResourceEfficiency: nil, // not measured — see models.SourceResourceMetering
		PerformanceMetrics: performanceScore,
		SecurityPosture:    securityScore,
		BusinessActivity:   businessScore,
		CostOptimization:   costScore,
		UnavailableSources: sources,
		DataCompleteness:   completeness,
	}

	// Generate recommendations
	recommendations := hs.generateRecommendations(metrics, breakdown)

	// Trends will be generated by the service layer using historical data
	trends := models.HealthTrends{
		ScoreHistory:   []models.HealthDataPoint{{Timestamp: time.Now(), Score: overallScore, Status: healthStatus}},
		TrendDirection: "stable",
		TrendStrength:  0.5,
		PredictedScore: overallScore,
	}

	return models.HealthScoreResponse{
		TenantID:        metrics.TenantID,
		OverallScore:    overallScore,
		HealthStatus:    healthStatus,
		ScoreBreakdown:  breakdown,
		Recommendations: recommendations,
		Trends:          trends,
		LastCalculated:  time.Now(),
	}
}

// belowThreshold reports whether a MEASURED factor score is under a threshold.
// A nil (unmeasured) factor is never "below" anything — we do not know.
func belowThreshold(v *float64, threshold float64) bool {
	return v != nil && *v < threshold
}

// calculatePerformanceMetrics calculates score based on performance indicators
func (hs *HealthScorer) calculatePerformanceMetrics(metrics models.HealthMetrics) float64 {
	// Response time score (lower is better, optimal < 200ms)
	responseScore := hs.calculateResponseTimeScore(metrics.AvgResponseTime)

	// Error rate score (lower is better, optimal < 1%)
	errorScore := hs.calculateErrorRateScore(metrics.ErrorRate)

	// Throughput score (higher is better, normalized)
	throughputScore := hs.calculateThroughputScore(metrics.Throughput)

	// Uptime score (higher is better, optimal > 99.9%)
	uptimeScore := hs.calculateUptimeScore(metrics.Uptime)

	// Weighted average
	return (responseScore*0.3 + errorScore*0.3 + throughputScore*0.2 + uptimeScore*0.2)
}

// calculateSecurityPosture calculates score based on security metrics
func (hs *HealthScorer) calculateSecurityPosture(metrics models.HealthMetrics) float64 {
	// Failed logins score (lower is better)
	loginScore := hs.calculateFailedLoginsScore(metrics.FailedLogins)

	// Security alerts score (lower is better)
	alertScore := hs.calculateSecurityAlertsScore(metrics.SecurityAlerts)

	// Compliance score (higher is better)
	complianceScore := metrics.ComplianceScore

	// Security update recency (more recent is better)
	updateScore := hs.calculateSecurityUpdateScore(metrics.LastSecurityUpdate)

	// Weighted average
	return (loginScore*0.25 + alertScore*0.25 + complianceScore*0.3 + updateScore*0.2)
}

// calculateBusinessActivity calculates score based on business engagement
func (hs *HealthScorer) calculateBusinessActivity(metrics models.HealthMetrics) float64 {
	// Active users score (normalized)
	userScore := hs.calculateActiveUsersScore(metrics.ActiveUsers)

	// API calls score (normalized)
	apiScore := hs.calculateAPICallsScore(metrics.APICalls)

	// User engagement score (higher is better)
	engagementScore := metrics.UserEngagement

	// Feature usage diversity (more features used is better)
	featureScore := hs.calculateFeatureUsageScore(metrics.FeatureUsage)

	// Weighted average
	return (userScore*0.3 + apiScore*0.3 + engagementScore*0.25 + featureScore*0.15)
}

// calculateCostOptimization calculates score based on cost efficiency
func (hs *HealthScorer) calculateCostOptimization(metrics models.HealthMetrics) float64 {
	// Cost per user score (lower is better)
	costPerUserScore := hs.calculateCostPerUserScore(metrics.CostPerUser)

	// Cost efficiency score (higher is better)
	efficiencyScore := metrics.CostEfficiency

	// Resource cost optimization (normalized)
	resourceCostScore := hs.calculateResourceCostScore(metrics.ResourceCost)

	// Weighted average
	return (costPerUserScore*0.4 + efficiencyScore*0.4 + resourceCostScore*0.2)
}

// Helper functions for individual score calculations

func (hs *HealthScorer) calculateResponseTimeScore(responseTime float64) float64 {
	// Exponential decay: 200ms = 100, 500ms = 50, 1000ms = 0
	if responseTime <= 200 {
		return 100.0
	}
	return math.Max(0, 100.0*math.Exp(-(responseTime-200)/300))
}

func (hs *HealthScorer) calculateErrorRateScore(errorRate float64) float64 {
	// Linear decay: 0% = 100, 1% = 50, 5% = 0
	if errorRate <= 0.01 {
		return 100.0 - (errorRate/0.01)*50.0
	}
	return math.Max(0, 50.0-(errorRate-0.01)/0.04*50.0)
}

func (hs *HealthScorer) calculateThroughputScore(throughput float64) float64 {
	// Normalized score based on throughput (assumes max 1000 req/s)
	return math.Min(100.0, throughput/10.0)
}

func (hs *HealthScorer) calculateUptimeScore(uptime float64) float64 {
	// Linear scale: 99.9% = 100, 99% = 0
	if uptime >= 99.9 {
		return 100.0
	}
	return math.Max(0, (uptime-99.0)/0.9*100.0)
}

func (hs *HealthScorer) calculateFailedLoginsScore(failedLogins int) float64 {
	// Exponential decay: 0 = 100, 10 = 50, 50 = 0
	if failedLogins == 0 {
		return 100.0
	}
	return math.Max(0, 100.0*math.Exp(-float64(failedLogins)/10.0))
}

func (hs *HealthScorer) calculateSecurityAlertsScore(alerts int) float64 {
	// Linear decay: 0 = 100, 5 = 0
	return math.Max(0, 100.0-float64(alerts)*20.0)
}

func (hs *HealthScorer) calculateSecurityUpdateScore(lastUpdate time.Time) float64 {
	// Score decreases with time since last update
	daysSinceUpdate := time.Since(lastUpdate).Hours() / 24
	if daysSinceUpdate <= 7 {
		return 100.0
	} else if daysSinceUpdate <= 30 {
		return 100.0 - (daysSinceUpdate-7)/23*30.0 // 30 point penalty over 23 days
	}
	return math.Max(0, 70.0-(daysSinceUpdate-30)/30*70.0) // Additional penalty
}

func (hs *HealthScorer) calculateActiveUsersScore(activeUsers int) float64 {
	// Normalized score (assumes max 1000 users)
	return math.Min(100.0, float64(activeUsers)/10.0)
}

func (hs *HealthScorer) calculateAPICallsScore(apiCalls int) float64 {
	// Normalized score (assumes max 10000 calls)
	return math.Min(100.0, float64(apiCalls)/100.0)
}

func (hs *HealthScorer) calculateFeatureUsageScore(featureUsage map[string]int) float64 {
	// Score based on number of features used and usage diversity
	featureCount := len(featureUsage)
	if featureCount == 0 {
		return 0.0
	}

	// Bonus for using more features (up to 5 features)
	featureBonus := math.Min(20.0, float64(featureCount)*4.0)

	// Calculate usage diversity (entropy-like measure)
	totalUsage := 0
	for _, usage := range featureUsage {
		totalUsage += usage
	}

	if totalUsage == 0 {
		return featureBonus
	}

	diversity := 0.0
	for _, usage := range featureUsage {
		if usage > 0 {
			ratio := float64(usage) / float64(totalUsage)
			diversity -= ratio * math.Log2(ratio)
		}
	}

	// Normalize diversity (max entropy for 5 features is ~2.32)
	diversityScore := math.Min(80.0, diversity/2.32*80.0)

	return featureBonus + diversityScore
}

func (hs *HealthScorer) calculateCostPerUserScore(costPerUser float64) float64 {
	// Lower cost per user is better (assumes optimal < $10/user)
	if costPerUser <= 10.0 {
		return 100.0
	}
	return math.Max(0, 100.0-(costPerUser-10.0)*5.0) // 5 point penalty per dollar
}

func (hs *HealthScorer) calculateResourceCostScore(resourceCost float64) float64 {
	// Normalized score (assumes max $1000/month)
	return math.Min(100.0, 100.0-resourceCost/10.0)
}

// determineHealthStatus converts score to status
func (hs *HealthScorer) determineHealthStatus(score float64) string {
	return healthbands.Status(&score)
}

// generateRecommendations creates actionable recommendations
func (hs *HealthScorer) generateRecommendations(metrics models.HealthMetrics, breakdown models.HealthBreakdown) []models.Recommendation {
	var recommendations []models.Recommendation

	// Performance recommendations
	if belowThreshold(breakdown.PerformanceMetrics, 70) {
		if metrics.AvgResponseTime > 500 {
			recommendations = append(recommendations, models.Recommendation{
				ID:            uuid.New(),
				Category:      "performance",
				Priority:      "high",
				Title:         "Improve Response Times",
				Description:   "Response times are above optimal. Consider caching, database optimization, or infrastructure scaling.",
				Impact:        "high",
				Effort:        "high",
				PotentialGain: 20.0,
			})
		}

		if metrics.ErrorRate > 0.02 {
			recommendations = append(recommendations, models.Recommendation{
				ID:            uuid.New(),
				Category:      "performance",
				Priority:      "critical",
				Title:         "Reduce Error Rate",
				Description:   "Error rate is above acceptable levels. Investigate and fix underlying issues.",
				Impact:        "high",
				Effort:        "high",
				PotentialGain: 25.0,
			})
		}
	}

	// Security recommendations
	if belowThreshold(breakdown.SecurityPosture, 70) {
		if metrics.FailedLogins > 10 {
			recommendations = append(recommendations, models.Recommendation{
				ID:            uuid.New(),
				Category:      "security",
				Priority:      "high",
				Title:         "Review Authentication Security",
				Description:   "High number of failed login attempts. Consider implementing additional security measures.",
				Impact:        "high",
				Effort:        "medium",
				PotentialGain: 15.0,
			})
		}

		if time.Since(metrics.LastSecurityUpdate).Hours() > 24*30 {
			recommendations = append(recommendations, models.Recommendation{
				ID:            uuid.New(),
				Category:      "security",
				Priority:      "medium",
				Title:         "Update Security Patches",
				Description:   "Security updates are overdue. Apply latest patches to maintain security posture.",
				Impact:        "medium",
				Effort:        "low",
				PotentialGain: 10.0,
			})
		}
	}

	// Business activity recommendations
	if belowThreshold(breakdown.BusinessActivity, 60) {
		if metrics.ActiveUsers < 10 {
			recommendations = append(recommendations, models.Recommendation{
				ID:            uuid.New(),
				Category:      "business",
				Priority:      "medium",
				Title:         "Increase User Engagement",
				Description:   "Low user activity detected. Consider user onboarding improvements or feature promotion.",
				Impact:        "medium",
				Effort:        "medium",
				PotentialGain: 8.0,
			})
		}
	}

	// Cost optimization recommendations
	if belowThreshold(breakdown.CostOptimization, 70) {
		if metrics.CostPerUser > 20 {
			recommendations = append(recommendations, models.Recommendation{
				ID:            uuid.New(),
				Category:      "cost",
				Priority:      "medium",
				Title:         "Optimize Cost Per User",
				Description:   "Cost per user is above benchmark. Consider resource optimization or pricing review.",
				Impact:        "medium",
				Effort:        "medium",
				PotentialGain: 12.0,
			})
		}
	}

	return recommendations
}
