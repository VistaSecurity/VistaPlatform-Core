package models

import (
	"time"

	"github.com/google/uuid"
)

// TenantHealth represents the overall health score and metrics for a tenant
type TenantHealth struct {
	ID              uuid.UUID        `json:"id" db:"id"`
	TenantID        uuid.UUID        `json:"tenant_id" db:"tenant_id"`
	OverallScore    float64          `json:"overall_score" db:"overall_score"`
	HealthStatus    string           `json:"health_status" db:"health_status"` // "excellent", "good", "fair", "poor", "critical"
	LastCalculated  time.Time        `json:"last_calculated" db:"last_calculated"`
	ScoreBreakdown  HealthBreakdown  `json:"score_breakdown" db:"score_breakdown"`
	Recommendations []Recommendation `json:"recommendations" db:"recommendations"`
	Trends          HealthTrends     `json:"trends" db:"trends"`
	CreatedAt       time.Time        `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at" db:"updated_at"`
}

// HealthBreakdown provides detailed scoring for each health factor
type HealthBreakdown struct {
	ResourceEfficiency float64 `json:"resource_efficiency"` // 0-100
	PerformanceMetrics float64 `json:"performance_metrics"` // 0-100
	SecurityPosture    float64 `json:"security_posture"`    // 0-100
	BusinessActivity   float64 `json:"business_activity"`   // 0-100
	CostOptimization   float64 `json:"cost_optimization"`   // 0-100
}

// Recommendation provides actionable advice for improving tenant health
type Recommendation struct {
	ID            uuid.UUID `json:"id"`
	Category      string    `json:"category"` // "resource", "performance", "security", "business", "cost"
	Priority      string    `json:"priority"` // "high", "medium", "low"
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	Impact        string    `json:"impact"`         // "high", "medium", "low"
	Effort        string    `json:"effort"`         // "high", "medium", "low"
	PotentialGain float64   `json:"potential_gain"` // Expected score improvement
}

// HealthTrends shows historical health data
type HealthTrends struct {
	ScoreHistory   []HealthDataPoint `json:"score_history"`
	TrendDirection string            `json:"trend_direction"` // "improving", "stable", "declining"
	TrendStrength  float64           `json:"trend_strength"`  // 0-1
	PredictedScore float64           `json:"predicted_score"` // Next period prediction
}

// HealthDataPoint represents a single health measurement
type HealthDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Score     float64   `json:"score"`
	Status    string    `json:"status"`
}

// HealthMetrics represents raw metrics used for health calculation
type HealthMetrics struct {
	TenantID  uuid.UUID `json:"tenant_id"`
	Timestamp time.Time `json:"timestamp"`

	// Resource Efficiency Metrics
	CPUUtilization     float64 `json:"cpu_utilization"`
	MemoryUtilization  float64 `json:"memory_utilization"`
	StorageUtilization float64 `json:"storage_utilization"`
	NetworkUtilization float64 `json:"network_utilization"`

	// Performance Metrics
	AvgResponseTime float64 `json:"avg_response_time"`
	ErrorRate       float64 `json:"error_rate"`
	Throughput      float64 `json:"throughput"`
	Uptime          float64 `json:"uptime"`

	// Security Metrics
	FailedLogins       int       `json:"failed_logins"`
	SecurityAlerts     int       `json:"security_alerts"`
	ComplianceScore    float64   `json:"compliance_score"`
	LastSecurityUpdate time.Time `json:"last_security_update"`

	// Business Activity Metrics
	ActiveUsers    int            `json:"active_users"`
	APICalls       int            `json:"api_calls"`
	FeatureUsage   map[string]int `json:"feature_usage"`
	UserEngagement float64        `json:"user_engagement"`

	// Cost Metrics
	ResourceCost   float64 `json:"resource_cost"`
	CostPerUser    float64 `json:"cost_per_user"`
	CostEfficiency float64 `json:"cost_efficiency"`
}

// HealthAlert represents alerts for health issues
type HealthAlert struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	TenantID     uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	AlertType    string     `json:"alert_type" db:"alert_type"` // "health_decline", "critical_issue", "improvement_opportunity"
	Severity     string     `json:"severity" db:"severity"`     // "critical", "high", "medium", "low"
	Title        string     `json:"title" db:"title"`
	Description  string     `json:"description" db:"description"`
	Category     string     `json:"category" db:"category"` // "resource", "performance", "security", "business", "cost"
	CurrentValue float64    `json:"current_value" db:"current_value"`
	Threshold    float64    `json:"threshold" db:"threshold"`
	IsActive     bool       `json:"is_active" db:"is_active"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	ResolvedAt   *time.Time `json:"resolved_at" db:"resolved_at"`
}

// HealthScoreRequest represents a request to calculate health score
type HealthScoreRequest struct {
	TenantID    uuid.UUID     `json:"tenant_id"`
	Metrics     HealthMetrics `json:"metrics"`
	ForceRecalc bool          `json:"force_recalc,omitempty"`
}

// HealthScoreResponse represents the calculated health score
type HealthScoreResponse struct {
	TenantID        uuid.UUID        `json:"tenant_id"`
	OverallScore    float64          `json:"overall_score"`
	HealthStatus    string           `json:"health_status"`
	ScoreBreakdown  HealthBreakdown  `json:"score_breakdown"`
	Recommendations []Recommendation `json:"recommendations"`
	Trends          HealthTrends     `json:"trends"`
	LastCalculated  time.Time        `json:"last_calculated"`
}

// TenantHealthSummary provides a summary of health for multiple tenants
type TenantHealthSummary struct {
	TenantID        uuid.UUID `json:"tenant_id"`
	TenantName      string    `json:"tenant_name"`
	OverallScore    float64   `json:"overall_score"`
	HealthStatus    string    `json:"health_status"`
	LastCalculated  time.Time `json:"last_calculated"`
	TrendDirection  string    `json:"trend_direction"`
	CriticalAlerts  int       `json:"critical_alerts"`
	Recommendations int       `json:"recommendations"`
}

// HealthComparison represents comparison data between tenants
type HealthComparison struct {
	TenantID     uuid.UUID `json:"tenant_id"`
	TenantName   string    `json:"tenant_name"`
	Score        float64   `json:"score"`
	Percentile   float64   `json:"percentile"`    // 0-100, where 100 is best
	Rank         int       `json:"rank"`          // 1-based ranking
	BenchmarkGap float64   `json:"benchmark_gap"` // Gap from benchmark
}

// HealthBenchmark represents industry or platform benchmarks
type HealthBenchmark struct {
	Category       string  `json:"category"`
	BenchmarkScore float64 `json:"benchmark_score"`
	Description    string  `json:"description"`
	Source         string  `json:"source"`
}

// HealthInsights provides AI-driven insights about tenant health
type HealthInsights struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	Insights    []Insight `json:"insights"`
	GeneratedAt time.Time `json:"generated_at"`
	Confidence  float64   `json:"confidence"` // 0-1
}

// Insight represents a single health insight
type Insight struct {
	Type        string  `json:"type"`     // "anomaly", "trend", "recommendation", "prediction"
	Category    string  `json:"category"` // "resource", "performance", "security", "business", "cost"
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Impact      string  `json:"impact"`     // "high", "medium", "low"
	Confidence  float64 `json:"confidence"` // 0-1
	Actionable  bool    `json:"actionable"`
}
