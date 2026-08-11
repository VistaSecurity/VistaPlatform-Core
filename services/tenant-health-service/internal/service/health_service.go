package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/models"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/repository"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/scoring"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

type HealthService struct {
	repo                      *repository.HealthRepository
	scorer                    *scoring.HealthScorer
	httpClient                *http.Client
	monitoringServiceURL      string
	authServiceURL            string
	inventoryServiceURL       string
	resourceTrackerServiceURL string
}

func NewHealthService(repo *repository.HealthRepository) *HealthService {
	getURL := func(env, def string) string {
		if v := os.Getenv(env); v != "" {
			return v
		}
		return def
	}

	return &HealthService{
		repo:   repo,
		scorer: scoring.NewHealthScorer(),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		monitoringServiceURL:      getURL("MONITORING_SERVICE_URL", sharedconfig.PeerURL("monitoring-service", sharedconfig.MTLSEnabled())),
		authServiceURL:            getURL("AUTH_SERVICE_URL", sharedconfig.PeerURL("auth-service", sharedconfig.MTLSEnabled())),
		inventoryServiceURL:       getURL("INVENTORY_SERVICE_URL", sharedconfig.PeerURL("inventory-service", sharedconfig.MTLSEnabled())),
		resourceTrackerServiceURL: getURL("RESOURCE_TRACKER_SERVICE_URL", sharedconfig.PeerURL("resource-tracker-service", sharedconfig.MTLSEnabled())),
	}
}

// CalculateTenantHealth calculates and stores health score for a tenant
func (s *HealthService) CalculateTenantHealth(req *models.HealthScoreRequest) (*models.HealthScoreResponse, error) {
	// Save the raw metrics first
	if err := s.repo.SaveHealthMetrics(context.Background(), &req.Metrics); err != nil {
		logrus.WithError(err).Error("Failed to save health metrics")
		return nil, fmt.Errorf("failed to save health metrics: %w", err)
	}

	// Calculate health score
	healthResponse := s.scorer.CalculateHealthScore(req.Metrics)

	// Generate trends from historical data
	trends := s.generateTrendsFromHistory(req.TenantID, healthResponse.OverallScore, healthResponse.HealthStatus)

	// Convert to TenantHealth model for storage
	tenantHealth := &models.TenantHealth{
		ID:              uuid.New(),
		TenantID:        req.TenantID,
		OverallScore:    healthResponse.OverallScore,
		HealthStatus:    healthResponse.HealthStatus,
		LastCalculated:  healthResponse.LastCalculated,
		ScoreBreakdown:  healthResponse.ScoreBreakdown,
		Recommendations: healthResponse.Recommendations,
		Trends:          trends,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// Save the calculated health data
	if err := s.repo.SaveTenantHealth(context.Background(), tenantHealth); err != nil {
		logrus.WithError(err).Error("Failed to save tenant health")
		return nil, fmt.Errorf("failed to save tenant health: %w", err)
	}

	// Generate and save health alerts if needed
	if err := s.generateHealthAlerts(tenantHealth); err != nil {
		logrus.WithError(err).Warn("Failed to generate health alerts")
		// Don't fail the entire operation for alert generation issues
	}

	return &healthResponse, nil
}

// CalculateTenantHealthAuto automatically collects metrics from source services and calculates health score
func (s *HealthService) CalculateTenantHealthAuto(tenantID uuid.UUID) (*models.HealthScoreResponse, error) {
	// Collect metrics from all source services
	metrics, err := s.collectMetricsFromServices(tenantID)
	if err != nil {
		logrus.WithError(err).WithField("tenant_id", tenantID).Error("Failed to collect metrics from services")
		return nil, fmt.Errorf("failed to collect metrics from services: %w", err)
	}

	// Create health score request
	req := &models.HealthScoreRequest{
		TenantID: tenantID,
		Metrics:  *metrics,
	}

	// Calculate health score using existing method
	return s.CalculateTenantHealth(req)
}

// collectMetricsFromServices collects metrics from all source services via the gateway
func (s *HealthService) collectMetricsFromServices(tenantID uuid.UUID) (*models.HealthMetrics, error) {
	metrics := &models.HealthMetrics{
		TenantID:     tenantID,
		Timestamp:    time.Now(),
		FeatureUsage: make(map[string]int),
	}

	// Collect performance metrics from monitoring-service
	if perfMetrics, err := s.getPerformanceMetrics(tenantID); err == nil {
		metrics.AvgResponseTime = perfMetrics.AvgResponseTime
		metrics.ErrorRate = perfMetrics.ErrorRate
		metrics.Throughput = perfMetrics.Throughput
		metrics.Uptime = perfMetrics.Uptime
	} else {
		logrus.WithError(err).WithField("tenant_id", tenantID).Warn("Failed to get performance metrics, using defaults")
		// Use defaults if monitoring-service is unavailable
		metrics.AvgResponseTime = 150.0
		metrics.ErrorRate = 0.005
		metrics.Throughput = 100.0
		metrics.Uptime = 99.9
	}

	// Collect security metrics from auth-service
	if secMetrics, err := s.getSecurityMetrics(tenantID); err == nil {
		metrics.FailedLogins = secMetrics.FailedLogins
		metrics.SecurityAlerts = secMetrics.SecurityAlerts
		metrics.ComplianceScore = secMetrics.ComplianceScore
		metrics.LastSecurityUpdate = secMetrics.LastSecurityUpdate
	} else {
		logrus.WithError(err).WithField("tenant_id", tenantID).Warn("Failed to get security metrics, using defaults")
		// Use defaults if auth-service is unavailable
		metrics.FailedLogins = 0
		metrics.SecurityAlerts = 0
		metrics.ComplianceScore = 85.0
		metrics.LastSecurityUpdate = time.Now()
	}

	// Collect activity metrics from inventory-service
	if actMetrics, err := s.getActivityMetrics(tenantID); err == nil {
		metrics.ActiveUsers = actMetrics.ActiveUsers
		metrics.APICalls = actMetrics.APICalls
		metrics.FeatureUsage = actMetrics.FeatureUsage
		metrics.UserEngagement = actMetrics.UserEngagement
	} else {
		logrus.WithError(err).WithField("tenant_id", tenantID).Warn("Failed to get activity metrics, using defaults")
		// Use defaults if inventory-service is unavailable
		metrics.ActiveUsers = 0
		metrics.APICalls = 0
		metrics.UserEngagement = 50.0
	}

	// Collect resource metrics from resource-tracker-service
	if resMetrics, err := s.getResourceMetrics(tenantID); err == nil {
		metrics.CPUUtilization = resMetrics.AvgCPUPercent
		metrics.MemoryUtilization = resMetrics.AvgMemoryMB / 100.0 // Convert MB to percentage (assumes 100MB = 1%)
		metrics.ResourceCost = resMetrics.TotalCostUSD
		metrics.CostEfficiency = resMetrics.ResourceEfficiencyScore
		// Calculate cost per user
		if metrics.ActiveUsers > 0 {
			metrics.CostPerUser = resMetrics.TotalCostUSD / float64(metrics.ActiveUsers)
		} else {
			metrics.CostPerUser = resMetrics.TotalCostUSD // Fallback if no active users
		}
		// Estimate storage/network utilization from resource data
		metrics.StorageUtilization = 50.0 // Default - could be enhanced with actual storage data
		metrics.NetworkUtilization = 60.0 // Default - could be enhanced with actual network data
	} else {
		logrus.WithError(err).WithField("tenant_id", tenantID).Warn("Failed to get resource metrics, using defaults")
		// Use defaults if resource-tracker-service is unavailable
		metrics.CPUUtilization = 50.0
		metrics.MemoryUtilization = 60.0
		metrics.StorageUtilization = 50.0
		metrics.NetworkUtilization = 60.0
		metrics.ResourceCost = 0.0
		metrics.CostPerUser = 0.0
		metrics.CostEfficiency = 75.0
	}

	return metrics, nil
}

// PerformanceMetrics represents performance metrics from monitoring-service
type PerformanceMetrics struct {
	AvgResponseTime float64 `json:"avg_response_time_ms"`
	ErrorRate       float64 `json:"error_rate"`
	Throughput      float64 `json:"throughput_rps"`
	Uptime          float64 `json:"uptime_percent"`
}

// getPerformanceMetrics retrieves performance metrics from monitoring-service
func (s *HealthService) getPerformanceMetrics(tenantID uuid.UUID) (*PerformanceMetrics, error) {
	url := fmt.Sprintf("%s/api/v1/monitoring-service/tenant/%s/performance-summary", s.monitoringServiceURL, tenantID.String())
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Tenant-ID", tenantID.String())
	serviceauth.SignRequestFromEnv(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call monitoring-service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("monitoring-service returned status %d: %s", resp.StatusCode, string(body))
	}

	var data PerformanceMetrics

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &data, nil
}

// SecurityMetrics represents security metrics from auth-service
type SecurityMetrics struct {
	FailedLogins       int       `json:"failed_logins"`
	SecurityAlerts     int       `json:"security_alerts"`
	ComplianceScore    float64   `json:"compliance_score"`
	LastSecurityUpdate time.Time `json:"-"` // Not directly from JSON, parsed separately
}

// getSecurityMetrics retrieves security metrics from auth-service
func (s *HealthService) getSecurityMetrics(tenantID uuid.UUID) (*SecurityMetrics, error) {
	url := fmt.Sprintf("%s/api/v1/auth-service/tenant/%s/security-summary", s.authServiceURL, tenantID.String())
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Tenant-ID", tenantID.String())
	serviceauth.SignRequestFromEnv(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call auth-service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("auth-service returned status %d: %s", resp.StatusCode, string(body))
	}

	var data struct {
		FailedLogins       int     `json:"failed_logins"`
		SecurityAlerts     int     `json:"security_alerts"`
		ComplianceScore    float64 `json:"compliance_score"`
		LastSecurityUpdate string  `json:"last_security_update"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Parse LastSecurityUpdate
	var lastUpdate time.Time
	if data.LastSecurityUpdate != "" {
		parsed, err := time.Parse(time.RFC3339, data.LastSecurityUpdate)
		if err == nil {
			lastUpdate = parsed
		} else {
			lastUpdate = time.Now()
		}
	} else {
		lastUpdate = time.Now()
	}

	return &SecurityMetrics{
		FailedLogins:       data.FailedLogins,
		SecurityAlerts:     data.SecurityAlerts,
		ComplianceScore:    data.ComplianceScore,
		LastSecurityUpdate: lastUpdate,
	}, nil
}

// ActivityMetrics represents activity metrics from inventory-service
type ActivityMetrics struct {
	ActiveUsers    int            `json:"active_users"`
	APICalls       int            `json:"api_calls"`
	FeatureUsage   map[string]int `json:"feature_usage"`
	UserEngagement float64        `json:"user_engagement"`
}

// getActivityMetrics retrieves activity metrics from inventory-service
func (s *HealthService) getActivityMetrics(tenantID uuid.UUID) (*ActivityMetrics, error) {
	url := fmt.Sprintf("%s/api/v1/inventory-service/tenant/%s/activity-summary", s.inventoryServiceURL, tenantID.String())
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Tenant-ID", tenantID.String())
	serviceauth.SignRequestFromEnv(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call inventory-service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("inventory-service returned status %d: %s", resp.StatusCode, string(body))
	}

	var data ActivityMetrics

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &data, nil
}

// ResourceMetrics represents resource metrics from resource-tracker-service
type ResourceMetrics struct {
	AvgCPUPercent           float64 `json:"avg_cpu_percent"`
	AvgMemoryMB             float64 `json:"avg_memory_mb"`
	TotalCostUSD            float64 `json:"total_cost_usd"`
	ResourceEfficiencyScore float64 `json:"resource_efficiency_score"`
}

// getResourceMetrics retrieves resource metrics from resource-tracker-service
func (s *HealthService) getResourceMetrics(tenantID uuid.UUID) (*ResourceMetrics, error) {
	url := fmt.Sprintf("%s/api/v1/resource-tracker-service/tenant/%s/resource-summary", s.resourceTrackerServiceURL, tenantID.String())
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Tenant-ID", tenantID.String())
	serviceauth.SignRequestFromEnv(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call resource-tracker-service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("resource-tracker-service returned status %d: %s", resp.StatusCode, string(body))
	}

	var data ResourceMetrics

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &data, nil
}

// GetTenantHealth retrieves health data for a specific tenant
// If autoCalculate is true and no health data exists, it will automatically collect metrics and calculate health
func (s *HealthService) GetTenantHealth(tenantID uuid.UUID, autoCalculate bool) (*models.TenantHealth, error) {
	health, err := s.repo.GetTenantHealth(context.Background(), tenantID)
	if err != nil {
		logrus.WithError(err).Error("Failed to get tenant health")
		return nil, fmt.Errorf("failed to get tenant health: %w", err)
	}

	if health == nil {
		if autoCalculate {
			// Automatically calculate health if no data exists
			logrus.WithField("tenant_id", tenantID).Info("No health data found, auto-calculating health score")
			_, err := s.CalculateTenantHealthAuto(tenantID)
			if err != nil {
				logrus.WithError(err).Error("Failed to auto-calculate tenant health")
				// Return default response if auto-calculation fails
				return &models.TenantHealth{
					ID:              uuid.New(),
					TenantID:        tenantID,
					OverallScore:    0.0,
					HealthStatus:    "unknown",
					LastCalculated:  time.Now(),
					ScoreBreakdown:  models.HealthBreakdown{},
					Recommendations: []models.Recommendation{},
					Trends:          models.HealthTrends{},
					CreatedAt:       time.Now(),
					UpdatedAt:       time.Now(),
				}, nil
			}

			// Fetch the newly calculated health from the database
			health, err = s.repo.GetTenantHealth(context.Background(), tenantID)
			if err != nil {
				logrus.WithError(err).Error("Failed to get newly calculated health")
				return nil, fmt.Errorf("failed to get newly calculated health: %w", err)
			}
		} else {
			// No health data exists, return a default response
			return &models.TenantHealth{
				ID:              uuid.New(),
				TenantID:        tenantID,
				OverallScore:    0.0,
				HealthStatus:    "unknown",
				LastCalculated:  time.Now(),
				ScoreBreakdown:  models.HealthBreakdown{},
				Recommendations: []models.Recommendation{},
				Trends:          models.HealthTrends{},
				CreatedAt:       time.Now(),
				UpdatedAt:       time.Now(),
			}, nil
		}
	}

	return health, nil
}

// GetAllTenantHealthOptions defines filtering and pagination options for GetAllTenantHealth
type GetAllTenantHealthOptions struct {
	Limit     int
	Offset    int
	Status    string
	MinScore  float64
	MaxScore  float64
	SortBy    string
	SortOrder string
}

// GetAllTenantHealth retrieves health summaries for all tenants with optional filtering and pagination
func (s *HealthService) GetAllTenantHealth(options *GetAllTenantHealthOptions) ([]models.TenantHealthSummary, error) {
	repoOptions := &repository.GetAllTenantHealthOptions{
		Limit:     options.Limit,
		Offset:    options.Offset,
		Status:    options.Status,
		MinScore:  options.MinScore,
		MaxScore:  options.MaxScore,
		SortBy:    options.SortBy,
		SortOrder: options.SortOrder,
	}
	summaries, err := s.repo.GetAllTenantHealth(repoOptions)
	if err != nil {
		logrus.WithError(err).Error("Failed to get all tenant health")
		return nil, fmt.Errorf("failed to get all tenant health: %w", err)
	}

	return summaries, nil
}

// GetHealthAlerts retrieves health alerts for a tenant
func (s *HealthService) GetHealthAlerts(tenantID uuid.UUID, activeOnly bool) ([]models.HealthAlert, error) {
	alerts, err := s.repo.GetHealthAlerts(context.Background(), tenantID, activeOnly)
	if err != nil {
		logrus.WithError(err).Error("Failed to get health alerts")
		return nil, fmt.Errorf("failed to get health alerts: %w", err)
	}

	return alerts, nil
}

// GetHealthMetrics retrieves health metrics for a tenant
func (s *HealthService) GetHealthMetrics(tenantID uuid.UUID, startTime, endTime time.Time) ([]models.HealthMetrics, error) {
	metrics, err := s.repo.GetHealthMetrics(context.Background(), tenantID, startTime, endTime)
	if err != nil {
		logrus.WithError(err).Error("Failed to get health metrics")
		return nil, fmt.Errorf("failed to get health metrics: %w", err)
	}

	return metrics, nil
}

// GetHealthBenchmarks retrieves industry benchmarks
func (s *HealthService) GetHealthBenchmarks() ([]models.HealthBenchmark, error) {
	benchmarks, err := s.repo.GetHealthBenchmarks()
	if err != nil {
		logrus.WithError(err).Error("Failed to get health benchmarks")
		return nil, fmt.Errorf("failed to get health benchmarks: %w", err)
	}

	return benchmarks, nil
}

// GetHealthComparison compares tenant health against benchmarks and other tenants
func (s *HealthService) GetHealthComparison(tenantID uuid.UUID) (*models.HealthComparison, error) {
	// Get tenant health (with auto-calculation if needed)
	health, err := s.GetTenantHealth(tenantID, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant health: %w", err)
	}

	// Get all tenant summaries for comparison (no filtering/pagination needed for comparison)
	summaries, err := s.GetAllTenantHealth(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant summaries: %w", err)
	}

	// Calculate percentile and rank
	rank := 1
	betterCount := 0
	totalCount := len(summaries)

	for _, summary := range summaries {
		if summary.TenantID == tenantID {
			continue
		}
		if summary.OverallScore > health.OverallScore {
			betterCount++
			rank++
		}
	}

	percentile := float64(totalCount-betterCount) / float64(totalCount) * 100.0
	if totalCount == 0 {
		percentile = 50.0 // Default to median if no other tenants
	}

	// Calculate benchmark gap (assuming 75.0 as industry benchmark)
	benchmarkGap := health.OverallScore - 75.0

	comparison := &models.HealthComparison{
		TenantID:     tenantID,
		TenantName:   s.repo.GetTenantName(tenantID),
		Score:        health.OverallScore,
		Percentile:   percentile,
		Rank:         rank,
		BenchmarkGap: benchmarkGap,
	}

	return comparison, nil
}

// GenerateHealthInsights creates AI-driven insights about tenant health
func (s *HealthService) GenerateHealthInsights(tenantID uuid.UUID) (*models.HealthInsights, error) {
	// Get tenant health data (with auto-calculation if needed)
	health, err := s.GetTenantHealth(tenantID, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant health: %w", err)
	}

	// Get recent metrics for trend analysis
	endTime := time.Now()
	startTime := endTime.Add(-7 * 24 * time.Hour) // Last 7 days
	metrics, err := s.GetHealthMetrics(tenantID, startTime, endTime)
	if err != nil {
		logrus.WithError(err).Warn("Failed to get health metrics for insights")
		metrics = []models.HealthMetrics{} // Continue with empty metrics
	}

	// Generate insights based on health data and trends
	insights := s.generateInsights(health, metrics)

	healthInsights := &models.HealthInsights{
		TenantID:    tenantID,
		Insights:    insights,
		GeneratedAt: time.Now(),
		Confidence:  s.calculateInsightConfidence(insights),
	}

	return healthInsights, nil
}

// generateHealthAlerts creates alerts based on health score and recommendations
func (s *HealthService) generateHealthAlerts(health *models.TenantHealth) error {
	var alerts []models.HealthAlert

	// Critical health status alert
	if health.HealthStatus == "critical" {
		alerts = append(alerts, models.HealthAlert{
			ID:           uuid.New(),
			TenantID:     health.TenantID,
			AlertType:    "health_decline",
			Severity:     "critical",
			Title:        "Critical Health Status",
			Description:  "Tenant health has reached critical levels. Immediate attention required.",
			Category:     "overall",
			CurrentValue: health.OverallScore,
			Threshold:    40.0,
			IsActive:     true,
			CreatedAt:    time.Now(),
		})
	}

	// Poor health status alert
	if health.HealthStatus == "poor" {
		alerts = append(alerts, models.HealthAlert{
			ID:           uuid.New(),
			TenantID:     health.TenantID,
			AlertType:    "health_decline",
			Severity:     "high",
			Title:        "Poor Health Status",
			Description:  "Tenant health is below acceptable levels. Review recommendations.",
			Category:     "overall",
			CurrentValue: health.OverallScore,
			Threshold:    60.0,
			IsActive:     true,
			CreatedAt:    time.Now(),
		})
	}

	// High priority recommendations alert
	highPriorityRecs := 0
	for _, rec := range health.Recommendations {
		if rec.Priority == "high" || rec.Priority == "critical" {
			highPriorityRecs++
		}
	}

	if highPriorityRecs > 0 {
		alerts = append(alerts, models.HealthAlert{
			ID:           uuid.New(),
			TenantID:     health.TenantID,
			AlertType:    "improvement_opportunity",
			Severity:     "medium",
			Title:        "High Priority Recommendations",
			Description:  fmt.Sprintf("%d high priority recommendations available for health improvement.", highPriorityRecs),
			Category:     "recommendations",
			CurrentValue: float64(highPriorityRecs),
			Threshold:    0.0,
			IsActive:     true,
			CreatedAt:    time.Now(),
		})
	}

	// Save alerts
	for _, alert := range alerts {
		if err := s.repo.SaveHealthAlert(context.Background(), &alert); err != nil {
			logrus.WithError(err).Error("Failed to save health alert")
			return err
		}
	}

	return nil
}

// generateInsights creates AI-driven insights based on health data
func (s *HealthService) generateInsights(health *models.TenantHealth, metrics []models.HealthMetrics) []models.Insight {
	var insights []models.Insight

	// Overall health insight
	if health.OverallScore >= 90 {
		insights = append(insights, models.Insight{
			Type:        "trend",
			Category:    "overall",
			Title:       "Excellent Health Performance",
			Description: "This tenant demonstrates exceptional health across all metrics. Consider sharing best practices with other tenants.",
			Impact:      "high",
			Confidence:  0.95,
			Actionable:  true,
		})
	} else if health.OverallScore < 50 {
		insights = append(insights, models.Insight{
			Type:        "anomaly",
			Category:    "overall",
			Title:       "Critical Health Issues Detected",
			Description: "Multiple health factors require immediate attention. Focus on high-impact recommendations first.",
			Impact:      "critical",
			Confidence:  0.90,
			Actionable:  true,
		})
	}

	// Resource efficiency insights
	if health.ScoreBreakdown.ResourceEfficiency < 60 {
		insights = append(insights, models.Insight{
			Type:        "recommendation",
			Category:    "resource",
			Title:       "Resource Optimization Opportunity",
			Description: "Resource utilization can be significantly improved. Consider implementing auto-scaling or resource optimization strategies.",
			Impact:      "high",
			Confidence:  0.85,
			Actionable:  true,
		})
	}

	// Performance insights
	if health.ScoreBreakdown.PerformanceMetrics < 70 {
		insights = append(insights, models.Insight{
			Type:        "anomaly",
			Category:    "performance",
			Title:       "Performance Bottlenecks Identified",
			Description: "Performance metrics indicate potential bottlenecks. Review response times and error rates for optimization opportunities.",
			Impact:      "high",
			Confidence:  0.80,
			Actionable:  true,
		})
	}

	// Security insights
	if health.ScoreBreakdown.SecurityPosture < 80 {
		insights = append(insights, models.Insight{
			Type:        "recommendation",
			Category:    "security",
			Title:       "Security Posture Enhancement",
			Description: "Security metrics suggest room for improvement. Review authentication, authorization, and compliance measures.",
			Impact:      "high",
			Confidence:  0.75,
			Actionable:  true,
		})
	}

	// Trend-based insights
	if health.Trends.TrendDirection == "declining" && health.Trends.TrendStrength > 0.7 {
		insights = append(insights, models.Insight{
			Type:        "prediction",
			Category:    "trend",
			Title:       "Declining Health Trend",
			Description: "Health metrics show a strong declining trend. Proactive intervention recommended to prevent further degradation.",
			Impact:      "high",
			Confidence:  0.70,
			Actionable:  true,
		})
	} else if health.Trends.TrendDirection == "improving" && health.Trends.TrendStrength > 0.7 {
		insights = append(insights, models.Insight{
			Type:        "trend",
			Category:    "trend",
			Title:       "Improving Health Trend",
			Description: "Health metrics show strong improvement. Continue current optimization strategies for sustained growth.",
			Impact:      "medium",
			Confidence:  0.80,
			Actionable:  true,
		})
	}

	return insights
}

// calculateInsightConfidence calculates overall confidence in the insights
func (s *HealthService) calculateInsightConfidence(insights []models.Insight) float64 {
	if len(insights) == 0 {
		return 0.0
	}

	totalConfidence := 0.0
	for _, insight := range insights {
		totalConfidence += insight.Confidence
	}

	return totalConfidence / float64(len(insights))
}

// generateTrendsFromHistory generates trend analysis from historical health data
func (s *HealthService) generateTrendsFromHistory(tenantID uuid.UUID, currentScore float64, currentStatus string) models.HealthTrends {
	// Query historical health metrics from the last 30 days
	endTime := time.Now()
	startTime := endTime.Add(-30 * 24 * time.Hour)

	historicalMetrics, err := s.repo.GetHealthMetrics(context.Background(), tenantID, startTime, endTime)
	if err != nil || len(historicalMetrics) == 0 {
		// Fallback to simple trend if no historical data
		return models.HealthTrends{
			ScoreHistory:   []models.HealthDataPoint{{Timestamp: time.Now(), Score: currentScore, Status: currentStatus}},
			TrendDirection: "stable",
			TrendStrength:  0.5,
			PredictedScore: currentScore,
		}
	}

	// Build score history from historical metrics
	var scoreHistory []models.HealthDataPoint

	// Calculate approximate scores from metrics for trend
	for i, metric := range historicalMetrics {
		if i >= 30 { // Limit to 30 data points
			break
		}
		// Calculate approximate score from metrics
		approxScore := s.calculateScoreFromMetrics(metric)
		scoreHistory = append(scoreHistory, models.HealthDataPoint{
			Timestamp: metric.Timestamp,
			Score:     approxScore,
			Status:    s.determineStatusFromScore(approxScore),
		})
	}

	// Add current score at the beginning
	scoreHistory = append([]models.HealthDataPoint{{
		Timestamp: time.Now(),
		Score:     currentScore,
		Status:    currentStatus,
	}}, scoreHistory...)

	// Calculate trend direction and strength
	trendDirection := "stable"
	trendStrength := 0.5
	predictedScore := currentScore

	if len(scoreHistory) >= 2 {
		// Calculate trend from recent data points
		recent := scoreHistory[0].Score
		previous := scoreHistory[1].Score
		diff := recent - previous

		if diff > 2 {
			trendDirection = "improving"
			trendStrength = math.Min(1.0, diff/10.0)
		} else if diff < -2 {
			trendDirection = "declining"
			trendStrength = math.Min(1.0, math.Abs(diff)/10.0)
		}

		// Calculate average change rate for prediction
		if len(scoreHistory) >= 3 {
			avgChange := 0.0
			count := 0
			for i := 0; i < len(scoreHistory)-1 && i < 10; i++ {
				avgChange += scoreHistory[i].Score - scoreHistory[i+1].Score
				count++
			}
			if count > 0 {
				avgChange = avgChange / float64(count)
			}

			// Predict next score based on average change
			predictedScore = currentScore + avgChange
			if predictedScore > 100.0 {
				predictedScore = 100.0
			}
			if predictedScore < 0.0 {
				predictedScore = 0.0
			}
		} else {
			// Simple prediction for limited data
			if trendDirection == "improving" {
				predictedScore = math.Min(100.0, currentScore+trendStrength*5.0)
			} else if trendDirection == "declining" {
				predictedScore = math.Max(0.0, currentScore-trendStrength*5.0)
			}
		}
	}

	return models.HealthTrends{
		ScoreHistory:   scoreHistory,
		TrendDirection: trendDirection,
		TrendStrength:  trendStrength,
		PredictedScore: predictedScore,
	}
}

// calculateScoreFromMetrics calculates an approximate health score from metrics
func (s *HealthService) calculateScoreFromMetrics(metrics models.HealthMetrics) float64 {
	// Use the scorer to calculate score from metrics
	response := s.scorer.CalculateHealthScore(metrics)
	return response.OverallScore
}

// determineStatusFromScore determines health status from score
func (s *HealthService) determineStatusFromScore(score float64) string {
	if score >= 80 {
		return "excellent"
	} else if score >= 60 {
		return "good"
	} else if score >= 40 {
		return "fair"
	} else if score >= 20 {
		return "poor"
	}
	return "critical"
}
