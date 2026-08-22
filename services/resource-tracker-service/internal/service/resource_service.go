package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/aws"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/models"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/repository"
	"github.com/vistasecurity/vistaplatform/shared/costing"
)

type ResourceService struct {
	repo           *repository.ResourceRepository
	awsCostRepo    *repository.AWSCostRepository
	awsCostService *aws.CostExplorerService
	awsCostEnabled bool
	log            *logrus.Logger
}

func NewResourceService(repo *repository.ResourceRepository, awsCostRepo *repository.AWSCostRepository, awsCostService *aws.CostExplorerService, awsCostEnabled bool, log *logrus.Logger) *ResourceService {
	return &ResourceService{
		repo:           repo,
		awsCostRepo:    awsCostRepo,
		awsCostService: awsCostService,
		awsCostEnabled: awsCostEnabled,
		log:            log,
	}
}

// RecordResourceMetrics records resource usage metrics for a tenant
func (s *ResourceService) RecordResourceMetrics(req *models.ResourceMetricsRequest) error {
	exists, err := s.repo.TenantExists(req.TenantID)
	if err != nil {
		s.log.WithError(err).WithField("tenant_id", req.TenantID).Warn("Tenant lookup failed; skipping resource metrics")
		return nil
	}
	if !exists {
		s.log.WithField("tenant_id", req.TenantID).Debug("Skipping resource metrics for unknown or deleted tenant")
		return nil
	}

	usage := &models.ResourceUsage{
		ID:              uuid.New(),
		TenantID:        req.TenantID,
		Timestamp:       time.Now(),
		APICalls:        req.APICalls,
		DatabaseQueries: req.DatabaseQueries,
		MemoryUsageMB:   req.MemoryUsageMB,
		CPUUsagePercent: req.CPUUsagePercent,
		StorageUsedMB:   req.StorageUsedMB,
		NetworkBytes:    req.NetworkBytes,
		CreatedAt:       time.Now(),
	}

	// Calculate estimated cost first (as fallback)
	estimatedCost := s.calculateCost(usage)
	usage.CostUSD = estimatedCost

	// If AWS cost integration is enabled, try to get real AWS costs
	if s.awsCostEnabled && s.awsCostRepo != nil {
		ctx := context.Background()
		now := time.Now()
		periodStart := now.Add(-24 * time.Hour) // Last 24 hours

		// Try to get AWS costs from database
		awsCost, err := s.awsCostRepo.GetTotalCostForPeriod(ctx, &req.TenantID, periodStart, now)
		if err == nil && awsCost > 0 {
			// Use AWS cost if available
			usage.CostUSD = awsCost
			s.log.WithFields(logrus.Fields{
				"tenant_id": req.TenantID,
				"aws_cost":  awsCost,
				"estimated": estimatedCost,
			}).Info("Using AWS cost data")
		} else {
			// Fallback to estimated cost
			s.log.WithError(err).WithFields(logrus.Fields{
				"tenant_id": req.TenantID,
				"estimated": estimatedCost,
			}).Debug("Falling back to estimated cost")
		}
	}

	// Record the usage
	err = s.repo.RecordResourceUsage(usage)
	if err != nil {
		s.log.WithError(err).Error("Failed to record resource usage")
		return err
	}

	// Check for alerts
	s.checkAndCreateAlerts(usage)

	s.log.WithFields(logrus.Fields{
		"tenant_id": req.TenantID,
		"api_calls": req.APICalls,
		"cost_usd":  usage.CostUSD,
	}).Info("Resource metrics recorded")

	return nil
}

// GetTenantResourceUsage retrieves resource usage for a specific tenant
func (s *ResourceService) GetTenantResourceUsage(tenantID uuid.UUID, period string) (*models.ResourceUsageResponse, error) {
	usage, err := s.repo.GetResourceUsageByTenant(tenantID, period)
	if err != nil {
		s.log.WithError(err).WithField("tenant_id", tenantID).Error("Failed to get tenant resource usage")
		return nil, err
	}

	// Get active alerts for the tenant
	alerts, err := s.repo.GetActiveAlerts(tenantID)
	if err != nil {
		s.log.WithError(err).WithField("tenant_id", tenantID).Error("Failed to get active alerts")
		// Don't fail the request if alerts can't be retrieved
		alerts = []models.ResourceAlert{}
	}

	usage.Alerts = alerts

	return usage, nil
}

// GetTenantResourceTrend retrieves resource usage trend for a tenant
func (s *ResourceService) GetTenantResourceTrend(tenantID uuid.UUID, period string) ([]models.ResourceDataPoint, error) {
	trend, err := s.repo.GetResourceUsageTrend(tenantID, period)
	if err != nil {
		s.log.WithError(err).WithField("tenant_id", tenantID).Error("Failed to get resource trend")
		return nil, err
	}

	return trend, nil
}

// GetTenantCostTrend retrieves cost trend for a tenant
func (s *ResourceService) GetTenantCostTrend(tenantID uuid.UUID, period string) ([]models.CostDataPoint, error) {
	trend, err := s.repo.GetCostTrend(tenantID, period)
	if err != nil {
		s.log.WithError(err).WithField("tenant_id", tenantID).Error("Failed to get cost trend")
		return nil, err
	}

	return trend, nil
}

// GetAllTenantsResourceUsage retrieves resource usage summary for all tenants
func (s *ResourceService) GetAllTenantsResourceUsage(period string) ([]models.TenantResourceSummary, error) {
	summaries, err := s.repo.GetAllTenantsResourceUsage(period)
	if err != nil {
		s.log.WithError(err).Error("Failed to get all tenants resource usage")
		return nil, err
	}

	return summaries, nil
}

// GenerateCostAnalysis generates cost analysis for a tenant
func (s *ResourceService) GenerateCostAnalysis(tenantID uuid.UUID, period string) (*models.CostAnalysis, error) {
	// Get current usage
	usage, err := s.GetTenantResourceUsage(tenantID, period)
	if err != nil {
		return nil, err
	}

	// Get cost trend
	_, err = s.GetTenantCostTrend(tenantID, period)
	if err != nil {
		return nil, err
	}

	// Generate optimization suggestions
	suggestions := s.generateOptimizationSuggestions(usage)

	// Calculate period dates
	now := time.Now()
	var periodStart time.Time
	switch period {
	case "1h":
		periodStart = now.Add(-1 * time.Hour)
	case "24h":
		periodStart = now.Add(-24 * time.Hour)
	case "7d":
		periodStart = now.Add(-7 * 24 * time.Hour)
	case "30d":
		periodStart = now.Add(-30 * 24 * time.Hour)
	default:
		periodStart = now.Add(-24 * time.Hour)
	}

	analysis := &models.CostAnalysis{
		ID:                      uuid.New(),
		TenantID:                tenantID,
		PeriodStart:             periodStart,
		PeriodEnd:               now,
		TotalCostUSD:            usage.TotalCostUSD,
		ResourceBreakdown:       usage.CostBreakdown,
		OptimizationSuggestions: suggestions,
		CreatedAt:               now,
	}

	return analysis, nil
}

// calculateCost prices a single sample's per-unit (counter) components.
//
// Only counters are priceable here. A sample's api_calls / database_queries /
// network_bytes are already interval sums, so a per-unit rate applies directly
// and no window is needed. Storage is a point-in-time gauge rated per
// GB-month: it has no meaning for one sample and is priced only at read time,
// over a known window. The superseded version priced the gauge per sample AND
// applied the per-GB rates to megabyte counts.
//
// Read paths do not consume this value — they recompute from the raw columns
// over the requested window, so a headline and its itemisation always come
// from a single costing.Compute call and cannot diverge.
func (s *ResourceService) calculateCost(usage *models.ResourceUsage) float64 {
	return costing.Compute(costing.Usage{
		APICalls:        usage.APICalls,
		DatabaseQueries: usage.DatabaseQueries,
		NetworkBytes:    usage.NetworkBytes,
		// StorageBytes and Window are deliberately unset: see above.
	}, costing.DefaultRates()).TotalUSD
}

// createAlert persists a threshold alert.
//
// A persist failure is logged rather than discarded: an alert that was never
// written is indistinguishable, downstream, from a threshold that was never
// crossed. The caller has no return path, so logging is the handling.
func (s *ResourceService) createAlert(alert *models.ResourceAlert) {
	if err := s.repo.CreateResourceAlert(alert); err != nil {
		s.log.WithError(err).WithFields(logrus.Fields{
			"tenant_id": alert.TenantID,
			"metric":    alert.Metric,
		}).Error("Failed to create resource alert")
	}
}

// Helper function to check and create alerts.
//
// Every threshold reads through a nil check: an unmeasured metric must not
// raise an alert, and must not be treated as a comfortable zero either.
func (s *ResourceService) checkAndCreateAlerts(usage *models.ResourceUsage) {
	// Check for high API usage
	if usage.APICalls != nil && *usage.APICalls > 10000 {
		alert := &models.ResourceAlert{
			ID:           uuid.New(),
			TenantID:     usage.TenantID,
			AlertType:    "usage",
			Metric:       "api_calls",
			Threshold:    10000,
			CurrentValue: float64(*usage.APICalls),
			Message:      "High API usage detected",
			Severity:     "warning",
			IsActive:     true,
			CreatedAt:    time.Now(),
		}
		s.createAlert(alert)
	}

	// Check for high memory usage
	if usage.MemoryUsageMB != nil && *usage.MemoryUsageMB > 1000 {
		alert := &models.ResourceAlert{
			ID:           uuid.New(),
			TenantID:     usage.TenantID,
			AlertType:    "usage",
			Metric:       "memory_usage",
			Threshold:    1000,
			CurrentValue: float64(*usage.MemoryUsageMB),
			Message:      "High memory usage detected",
			Severity:     "warning",
			IsActive:     true,
			CreatedAt:    time.Now(),
		}
		s.createAlert(alert)
	}

	// Check for high CPU usage
	if usage.CPUUsagePercent != nil && *usage.CPUUsagePercent > 80 {
		alert := &models.ResourceAlert{
			ID:           uuid.New(),
			TenantID:     usage.TenantID,
			AlertType:    "performance",
			Metric:       "cpu_usage",
			Threshold:    80,
			CurrentValue: *usage.CPUUsagePercent,
			Message:      "High CPU usage detected",
			Severity:     "critical",
			IsActive:     true,
			CreatedAt:    time.Now(),
		}
		s.createAlert(alert)
	}

	// Check for high cost
	if usage.CostUSD > 10.0 {
		alert := &models.ResourceAlert{
			ID:           uuid.New(),
			TenantID:     usage.TenantID,
			AlertType:    "cost",
			Metric:       "cost_usd",
			Threshold:    10.0,
			CurrentValue: usage.CostUSD,
			Message:      "High cost detected",
			Severity:     "warning",
			IsActive:     true,
			CreatedAt:    time.Now(),
		}
		s.createAlert(alert)
	}
}

// Helper function to generate optimization suggestions
func (s *ResourceService) generateOptimizationSuggestions(usage *models.ResourceUsageResponse) []models.OptimizationSuggestion {
	var suggestions []models.OptimizationSuggestion

	// API optimization suggestions
	if usage.TotalAPICalls > 50000 {
		suggestions = append(suggestions, models.OptimizationSuggestion{
			Type:             "api",
			Description:      "Consider implementing API caching to reduce redundant calls",
			PotentialSavings: float64(usage.TotalAPICalls) * 0.00005,
			Priority:         "high",
		})
	}

	// Database optimization suggestions
	if usage.TotalDBQueries > 10000 {
		suggestions = append(suggestions, models.OptimizationSuggestion{
			Type:             "database",
			Description:      "Optimize database queries and consider query caching",
			PotentialSavings: float64(usage.TotalDBQueries) * 0.00002,
			Priority:         "medium",
		})
	}

	// Memory optimization suggestions
	if usage.AvgMemoryMB > 500 {
		suggestions = append(suggestions, models.OptimizationSuggestion{
			Type:             "compute",
			Description:      "Consider memory optimization and garbage collection tuning",
			PotentialSavings: float64(usage.AvgMemoryMB) * 0.01,
			Priority:         "medium",
		})
	}

	// Storage optimization suggestions
	if usage.TotalStorageMB > 10000 {
		suggestions = append(suggestions, models.OptimizationSuggestion{
			Type:             "storage",
			Description:      "Implement data compression and cleanup old data",
			PotentialSavings: float64(usage.TotalStorageMB) * 0.005,
			Priority:         "low",
		})
	}

	return suggestions
}

// GetTenantResourceHealthSummary returns resource health metrics for a specific tenant (for tenant health service)
func (s *ResourceService) GetTenantResourceHealthSummary(tenantID uuid.UUID) (*models.TenantResourceHealthSummary, error) {
	summary := &models.TenantResourceHealthSummary{
		TenantID:                tenantID,
		LastUpdated:             time.Now(),
		ResourceEfficiencyScore: 75.0, // Default efficiency score
	}

	// Get resource usage for last 24 hours
	usage, err := s.GetTenantResourceUsage(tenantID, "24h")
	if err != nil {
		// If we can't get usage data, return defaults
		s.log.WithError(err).WithField("tenant_id", tenantID).Warn("Failed to get tenant resource usage, using defaults")
		return summary, nil
	}

	// Populate summary from usage data
	summary.TotalAPICalls = usage.TotalAPICalls
	summary.TotalDBQueries = usage.TotalDBQueries
	summary.AvgCPUPercent = usage.AvgCPUPercent
	summary.AvgMemoryMB = usage.AvgMemoryMB
	summary.TotalCostUSD = usage.TotalCostUSD

	// Calculate resource efficiency score (0-100, higher is better)
	// Base score starts at 100, deducted for inefficiencies
	efficiencyScore := 100.0

	// Deduct for high CPU usage (penalty increases with CPU %)
	if usage.AvgCPUPercent > 80 {
		efficiencyScore -= 20.0 // High CPU penalty
	} else if usage.AvgCPUPercent > 60 {
		efficiencyScore -= 10.0 // Medium CPU penalty
	}

	// Deduct for high memory usage
	if usage.AvgMemoryMB > 1000 {
		efficiencyScore -= 15.0 // High memory penalty
	} else if usage.AvgMemoryMB > 500 {
		efficiencyScore -= 7.5 // Medium memory penalty
	}

	// Deduct for excessive API calls (indicates potential inefficiency)
	if usage.TotalAPICalls > 100000 {
		efficiencyScore -= 10.0 // Excessive API calls penalty
	} else if usage.TotalAPICalls > 50000 {
		efficiencyScore -= 5.0 // High API calls penalty
	}

	// Deduct for excessive database queries
	if usage.TotalDBQueries > 50000 {
		efficiencyScore -= 10.0 // Excessive DB queries penalty
	} else if usage.TotalDBQueries > 25000 {
		efficiencyScore -= 5.0 // High DB queries penalty
	}

	// Deduct for high cost (relative to usage)
	if usage.TotalCostUSD > 100 {
		efficiencyScore -= 15.0 // High cost penalty
	} else if usage.TotalCostUSD > 50 {
		efficiencyScore -= 7.5 // Medium cost penalty
	}

	// Ensure score is within bounds
	if efficiencyScore < 0 {
		efficiencyScore = 0
	}
	if efficiencyScore > 100 {
		efficiencyScore = 100
	}

	summary.ResourceEfficiencyScore = efficiencyScore

	return summary, nil
}
