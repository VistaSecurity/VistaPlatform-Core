package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/aws"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/repository"
)

// AWSCostService handles AWS cost-related business logic
type AWSCostService struct {
	costRepo    *repository.AWSCostRepository
	costService *aws.CostExplorerService
	log         *logrus.Logger
}

// NewAWSCostService creates a new AWS cost service
func NewAWSCostService(costRepo *repository.AWSCostRepository, costService *aws.CostExplorerService, log *logrus.Logger) *AWSCostService {
	return &AWSCostService{
		costRepo:    costRepo,
		costService: costService,
		log:         log,
	}
}

// GetServiceBreakdown returns cost breakdown by AWS service for a period
func (s *AWSCostService) GetServiceBreakdown(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (map[string]float64, error) {
	// Get costs from database (preferred - faster and cached)
	costs, err := s.costRepo.GetCostsForPeriod(ctx, tenantID, startDate, endDate)
	if err != nil {
		s.log.WithError(err).Warn("Failed to get costs from database, trying AWS API")
		// Fallback to AWS API if database doesn't have data
		if s.costService != nil {
			if tenantID != nil {
				costs, err = s.costService.GetCostsByTenant(ctx, *tenantID, startDate, endDate)
			} else {
				costs, err = s.costService.GetTotalPlatformCosts(ctx, startDate, endDate)
			}
			if err != nil {
				return nil, fmt.Errorf("failed to get costs from AWS: %w", err)
			}
			// Store in database for future queries
			if len(costs) > 0 {
				_ = s.costRepo.StoreCostData(ctx, costs)
			}
		}
	}

	// Aggregate by service
	serviceBreakdown := make(map[string]float64)
	for _, cost := range costs {
		serviceBreakdown[cost.Service] += cost.Amount
	}

	return serviceBreakdown, nil
}

// GetTotalAWSCost returns total AWS cost for a period
func (s *AWSCostService) GetTotalAWSCost(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (float64, error) {
	return s.costRepo.GetTotalCostForPeriod(ctx, tenantID, startDate, endDate)
}
