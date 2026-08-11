package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// CostExplorerService handles AWS Cost Explorer API integration
type CostExplorerService struct {
	client       *costexplorer.Client
	accountID    string
	tenantTagKey string
	log          *logrus.Logger
}

// AWSCostData represents cost data from AWS Cost Explorer
type AWSCostData struct {
	TenantID      *uuid.UUID
	Service       string
	Amount        float64
	Currency      string
	UsageQuantity float64
	UsageUnit     string
	Date          time.Time
	Tags          map[string]string
}

// GetCostsForPeriod retrieves cost data from AWS Cost Explorer for a given time period
func (s *CostExplorerService) GetCostsForPeriod(ctx context.Context, startDate, endDate time.Time, tenantID *uuid.UUID) ([]AWSCostData, error) {
	// Build the time period
	timePeriod := types.DateInterval{
		Start: aws.String(startDate.Format("2006-01-02")),
		End:   aws.String(endDate.Format("2006-01-02")),
	}

	// Build group by parameters
	groupBy := []types.GroupDefinition{
		{
			Type: types.GroupDefinitionTypeDimension,
			Key:  aws.String("SERVICE"),
		},
		{
			Type: types.GroupDefinitionTypeDimension,
			Key:  aws.String("USAGE_TYPE"),
		},
	}

	// If tenant ID is provided, filter by tag
	var filters []types.Expression
	if tenantID != nil {
		filters = append(filters, types.Expression{
			Tags: &types.TagValues{
				Key:    aws.String(s.tenantTagKey),
				Values: []string{tenantID.String()},
			},
		})
	}

	// Build the request
	request := &costexplorer.GetCostAndUsageInput{
		TimePeriod:  &timePeriod,
		Granularity: types.GranularityDaily,
		Metrics:     []string{"BlendedCost", "UsageQuantity"},
		GroupBy:     groupBy,
	}

	if len(filters) > 0 {
		request.Filter = &types.Expression{
			And: filters,
		}
	}

	// Execute the request
	result, err := s.client.GetCostAndUsage(ctx, request)
	if err != nil {
		s.log.WithError(err).Error("Failed to retrieve costs from AWS Cost Explorer")
		return nil, fmt.Errorf("failed to retrieve costs: %w", err)
	}

	// Parse the results
	var costs []AWSCostData
	for _, resultByTime := range result.ResultsByTime {
		date, err := time.Parse("2006-01-02", *resultByTime.TimePeriod.Start)
		if err != nil {
			s.log.WithError(err).Warn("Failed to parse date from AWS response")
			continue
		}

		for _, group := range resultByTime.Groups {
			// Extract service name
			serviceName := "Unknown"
			if len(group.Keys) > 0 {
				// First key is usually the service name
				serviceName = group.Keys[0]
			}

			// Extract cost metrics
			var amount float64
			var currency string
			var usageQuantity float64
			var usageUnit string

			for metricName, metricValue := range group.Metrics {
				switch metricName {
				case "BlendedCost":
					if metricValue.Amount != nil {
						// Parse amount (stored as string)
						_, err := fmt.Sscanf(*metricValue.Amount, "%f", &amount)
						if err != nil {
							s.log.WithError(err).Warn("Failed to parse cost amount")
							continue
						}
					}
					if metricValue.Unit != nil {
						currency = *metricValue.Unit
					}
				case "UsageQuantity":
					if metricValue.Amount != nil {
						_, err := fmt.Sscanf(*metricValue.Amount, "%f", &usageQuantity)
						if err != nil {
							s.log.WithError(err).Warn("Failed to parse usage quantity")
							continue
						}
					}
					if metricValue.Unit != nil {
						usageUnit = *metricValue.Unit
					}
				}
			}

			costs = append(costs, AWSCostData{
				TenantID:      tenantID,
				Service:       serviceName,
				Amount:        amount,
				Currency:      currency,
				UsageQuantity: usageQuantity,
				UsageUnit:     usageUnit,
				Date:          date,
				Tags:          make(map[string]string),
			})
		}
	}

	s.log.WithFields(logrus.Fields{
		"period_start": startDate,
		"period_end":   endDate,
		"cost_count":   len(costs),
	}).Info("Retrieved costs from AWS Cost Explorer")

	return costs, nil
}

// GetCostsByTenant retrieves costs for a specific tenant
func (s *CostExplorerService) GetCostsByTenant(ctx context.Context, tenantID uuid.UUID, startDate, endDate time.Time) ([]AWSCostData, error) {
	return s.GetCostsForPeriod(ctx, startDate, endDate, &tenantID)
}

// GetTotalPlatformCosts retrieves costs for the entire platform (all tenants)
func (s *CostExplorerService) GetTotalPlatformCosts(ctx context.Context, startDate, endDate time.Time) ([]AWSCostData, error) {
	return s.GetCostsForPeriod(ctx, startDate, endDate, nil)
}

// NewCostExplorerService creates a new AWS Cost Explorer service
func NewCostExplorerService(region, accountID, tenantTagKey string, log *logrus.Logger) (*CostExplorerService, error) {
	ctx := context.Background()

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return newCostExplorerFromConfig(cfg, accountID, tenantTagKey, log), nil
}

// NewCostExplorerServiceWithStaticCredentials builds a Cost Explorer client using explicit AWS credentials.
func NewCostExplorerServiceWithStaticCredentials(region, accountID, tenantTagKey, accessKey, secretKey, sessionToken string, log *logrus.Logger) (*CostExplorerService, error) {
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("aws credentials are required")
	}

	cfg := aws.Config{
		Region: region,
		Credentials: aws.NewCredentialsCache(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken),
		),
	}

	return newCostExplorerFromConfig(cfg, accountID, tenantTagKey, log), nil
}

func newCostExplorerFromConfig(cfg aws.Config, accountID, tenantTagKey string, log *logrus.Logger) *CostExplorerService {
	client := costexplorer.NewFromConfig(cfg)
	return &CostExplorerService{
		client:       client,
		accountID:    accountID,
		tenantTagKey: tenantTagKey,
		log:          log,
	}
}
