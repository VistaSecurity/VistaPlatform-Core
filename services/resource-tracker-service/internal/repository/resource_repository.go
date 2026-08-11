package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

type ResourceRepository struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used only by the
	// `// RLS: cross-tenant` paths in this repository. Under crypto_app these
	// cross-tenant queries fail closed; bypassDB lets the deliberate
	// platform-rollup paths run on the bypass role.
	bypassDB *sql.DB
}

func NewResourceRepository(db, bypassDB *sql.DB) *ResourceRepository {
	return &ResourceRepository{db: db, bypassDB: bypassDB}
}

// TenantExists returns true if the tenant row exists and is not soft-deleted.
func (r *ResourceRepository) TenantExists(tenantID uuid.UUID) (bool, error) {
	var exists bool
	err := r.db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1 AND deleted_at IS NULL)`,
		tenantID,
	).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// RecordResourceUsage records resource usage metrics for a tenant
func (r *ResourceRepository) RecordResourceUsage(usage *models.ResourceUsage) error {
	query := `
		INSERT INTO tenant_resource_usage (
			id, tenant_id, timestamp, api_calls, database_queries,
			memory_usage_mb, cpu_usage_percent, storage_used_mb,
			network_bytes, cost_usd, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	// RLS-scoped write: tenant_resource_usage carries a tenant_isolation policy,
	// so the INSERT runs inside WithTenantTx (sets app.tenant_id) and the row's
	// tenant_id satisfies the policy's USING/WITH CHECK.
	ctx := context.Background()
	return shareddatabase.WithTenantTx(ctx, r.db, usage.TenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, query,
			usage.ID, usage.TenantID, usage.Timestamp, usage.APICalls,
			usage.DatabaseQueries, usage.MemoryUsageMB, usage.CPUUsagePercent,
			usage.StorageUsedMB, usage.NetworkBytes, usage.CostUSD, usage.CreatedAt,
		)
		return err
	})
}

// GetResourceUsageByTenant retrieves resource usage for a specific tenant
func (r *ResourceRepository) GetResourceUsageByTenant(tenantID uuid.UUID, period string) (*models.ResourceUsageResponse, error) {
	var timeFilter string
	switch period {
	case "1h":
		timeFilter = "timestamp >= NOW() - INTERVAL '1 hour'"
	case "24h":
		timeFilter = "timestamp >= NOW() - INTERVAL '24 hours'"
	case "7d":
		timeFilter = "timestamp >= NOW() - INTERVAL '7 days'"
	case "30d":
		timeFilter = "timestamp >= NOW() - INTERVAL '30 days'"
	default:
		timeFilter = "timestamp >= NOW() - INTERVAL '24 hours'"
	}

	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(`
		SELECT 
			tenant_id,
			COALESCE(SUM(api_calls), 0) as total_api_calls,
			COALESCE(SUM(database_queries), 0) as total_db_queries,
			COALESCE(AVG(memory_usage_mb), 0) as avg_memory_mb,
			COALESCE(AVG(cpu_usage_percent), 0) as avg_cpu_percent,
			COALESCE(SUM(storage_used_mb), 0) as total_storage_mb,
			COALESCE(SUM(network_bytes), 0) as total_network_bytes,
			COALESCE(SUM(cost_usd), 0) as total_cost_usd
		FROM tenant_resource_usage 
		WHERE tenant_id = $1 AND %s
		GROUP BY tenant_id
	`, timeFilter)

	var response models.ResourceUsageResponse
	response.TenantID = tenantID
	response.Period = period

	// RLS-scoped read over tenant_resource_usage.
	ctx := context.Background()
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, query, tenantID).Scan(
			&response.TenantID,
			&response.TotalAPICalls,
			&response.TotalDBQueries,
			&response.AvgMemoryMB,
			&response.AvgCPUPercent,
			&response.TotalStorageMB,
			&response.TotalNetworkMB,
			&response.TotalCostUSD,
		)
		if scanErr == sql.ErrNoRows {
			return nil // no data is not an error for this aggregate
		}
		return scanErr
	})
	if err != nil {
		return nil, err
	}

	// Convert network bytes to MB
	response.TotalNetworkMB = response.TotalNetworkMB / (1024 * 1024)

	// Calculate cost breakdown
	response.CostBreakdown = r.calculateCostBreakdown(&response)

	return &response, nil
}

// GetResourceUsageTrend retrieves resource usage trend data
func (r *ResourceRepository) GetResourceUsageTrend(tenantID uuid.UUID, period string) ([]models.ResourceDataPoint, error) {
	var timeFilter string
	var interval string

	switch period {
	case "1h":
		timeFilter = "timestamp >= NOW() - INTERVAL '1 hour'"
		interval = "5 minutes"
	case "24h":
		timeFilter = "timestamp >= NOW() - INTERVAL '24 hours'"
		interval = "1 hour"
	case "7d":
		timeFilter = "timestamp >= NOW() - INTERVAL '7 days'"
		interval = "1 day"
	case "30d":
		timeFilter = "timestamp >= NOW() - INTERVAL '30 days'"
		interval = "1 day"
	default:
		timeFilter = "timestamp >= NOW() - INTERVAL '24 hours'"
		interval = "1 hour"
	}

	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(`
		SELECT 
			DATE_TRUNC('%s', timestamp) as time_bucket,
			COALESCE(SUM(api_calls), 0) as api_calls,
			COALESCE(SUM(database_queries), 0) as database_queries,
			COALESCE(AVG(memory_usage_mb), 0) as memory_usage_mb,
			COALESCE(AVG(cpu_usage_percent), 0) as cpu_usage_percent
		FROM tenant_resource_usage 
		WHERE tenant_id = $1 AND %s
		GROUP BY time_bucket
		ORDER BY time_bucket
	`, interval, timeFilter)

	// RLS-scoped read over tenant_resource_usage.
	ctx := context.Background()
	var dataPoints []models.ResourceDataPoint
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, tenantID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var dp models.ResourceDataPoint
			if e := rows.Scan(
				&dp.Timestamp,
				&dp.APICalls,
				&dp.DatabaseQueries,
				&dp.MemoryUsageMB,
				&dp.CPUUsagePercent,
			); e != nil {
				return e
			}
			dataPoints = append(dataPoints, dp)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return dataPoints, nil
}

// GetCostTrend retrieves cost trend data for a tenant
func (r *ResourceRepository) GetCostTrend(tenantID uuid.UUID, period string) ([]models.CostDataPoint, error) {
	var timeFilter string
	var interval string

	switch period {
	case "1h":
		timeFilter = "timestamp >= NOW() - INTERVAL '1 hour'"
		interval = "5 minutes"
	case "24h":
		timeFilter = "timestamp >= NOW() - INTERVAL '24 hours'"
		interval = "1 hour"
	case "7d":
		timeFilter = "timestamp >= NOW() - INTERVAL '7 days'"
		interval = "1 day"
	case "30d":
		timeFilter = "timestamp >= NOW() - INTERVAL '30 days'"
		interval = "1 day"
	default:
		timeFilter = "timestamp >= NOW() - INTERVAL '24 hours'"
		interval = "1 hour"
	}

	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(`
		SELECT 
			DATE_TRUNC('%s', timestamp) as time_bucket,
			COALESCE(SUM(cost_usd), 0) as cost_usd
		FROM tenant_resource_usage 
		WHERE tenant_id = $1 AND %s
		GROUP BY time_bucket
		ORDER BY time_bucket
	`, interval, timeFilter)

	// RLS-scoped read over tenant_resource_usage.
	ctx := context.Background()
	var dataPoints []models.CostDataPoint
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, tenantID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var dp models.CostDataPoint
			if e := rows.Scan(&dp.Timestamp, &dp.CostUSD); e != nil {
				return e
			}
			dataPoints = append(dataPoints, dp)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return dataPoints, nil
}

// GetAllTenantsResourceUsage retrieves resource usage for all tenants.
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). This is a platform
// rollup that joins tenants ⨯ tenant_resource_usage and GROUPs BY tenant, so it
// must see every tenant's rows. It cannot be scoped via WithTenantTx.
func (r *ResourceRepository) GetAllTenantsResourceUsage(period string) ([]models.TenantResourceSummary, error) {
	var timeFilter string
	switch period {
	case "1h":
		timeFilter = "timestamp >= NOW() - INTERVAL '1 hour'"
	case "24h":
		timeFilter = "timestamp >= NOW() - INTERVAL '24 hours'"
	case "7d":
		timeFilter = "timestamp >= NOW() - INTERVAL '7 days'"
	case "30d":
		timeFilter = "timestamp >= NOW() - INTERVAL '30 days'"
	default:
		timeFilter = "timestamp >= NOW() - INTERVAL '24 hours'"
	}

	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(`
		SELECT 
			t.id as tenant_id,
			t.name as tenant_name,
			COALESCE(SUM(ru.api_calls), 0) as total_api_calls,
			COALESCE(SUM(ru.database_queries), 0) as total_db_queries,
			COALESCE(AVG(ru.memory_usage_mb), 0) as avg_memory_mb,
			COALESCE(AVG(ru.cpu_usage_percent), 0) as avg_cpu_percent,
			COALESCE(SUM(ru.storage_used_mb), 0) as total_storage_mb,
			COALESCE(SUM(ru.network_bytes), 0) as total_network_bytes,
			COALESCE(SUM(ru.cost_usd), 0) as total_cost_usd
		FROM tenants t
		LEFT JOIN tenant_resource_usage ru ON t.id = ru.tenant_id AND %s
		GROUP BY t.id, t.name
		ORDER BY total_cost_usd DESC
	`, timeFilter)

	// RLS: cross-tenant — runs directly on the bypass connection (no
	// WithTenantTx / set_tenant_context), so the platform rollup sees every
	// tenant's rows.
	rows, err := r.bypassDB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var summaries []models.TenantResourceSummary
	for rows.Next() {
		var summary models.TenantResourceSummary
		var totalNetworkBytes int64

		err := rows.Scan(
			&summary.TenantID,
			&summary.TenantName,
			&summary.CurrentUsage.TotalAPICalls,
			&summary.CurrentUsage.TotalDBQueries,
			&summary.CurrentUsage.AvgMemoryMB,
			&summary.CurrentUsage.AvgCPUPercent,
			&summary.CurrentUsage.TotalStorageMB,
			&totalNetworkBytes,
			&summary.CurrentUsage.TotalCostUSD,
		)
		if err != nil {
			return nil, err
		}

		summary.CurrentUsage.TenantID = summary.TenantID
		summary.CurrentUsage.Period = period
		summary.CurrentUsage.TotalNetworkMB = float64(totalNetworkBytes) / (1024 * 1024)
		summary.CurrentUsage.CostBreakdown = r.calculateCostBreakdown(&summary.CurrentUsage)

		// Get cost and resource trends
		costTrend, _ := r.GetCostTrend(summary.TenantID, period)
		resourceTrend, _ := r.GetResourceUsageTrend(summary.TenantID, period)

		summary.CostTrend = costTrend
		summary.ResourceTrend = resourceTrend
		summary.OptimizationScore = r.calculateOptimizationScore(&summary.CurrentUsage)

		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// CreateResourceAlert creates a new resource alert
func (r *ResourceRepository) CreateResourceAlert(alert *models.ResourceAlert) error {
	query := `
		INSERT INTO resource_alerts (
			id, tenant_id, alert_type, metric, threshold, current_value,
			message, severity, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	// RLS-scoped write: resource_alerts carries a tenant_isolation policy.
	ctx := context.Background()
	return shareddatabase.WithTenantTx(ctx, r.db, alert.TenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, query,
			alert.ID, alert.TenantID, alert.AlertType, alert.Metric,
			alert.Threshold, alert.CurrentValue, alert.Message, alert.Severity,
			alert.IsActive, alert.CreatedAt,
		)
		return err
	})
}

// GetActiveAlerts retrieves active alerts for a tenant
func (r *ResourceRepository) GetActiveAlerts(tenantID uuid.UUID) ([]models.ResourceAlert, error) {
	query := `
		SELECT id, tenant_id, alert_type, metric, threshold, current_value,
			   message, severity, is_active, created_at, resolved_at
		FROM resource_alerts 
		WHERE tenant_id = $1 AND is_active = true
		ORDER BY created_at DESC
	`

	// RLS-scoped read over resource_alerts.
	ctx := context.Background()
	var alerts []models.ResourceAlert
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, tenantID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var alert models.ResourceAlert
			if e := rows.Scan(
				&alert.ID, &alert.TenantID, &alert.AlertType, &alert.Metric,
				&alert.Threshold, &alert.CurrentValue, &alert.Message, &alert.Severity,
				&alert.IsActive, &alert.CreatedAt, &alert.ResolvedAt,
			); e != nil {
				return e
			}
			alerts = append(alerts, alert)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return alerts, nil
}

// Helper function to calculate cost breakdown
func (r *ResourceRepository) calculateCostBreakdown(usage *models.ResourceUsageResponse) models.ResourceBreakdown {
	// Simple cost calculation - in production, these would be configurable rates
	apiCost := float64(usage.TotalAPICalls) * 0.0001        // $0.0001 per API call
	databaseCost := float64(usage.TotalDBQueries) * 0.00005 // $0.00005 per query
	storageCost := float64(usage.TotalStorageMB) * 0.023    // $0.023 per GB per month
	computeCost := usage.AvgCPUPercent * 0.1                // $0.1 per CPU percent
	networkCost := usage.TotalNetworkMB * 0.09              // $0.09 per GB

	totalCost := apiCost + databaseCost + storageCost + computeCost + networkCost

	return models.ResourceBreakdown{
		APICost:      apiCost,
		DatabaseCost: databaseCost,
		StorageCost:  storageCost,
		ComputeCost:  computeCost,
		NetworkCost:  networkCost,
		TotalCost:    totalCost,
	}
}

// Helper function to calculate optimization score
func (r *ResourceRepository) calculateOptimizationScore(usage *models.ResourceUsageResponse) float64 {
	// Simple optimization score calculation
	// Higher score means better optimization (0-100)

	score := 100.0

	// Penalize high API call to query ratio (inefficient queries)
	if usage.TotalDBQueries > 0 {
		ratio := float64(usage.TotalAPICalls) / float64(usage.TotalDBQueries)
		if ratio > 10 {
			score -= 20 // High ratio suggests inefficient queries
		}
	}

	// Penalize high memory usage
	if usage.AvgMemoryMB > 1000 {
		score -= 15 // High memory usage
	}

	// Penalize high CPU usage
	if usage.AvgCPUPercent > 80 {
		score -= 25 // High CPU usage
	}

	// Reward low cost per API call
	if usage.TotalAPICalls > 0 {
		costPerCall := usage.TotalCostUSD / float64(usage.TotalAPICalls)
		if costPerCall > 0.001 {
			score -= 10 // High cost per call
		}
	}

	if score < 0 {
		score = 0
	}

	return score
}
