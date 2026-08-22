package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/costing"
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

	// The aggregates deliberately carry NO COALESCE: SUM/AVG over a column that
	// is NULL in every sample returns NULL, which is precisely "not measured",
	// and COALESCE(...,0) would relabel that as a measured zero.
	//
	// storage_used_mb is a point-in-time GAUGE, so it is averaged, not summed —
	// summing a gauge multiplies the answer by the number of samples in the
	// window.
	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(`
		SELECT
			tenant_id,
			SUM(api_calls) as total_api_calls,
			SUM(database_queries) as total_db_queries,
			AVG(memory_usage_mb) as avg_memory_mb,
			AVG(cpu_usage_percent) as avg_cpu_percent,
			AVG(storage_used_mb) as mean_storage_mb,
			SUM(network_bytes) as total_network_bytes
		FROM tenant_resource_usage
		WHERE tenant_id = $1 AND %s
		GROUP BY tenant_id
	`, timeFilter)

	var response models.ResourceUsageResponse
	response.TenantID = tenantID
	response.Period = period

	measured := windowMeasurements{window: periodWindow(period)}
	var avgMemoryMB, avgCPUPercent sql.NullFloat64

	// RLS-scoped read over tenant_resource_usage.
	ctx := context.Background()
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, query, tenantID).Scan(
			&response.TenantID,
			&measured.apiCalls,
			&measured.databaseQueries,
			&avgMemoryMB,
			&avgCPUPercent,
			&measured.storageMeanMB,
			&measured.networkBytes,
		)
		if scanErr == sql.ErrNoRows {
			return nil // no data is not an error for this aggregate
		}
		return scanErr
	})
	if err != nil {
		return nil, err
	}

	response.TotalAPICalls = int(measured.apiCalls.Int64)
	response.TotalDBQueries = int(measured.databaseQueries.Int64)
	response.AvgMemoryMB = avgMemoryMB.Float64
	response.AvgCPUPercent = avgCPUPercent.Float64
	response.TotalStorageMB = int(measured.storageMeanMB.Float64)
	response.TotalNetworkMB = float64(measured.networkBytes.Int64) / (1024 * 1024)

	// The headline and the itemisation come from one costing.Compute call, so
	// they cannot disagree. total_cost_usd is NOT read back from the stored
	// per-sample cost_usd column: that column prices only the per-unit
	// components and summing it beside a differently-derived breakdown is the
	// exact contradiction this replaces.
	response.CostBreakdown = r.calculateCostBreakdown(measured)
	response.TotalCostUSD = response.CostBreakdown.TotalCost

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

	// Each bucket is priced from its own raw aggregates through the same
	// costing.Compute the point-in-time reads use, rather than from
	// SUM(cost_usd): the stored column prices only the per-unit components, so
	// summing it here would draw a trend line that disagrees with the headline
	// plotted above it.
	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(`
		SELECT
			DATE_TRUNC('%s', timestamp) as time_bucket,
			SUM(api_calls) as total_api_calls,
			SUM(database_queries) as total_db_queries,
			AVG(storage_used_mb) as mean_storage_mb,
			SUM(network_bytes) as total_network_bytes
		FROM tenant_resource_usage
		WHERE tenant_id = $1 AND %s
		GROUP BY time_bucket
		ORDER BY time_bucket
	`, interval, timeFilter)

	bucketWindow := bucketDuration(interval)

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
			measured := windowMeasurements{window: bucketWindow}
			if e := rows.Scan(
				&dp.Timestamp,
				&measured.apiCalls,
				&measured.databaseQueries,
				&measured.storageMeanMB,
				&measured.networkBytes,
			); e != nil {
				return e
			}
			dp.CostUSD = costing.Compute(measured.usage(), costing.DefaultRates()).TotalUSD
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

	// No COALESCE, and storage is averaged rather than summed — see the note on
	// the same aggregates in GetResourceUsageByTenant. Ordering is by measured
	// API volume rather than by SUM(cost_usd): cost is now derived at read time
	// from these aggregates, so ordering by the stored column would rank the
	// list by a number no longer shown.
	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(`
		SELECT
			t.id as tenant_id,
			t.name as tenant_name,
			SUM(ru.api_calls) as total_api_calls,
			SUM(ru.database_queries) as total_db_queries,
			AVG(ru.memory_usage_mb) as avg_memory_mb,
			AVG(ru.cpu_usage_percent) as avg_cpu_percent,
			AVG(ru.storage_used_mb) as mean_storage_mb,
			SUM(ru.network_bytes) as total_network_bytes
		FROM tenants t
		LEFT JOIN tenant_resource_usage ru ON t.id = ru.tenant_id AND %s
		GROUP BY t.id, t.name
		ORDER BY total_api_calls DESC NULLS LAST
	`, timeFilter)

	// RLS: cross-tenant — runs directly on the bypass connection (no
	// WithTenantTx / set_tenant_context), so the platform rollup sees every
	// tenant's rows.
	rows, err := r.bypassDB.Query(query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var summaries []models.TenantResourceSummary
	for rows.Next() {
		var summary models.TenantResourceSummary
		measured := windowMeasurements{window: periodWindow(period)}
		var avgMemoryMB, avgCPUPercent sql.NullFloat64

		err := rows.Scan(
			&summary.TenantID,
			&summary.TenantName,
			&measured.apiCalls,
			&measured.databaseQueries,
			&avgMemoryMB,
			&avgCPUPercent,
			&measured.storageMeanMB,
			&measured.networkBytes,
		)
		if err != nil {
			return nil, err
		}

		summary.CurrentUsage.TenantID = summary.TenantID
		summary.CurrentUsage.Period = period
		summary.CurrentUsage.TotalAPICalls = int(measured.apiCalls.Int64)
		summary.CurrentUsage.TotalDBQueries = int(measured.databaseQueries.Int64)
		summary.CurrentUsage.AvgMemoryMB = avgMemoryMB.Float64
		summary.CurrentUsage.AvgCPUPercent = avgCPUPercent.Float64
		summary.CurrentUsage.TotalStorageMB = int(measured.storageMeanMB.Float64)
		summary.CurrentUsage.TotalNetworkMB = float64(measured.networkBytes.Int64) / (1024 * 1024)
		summary.CurrentUsage.CostBreakdown = r.calculateCostBreakdown(measured)
		summary.CurrentUsage.TotalCostUSD = summary.CurrentUsage.CostBreakdown.TotalCost

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
// calculateCostBreakdown prices an aggregated window through shared/costing.
//
// This used to be an independent third rate card that applied the per-GB
// storage and network rates to megabyte counts (a 1024x error each) and priced
// AVG(cpu_usage_percent) as compute. It now delegates, so the repository, the
// persister and the admin cost pages can no longer drift apart.
func (r *ResourceRepository) calculateCostBreakdown(m windowMeasurements) models.ResourceBreakdown {
	b := costing.Compute(m.usage(), costing.DefaultRates())

	pick := func(name string) *float64 {
		if v, ok := b.Components[name]; ok {
			return &v
		}
		return nil
	}

	return models.ResourceBreakdown{
		APICost:      pick(costing.ComponentAPICalls),
		DatabaseCost: pick(costing.ComponentDatabase),
		StorageCost:  pick(costing.ComponentStorage),
		ComputeCost:  pick(costing.ComponentCompute),
		NetworkCost:  pick(costing.ComponentNetwork),
		TotalCost:    b.TotalUSD,
		NotMeasured:  b.NotMeasured,
	}
}

// windowMeasurements carries the raw aggregates for one costing window,
// preserving NULL (not measured) as nil rather than collapsing it to zero.
type windowMeasurements struct {
	window          time.Duration
	apiCalls        sql.NullInt64
	databaseQueries sql.NullInt64
	networkBytes    sql.NullInt64
	storageMeanMB   sql.NullFloat64
}

func (m windowMeasurements) usage() costing.Usage {
	u := costing.Usage{Window: m.window}
	if m.apiCalls.Valid {
		u.APICalls = &m.apiCalls.Int64
	}
	if m.databaseQueries.Valid {
		u.DatabaseQueries = &m.databaseQueries.Int64
	}
	if m.networkBytes.Valid {
		u.NetworkBytes = &m.networkBytes.Int64
	}
	if m.storageMeanMB.Valid {
		u.StorageBytes = costing.Float64(m.storageMeanMB.Float64 * 1024 * 1024)
	}
	return u
}

// bucketDuration maps a DATE_TRUNC interval to the duration one bucket spans,
// so a trend point's storage term is prorated over the bucket rather than over
// the whole requested period.
func bucketDuration(interval string) time.Duration {
	switch interval {
	case "5 minutes":
		return 5 * time.Minute
	case "1 day":
		return 24 * time.Hour
	default: // "1 hour"
		return time.Hour
	}
}

// periodWindow maps a period label to the duration its aggregates cover.
// Storage is rated per GB-month, so the window is part of the price.
func periodWindow(period string) time.Duration {
	switch period {
	case "1h":
		return time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	case "30d":
		return 30 * 24 * time.Hour
	default: // "24h" and anything unrecognised
		return 24 * time.Hour
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
