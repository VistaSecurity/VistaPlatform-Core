package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

type HealthRepository struct {
	db *sql.DB
	// bypassDB runs on the BYPASSRLS crypto_bypass role (BYPASS_DATABASE_URL,
	// falling back to DATABASE_URL). Used only by the cross-tenant methods that
	// would FAIL CLOSED under the RLS-subject crypto_app role.
	bypassDB *sql.DB
}

func NewHealthRepository(db, bypassDB *sql.DB) *HealthRepository {
	return &HealthRepository{db: db, bypassDB: bypassDB}
}

// SaveTenantHealth saves or updates tenant health data.
// RLS-scoped: tenant_health carries a tenant_isolation policy, so the write runs
// inside WithTenantTx (sets app.tenant_id). The INSERT's tenant_id satisfies the
// policy's WITH CHECK; the ON CONFLICT update is confined to the caller's tenant.
func (r *HealthRepository) SaveTenantHealth(ctx context.Context, health *models.TenantHealth) error {
	scoreBreakdownJSON, err := json.Marshal(health.ScoreBreakdown)
	if err != nil {
		return fmt.Errorf("failed to marshal score breakdown: %w", err)
	}

	recs := health.Recommendations
	if recs == nil {
		recs = []models.Recommendation{}
	}
	recommendationsJSON, err := json.Marshal(recs)
	if err != nil {
		return fmt.Errorf("failed to marshal recommendations: %w", err)
	}

	trendsJSON, err := json.Marshal(health.Trends)
	if err != nil {
		return fmt.Errorf("failed to marshal trends: %w", err)
	}

	query := `
		INSERT INTO tenant_health (id, tenant_id, overall_score, health_status, last_calculated, 
			score_breakdown, recommendations, trends, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (tenant_id) DO UPDATE SET
			overall_score = EXCLUDED.overall_score,
			health_status = EXCLUDED.health_status,
			last_calculated = EXCLUDED.last_calculated,
			score_breakdown = EXCLUDED.score_breakdown,
			recommendations = EXCLUDED.recommendations,
			trends = EXCLUDED.trends,
			updated_at = EXCLUDED.updated_at
	`

	return shareddatabase.WithTenantTx(ctx, r.db, health.TenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, query, health.ID, health.TenantID, health.OverallScore, health.HealthStatus,
			health.LastCalculated, scoreBreakdownJSON, recommendationsJSON, trendsJSON,
			health.CreatedAt, health.UpdatedAt)
		return err
	})
}

// GetTenantHealth retrieves health data for a specific tenant.
// RLS-scoped read over tenant_health; the explicit WHERE tenant_id = $1 is kept
// as the primary control (belt-and-suspenders).
func (r *HealthRepository) GetTenantHealth(ctx context.Context, tenantID uuid.UUID) (*models.TenantHealth, error) {
	query := `
		SELECT id, tenant_id, overall_score, health_status, last_calculated,
			score_breakdown, recommendations, trends, created_at, updated_at
		FROM tenant_health
		WHERE tenant_id = $1
	`

	var health models.TenantHealth
	var scoreBreakdownJSON, recommendationsJSON, trendsJSON []byte

	found := false
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, query, tenantID).Scan(
			&health.ID, &health.TenantID, &health.OverallScore, &health.HealthStatus,
			&health.LastCalculated, &scoreBreakdownJSON, &recommendationsJSON,
			&trendsJSON, &health.CreatedAt, &health.UpdatedAt,
		)
		if scanErr == sql.ErrNoRows {
			return nil // No health data found
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil // No health data found
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(scoreBreakdownJSON, &health.ScoreBreakdown); err != nil {
		return nil, fmt.Errorf("failed to unmarshal score breakdown: %w", err)
	}

	if err := json.Unmarshal(recommendationsJSON, &health.Recommendations); err != nil {
		return nil, fmt.Errorf("failed to unmarshal recommendations: %w", err)
	}

	if err := json.Unmarshal(trendsJSON, &health.Trends); err != nil {
		return nil, fmt.Errorf("failed to unmarshal trends: %w", err)
	}

	return &health, nil
}

// SaveHealthMetrics saves raw health metrics.
// RLS-scoped write over health_metrics — WithTenantTx sets app.tenant_id so the
// INSERT's tenant_id satisfies the policy's WITH CHECK.
func (r *HealthRepository) SaveHealthMetrics(ctx context.Context, metrics *models.HealthMetrics) error {
	featureUsageJSON, err := json.Marshal(metrics.FeatureUsage)
	if err != nil {
		return fmt.Errorf("failed to marshal feature usage: %w", err)
	}

	query := `
		INSERT INTO health_metrics (tenant_id, timestamp, cpu_utilization, memory_utilization,
			storage_utilization, network_utilization, avg_response_time, error_rate, throughput,
			uptime, failed_logins, security_alerts, compliance_score, last_security_update,
			active_users, api_calls, feature_usage, user_engagement, resource_cost,
			cost_per_user, cost_efficiency)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
	`

	return shareddatabase.WithTenantTx(ctx, r.db, metrics.TenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, query, metrics.TenantID, metrics.Timestamp,
			metrics.CPUUtilization, metrics.MemoryUtilization, metrics.StorageUtilization,
			metrics.NetworkUtilization, metrics.AvgResponseTime, metrics.ErrorRate,
			metrics.Throughput, metrics.Uptime, metrics.FailedLogins, metrics.SecurityAlerts,
			metrics.ComplianceScore, metrics.LastSecurityUpdate, metrics.ActiveUsers,
			metrics.APICalls, featureUsageJSON, metrics.UserEngagement, metrics.ResourceCost,
			metrics.CostPerUser, metrics.CostEfficiency)
		return err
	})
}

// GetHealthMetrics retrieves health metrics for a tenant within a time range.
// RLS-scoped read over health_metrics; WHERE tenant_id = $1 kept as the primary
// control.
func (r *HealthRepository) GetHealthMetrics(ctx context.Context, tenantID uuid.UUID, startTime, endTime time.Time) ([]models.HealthMetrics, error) {
	query := `
		SELECT tenant_id, timestamp, cpu_utilization, memory_utilization,
			storage_utilization, network_utilization, avg_response_time, error_rate, throughput,
			uptime, failed_logins, security_alerts, compliance_score, last_security_update,
			active_users, api_calls, feature_usage, user_engagement, resource_cost,
			cost_per_user, cost_efficiency
		FROM health_metrics
		WHERE tenant_id = $1 AND timestamp BETWEEN $2 AND $3
		ORDER BY timestamp DESC
	`

	var metrics []models.HealthMetrics
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, tenantID, startTime, endTime)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var metric models.HealthMetrics
			var featureUsageJSON []byte

			if e := rows.Scan(
				&metric.TenantID, &metric.Timestamp, &metric.CPUUtilization, &metric.MemoryUtilization,
				&metric.StorageUtilization, &metric.NetworkUtilization, &metric.AvgResponseTime,
				&metric.ErrorRate, &metric.Throughput, &metric.Uptime, &metric.FailedLogins,
				&metric.SecurityAlerts, &metric.ComplianceScore, &metric.LastSecurityUpdate,
				&metric.ActiveUsers, &metric.APICalls, &featureUsageJSON, &metric.UserEngagement,
				&metric.ResourceCost, &metric.CostPerUser, &metric.CostEfficiency,
			); e != nil {
				return e
			}

			if e := json.Unmarshal(featureUsageJSON, &metric.FeatureUsage); e != nil {
				return fmt.Errorf("failed to unmarshal feature usage: %w", e)
			}

			metrics = append(metrics, metric)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return metrics, nil
}

// SaveHealthAlert saves a health alert.
// RLS-scoped write over health_alerts — WithTenantTx sets app.tenant_id so the
// INSERT's tenant_id satisfies the policy's WITH CHECK.
func (r *HealthRepository) SaveHealthAlert(ctx context.Context, alert *models.HealthAlert) error {
	query := `
		INSERT INTO health_alerts (id, tenant_id, alert_type, severity, title, description,
			category, current_value, threshold, is_active, created_at, resolved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	return shareddatabase.WithTenantTx(ctx, r.db, alert.TenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, query, alert.ID, alert.TenantID, alert.AlertType, alert.Severity,
			alert.Title, alert.Description, alert.Category, alert.CurrentValue, alert.Threshold,
			alert.IsActive, alert.CreatedAt, alert.ResolvedAt)
		return err
	})
}

// GetHealthAlerts retrieves health alerts for a tenant.
// RLS-scoped read over health_alerts; WHERE tenant_id = $1 kept as the primary
// control.
func (r *HealthRepository) GetHealthAlerts(ctx context.Context, tenantID uuid.UUID, activeOnly bool) ([]models.HealthAlert, error) {
	query := `
		SELECT id, tenant_id, alert_type, severity, title, description, category,
			current_value, threshold, is_active, created_at, resolved_at
		FROM health_alerts
		WHERE tenant_id = $1
	`

	if activeOnly {
		query += " AND is_active = true"
	}

	query += " ORDER BY created_at DESC"

	var alerts []models.HealthAlert
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, tenantID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var alert models.HealthAlert

			if e := rows.Scan(
				&alert.ID, &alert.TenantID, &alert.AlertType, &alert.Severity,
				&alert.Title, &alert.Description, &alert.Category, &alert.CurrentValue,
				&alert.Threshold, &alert.IsActive, &alert.CreatedAt, &alert.ResolvedAt,
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

// GetAllActiveTenantIDs retrieves all active tenant IDs from the database.
// RLS: cross-tenant — enumerates every tenant; runs on the bypass role (Phase 4).
func (r *HealthRepository) GetAllActiveTenantIDs() ([]uuid.UUID, error) {
	query := `
		SELECT id
		FROM tenants
		WHERE deleted_at IS NULL
		ORDER BY created_at ASC
	`

	rows, err := r.bypassDB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tenantIDs []uuid.UUID
	for rows.Next() {
		var tenantID uuid.UUID
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		tenantIDs = append(tenantIDs, tenantID)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tenantIDs, nil
}

// GetAllTenantHealthOptions defines filtering and pagination options
type GetAllTenantHealthOptions struct {
	Limit     int
	Offset    int
	Status    string // Filter by health_status
	MinScore  float64
	MaxScore  float64
	SortBy    string // "score", "status", "last_calculated"
	SortOrder string // "asc", "desc"
}

// GetAllTenantHealth retrieves health data for all tenants with pagination and filtering.
// RLS: cross-tenant — aggregates tenant_health + health_alerts across every
// tenant (platform-admin view); runs on the bypass role (Phase 4). Not wrapped
// in WithTenantTx, which would confine it to a single tenant.
func (r *HealthRepository) GetAllTenantHealth(options *GetAllTenantHealthOptions) ([]models.TenantHealthSummary, error) {
	// Build query with filters
	query := `
		SELECT th.tenant_id, 
			COALESCE(t.name, 'Unknown Tenant') as tenant_name,
			th.overall_score, th.health_status, th.last_calculated,
			th.trends->>'trend_direction' as trend_direction,
			COALESCE(alert_counts.critical_alerts, 0) as critical_alerts,
			COALESCE(rec_counts.recommendations, 0) as recommendations
		FROM tenant_health th
		LEFT JOIN tenants t ON th.tenant_id = t.id
		LEFT JOIN (
			SELECT tenant_id, COUNT(*) as critical_alerts
			FROM health_alerts
			WHERE severity = 'critical' AND is_active = true
			GROUP BY tenant_id
		) alert_counts ON th.tenant_id = alert_counts.tenant_id
		LEFT JOIN (
			SELECT tenant_id,
				CASE WHEN recommendations IS NOT NULL AND jsonb_typeof(recommendations) = 'array'
				     THEN jsonb_array_length(recommendations)
				     ELSE 0 END AS recommendations
			FROM tenant_health
		) rec_counts ON th.tenant_id = rec_counts.tenant_id
		WHERE 1=1
	`

	args := []interface{}{}
	argIndex := 1

	// Apply filters
	if options != nil {
		if options.Status != "" {
			query += fmt.Sprintf(" AND th.health_status = $%d", argIndex)
			args = append(args, options.Status)
			argIndex++
		}

		if options.MinScore > 0 {
			query += fmt.Sprintf(" AND th.overall_score >= $%d", argIndex)
			args = append(args, options.MinScore)
			argIndex++
		}

		if options.MaxScore > 0 && options.MaxScore < 100 {
			query += fmt.Sprintf(" AND th.overall_score <= $%d", argIndex)
			args = append(args, options.MaxScore)
			argIndex++
		}
	}

	// Apply sorting
	sortBy := "th.overall_score"
	sortOrder := "DESC"
	if options != nil {
		if options.SortBy != "" {
			switch options.SortBy {
			case "status":
				sortBy = "th.health_status"
			case "last_calculated":
				sortBy = "th.last_calculated"
			case "score":
				sortBy = "th.overall_score"
			}
		}
		if options.SortOrder != "" {
			if options.SortOrder == "asc" {
				sortOrder = "ASC"
			}
		}
	}
	query += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)

	// Apply pagination
	if options != nil && options.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, options.Limit)
		argIndex++
		if options.Offset > 0 {
			query += fmt.Sprintf(" OFFSET $%d", argIndex)
			args = append(args, options.Offset)
		}
	}

	rows, err := r.bypassDB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var summaries []models.TenantHealthSummary
	for rows.Next() {
		var summary models.TenantHealthSummary
		var trendDirection sql.NullString

		err := rows.Scan(
			&summary.TenantID, &summary.TenantName, &summary.OverallScore, &summary.HealthStatus,
			&summary.LastCalculated, &trendDirection, &summary.CriticalAlerts,
			&summary.Recommendations,
		)

		if err != nil {
			return nil, err
		}

		if trendDirection.Valid {
			summary.TrendDirection = trendDirection.String
		} else {
			summary.TrendDirection = "unknown"
		}

		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// GetHealthBenchmarks returns industry benchmarks for health scoring.
// RLS: health_benchmarks is a global reference table (no tenant_id, no
// tenant_isolation policy) — left unwrapped.
func (r *HealthRepository) GetHealthBenchmarks() ([]models.HealthBenchmark, error) {
	query := `
		SELECT category, benchmark_score, description, source
		FROM health_benchmarks
		ORDER BY category
	`

	rows, err := r.db.Query(query)
	if err != nil {
		// Fallback to default benchmarks if table doesn't exist or query fails
		return []models.HealthBenchmark{
			{
				Category:       "resource_efficiency",
				BenchmarkScore: 75.0,
				Description:    "Industry average for resource utilization efficiency",
				Source:         "Industry Report 2024",
			},
			{
				Category:       "performance_metrics",
				BenchmarkScore: 80.0,
				Description:    "Industry average for application performance",
				Source:         "Performance Benchmark Study",
			},
			{
				Category:       "security_posture",
				BenchmarkScore: 85.0,
				Description:    "Industry average for security compliance",
				Source:         "Security Standards Report",
			},
			{
				Category:       "business_activity",
				BenchmarkScore: 70.0,
				Description:    "Industry average for user engagement",
				Source:         "User Engagement Study",
			},
			{
				Category:       "cost_optimization",
				BenchmarkScore: 65.0,
				Description:    "Industry average for cost efficiency",
				Source:         "Cost Optimization Report",
			},
		}, nil
	}
	defer rows.Close()

	var benchmarks []models.HealthBenchmark
	for rows.Next() {
		var b models.HealthBenchmark
		var score float64
		err := rows.Scan(&b.Category, &score, &b.Description, &b.Source)
		if err != nil {
			continue // Skip invalid rows
		}
		b.BenchmarkScore = score
		benchmarks = append(benchmarks, b)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan benchmarks: %w", err)
	}

	// If no benchmarks found, return defaults
	if len(benchmarks) == 0 {
		return []models.HealthBenchmark{
			{
				Category:       "resource_efficiency",
				BenchmarkScore: 75.0,
				Description:    "Industry average for resource utilization efficiency",
				Source:         "Industry Report 2024",
			},
			{
				Category:       "performance_metrics",
				BenchmarkScore: 80.0,
				Description:    "Industry average for application performance",
				Source:         "Performance Benchmark Study",
			},
			{
				Category:       "security_posture",
				BenchmarkScore: 85.0,
				Description:    "Industry average for security compliance",
				Source:         "Security Standards Report",
			},
			{
				Category:       "business_activity",
				BenchmarkScore: 70.0,
				Description:    "Industry average for user engagement",
				Source:         "User Engagement Study",
			},
			{
				Category:       "cost_optimization",
				BenchmarkScore: 65.0,
				Description:    "Industry average for cost efficiency",
				Source:         "Cost Optimization Report",
			},
		}, nil
	}

	return benchmarks, nil
}

// GetTenantName returns the tenant name from the database.
// RLS: tenants is a global directory table (no tenant_isolation policy) — a
// single-row reference lookup, left unwrapped.
func (r *HealthRepository) GetTenantName(tenantID uuid.UUID) string {
	var name string
	query := `SELECT name FROM tenants WHERE id = $1`
	err := r.db.QueryRow(query, tenantID).Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			return "Unknown Tenant"
		}
		// On error, return a fallback
		return "Tenant " + tenantID.String()[:8]
	}
	return name
}
