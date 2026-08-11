package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/aws"
)

// AWSCostRepository handles database operations for AWS cost data.
//
// Every query in this repository is a `// RLS: cross-tenant` platform
// cost-sync path (rows span many tenants, or tenant_id is nullable/NULL), so
// they all run on the bypass connection. The repository therefore holds no
// RLS-scoped (crypto_app) handle.
type AWSCostRepository struct {
	log *logrus.Logger
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used by every method.
	bypassDB *sql.DB
}

// NewAWSCostRepository creates a new AWS cost repository. The first parameter
// (the RLS-scoped handle) is accepted for signature symmetry with the other
// repositories but is unused — this repository has only cross-tenant paths.
func NewAWSCostRepository(_, bypassDB *sql.DB, log *logrus.Logger) *AWSCostRepository {
	return &AWSCostRepository{
		log:      log,
		bypassDB: bypassDB,
	}
}

// StoreCostData stores AWS cost data in the database.
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). The platform AWS
// cost-sync job calls this with a batch of rows spanning many tenants (each
// row's tenant_id comes from AWS, not a single caller tenant), so a single
// app.tenant_id cannot scope the write. aws_cost_data is RLS-scoped, so this
// path is deliberately assigned to bypassDB rather than WithTenantTx.
func (r *AWSCostRepository) StoreCostData(ctx context.Context, costs []aws.AWSCostData) error {
	if len(costs) == 0 {
		return nil
	}

	query := `
		INSERT INTO aws_cost_data (
			tenant_id, cost_date, service_name, amount, currency,
			usage_quantity, usage_unit, usage_type, tags, account_id, region, synced_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (tenant_id, cost_date, service_name, COALESCE(usage_type, ''))
		DO UPDATE SET
			amount = EXCLUDED.amount,
			currency = EXCLUDED.currency,
			usage_quantity = EXCLUDED.usage_quantity,
			usage_unit = EXCLUDED.usage_unit,
			tags = EXCLUDED.tags,
			account_id = EXCLUDED.account_id,
			region = EXCLUDED.region,
			synced_at = EXCLUDED.synced_at,
			updated_at = NOW()
	`

	tx, err := r.bypassDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	syncedAt := time.Now()
	for _, cost := range costs {
		// Convert tags map to JSONB
		tagsJSON := "{}"
		if len(cost.Tags) > 0 {
			tagsBytes, err := json.Marshal(cost.Tags)
			if err == nil {
				tagsJSON = string(tagsBytes)
			}
		}

		costDate := cost.Date.Format("2006-01-02")
		_, err := stmt.ExecContext(ctx,
			cost.TenantID,
			costDate,
			cost.Service,
			cost.Amount,
			cost.Currency,
			cost.UsageQuantity,
			cost.UsageUnit,
			"", // usage_type - will be added later if needed
			tagsJSON,
			"", // account_id - will be added later if needed
			"", // region - will be added later if needed
			syncedAt,
		)
		if err != nil {
			r.log.WithError(err).WithFields(logrus.Fields{
				"tenant_id": cost.TenantID,
				"service":   cost.Service,
				"cost_date": costDate,
			}).Error("Failed to store AWS cost data")
			// Continue with other records
			continue
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.log.WithField("record_count", len(costs)).Info("Stored AWS cost data")
	return nil
}

// GetCostsForPeriod retrieves AWS costs for a specific period.
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). tenantID is nullable:
// when nil the query intentionally spans all tenants (platform-wide cost view),
// so it cannot be confined via WithTenantTx. aws_cost_data is RLS-scoped; this
// path is assigned to bypassDB.
func (r *AWSCostRepository) GetCostsForPeriod(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) ([]aws.AWSCostData, error) {
	query := `
		SELECT tenant_id, cost_date, service_name, amount, currency,
		       usage_quantity, usage_unit, usage_type, tags, synced_at
		FROM aws_cost_data
		WHERE cost_date >= $1 AND cost_date <= $2
	`

	var args []interface{}
	args = append(args, startDate.Format("2006-01-02"), endDate.Format("2006-01-02"))

	if tenantID != nil {
		query += " AND tenant_id = $3"
		args = append(args, tenantID)
	}

	query += " ORDER BY cost_date DESC, service_name"

	rows, err := r.bypassDB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query AWS cost data: %w", err)
	}
	defer rows.Close()

	var costs []aws.AWSCostData
	for rows.Next() {
		var cost aws.AWSCostData
		var costDateStr string
		var tagsJSON sql.NullString
		var usageType sql.NullString

		err := rows.Scan(
			&cost.TenantID,
			&costDateStr,
			&cost.Service,
			&cost.Amount,
			&cost.Currency,
			&cost.UsageQuantity,
			&cost.UsageUnit,
			&usageType,
			&tagsJSON,
			&cost.Date,
		)
		if err != nil {
			r.log.WithError(err).Warn("Failed to scan AWS cost data")
			continue
		}

		// Parse date
		cost.Date, err = time.Parse("2006-01-02", costDateStr)
		if err != nil {
			r.log.WithError(err).Warn("Failed to parse cost date")
			continue
		}

		// Parse tags JSON
		cost.Tags = make(map[string]string)
		if tagsJSON.Valid && tagsJSON.String != "" && tagsJSON.String != "{}" {
			if err := json.Unmarshal([]byte(tagsJSON.String), &cost.Tags); err != nil {
				r.log.WithError(err).Warn("Failed to parse tags JSON")
			}
		}

		costs = append(costs, cost)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return costs, nil
}

// GetTotalCostForPeriod calculates total cost for a period.
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). Same nullable-tenant
// shape as GetCostsForPeriod: a nil tenantID sums across all tenants. Although
// the per-tenant caller (RecordResourceMetrics) passes a concrete tenant id,
// the method's contract supports the platform-wide aggregate, so it stays on
// bypassDB rather than WithTenantTx. aws_cost_data is RLS-scoped.
func (r *AWSCostRepository) GetTotalCostForPeriod(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (float64, error) {
	query := `
		SELECT COALESCE(SUM(amount), 0)
		FROM aws_cost_data
		WHERE cost_date >= $1 AND cost_date <= $2
	`

	var args []interface{}
	args = append(args, startDate.Format("2006-01-02"), endDate.Format("2006-01-02"))

	if tenantID != nil {
		query += " AND tenant_id = $3"
		args = append(args, tenantID)
	}

	var totalCost float64
	err := r.bypassDB.QueryRowContext(ctx, query, args...).Scan(&totalCost)
	if err != nil {
		return 0, fmt.Errorf("failed to get total cost: %w", err)
	}

	return totalCost, nil
}

// RecordSyncJob records a sync job in the database.
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). tenantID is nullable
// and the platform cost-sync job records platform-wide jobs with tenant_id=NULL,
// which a tenant-scoped WITH CHECK could never satisfy. aws_cost_sync_jobs is
// RLS-scoped; this path stays on bypassDB.
func (r *AWSCostRepository) RecordSyncJob(ctx context.Context, jobType string, periodStart, periodEnd time.Time, tenantID *uuid.UUID) (*uuid.UUID, error) {
	query := `
		INSERT INTO aws_cost_sync_jobs (job_type, status, period_start, period_end, tenant_id, start_time)
		VALUES ($1, $2, $3, $4, $5, NOW())
		RETURNING id
	`

	var jobID uuid.UUID
	err := r.bypassDB.QueryRowContext(ctx, query,
		jobType,
		"running",
		periodStart.Format("2006-01-02"),
		periodEnd.Format("2006-01-02"),
		tenantID,
	).Scan(&jobID)
	if err != nil {
		return nil, fmt.Errorf("failed to record sync job: %w", err)
	}

	return &jobID, nil
}

// UpdateSyncJob updates a sync job status.
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). The method is keyed by
// jobID alone and carries no tenant id (the job may be a platform-wide, tenant
// NULL row), so it cannot set app.tenant_id. aws_cost_sync_jobs is RLS-scoped;
// this path stays on bypassDB.
func (r *AWSCostRepository) UpdateSyncJob(ctx context.Context, jobID uuid.UUID, status string, recordsSynced int, totalCost float64, errorMsg *string) error {
	query := `
		UPDATE aws_cost_sync_jobs
		SET status = $1,
		    end_time = NOW(),
		    records_synced = $2,
		    total_cost = $3,
		    error_message = $4,
		    updated_at = NOW()
		WHERE id = $5
	`

	_, err := r.bypassDB.ExecContext(ctx, query, status, recordsSynced, totalCost, errorMsg, jobID)
	if err != nil {
		return fmt.Errorf("failed to update sync job: %w", err)
	}

	return nil
}
