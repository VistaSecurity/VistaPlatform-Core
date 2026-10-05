package services

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type RateLimiter struct {
	db *sqlx.DB
}

func NewRateLimiter(db *sqlx.DB) *RateLimiter {
	return &RateLimiter{db: db}
}

// withTenantTxx runs fn inside a tenant-scoped sqlx transaction, preserving
// sqlx's struct-scanning (Get/Select). Mirrors shareddatabase.WithTenantTx but
// yields a *sqlx.Tx; tenant context is set on the embedded *sql.Tx.
func (r *RateLimiter) withTenantTxx(ctx context.Context, tenantID uuid.UUID, fn func(*sqlx.Tx) error) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rls: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *RateLimiter) GetRateLimit(tenantID string) (*models.DiscoveryRateLimit, error) {
	return r.getRateLimit(tenantID, true)
}

// getRateLimit reads the tenant's limits. A tenant with none stored gets the
// defaults, and persistDefault says whether they are written down (the first
// real request does; a dry run must write nothing).
func (r *RateLimiter) getRateLimit(tenantID string, persistDefault bool) (*models.DiscoveryRateLimit, error) {
	// RLS-scoped read over discovery_rate_limits (tenant_isolation policy). The
	// explicit WHERE tenant_id = $1 stays as the primary control.
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id: %w", err)
	}

	rateLimit := &models.DiscoveryRateLimit{}
	query := `SELECT id, tenant_id, scans_per_hour, concurrent_jobs, max_targets_per_job, is_active, created_at, updated_at
	          FROM discovery_rate_limits WHERE tenant_id = $1 AND is_active = true`

	found := true
	err = r.withTenantTxx(context.Background(), tenantUUID, func(tx *sqlx.Tx) error {
		e := tx.Get(rateLimit, query, tenantID)
		if e == sql.ErrNoRows {
			found = false
			return nil
		}
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get rate limit: %w", err)
	}
	if !found {
		if !persistDefault {
			return defaultRateLimit(tenantID), nil
		}
		// Create default rate limit
		return r.createDefaultRateLimit(tenantID)
	}
	return rateLimit, nil
}

// defaultRateLimit is what a tenant with no stored limits is held to.
func defaultRateLimit(tenantID string) *models.DiscoveryRateLimit {
	return &models.DiscoveryRateLimit{
		TenantID:         tenantID,
		ScansPerHour:     100,
		ConcurrentJobs:   5,
		MaxTargetsPerJob: 1000,
		IsActive:         true,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

func (r *RateLimiter) createDefaultRateLimit(tenantID string) (*models.DiscoveryRateLimit, error) {
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id: %w", err)
	}

	rateLimit := defaultRateLimit(tenantID)

	// ON CONFLICT: two first requests for a tenant (concurrent deliveries of
	// its first job) both find no row and both insert. The loser used to get a
	// unique violation, which CheckRateLimit reported as "rate limit exceeded"
	// and the processor turned into a FAILED job. It now reads the winner's row.
	query := `
		INSERT INTO discovery_rate_limits (tenant_id, scans_per_hour, concurrent_jobs, max_targets_per_job, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id) DO NOTHING
		RETURNING id`

	// RLS-scoped write: WithTenantTx sets app.tenant_id so the INSERT's
	// tenant_id satisfies the policy WITH CHECK.
	inserted := true
	err = shareddatabase.WithTenantTx(context.Background(), r.db.DB, tenantUUID, func(tx *sql.Tx) error {
		e := tx.QueryRow(query,
			rateLimit.TenantID, rateLimit.ScansPerHour, rateLimit.ConcurrentJobs,
			rateLimit.MaxTargetsPerJob, rateLimit.IsActive, rateLimit.CreatedAt, rateLimit.UpdatedAt).Scan(&rateLimit.ID)
		if e == sql.ErrNoRows {
			inserted = false
			return nil
		}
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create default rate limit: %w", err)
	}
	if !inserted {
		existing := &models.DiscoveryRateLimit{}
		err = r.withTenantTxx(context.Background(), tenantUUID, func(tx *sqlx.Tx) error {
			return tx.Get(existing, `SELECT id, tenant_id, scans_per_hour, concurrent_jobs, max_targets_per_job, is_active, created_at, updated_at
			          FROM discovery_rate_limits WHERE tenant_id = $1 AND is_active = true`, tenantID)
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create default rate limit: %w", err)
		}
		return existing, nil
	}
	return rateLimit, nil
}

func (r *RateLimiter) UpdateRateLimit(tenantID string, req models.RateLimitConfigRequest) error {
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant_id: %w", err)
	}

	query := `
		UPDATE discovery_rate_limits
		SET scans_per_hour = $1, concurrent_jobs = $2, max_targets_per_job = $3, is_active = $4, updated_at = NOW()
		WHERE tenant_id = $5`

	// RLS-scoped UPDATE over discovery_rate_limits.
	err = shareddatabase.WithTenantTx(context.Background(), r.db.DB, tenantUUID, func(tx *sql.Tx) error {
		_, e := tx.Exec(query, req.ScansPerHour, req.ConcurrentJobs, req.MaxTargetsPerJob, req.IsActive, tenantID)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to update rate limit: %w", err)
	}
	return nil
}

func (r *RateLimiter) CheckRateLimit(tenantID string) error {
	return r.checkRateLimit(tenantID, true)
}

// CheckRateLimitReadOnly is CheckRateLimit for a request that creates nothing
// (a dry run): the same two counts against the same limits, and the same
// refusal, but a tenant with no stored limits is judged against the defaults
// without the defaults being stored.
func (r *RateLimiter) CheckRateLimitReadOnly(tenantID string) error {
	return r.checkRateLimit(tenantID, false)
}

func (r *RateLimiter) checkRateLimit(tenantID string, persistDefault bool) error {
	rateLimit, err := r.getRateLimit(tenantID, persistDefault)
	if err != nil {
		return err
	}

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant_id: %w", err)
	}

	// RLS-scoped reads over discovery_jobs. Both counts run on one
	// tenant-scoped transaction; the explicit WHERE tenant_id = $1 stays as the
	// primary control.
	var concurrentJobs, scansThisHour int
	err = r.withTenantTxx(context.Background(), tenantUUID, func(tx *sqlx.Tx) error {
		query := `SELECT COUNT(*) FROM discovery_jobs WHERE tenant_id = $1 AND status IN ('queued', 'running')`
		if e := tx.Get(&concurrentJobs, query, tenantID); e != nil {
			return fmt.Errorf("failed to check concurrent jobs: %w", e)
		}

		query = `SELECT COUNT(*) FROM discovery_jobs WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '1 hour'`
		if e := tx.Get(&scansThisHour, query, tenantID); e != nil {
			return fmt.Errorf("failed to check scans per hour: %w", e)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if concurrentJobs >= rateLimit.ConcurrentJobs {
		return fmt.Errorf("rate limit exceeded: too many concurrent jobs (%d/%d)", concurrentJobs, rateLimit.ConcurrentJobs)
	}

	if scansThisHour >= rateLimit.ScansPerHour {
		return fmt.Errorf("rate limit exceeded: too many scans this hour (%d/%d)", scansThisHour, rateLimit.ScansPerHour)
	}

	return nil
}
