package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type RateLimiter struct {
	db *sqlx.DB
}

// RateLimitExceededError is a refusal: the tenant is at one of its limits.
// Any other error from a check is a failure to check (the database), which a
// caller must not report as a refusal.
type RateLimitExceededError struct {
	Limit string // "concurrent jobs" or "scans this hour"
	Count int
	Max   int
}

func (e *RateLimitExceededError) Error() string {
	return fmt.Sprintf("rate limit exceeded: too many %s (%d/%d)", e.Limit, e.Count, e.Max)
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
	query := rateLimitSelect

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
	return effectiveLimits(tenantID, rateLimit), nil
}

// rateLimitSelect reads the tenant's stored row whatever its is_active. Reading
// only active rows made a stored inactive row indistinguishable from no row:
// the default insert then hit ON CONFLICT, the re-read (is_active = true again)
// found nothing, and every job creation failed with sql.ErrNoRows.
const rateLimitSelect = `SELECT id, tenant_id, scans_per_hour, concurrent_jobs, max_targets_per_job, is_active, created_at, updated_at
	FROM discovery_rate_limits WHERE tenant_id = $1`

// maxTargetsPerJobCeiling is the most targets one job may ever carry; a tenant's
// max_targets_per_job can lower it, never raise it.
const maxTargetsPerJobCeiling = 1000

// effectiveLimits is the limits a tenant is actually held to. An inactive row
// means the tenant's configuration is switched off, so the defaults apply (a
// "disabled" limit is not "no limit"). A stored value below 1 — written by an
// earlier version that accepted anything — would refuse every request, so that
// field falls back to its default too: a limits-config problem must never stop
// jobs being created.
func effectiveLimits(tenantID string, stored *models.DiscoveryRateLimit) *models.DiscoveryRateLimit {
	def := defaultRateLimit(tenantID)
	if stored == nil || !stored.IsActive {
		return def
	}
	out := *stored
	if out.ScansPerHour < 1 {
		out.ScansPerHour = def.ScansPerHour
	}
	if out.ConcurrentJobs < 1 {
		out.ConcurrentJobs = def.ConcurrentJobs
	}
	if out.MaxTargetsPerJob < 1 {
		out.MaxTargetsPerJob = def.MaxTargetsPerJob
	}
	return &out
}

// MaxTargetsFor is the number of targets one job may carry for this tenant: the
// lower of its max_targets_per_job and the platform ceiling. Read-only; a
// failure to read falls back to the ceiling's default rather than failing the
// request.
func (r *RateLimiter) MaxTargetsFor(tenantID string) int {
	limits, err := r.getRateLimit(tenantID, false)
	if err != nil {
		log.Printf("[RateLimiter] reading limits for tenant %s failed, using defaults: %v", tenantID, err)
		limits = defaultRateLimit(tenantID)
	}
	if limits.MaxTargetsPerJob < maxTargetsPerJobCeiling {
		return limits.MaxTargetsPerJob
	}
	return maxTargetsPerJobCeiling
}

// CheckAndReserveInTx is the rate check made atomic with the job insert. It
// takes a per-tenant transaction-scoped advisory lock, then counts the tenant's
// jobs on the caller's transaction: a concurrent create for the same tenant
// waits for this transaction to commit (its job row visible) before it counts,
// so the limits hold under concurrency. Call it immediately before the INSERT.
func (r *RateLimiter) CheckAndReserveInTx(tx *sql.Tx, tenantID string) error {
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1, 72048))`, tenantID); err != nil {
		return fmt.Errorf("lock tenant rate limit: %w", err)
	}
	stored := &models.DiscoveryRateLimit{}
	err := tx.QueryRow(rateLimitSelect, tenantID).Scan(&stored.ID, &stored.TenantID, &stored.ScansPerHour,
		&stored.ConcurrentJobs, &stored.MaxTargetsPerJob, &stored.IsActive, &stored.CreatedAt, &stored.UpdatedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		stored = nil
	case err != nil:
		return fmt.Errorf("failed to get rate limit: %w", err)
	}
	limits := effectiveLimits(tenantID, stored)
	var concurrentJobs, scansThisHour int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM discovery_jobs WHERE tenant_id = $1 AND status IN ('queued', 'running')`, tenantID).Scan(&concurrentJobs); err != nil {
		return fmt.Errorf("failed to check concurrent jobs: %w", err)
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM discovery_jobs WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '1 hour'`, tenantID).Scan(&scansThisHour); err != nil {
		return fmt.Errorf("failed to check scans per hour: %w", err)
	}
	return compareLimits(limits, concurrentJobs, scansThisHour)
}

func compareLimits(limits *models.DiscoveryRateLimit, concurrentJobs, scansThisHour int) error {
	if concurrentJobs >= limits.ConcurrentJobs {
		return &RateLimitExceededError{Limit: "concurrent jobs", Count: concurrentJobs, Max: limits.ConcurrentJobs}
	}
	if scansThisHour >= limits.ScansPerHour {
		return &RateLimitExceededError{Limit: "scans this hour", Count: scansThisHour, Max: limits.ScansPerHour}
	}
	return nil
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
			return tx.Get(existing, rateLimitSelect, tenantID)
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create default rate limit: %w", err)
		}
		return effectiveLimits(tenantID, existing), nil
	}
	return rateLimit, nil
}

// UpdateRateLimit stores the tenant's limits. A field the request omits keeps
// its stored value (or the default, for a tenant with no row yet), so a partial
// PUT cannot zero the rest. The caller validates req first.
func (r *RateLimiter) UpdateRateLimit(tenantID string, req models.RateLimitConfigRequest) error {
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant_id: %w", err)
	}

	query := `
		INSERT INTO discovery_rate_limits (tenant_id, scans_per_hour, concurrent_jobs, max_targets_per_job, is_active, created_at, updated_at)
		VALUES ($1, COALESCE($2::int, 100), COALESCE($3::int, 5), COALESCE($4::int, 1000), COALESCE($5::boolean, true), NOW(), NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			scans_per_hour = COALESCE($2::int, discovery_rate_limits.scans_per_hour),
			concurrent_jobs = COALESCE($3::int, discovery_rate_limits.concurrent_jobs),
			max_targets_per_job = COALESCE($4::int, discovery_rate_limits.max_targets_per_job),
			is_active = COALESCE($5::boolean, discovery_rate_limits.is_active),
			updated_at = NOW()`

	// RLS-scoped upsert over discovery_rate_limits.
	err = shareddatabase.WithTenantTx(context.Background(), r.db.DB, tenantUUID, func(tx *sql.Tx) error {
		_, e := tx.Exec(query, tenantID, req.ScansPerHour, req.ConcurrentJobs, req.MaxTargetsPerJob, req.IsActive)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to update rate limit: %w", err)
	}
	return nil
}

func (r *RateLimiter) CheckRateLimit(tenantID string) error {
	return r.checkRateLimit(tenantID, true, "")
}

// CheckRateLimitForJob is CheckRateLimit at the moment a queued job is picked
// up to run. The job's own row is already in the queue — it passed this check
// when it was created, against the jobs ahead of it — so it is left out of
// both counts. Counted, a job was its own fifth concurrent job: at exactly
// concurrent_jobs queued the oldest was refused with "5/5" and failed, with
// nothing running at all; and the hundredth scan of an hour, admitted at
// creation as the hundredth, was refused at processing as one too many.
func (r *RateLimiter) CheckRateLimitForJob(tenantID, jobID string) error {
	return r.checkRateLimit(tenantID, true, jobID)
}

// CheckRateLimitReadOnly is CheckRateLimit for a request that creates nothing
// (a dry run): the same two counts against the same limits, and the same
// refusal, but a tenant with no stored limits is judged against the defaults
// without the defaults being stored.
func (r *RateLimiter) CheckRateLimitReadOnly(tenantID string) error {
	return r.checkRateLimit(tenantID, false, "")
}

// checkRateLimit counts the tenant's jobs against its limits. excludeJobID,
// when set, is a job already in the queue whose own row must not count
// against itself (CheckRateLimitForJob).
func (r *RateLimiter) checkRateLimit(tenantID string, persistDefault bool, excludeJobID string) error {
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
	// $2 is the excluded job, or '' for none: id <> '' is true for every row
	// without the query having to take two shapes. NULLIF keeps the empty
	// string from being cast to uuid.
	var concurrentJobs, scansThisHour int
	err = r.withTenantTxx(context.Background(), tenantUUID, func(tx *sqlx.Tx) error {
		query := `SELECT COUNT(*) FROM discovery_jobs WHERE tenant_id = $1 AND status IN ('queued', 'running')
		          AND id IS DISTINCT FROM NULLIF($2, '')::uuid`
		if e := tx.Get(&concurrentJobs, query, tenantID, excludeJobID); e != nil {
			return fmt.Errorf("failed to check concurrent jobs: %w", e)
		}

		query = `SELECT COUNT(*) FROM discovery_jobs WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '1 hour'
		         AND id IS DISTINCT FROM NULLIF($2, '')::uuid`
		if e := tx.Get(&scansThisHour, query, tenantID, excludeJobID); e != nil {
			return fmt.Errorf("failed to check scans per hour: %w", e)
		}
		return nil
	})
	if err != nil {
		return err
	}

	return compareLimits(rateLimit, concurrentJobs, scansThisHour)
}
