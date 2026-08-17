package services

// Tenant-triggered compliance re-evaluation — the persisted, per-tenant cooldown.
//
// Findings are materialized: stored scores are recomputed only on asset/cert change,
// framework activation/publish, or a manual re-evaluation — never by an upgrade. So
// after an engine fix a tenant sees a stale score until something triggers a
// reconcile, and until now the only manual trigger was platform-admin.
//
// # Why the cooldown is in Postgres and not in a process
//
// compliance-engine runs multiple replicas, and the chart's `checksum/config` rolls
// the Deployment on every config change. An in-process timer therefore (a) resets on
// restart and (b) disagrees between pods — a tenant could bypass it simply by
// retrying until it hit a fresh pod. `Claim` is ONE conditional upsert, so Postgres
// arbitrates: two concurrent requests landing on two pods cannot both win, because
// the loser's ON CONFLICT DO UPDATE ... WHERE finds the row already fresh.
//
// This is a cooldown, NOT the in-flight de-duplication that
// FindingsService.ReconcileTenantCoalesced already does. Coalescing collapses
// CONCURRENT requests into one run; once that run finishes another can start
// immediately. Both are wanted; neither substitutes for the other.
//
// # Platform admin is exempt, deliberately
//
// AdminReconcileHandler does not go through this service at all. It stays unbounded
// as the escape hatch after an engine fix or a bulk import (owner decision, 2026-08).
// Two tests pin the exemption so it cannot be quietly closed:
// TestIntegration_PlatformAdminReevaluation_IsNotRateLimited here, and
// TestContract_AdminReevaluateIsNotRateLimited on the admin route itself.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// DefaultReevaluationCooldown is the per-tenant window between accepted tenant-
// triggered re-evaluations (owner decision: one hour, per tenant, regardless of
// which user clicks).
const DefaultReevaluationCooldown = time.Hour

// ReevaluationState is the cooldown as the UI needs to render it: what happened
// last, whether a run may start now, and when the next one may.
type ReevaluationState struct {
	// LastRequestedAt is nil when this tenant has never triggered one.
	LastRequestedAt *time.Time
	// NextAllowedAt is nil exactly when Allowed is true.
	NextAllowedAt *time.Time
	Allowed       bool
	Cooldown      time.Duration
}

// RetryAfter is the whole number of seconds until the next request is allowed,
// rounded up (never negative, never 0 while blocked — a 0 would read as "now").
func (s ReevaluationState) RetryAfter(now time.Time) int {
	if s.Allowed || s.NextAllowedAt == nil {
		return 0
	}
	d := s.NextAllowedAt.Sub(now)
	if d <= 0 {
		return 0
	}
	secs := int(d / time.Second)
	if d%time.Second != 0 {
		secs++
	}
	return secs
}

// ReevaluationService owns the persisted cooldown. It does NOT run the reconcile —
// that stays with ReconcileEnqueuer, so there is exactly one reconcile path.
type ReevaluationService struct {
	db       *sqlx.DB
	cooldown time.Duration
}

// NewReevaluationService builds the service at the default cooldown.
func NewReevaluationService(db *sqlx.DB) *ReevaluationService {
	return &ReevaluationService{db: db, cooldown: DefaultReevaluationCooldown}
}

// WithCooldown returns a copy using a different window. Tests use it to exercise
// the boundary without sleeping an hour; production always uses the default.
func (s *ReevaluationService) WithCooldown(d time.Duration) *ReevaluationService {
	return &ReevaluationService{db: s.db, cooldown: d}
}

// Cooldown reports the configured window.
func (s *ReevaluationService) Cooldown() time.Duration { return s.cooldown }

func (s *ReevaluationService) stateFrom(last *time.Time, now time.Time) ReevaluationState {
	st := ReevaluationState{LastRequestedAt: last, Allowed: true, Cooldown: s.cooldown}
	if last == nil {
		return st
	}
	next := last.Add(s.cooldown)
	if next.After(now) {
		st.Allowed = false
		st.NextAllowedAt = &next
	}
	return st
}

// State reads the current cooldown for one tenant. RLS-scoped: the row is only
// visible under the caller's own app.tenant_id.
func (s *ReevaluationService) State(ctx context.Context, tenantID uuid.UUID) (ReevaluationState, error) {
	var last *time.Time
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT last_requested_at FROM public.tenant_reevaluation_requests WHERE tenant_id = $1`,
			tenantID)
		switch err := row.Scan(&last); {
		case err == sql.ErrNoRows:
			last = nil
			return nil
		case err != nil:
			return err
		}
		return nil
	})
	if err != nil {
		return ReevaluationState{}, fmt.Errorf("reevaluation: read state: %w", err)
	}
	return s.stateFrom(last, time.Now()), nil
}

// Claim attempts to consume the cooldown for tenantID. It returns the resulting
// state and whether the claim succeeded; when it did not, NOTHING was written and
// the caller must not enqueue a reconcile.
//
// The whole decision is one statement on purpose. Read-then-write would let two
// replicas both read "allowed" and both write, which is precisely the bypass the
// persisted cooldown exists to prevent. The ON CONFLICT ... WHERE clause makes the
// update conditional inside the same statement, and the absence of a RETURNING row
// IS the refusal.
func (s *ReevaluationService) Claim(ctx context.Context, tenantID, userID uuid.UUID) (ReevaluationState, bool, error) {
	var (
		claimed bool
		last    *time.Time
	)
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		var by any
		if userID != uuid.Nil {
			by = userID
		}
		var claimedAt time.Time
		err := tx.QueryRowContext(ctx, `
			INSERT INTO public.tenant_reevaluation_requests
			       (tenant_id, last_requested_at, last_requested_by, request_count)
			VALUES ($1, now(), $2, 1)
			ON CONFLICT (tenant_id) DO UPDATE
			   SET last_requested_at = now(),
			       last_requested_by = EXCLUDED.last_requested_by,
			       request_count     = public.tenant_reevaluation_requests.request_count + 1
			 WHERE public.tenant_reevaluation_requests.last_requested_at <= now() - $3::interval
			RETURNING last_requested_at`,
			tenantID, by, fmt.Sprintf("%d seconds", int64(s.cooldown/time.Second))).Scan(&claimedAt)
		switch {
		case err == sql.ErrNoRows:
			// Refused. Re-read so the caller can tell the user when it reopens.
			claimed = false
			row := tx.QueryRowContext(ctx,
				`SELECT last_requested_at FROM public.tenant_reevaluation_requests WHERE tenant_id = $1`,
				tenantID)
			if err := row.Scan(&last); err != nil && err != sql.ErrNoRows {
				return err
			}
			return nil
		case err != nil:
			return err
		}
		claimed = true
		last = &claimedAt
		return nil
	})
	if err != nil {
		return ReevaluationState{}, false, fmt.Errorf("reevaluation: claim: %w", err)
	}
	return s.stateFrom(last, time.Now()), claimed, nil
}
