package api

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/trials"
)

// trialStatusResponse is the JSON shape consumed by web-ui's trial
// banner + hard-lock route guards. Fields stay tolerant of NULLs from
// the DB (paid tenants, pre-PR-1 tenants) so the frontend can render
// a single "no trial in progress" code path.
type trialStatusResponse struct {
	// Phase is the canonical state: none / full / soft_prompt / locked /
	// converted. UI gates everything off of this.
	Phase trials.Phase `json:"phase"`

	// TrialStart and TrialEnd come from billing_trial_tracking. Both
	// null for paid tenants. TrialEnd reflects the original computed
	// end; extensions update it via TrialManager.
	TrialStart *time.Time `json:"trial_start,omitempty"`
	TrialEnd   *time.Time `json:"trial_end,omitempty"`

	// DaysRemaining is the floored days-until-next-transition. 0 in
	// locked/converted/none. Surfaced as "N days left in trial" or
	// "N days until lockout" depending on Phase.
	DaysRemaining int `json:"days_remaining"`

	// TrialDaysFull and TrialDaysSoft mirror the tier configuration
	// so the UI can show the phase boundaries on a progress bar
	// without a second round trip.
	TrialDaysFull *int `json:"trial_days_full,omitempty"`
	TrialDaysSoft *int `json:"trial_days_soft,omitempty"`
}

// trialStatusRow holds the raw nullable columns read for a tenant's trial
// state, before they are interpreted into a phase.
type trialStatusRow struct {
	isTrial       sql.NullBool
	trialDaysFull sql.NullInt64
	trialDaysSoft sql.NullInt64
	trialStart    sql.NullTime
	trialEnd      sql.NullTime
	converted     sql.NullBool
}

// trialStatusStore is the narrow read interface the trial-status handler
// depends on. The concrete repository runs the join; the contract test drives a
// stub so the handler can be exercised without a database.
type trialStatusStore interface {
	GetTrialStatusRow(tenantID uuid.UUID) (trialStatusRow, error)
}

// trialStatusRepository is the production trialStatusStore backed by *sql.DB.
// The join is moved verbatim from the previous inline resolver.
type trialStatusRepository struct{ db *sql.DB }

func (r *trialStatusRepository) GetTrialStatusRow(tenantID uuid.UUID) (trialStatusRow, error) {
	var row trialStatusRow
	// Single statement joins tenants → subscription_tiers → optional
	// billing_trial_tracking. LEFT JOIN on trial tracking so paid
	// tenants (no row) still produce a result we can interpret as
	// "no trial."
	//
	// RLS-scoped: the LEFT JOIN pulls billing_trial_tracking (tenant_isolation
	// policy); without app.tenant_id that row would drop once RLS enforces. The
	// lead tenants/subscription_tiers tables are global. Tenant is known.
	err := shareddatabase.WithTenantTx(context.Background(), r.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), `
			SELECT
			    st.is_trial,
			    st.trial_days_full,
			    st.trial_days_soft,
			    btt.trial_start,
			    btt.trial_end,
			    btt.converted_to_paid
			FROM tenants t
			LEFT JOIN subscription_tiers st ON st.id = t.subscription_tier_id
			LEFT JOIN billing_trial_tracking btt ON btt.tenant_id = t.id
			WHERE t.id = $1
		`, tenantID).Scan(&row.isTrial, &row.trialDaysFull, &row.trialDaysSoft, &row.trialStart, &row.trialEnd, &row.converted)
	})
	return row, err
}

// getTenantTrialStatusHandler resolves the calling tenant's current
// trial phase from (tier trial_days_*) and (billing_trial_tracking row).
//
// Always returns 200 with a phase. Paid tenants and tenants with no
// trial row resolve to PhaseNone. Errors during lookup degrade to
// PhaseNone with a logged warning rather than failing the call — the
// banner is cosmetic and we never want it to break the rest of the UI.
func getTenantTrialStatusHandler(db *sql.DB) gin.HandlerFunc {
	return getTenantTrialStatusHandlerWithStore(&trialStatusRepository{db: db})
}

// getTenantTrialStatusHandlerWithStore is the store-backed handler core.
func getTenantTrialStatusHandlerWithStore(store trialStatusStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}
		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		resp := resolveTrialStatusFromStore(store, tenantID, time.Now())
		c.JSON(http.StatusOK, resp)
	}
}

// resolveTrialStatus keeps its *sql.DB signature so the DB-backed integration
// tests (trial_status_test.go) drive the real join. It delegates to the
// store-backed resolver.
func resolveTrialStatus(db *sql.DB, tenantID uuid.UUID, now time.Time) trialStatusResponse {
	return resolveTrialStatusFromStore(&trialStatusRepository{db: db}, tenantID, now)
}

// resolveTrialStatusFromStore reads the raw row via the store and interprets it
// into a phase with a fixed clock. A lookup error degrades to PhaseNone.
func resolveTrialStatusFromStore(store trialStatusStore, tenantID uuid.UUID, now time.Time) trialStatusResponse {
	row, err := store.GetTrialStatusRow(tenantID)
	if err != nil {
		log.Printf("getTenantTrialStatusHandler: tenant %s lookup failed: %v", tenantID, err)
		return trialStatusResponse{Phase: trials.PhaseNone}
	}
	isTrial := row.isTrial
	trialDaysFull := row.trialDaysFull
	trialDaysSoft := row.trialDaysSoft
	trialStart := row.trialStart
	trialEnd := row.trialEnd
	converted := row.converted

	inputs := trials.Inputs{Now: now}
	if trialStart.Valid {
		inputs.TrialStart = trialStart.Time
	}
	if trialEnd.Valid {
		te := trialEnd.Time
		inputs.TrialEnd = &te
	}
	if converted.Valid {
		inputs.ConvertedToPaid = converted.Bool
	}
	if trialDaysFull.Valid {
		v := int(trialDaysFull.Int64)
		inputs.TrialDaysFull = &v
	}
	if trialDaysSoft.Valid {
		v := int(trialDaysSoft.Int64)
		inputs.TrialDaysSoft = &v
	}

	resp := trialStatusResponse{
		Phase:         trials.Compute(inputs),
		DaysRemaining: trials.DaysRemaining(inputs),
		TrialDaysFull: inputs.TrialDaysFull,
		TrialDaysSoft: inputs.TrialDaysSoft,
	}
	if trialStart.Valid {
		t := trialStart.Time
		resp.TrialStart = &t
	}
	if trialEnd.Valid {
		t := trialEnd.Time
		resp.TrialEnd = &t
	}

	// Onboarding (no tier), paid tiers, and any tier with is_trial = false must
	// not be trial-gated — even when an obsolete billing_trial_tracking row
	// survives a tier migration.
	onTrialTier := isTrial.Valid && isTrial.Bool
	if !onTrialTier {
		resp.Phase = trials.PhaseNone
		resp.DaysRemaining = 0
		return resp
	}

	return resp
}
