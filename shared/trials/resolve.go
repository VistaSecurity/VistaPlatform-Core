package trials

import (
	"database/sql"
	"time"
)

// RowSelectSQL is the ONE statement that reads a tenant's trial state.
//
// It exists because the two halves of the trial system used to run their own
// version of this join, and they disagreed. The trial-lock middleware selected
// only trial_days_full / trial_days_soft / trial_start / converted_to_paid,
// omitting two columns the auth-service status endpoint reads:
//
//   - st.is_trial — without it, a tenant on a NON-trial tier (Pro/Enterprise
//     assigned through admin-ui, no Stripe webhook) whose obsolete
//     billing_trial_tracking row survived the tier migration got NULL day
//     counts, which Compute treats as 0, so any past trial_start resolved to
//     PhaseLocked. Result: HTTP 423 on every write across inventory, sensors,
//     CBOM, cluster-sensor and compliance — while /tenant/trial-status
//     cheerfully reported phase "none". An admin-granted POC trial on a
//     non-trial tier locked the tenant the instant it was granted.
//   - btt.trial_end — TrialManager.ExtendTrial writes ONLY trial_end, so an
//     administratively extended trial was invisible to the lock and the tenant
//     kept getting 423 after the extension was confirmed.
//
// Bind $1 = tenant id. Scan with ScanRow so the column order cannot drift from
// the SELECT.
const RowSelectSQL = `
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
		`

// Row holds the raw nullable columns RowSelectSQL returns, before they are
// interpreted into a Phase. Every field is nullable: a tenant may have no tier
// (onboarding) and/or no trial row (paid signup).
type Row struct {
	IsTrial         sql.NullBool
	TrialDaysFull   sql.NullInt64
	TrialDaysSoft   sql.NullInt64
	TrialStart      sql.NullTime
	TrialEnd        sql.NullTime
	ConvertedToPaid sql.NullBool
}

// rowScanner is satisfied by *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// ScanRow reads RowSelectSQL's columns in their declared order. Using it keeps
// the scan target list from drifting away from the SELECT list.
func ScanRow(s rowScanner) (Row, error) {
	var r Row
	err := s.Scan(&r.IsTrial, &r.TrialDaysFull, &r.TrialDaysSoft, &r.TrialStart, &r.TrialEnd, &r.ConvertedToPaid)
	return r, err
}

// Inputs converts the raw row into Compute's inputs at the given clock.
func (r Row) Inputs(now time.Time) Inputs {
	in := Inputs{Now: now}
	if r.TrialStart.Valid {
		in.TrialStart = r.TrialStart.Time
	}
	if r.TrialEnd.Valid {
		te := r.TrialEnd.Time
		in.TrialEnd = &te
	}
	if r.ConvertedToPaid.Valid {
		in.ConvertedToPaid = r.ConvertedToPaid.Bool
	}
	if r.TrialDaysFull.Valid {
		v := int(r.TrialDaysFull.Int64)
		in.TrialDaysFull = &v
	}
	if r.TrialDaysSoft.Valid {
		v := int(r.TrialDaysSoft.Int64)
		in.TrialDaysSoft = &v
	}
	return in
}

// OnTrialTier reports whether the tenant's tier is actually configured as a
// trial. Onboarding tenants (no tier → is_trial NULL) and paid tiers
// (is_trial = false) are NOT, regardless of what billing_trial_tracking says.
func (r Row) OnTrialTier() bool {
	return r.IsTrial.Valid && r.IsTrial.Bool
}

// ResolvePhase is the single interpretation of a trial row. Both the trial-lock
// middleware and the /tenant/trial-status endpoint go through it, so they
// cannot answer differently for the same tenant.
//
// A tenant not on a trial tier is PhaseNone: a stale billing_trial_tracking row
// left behind by a tier migration must never lock a paying customer out.
func ResolvePhase(r Row, now time.Time) (Phase, Inputs) {
	in := r.Inputs(now)
	if !r.OnTrialTier() {
		return PhaseNone, in
	}
	return Compute(in), in
}
