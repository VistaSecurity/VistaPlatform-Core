package entitlements

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/trials"
)

// The plan block: what a tenant is on, as a person should read it.
//
// It exists because the tier a tenant row points at is NOT the plan on two of
// the three editions. A self-hosted tenant lands on a capacity tier (named
// "community" in the seed) and, before the licence model, on a 30-day trial
// clock — and both UIs displayed those as the plan. On an Enterprise install
// that read "community · Trial · ends Oct 23" for a tenant holding every
// Enterprise capability (edition-licensing spec, Background §5).
//
// So every surface that names a tenant's plan — GET /tenant/features, the
// admin tenant list/detail, the effective-limits read-out — renders it from
// PlanFor, and only an MSP install ever shows a tier name or a trial:
//
//	Core        "Vista Platform Core"; no licensee, no expiry, no trial.
//	Enterprise  "Vista Platform Enterprise"; licensee + licence expiry. Never
//	            a tier name, never a trial — Enterprise has neither.
//	MSP         the tier's display_name (the MSP's own plan), plus a trial when
//	            the MSP marked that plan is_trial and the tenant has a live
//	            (unconverted) billing_trial_tracking row.
//
// An expired licence is Core here exactly as it is in the resolver.

// Display names for the two editions whose plan is the edition itself.
const (
	PlanDisplayNameCore       = "Vista Platform Core"
	PlanDisplayNameEnterprise = "Vista Platform Enterprise"
	// EditionDisplayNameMSP names the MSP edition itself (the licence card).
	// It is never an MSP tenant's plan: that is the MSP's own tier.
	EditionDisplayNameMSP = "Vista Platform MSP"
	// PlanDisplayNameUnassigned is shown on an MSP install for a tenant whose
	// row points at no tier. It should not happen (signup assigns one), but
	// an empty string would render as a blank badge.
	PlanDisplayNameUnassigned = "No plan assigned"
)

// PlanTrial is present only on an MSP install, for a tenant on a plan the MSP
// marked as a trial.
type PlanTrial struct {
	EndsAt time.Time `json:"ends_at"`
}

// Plan is the resolved plan block.
//
// Trial carries `omitempty` deliberately. "No trial" is the absent key, not
// `"trial": null`: an Enterprise response must not contain the word at all
// (spec §6 copy guard), and a key name is still the word.
type Plan struct {
	Edition     Edition    `json:"edition"`
	DisplayName string     `json:"display_name"`
	Licensee    *string    `json:"licensee"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Trial       *PlanTrial `json:"trial,omitempty"`
}

// TenantPlanFacts is what a tenant's own rows contribute to its plan. Only an
// MSP install reads it.
type TenantPlanFacts struct {
	TierDisplayName string
	TierIsTrial     bool
	TrialEndsAt     *time.Time
}

// EffectiveEdition is the edition the install runs as at `now`: the licence's
// edition while it is active, Core otherwise (no licence, expired licence, or
// an edition string this build does not know).
func (l *License) EffectiveEdition(now time.Time) Edition {
	if !l.Active(now) {
		return EditionCore
	}
	return l.Edition
}

// PlanFor renders the plan block. Pure, so list endpoints can call it per row
// after one licence read and one query for the tier facts.
func PlanFor(lic *License, now time.Time, facts TenantPlanFacts) Plan {
	switch lic.EffectiveEdition(now) {
	case EditionEnterprise:
		return Plan{
			Edition:     EditionEnterprise,
			DisplayName: PlanDisplayNameEnterprise,
			Licensee:    licenseeOf(lic),
			ExpiresAt:   expiryOf(lic),
		}
	case EditionMSP:
		p := Plan{
			Edition:     EditionMSP,
			DisplayName: facts.TierDisplayName,
			Licensee:    licenseeOf(lic),
			ExpiresAt:   expiryOf(lic),
		}
		if p.DisplayName == "" {
			p.DisplayName = PlanDisplayNameUnassigned
		}
		if facts.TierIsTrial && facts.TrialEndsAt != nil {
			p.Trial = &PlanTrial{EndsAt: *facts.TrialEndsAt}
		}
		return p
	default:
		return Plan{Edition: EditionCore, DisplayName: PlanDisplayNameCore}
	}
}

func licenseeOf(lic *License) *string {
	if lic == nil || lic.Licensee == "" {
		return nil
	}
	s := lic.Licensee
	return &s
}

func expiryOf(lic *License) *time.Time {
	if lic == nil {
		return nil
	}
	t := lic.ExpiresAt
	return &t
}

// HidesTierDetail reports whether tier names, trial dates and a "trial"
// payment status must be kept out of tenant and admin-tenant responses: true
// on every install except MSP. On Core the tier is unchanged product
// behaviour, but PlanFor already says "Vista Platform Core"; the tier columns
// themselves are only suppressed on Enterprise, where they are wrong rather
// than merely unhelpful.
func (p Plan) HidesTierDetail() bool {
	return p.Edition == EditionEnterprise
}

// PlanFactsSelectSQL reads a tenant's tier facts and its live trial, less the
// WHERE clause: the one-tenant read below appends `WHERE t.id = $1`,
// admin-service's tenant directory `WHERE t.id = ANY($1)`. One SELECT, so the
// two surfaces cannot disagree on what a trial is. Scan with ScanPlanFacts.
//
// The trial comes from billing_trial_tracking — the one trial store (owner
// decision 6) — not from tenants.trial_ends_at, which a since-removed trigger
// stamped with its own 30-day clock that disagreed with the trial row. A trial
// is shown only on a tier the MSP marked is_trial, and it ends when it locks
// (trials.LockAt), which honours an administrative extension and an
// administrative end (Billing → Trials → End trial stamps hard_locked_at).
//
// billing_trial_tracking carries a tenant_isolation RLS policy: read this on
// the bypass pool or in a tenant-scoped transaction (LoadTenantPlanFacts does
// the latter).
const PlanFactsSelectSQL = `
SELECT t.id, COALESCE(st.display_name, st.name, ''), st.is_trial,
       st.trial_days_full, st.trial_days_soft, btt.trial_start, btt.trial_end,
       btt.hard_locked_at
FROM tenants t
LEFT JOIN subscription_tiers st ON st.id = t.subscription_tier_id
LEFT JOIN LATERAL (
    SELECT b.trial_start, b.trial_end, b.hard_locked_at
    FROM billing_trial_tracking b
    WHERE b.tenant_id = t.id AND NOT COALESCE(b.converted_to_paid, false)
    ORDER BY b.created_at DESC
    LIMIT 1
) btt ON true`

// planFactsScanner is satisfied by *sql.Row and *sql.Rows.
type planFactsScanner interface {
	Scan(dest ...any) error
}

// ScanPlanFacts reads one PlanFactsSelectSQL row.
func ScanPlanFacts(s planFactsScanner) (uuid.UUID, TenantPlanFacts, error) {
	var (
		id  uuid.UUID
		f   TenantPlanFacts
		row trials.Row
	)
	if err := s.Scan(&id, &f.TierDisplayName, &row.IsTrial,
		&row.TrialDaysFull, &row.TrialDaysSoft, &row.TrialStart, &row.TrialEnd, &row.HardLockedAt); err != nil {
		return id, f, err
	}
	f.TierIsTrial = row.OnTrialTier()
	if f.TierIsTrial && row.TrialStart.Valid {
		ends := trials.LockAt(row.Inputs(time.Time{}))
		f.TrialEndsAt = &ends
	}
	return id, f, nil
}

// ErrPlanTenantNotFound is returned by ResolvePlan for an unknown tenant.
var ErrPlanTenantNotFound = errors.New("entitlements: plan for unknown tenant")

// LoadTenantPlanFacts reads one tenant's tier facts. It runs in a transaction
// scoped to the tenant, so the trial row is visible on the application pool;
// on the bypass pool the scoping is harmless.
func LoadTenantPlanFacts(ctx context.Context, db *sql.DB, tenantID uuid.UUID) (TenantPlanFacts, error) {
	var f TenantPlanFacts
	err := shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		var e error
		_, f, e = ScanPlanFacts(tx.QueryRowContext(ctx, PlanFactsSelectSQL+`
WHERE t.id = $1`, tenantID))
		return e
	})
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrPlanTenantNotFound
	}
	if err != nil {
		return f, fmt.Errorf("entitlements: read plan facts for tenant %s: %w", tenantID, err)
	}
	return f, nil
}

// ResolvePlan is PlanFor for one tenant, reading the licence (cached, see
// LoadLicense) and — only on MSP, the one edition that uses them — the
// tenant's tier facts.
func ResolvePlan(ctx context.Context, db *sql.DB, tenantID uuid.UUID) (Plan, error) {
	lic, err := LoadLicense(ctx, db)
	if err != nil {
		return Plan{}, err
	}
	now := time.Now()
	var facts TenantPlanFacts
	if lic.EffectiveEdition(now) == EditionMSP {
		if facts, err = LoadTenantPlanFacts(ctx, db, tenantID); err != nil {
			return Plan{}, err
		}
	}
	return PlanFor(lic, now, facts), nil
}
