package entitlements

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
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
//	            the MSP marked that plan is_trial and the tenant has an end date.
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

// selectTenantPlanFactsSQL reads the tier facts for one tenant. tenants and
// subscription_tiers are global tables (no RLS), so this answers identically
// on the application pool and the bypass pool.
const selectTenantPlanFactsSQL = `
SELECT COALESCE(st.display_name, st.name, ''), COALESCE(st.is_trial, false), t.trial_ends_at
FROM tenants t
LEFT JOIN subscription_tiers st ON st.id = t.subscription_tier_id
WHERE t.id = $1`

// ErrPlanTenantNotFound is returned by ResolvePlan for an unknown tenant.
var ErrPlanTenantNotFound = errors.New("entitlements: plan for unknown tenant")

// LoadTenantPlanFacts reads one tenant's tier facts.
func LoadTenantPlanFacts(ctx context.Context, db *sql.DB, tenantID uuid.UUID) (TenantPlanFacts, error) {
	var (
		f     TenantPlanFacts
		trial sql.NullTime
	)
	err := db.QueryRowContext(ctx, selectTenantPlanFactsSQL, tenantID).Scan(&f.TierDisplayName, &f.TierIsTrial, &trial)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrPlanTenantNotFound
	}
	if err != nil {
		return f, fmt.Errorf("entitlements: read plan facts for tenant %s: %w", tenantID, err)
	}
	if trial.Valid {
		t := trial.Time
		f.TrialEndsAt = &t
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
