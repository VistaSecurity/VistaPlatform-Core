// Package trials computes the single source of truth for a tenant's
// trial phase.
//
// The model is two-stage:
//
//	trial_start ──[trial_days_full]──> soft_prompt_starts ──[trial_days_soft]──> hard_lock
//
// During the "full" phase the tenant has unimpeded access. During the
// "soft_prompt" phase access is preserved but the UI nags. After
// hard_lock, the UI gates writes and pushes the tenant to upgrade.
//
// Conversion to a paid tier (via ConvertToPaid) freezes the trial in
// "converted" — the timestamps are kept for analytics but the phase
// is not advanced further.
//
// Compute is read-side authoritative: it derives the phase from the
// elapsed clock and the tier's trial_days_*, even when the periodic
// cron hasn't yet stamped soft_prompt_started_at / hard_locked_at.
// That keeps banner-style UI consistent within a phase boundary
// regardless of cron cadence.
package trials

import (
	"time"
)

// Phase enumerates the discrete states a trial can be in. Returned by
// Compute and persisted indirectly via the soft_prompt_started_at /
// hard_locked_at columns on billing_trial_tracking.
type Phase string

const (
	// PhaseNone means the tenant has no trial row at all. Either they
	// never had one (paid signup) or their tenant predates the trial
	// system. Callers should not assume the tenant is locked out — only
	// trial-aware callers check phase, and PhaseNone means "trial isn't
	// the right lens here."
	PhaseNone Phase = "none"

	// PhaseFull is the unrestricted-access portion of the trial. UI
	// surfaces no banners. Length = tier.trial_days_full.
	PhaseFull Phase = "full"

	// PhaseSoftPrompt is the post-PhaseFull nag window. UI shows a
	// dismissable upgrade banner; writes continue. Length =
	// tier.trial_days_soft.
	PhaseSoftPrompt Phase = "soft_prompt"

	// PhaseLocked is the post-PhaseSoftPrompt hard-lock. UI blocks
	// writes and routes the tenant to upgrade. Persists until the
	// tenant converts or the platform admin extends the trial.
	PhaseLocked Phase = "locked"

	// PhaseConverted means the trial ended successfully — the tenant
	// upgraded to a paid plan. The trial row is kept for conversion
	// analytics but phase never advances past this.
	PhaseConverted Phase = "converted"
)

// Inputs is everything Compute needs to determine a phase. It bundles
// the immutable trial-row fields, the relevant tier fields, and the
// current clock — passing them as a struct keeps the call sites tidy
// and the tests trivially shimable.
type Inputs struct {
	// TrialStart is billing_trial_tracking.trial_start. Zero value
	// (the zero time.Time) signals "no trial row" and Compute returns
	// PhaseNone.
	TrialStart time.Time

	// ConvertedToPaid mirrors billing_trial_tracking.converted_to_paid.
	// When true, Compute returns PhaseConverted regardless of clock.
	ConvertedToPaid bool

	// TrialDaysFull is subscription_tiers.trial_days_full for the
	// tenant's current tier. Nil means the tier is not configured as
	// a trial — Compute treats it as 0 (immediately past full phase).
	TrialDaysFull *int

	// TrialDaysSoft is subscription_tiers.trial_days_soft for the
	// tenant's current tier. Nil → 0 (no soft-prompt phase; full
	// goes straight to locked at trial_start + trial_days_full).
	TrialDaysSoft *int

	// Now is the clock the phase is computed against. Tests inject a
	// fixed time; production passes time.Now().
	Now time.Time

	// TrialEnd is billing_trial_tracking.trial_end when present. Used
	// only to delay hard-lock when the row has been extended past the
	// tier-derived calendar (trial_start + trial_days_full +
	// trial_days_soft). Nil/zero leaves lock timing tier-only — the
	// historical behavior before ExtendTrial lengthened trial_end alone.
	TrialEnd *time.Time
}

// Compute returns the phase a trial is in at Inputs.Now. It is pure:
// given the same inputs it always returns the same phase, so it can be
// safely called from any read path.
//
// Resolution order:
//
//  1. No trial row (TrialStart zero) → PhaseNone.
//  2. Converted to paid → PhaseConverted.
//  3. Past the effective hard-lock instant → PhaseLocked. That instant is
//     trial_start + trial_days_full + trial_days_soft, extended to trial_end
//     when TrialEnd is set and falls after that tier-derived moment
//     (TrialManager extension).
//  4. Past trial_start + full → PhaseSoftPrompt.
//  5. Otherwise → PhaseFull.
//
// The cron's job (CheckTrialExpiry) is to STAMP transitions and emit
// notifications when each new phase first applies — but the phase
// returned here is whatever the clock + tier values dictate, even when
// the cron hasn't run yet. That avoids the "day 15 banner shows up
// an hour late" UX problem.
func Compute(in Inputs) Phase {
	if in.TrialStart.IsZero() {
		return PhaseNone
	}
	if in.ConvertedToPaid {
		return PhaseConverted
	}

	fullDays := 0
	if in.TrialDaysFull != nil {
		fullDays = *in.TrialDaysFull
	}
	softDays := 0
	if in.TrialDaysSoft != nil {
		softDays = *in.TrialDaysSoft
	}

	endFull := in.TrialStart.Add(time.Duration(fullDays) * 24 * time.Hour)
	lockAt := endFull.Add(time.Duration(softDays) * 24 * time.Hour)
	if in.TrialEnd != nil && !in.TrialEnd.IsZero() && in.TrialEnd.After(lockAt) {
		lockAt = *in.TrialEnd
	}

	switch {
	case !in.Now.Before(lockAt):
		return PhaseLocked
	case !in.Now.Before(endFull):
		return PhaseSoftPrompt
	default:
		return PhaseFull
	}
}

// DaysRemaining returns days left until the next phase transition, or
// 0 in PhaseLocked / PhaseConverted / PhaseNone. UI shows it as
// "N days left in your trial" / "N days until your trial ends".
//
// Rounds DOWN intentionally — partial days remaining are reported as
// the floor so the banner doesn't say "1 day left" with two hours to
// go.
func DaysRemaining(in Inputs) int {
	phase := Compute(in)
	switch phase {
	case PhaseFull:
		fullDays := 0
		if in.TrialDaysFull != nil {
			fullDays = *in.TrialDaysFull
		}
		endFull := in.TrialStart.Add(time.Duration(fullDays) * 24 * time.Hour)
		return daysBetween(in.Now, endFull)
	case PhaseSoftPrompt:
		fullDays := 0
		if in.TrialDaysFull != nil {
			fullDays = *in.TrialDaysFull
		}
		softDays := 0
		if in.TrialDaysSoft != nil {
			softDays = *in.TrialDaysSoft
		}
		lockAt := in.TrialStart.Add(time.Duration(fullDays+softDays) * 24 * time.Hour)
		if in.TrialEnd != nil && !in.TrialEnd.IsZero() && in.TrialEnd.After(lockAt) {
			lockAt = *in.TrialEnd
		}
		return daysBetween(in.Now, lockAt)
	default:
		return 0
	}
}

// daysBetween returns whole days from a to b, never negative. Rounds
// down so 23h59m → 0 days.
func daysBetween(a, b time.Time) int {
	d := b.Sub(a)
	if d <= 0 {
		return 0
	}
	return int(d / (24 * time.Hour))
}
