package services

import (
	"errors"
	"fmt"

	"github.com/vistasecurity/vistaplatform/shared/riskbands"
)

// Marking an algorithm obsolete makes it grade Critical (owner decision 12,
// admin-ui data review RC-38).
//
// The Catalog → Ratings "Deprecate" dialog has always said the algorithm "will
// grade as Critical", but the write only changed deprecation_status. Grading
// reads risk_score (catalogue_risk.go), so an obsoleted algorithm kept its old
// band and the dialog's claim was false. The owner chose to make the claim true
// rather than change the text:
//
//   - Entering obsolete raises risk_score to at least the bottom of the Critical
//     band, and REMEMBERS the score it replaced (pre_obsolete_risk_score, with
//     obsolete_risk_floor_at marking that a score is remembered — the remembered
//     score may legitimately be NULL, "unassessed").
//   - Leaving obsolete restores the remembered score, unless the same request
//     sets a score explicitly, which wins.
//   - While obsolete, an explicit score below the floor is refused rather than
//     silently raised: an admin who typed 50 and saw 90 saved would be told
//     "saved" about a number they did not choose.
//
// The floor comes from shared/riskbands, never a literal, so it moves with the
// band ladder if the ladder is ever re-anchored.

// DeprecationObsolete is the deprecation_status that triggers the floor.
const DeprecationObsolete = "obsolete"

// criticalRiskBand is the band an obsolete algorithm must grade in.
const criticalRiskBand = "Critical"

// ObsoleteRiskFloor is the lowest risk_score an obsolete algorithm may carry:
// the inclusive lower bound of the Critical band.
func ObsoleteRiskFloor() int {
	floor, ok := riskbands.RiskBandMin(criticalRiskBand)
	if !ok {
		// A programmer error (the band was renamed), not a runtime condition.
		panic(fmt.Sprintf("risk band %q is not defined in shared/riskbands", criticalRiskBand))
	}
	return floor
}

// ErrObsoleteRiskBelowFloor is returned when a request keeps an algorithm
// obsolete while setting its risk_score below the Critical floor.
var ErrObsoleteRiskBelowFloor = errors.New("an obsolete algorithm must grade Critical")

// obsoleteRiskState is the stored state the plan is computed from.
type obsoleteRiskState struct {
	Status       string
	RiskScore    *int
	FloorApplied bool // obsolete_risk_floor_at IS NOT NULL
	PriorScore   *int // pre_obsolete_risk_score
}

// obsoleteRecordAction says what to do with the remembered pre-obsolete score.
type obsoleteRecordAction int

const (
	obsoleteRecordKeep obsoleteRecordAction = iota
	obsoleteRecordSet
	obsoleteRecordClear
)

// Transition names, carried into the audit record.
const (
	ObsoleteTransitionNone     = ""
	ObsoleteTransitionEntered  = "marked_obsolete"
	ObsoleteTransitionRestored = "restored_pre_obsolete_score"
	ObsoleteTransitionLeftKept = "left_obsolete_score_kept"
	ObsoleteTransitionExplicit = "left_obsolete_explicit_score"
)

// obsoleteRiskPlan is what the write must do beyond the caller's own fields.
type obsoleteRiskPlan struct {
	// WriteRisk: when true, risk_score is set to Risk (nil = NULL) instead of
	// the caller's COALESCE-style "leave unchanged unless supplied".
	WriteRisk bool
	Risk      *int
	Record    obsoleteRecordAction
	Prior     *int // the score to remember when Record == obsoleteRecordSet
	// Transition names what happened, for the audit record.
	Transition string
}

// planObsoleteRisk decides the risk_score side effects of one assessment update.
// reqStatus / reqRisk are the request's deprecation_status and risk_score (nil =
// not supplied). Pure: the tests pin every branch without a database.
func planObsoleteRisk(cur obsoleteRiskState, reqStatus *string, reqRisk *int) (obsoleteRiskPlan, error) {
	floor := ObsoleteRiskFloor()
	next := cur.Status
	if reqStatus != nil {
		next = *reqStatus
	}
	wasObsolete := cur.Status == DeprecationObsolete
	willBeObsolete := next == DeprecationObsolete

	switch {
	case !wasObsolete && willBeObsolete:
		// The score to remember is the one the algorithm would carry if it were
		// not obsolete: the caller's explicit score if they sent one in the same
		// request, otherwise the stored one.
		prior := cur.RiskScore
		if reqRisk != nil {
			prior = reqRisk
		}
		raised := floor
		if prior != nil && *prior > floor {
			raised = *prior
		}
		return obsoleteRiskPlan{
			WriteRisk:  true,
			Risk:       &raised,
			Record:     obsoleteRecordSet,
			Prior:      copyIntPtr(prior),
			Transition: ObsoleteTransitionEntered,
		}, nil

	case wasObsolete && willBeObsolete:
		if reqRisk != nil && *reqRisk < floor {
			return obsoleteRiskPlan{}, fmt.Errorf("%w: risk_score %d is below the Critical floor %d; change the deprecation status first",
				ErrObsoleteRiskBelowFloor, *reqRisk, floor)
		}
		return obsoleteRiskPlan{}, nil

	case wasObsolete && !willBeObsolete:
		if reqRisk != nil {
			// An explicit score wins over the remembered one; the memory is
			// spent either way.
			return obsoleteRiskPlan{
				WriteRisk:  true,
				Risk:       copyIntPtr(reqRisk),
				Record:     obsoleteRecordClear,
				Transition: ObsoleteTransitionExplicit,
			}, nil
		}
		if cur.FloorApplied {
			return obsoleteRiskPlan{
				WriteRisk:  true,
				Risk:       copyIntPtr(cur.PriorScore),
				Record:     obsoleteRecordClear,
				Transition: ObsoleteTransitionRestored,
			}, nil
		}
		// Obsoleted before the floor existed (or by seed data): there is no
		// remembered score, so the current one stays.
		return obsoleteRiskPlan{Transition: ObsoleteTransitionLeftKept}, nil
	}
	return obsoleteRiskPlan{}, nil
}

// planObsoleteRiskForCreate applies the same rule to a brand-new row: creating
// an algorithm directly as obsolete is "entering obsolete" from its own score.
func planObsoleteRiskForCreate(status *string, risk int) obsoleteRiskPlan {
	plan, _ := planObsoleteRisk(obsoleteRiskState{Status: "current", RiskScore: &risk}, status, &risk)
	return plan
}

func copyIntPtr(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
