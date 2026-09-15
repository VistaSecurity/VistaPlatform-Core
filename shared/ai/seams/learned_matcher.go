package seams

import (
	"context"
	"log"
	"sync"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
)

// ImplLearned is the name of the matcher seam's default implementation: the
// logistic-regression model of shared/identity/matcher, with its weights
// embedded in the binary.
//
// It is the DEFAULT rather than an opt-in for the same reason [ImplRules] is
// the classifier's: ADR-0008 D2 puts the classical family in Core, running
// in-process with no provider and no network, and its failure mode is "no
// proposal" — which is the null default anyway. Withholding it until an
// operator configures something would make a Core deployment's merge proposals
// arbitrarily ordered for no benefit.
//
// What it does NOT change: nothing is auto-merged. The engine's auto-accept
// threshold defaults to zero, meaning never, and a score at any value does not
// move it (ADR-0002 D5). Turning this model on changes the ORDER of a
// proposal's candidates and adds a reason to each; it does not change what is
// decided.
//
// An operator who wants no scores at all sets `matcher: none`, which is always
// available and always means no proposals.
const ImplLearned = "learned"

// LearnedMatcher adapts the classical model to the [Matcher] seam.
//
// This adapter lives here, rather than in shared/identity/matcher, because the
// matcher package must not import this one: shared/identity imports these seam
// types, and a matcher package importing them while this package registered it
// as a default would close an import cycle. The consequence is deliberate and
// small — the model is pure arithmetic over a [matcher.Pair], and knowing
// nothing about seams is what keeps it testable and shippable on its own.
type LearnedMatcher struct {
	model *matcher.Model
}

// NewLearnedMatcher builds the adapter over the embedded weights.
//
// A model that fails to load yields a matcher that proposes nothing, and says
// so once. It is not an error the caller must handle: "I have no proposal" is
// the documented answer for this seam, every caller already handles it, and a
// weights file that failed to parse must not stop a service from identifying
// assets — the rule-based engine is complete without any of this.
func NewLearnedMatcher() Matcher {
	m, err := loadMatcherModel()
	if err != nil {
		return NullMatcher{}
	}
	return LearnedMatcher{model: m}
}

var (
	matcherModelOnce sync.Once
	matcherModel     *matcher.Model
	matcherModelErr  error
)

func loadMatcherModel() (*matcher.Model, error) {
	matcherModelOnce.Do(func() {
		matcherModel, matcherModelErr = matcher.Default()
		if matcherModelErr != nil {
			// Once, at first use, not per call: a broken weights file would
			// otherwise print on every conflict in the tenant.
			log.Printf("[seams] the learned matcher's weights could not be loaded (%v); "+
				"merge proposals will be unscored and the rule-based engine is unaffected", matcherModelErr)
		}
	})
	return matcherModel, matcherModelErr
}

// ModelIdentifier is implemented by a seam implementation that can name the
// model it is using.
//
// It is a separate interface, not a method on every seam, because a NULL
// implementation has no model to name and "" is not a model called unknown. A
// caller asks, and an implementation that cannot answer says nothing.
type ModelIdentifier interface {
	ModelID() string
}

// MatcherModelID reports the model behind a configured matcher, empty when
// there is none.
//
// The UI uses it to say what a tenant's auto-accept threshold is a threshold
// ON — and, when it is empty, to say that nothing is being scored, so the
// threshold cannot fire whatever it is set to. A control that looks live while
// nothing can act on it is the "check that cannot fail" shape, pointed at a
// user instead of at a test.
func MatcherModelID(m Matcher) string {
	if id, ok := m.(ModelIdentifier); ok {
		return id.ModelID()
	}
	return ""
}

// ModelID reports which weights this matcher is scoring with, for the
// provenance a proposal carries.
func (m LearnedMatcher) ModelID() string {
	if m.model == nil {
		return ""
	}
	return m.model.ModelID
}

var _ ModelIdentifier = LearnedMatcher{}

// Match scores every candidate and explains each score.
//
// It never errors. A candidate it cannot say anything about gets a score
// computed from the little it had, which is the honest answer for a model whose
// whole input is comparisons — with nothing to compare, every feature is zero
// and the score is the trained base rate, which is low.
func (m LearnedMatcher) Match(_ context.Context, candidate Observation, existing []AssetSummary) ([]MatchScore, error) {
	if m.model == nil || len(existing) == 0 {
		return nil, nil
	}
	obs := observationSide(candidate)
	sourceRef := string(ai.SeamMatcher) + ":" + ImplLearned

	out := make([]MatchScore, 0, len(existing))
	for _, a := range existing {
		pair := matcher.Pair{Observation: obs, Candidate: assetSide(a)}
		features := matcher.Features(pair)
		score := m.model.ScoreVector(features)
		factors := m.model.ExplainVector(features)

		out = append(out, MatchScore{
			// Confidence and Score are the same number, deliberately. The seam's
			// provenance block carries the implementation's own confidence
			// (ADR-0008 D4.1) and the match carries the score a reviewer sees;
			// for a calibrated model those are one quantity and reporting two
			// different numbers would invite the question of which is real.
			Proposal:    NewProposal(m.model.ModelID, sourceRef, score),
			AssetID:     a.ID,
			Score:       score,
			Reason:      m.model.Reason(factors),
			Explanation: toMatchFactors(factors),
		})
	}
	return out, nil
}

func observationSide(o Observation) matcher.Side {
	return matcher.Side{
		Name:        o.Name,
		Class:       o.Kind,
		Identifiers: o.Identifiers,
		Segment:     o.Segment,
		Vendor:      attributeString(o.Attributes, "vendor"),
		Model:       attributeString(o.Attributes, "model"),
		SourceKind:  o.SourceKind,
		SeenAt:      o.ObservedAt,
	}
}

func assetSide(a AssetSummary) matcher.Side {
	return matcher.Side{
		Name:        a.Name,
		Class:       a.Class,
		Identifiers: a.Identifiers,
		Segment:     a.Segment,
		Vendor:      attributeString(a.Attributes, "vendor"),
		Model:       attributeString(a.Attributes, "model"),
		SourceKind:  a.SourceKind,
		SeenAt:      a.LastSeenAt,
		Status:      a.Status,
	}
}

// attributeString reads one attribute as a string, and returns "" for anything
// that is not one.
//
// Not a best-effort stringification: `fmt.Sprint` of a map or a number would
// produce a value that compares unequal to everything and reads, in the
// features, as a KNOWN vendor that disagrees — turning an absent attribute into
// evidence of two different things. Empty is the honest answer for "the
// attribute is not a string", and the agreement features treat empty as
// neither.
func attributeString(attrs map[string]any, key string) string {
	s, _ := attrs[key].(string)
	return s
}

func toMatchFactors(in []matcher.Factor) []MatchFactor {
	if len(in) == 0 {
		return nil
	}
	out := make([]MatchFactor, 0, len(in))
	for _, f := range in {
		out = append(out, MatchFactor{
			Feature:      f.Feature,
			Label:        f.Label,
			Value:        f.Value,
			Weight:       f.Weight,
			Contribution: f.Contribution,
		})
	}
	return out
}

var _ Matcher = LearnedMatcher{}
