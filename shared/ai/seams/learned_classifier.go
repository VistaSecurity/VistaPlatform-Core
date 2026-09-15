package seams

// The Classifier seam is a CHAIN: the curated rules first, and the learned
// classifier only underneath them (asset-inventory workstream 4.2, ADR-0008 D1
// and D4.3).
//
// The order is the whole design. A rule is deterministic, cites a source and
// can be corrected by editing a row; a model is none of those. So a rule that
// decides gets the answer, unchanged, with `rule` provenance — the model is not
// consulted, cannot outrank it, and cannot soften it. The model speaks in
// exactly two places:
//
//   - the rules matched no class at all (a GAP in the catalogue), and
//   - the rules matched two and refused to choose (a BUG in the catalogue),
//     where the model may pick one of the classes THEY named and no other.
//
// And even there it PROPOSES. Nothing it says reaches an asset without a person
// accepting it — on a new asset or an existing one, which is the pair of cases
// TestTheModelNeverSetsAClass holds in both polarities.

import (
	"context"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	classmodel "github.com/vistasecurity/vistaplatform/shared/classify/model"
)

// ImplRulesModel is the name of the classifier seam's DEFAULT implementation:
// the rule engine of ADR-0004 D6 with the learned classifier of workstream 4.2
// chained beneath it.
//
// It is the default rather than an opt-in for the same reason [ImplLearned] is
// the matcher's: ADR-0008 D2 puts the classical family in Core, in-process,
// with no provider and no network, and its failure mode is "no proposal" —
// which is the null default anyway.
//
// Two narrower choices remain selectable and always mean what they say:
// [ImplRules] is the rules with no model at all, and [ImplNone] is a classifier
// that proposes nothing whatsoever.
const ImplRulesModel = "rules+model"

// ModelEnabledEnvVar turns the MODEL half off while leaving the rules running.
//
// `CLASSIFIER_MODEL_ENABLED=false` (or `0`, or `off`) makes the default
// classifier behave exactly as [ImplRules] does. Anything else, including an
// unset variable, leaves it on.
//
// It is deliberately a different control from `Classifier: "none"`, which turns
// the whole SEAM off and is what an operator sets when they want no class
// proposals at all. The two answer different questions — "I do not trust the
// model" and "I do not want this feature" — and one switch for both would make
// the first answer cost the second.
const ModelEnabledEnvVar = "CLASSIFIER_MODEL_ENABLED"

// ChainClassifier is the rule engine with the learned classifier beneath it.
//
// A zero value is usable and is the rules alone: a nil Model is not an error,
// it is the state a deployment is in when the weights could not be parsed or an
// operator switched the model half off, and every caller already handles "no
// proposal".
type ChainClassifier struct {
	// Rules is the first stage and the only one that can DECIDE.
	Rules RuleClassifier

	// Model is the second stage. Nil means the rules alone.
	Model *classmodel.Model
}

// NewChainClassifier builds the default classifier: the rules, plus the
// embedded model unless it is switched off or will not load.
func NewChainClassifier() Classifier {
	return newChainClassifier(os.Getenv(ModelEnabledEnvVar))
}

// newChainClassifier is [NewChainClassifier] with the env value passed in, so
// both polarities of the switch are reachable from a test.
//
// The env var is read once per process at the call site above, which is right
// for a deployment setting and wrong for a test — and a switch that only one
// side of is ever exercised is the "check that cannot fail" shape: the OFF
// branch would ship untested, and a typo in it would leave the model running
// for every operator who had turned it off.
func newChainClassifier(enabled string) Classifier {
	if !modelEnabled(enabled) {
		modelOffOnce.Do(func() {
			log.Printf("[seams] %s is off: the classifier will run the curated rules only, "+
				"and propose nothing where they cannot decide", ModelEnabledEnvVar)
		})
		return ChainClassifier{}
	}
	return ChainClassifier{Model: embeddedChainModel()}
}

var (
	modelOffOnce   sync.Once
	chainModelOnce sync.Once
	chainModelVal  *classmodel.Model
)

func embeddedChainModel() *classmodel.Model {
	chainModelOnce.Do(func() {
		m, err := classmodel.Default()
		if err != nil {
			// Once, at first use, not per call. A broken weights file must not
			// stop a service classifying assets: the rule engine is complete
			// without any of this, and the model's absence means exactly "no
			// extra proposals".
			log.Printf("[seams] the learned classifier's weights could not be loaded (%v); "+
				"the curated rules are unaffected and nothing will be proposed where they cannot decide", err)
			return
		}
		chainModelVal = m
	})
	return chainModelVal
}

// modelEnabled reads the env var. Absent or unparseable means ON — a typo in an
// operator's value must not silently disable a capability, and the two explicit
// spellings of "off" are the ones a person would actually write.
func modelEnabled(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "false", "0", "off", "no":
		return false
	default:
		return true
	}
}

// ModelID reports which weights this classifier would propose with, empty when
// there is no model.
//
// The UI reads it to say whether anything is being proposed below the rules at
// all — a control that looks live while nothing can act on it is the "check
// that cannot fail" shape, pointed at a user instead of at a test.
func (c ChainClassifier) ModelID() string {
	if c.Model == nil {
		return ""
	}
	return c.Model.ModelID
}

var (
	_ Classifier      = ChainClassifier{}
	_ ModelIdentifier = ChainClassifier{}
)

// Classify runs the chain and returns the seam's narrow answer.
func (c ChainClassifier) Classify(ctx context.Context, facts AssetFacts) (ClassProposal, error) {
	out := c.Explain(ctx, facts)

	sourceRef := string(ai.SeamClassifier) + ":" + ImplRules
	modelID := ""
	if out.ModelID != "" {
		sourceRef = string(ai.SeamClassifier) + ":" + ImplModel
		modelID = out.ModelID
	}
	return ClassProposal{
		Proposal: NewProposal(modelID, sourceRef, out.Confidence),
		Class:    out.Class,
		Unknown:  out.Unknown,
	}, nil
}

// ImplModel is what a MODEL-derived proposal's source_ref names. It is not a
// selectable implementation — the model is never the whole classifier, only the
// second half of one — but a stored proposal has to be able to say which of the
// two producers answered, and "classifier:rules" on a class no rule argued
// would be false provenance on the one field a reviewer audits.
const ImplModel = "model"

// Explain runs the chain and returns the FULL answer — the matched rules and
// their citations for a rule-derived class, or the model's id, probability and
// top feature contributions for a learned one.
//
// # The five conditions
//
// The model's answer is used only when ALL of these hold. Each one is a
// separate refusal and each is tested in both polarities:
//
//  1. **The rules proposed no class.** A rule that decided is the answer.
//  2. **A model is loaded.** Otherwise the rules' answer stands as it is.
//  3. **P ≥ [classmodel.ModelProposalFloor].** Below the floor there is no
//     proposal at all — `unknown_host`, which is a complete and honest answer.
//  4. **The class is one the LIVE rule vocabulary contains.** The model's
//     targets come from the compiled-in table; an admin who removed the last
//     rule naming a class has said that class is not something this deployment
//     classifies, and a model proposing it anyway would route around the
//     catalogue. This is also what stops a stale weights file proposing a class
//     the taxonomy no longer has.
//  5. **On a CONFLICT, the class is one of the conflicting classes.** The rules
//     named the candidates; the model's job there is to settle their argument,
//     not to introduce a third opinion nobody was shown. A model answer outside
//     that set is discarded and the conflict stands unresolved, which is what a
//     reviewer needs to see.
//
// Whatever happens, the rules' own findings are preserved: the matched rules,
// the conflict flag and the tied classes all survive onto the returned
// proposal, so the approval row still shows the disagreement the model resolved.
func (c ChainClassifier) Explain(ctx context.Context, facts AssetFacts) classify.ClassProposal {
	in := classifyInput(facts)
	rules := c.Rules.engine().Classify(ctx, in)

	// 1 and 2.
	if rules.Class != "" || c.Model == nil {
		return rules
	}

	scores := c.Model.Predict(classmodel.Input{Facts: in, Rules: rules})
	if len(scores) == 0 {
		return rules
	}
	best := scores[0]

	// 3.
	if best.P < classmodel.ModelProposalFloor {
		return rules
	}
	// 4.
	if !c.Rules.engine().ProposesClass(best.Class) {
		return rules
	}
	// 5.
	if rules.Conflict && !containsClass(rules.ConflictingClasses, best.Class) {
		return rules
	}

	out := rules
	out.Class = best.Class
	out.Unknown = false
	out.Confidence = best.P
	out.ModelID = c.Model.ModelID
	out.ModelProbability = best.P
	out.ModelReasons = toModelReasons(best.Explanation)
	return out
}

func containsClass(classes []string, key string) bool {
	for _, c := range classes {
		if c == key {
			return true
		}
	}
	return false
}

// toModelReasons converts the model's contributions into the proposal's
// vocabulary, dropping any that carry no phrase a reviewer could read.
//
// A contribution with no label is a feature whose evidence phrase was not
// recorded — it would render as a blank bullet in the approval row, which reads
// as a missing reason rather than as one the UI could not build.
func toModelReasons(in []classmodel.Contribution) []classify.ModelReason {
	if len(in) == 0 {
		return nil
	}
	out := make([]classify.ModelReason, 0, len(in))
	for _, c := range in {
		if strings.TrimSpace(c.Label) == "" {
			continue
		}
		out = append(out, classify.ModelReason{
			Feature:      c.Feature,
			Label:        c.Label,
			Contribution: c.Contribution,
		})
	}
	return out
}
