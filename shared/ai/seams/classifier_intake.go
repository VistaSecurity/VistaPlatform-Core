package seams

// How an intake path gets a class proposal, and the full argument behind it
// (workstream 2.10b).
//
// Two services classify: inventory-service, over what a discovery or a passive
// host observation carried, and device-interrogation-service, over what an
// interrogated peer's identifiers say. Before this file each of them named
// [RuleClassifier] directly, which worked and was wrong in one specific way:
// the Classifier SEAM is selectable, `Config{Classifier: "none"}` means "propose
// no class at all", and a call site that constructs the implementation itself
// cannot honour that. A control an operator can set and nothing reads is worse
// than no control.
//
// So the selection happens once, here, through the seam, and both intakes ask
// for it by capability rather than by type.

import (
	"context"

	"github.com/vistasecurity/vistaplatform/shared/classify"
)

// ClassifierFor returns the Classifier a set has chosen, with `engine` swapped
// into whichever stage of it runs rules.
//
// The engine is the CURATED table — a service's live view of
// classification_rules — and the seam's defaults carry a nil engine, which
// means the compiled-in copy. Swapping rather than constructing is what keeps
// the operator's choice in charge: a set whose Classifier is [NullClassifier]
// comes back unchanged and goes on proposing nothing.
//
// Both rule-running choices are handled — [RuleClassifier] and the default
// [ChainClassifier], whose first stage is one. Handling only the first is the
// shape of bug this function exists to prevent: the chain would keep running
// the COMPILED-IN table, an admin's curated rules would never fire, and nothing
// anywhere would say so.
//
// A nil engine is fine and means "use whatever the implementation defaults to".
func ClassifierFor(set Set, engine *classify.Engine) Classifier {
	if engine == nil {
		return set.Classifier
	}
	switch c := set.Classifier.(type) {
	case RuleClassifier:
		c.Engine = engine
		return c
	case ChainClassifier:
		c.Rules.Engine = engine
		return c
	default:
		return set.Classifier
	}
}

// Explain runs a classifier and returns the engine's FULL answer — the matched
// rules, their citations, and any conflict — for a caller that has to show why a
// class was proposed.
//
// The seam interface deliberately returns only a class and a confidence, because
// that is all a contract can promise across eight implementations. But a
// rule-based proposal can be audited in a way a learned one cannot, and throwing
// that away at the seam boundary would put a class in the approval queue with no
// argument behind it — a proposal a reviewer cannot audit is one they can only
// rubber-stamp.
//
// An implementation that cannot explain itself is not an error: its class and
// confidence come back with no matched rules, which is an honest description of
// what it gave. `Unknown` is preserved either way, including for a conflict —
// [RuleClassifier] reports that as no class with the tied classes named, and
// nothing here flattens it.
func Explain(ctx context.Context, c Classifier, facts AssetFacts) classify.ClassProposal {
	if c == nil {
		return classify.ClassProposal{Unknown: true}
	}
	if e, ok := c.(interface {
		Explain(context.Context, AssetFacts) classify.ClassProposal
	}); ok {
		return e.Explain(ctx, facts)
	}
	out, err := c.Classify(ctx, facts)
	if err != nil || out.Unknown || out.Class == "" {
		// An error from a classifier is not a reason to fail an intake: the
		// answer it could not give is "no proposal", which is a complete one.
		// The caller records nothing and the asset stays as it was.
		return classify.ClassProposal{Unknown: true}
	}
	return classify.ClassProposal{Class: out.Class, Confidence: out.Confidence}
}

// ClassFacts builds the seam's free-form AssetFacts from the engine's typed
// input, so a caller that has assembled evidence once does not assemble it
// again in a second vocabulary.
//
// It is the inverse of the adapter in rule_classifier.go, and it exists so that
// the two are edited together: a field added to ClassifyInput and not to this
// map is evidence the classifier silently stops seeing.
func ClassFacts(in classify.ClassifyInput) AssetFacts {
	return AssetFacts{
		Facts: map[string]any{
			FactMACAddresses:      in.MACs,
			FactSysObjectID:       in.SysObjectID,
			FactENIPVendorID:      in.ENIPVendorID,
			FactCloudResourceType: in.CloudResourceType,
			FactBanners:           in.Banners,
			FactOpenPorts:         in.OpenPorts,
			FactVendor:            in.Vendor,
			FactModel:             in.Model,
			FactPlatform:          in.Platform,
			FactMDNSServices:      in.MDNSServices,
			FactLLDPCapabilities:  in.LLDPCapabilities,
			FactCDPCapabilities:   in.CDPCapabilities,
			FactOSName:            in.OS,
			FactOSVersion:         in.OSVersion,
		},
	}
}
