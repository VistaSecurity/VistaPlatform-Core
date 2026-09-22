package classificationrules

import (
	"fmt"
	"strings"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/catalogs"
	"github.com/vistasecurity/vistaplatform/shared/classify"
)

// Validate checks an admin-supplied rule before it reaches the database.
//
// It is deliberately the SAME check the engine applies at load
// (classify.Rule.Validate) rather than a second, looser copy: a rule the
// database accepts and the engine then refuses is a rule an admin sees saved,
// sees listed, and never sees fire — with nothing anywhere saying why. Running
// the engine's own validator here means the console's error and the engine's
// behaviour cannot disagree.
//
// The database CHECK constraints are the backstop underneath both (rule_kind in
// the list, confidence in 0..1, at least one of class/vendor/model). They catch
// a hand-run INSERT; this catches a typo while there is still a person looking
// at the form.
func Validate(in Input) error {
	if strings.TrimSpace(in.Pattern) == "" {
		return fmt.Errorf("pattern is required")
	}

	r := classify.Rule{
		Kind:       strings.TrimSpace(in.RuleKind),
		Pattern:    in.Pattern,
		Class:      strings.TrimSpace(deref(in.ClassKey)),
		Vendor:     strings.TrimSpace(deref(in.Vendor)),
		Model:      strings.TrimSpace(deref(in.Model)),
		Confidence: in.Confidence,
		SourceURL:  deref(in.SourceURL),
	}
	// The citation rule, applied to the one field of a rule that becomes a live
	// link in somebody else's browser.
	//
	// source_url is copied onto every class proposal the rule produces and
	// rendered as a raw href in EVERY tenant's console (the Discovery class
	// proposal row) as well as in the admin catalogue. A platform admin is
	// trusted, but "trusted" is not the same as "their typo is everyone's
	// problem": an https-only, no-private-address, no-internal-hostname,
	// no-bare-IP link is the difference between a citation a reader can open and
	// a link that probes a reader's own network when they click it.
	//
	// It is deliberately the SAME function the EOL catalogue uses
	// (catalogs.ValidateCitationURL) rather than a second copy of the policy:
	// that path enforces it at three doors and this one is the wider blast
	// radius, so a fourth spelling of "what makes a URL a citation" would be the
	// one that drifts.
	//
	// Applied only when a URL is actually given. classify.Rule documents an
	// uncited admin rule as legitimate — an admin adding a rule for their own
	// fleet may have nothing public to point at — and that stays true: this
	// governs what a CITED rule may cite, not whether it must.
	if u := strings.TrimSpace(deref(in.SourceURL)); u != "" {
		if err := catalogs.ValidateCitationURL(u); err != nil {
			return err
		}
	}

	if err := r.Validate(); err != nil {
		// The engine's messages name the rule and say what is wrong with it,
		// which is exactly what the form needs to show. The "classify: " prefix
		// is the package talking to a developer, so it is trimmed for the
		// admin.
		return fmt.Errorf("%s", strings.TrimPrefix(err.Error(), "classify: "))
	}
	return nil
}

// Kinds is the rule-kind vocabulary, for the console's filter and its form.
// Read off the engine rather than restated, so a ninth kind cannot appear in
// one and not the other.
func Kinds() []string { return append([]string(nil), classify.Kinds...) }

// ValidKind reports whether kind is one of them.
func ValidKind(kind string) bool {
	for _, k := range classify.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Confidence bounds, re-exported so the OpenAPI contract, the console's number
// input and the validator all state one number.
const (
	MinConfidence = classify.MinConfidence
	MaxConfidence = classify.MaxConfidence
)
