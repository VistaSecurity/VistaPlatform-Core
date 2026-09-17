package seams

import (
	"context"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/classify"
)

// ImplRules is the name of the rule-based Classifier — the seam's DEFAULT
// implementation, and the "rule-based default" column of ADR-0008 D1's table.
//
// It is a real, selectable name rather than a hidden behaviour, so an operator
// can turn it off by configuring [ImplNone] explicitly and get a classifier
// that proposes nothing at all. A deployment that says nothing gets the rules,
// because the rules are deterministic, auditable and free: they are not AI, and
// switching them off is not what "no AI configured" means.
const ImplRules = "rules"

// AssetFacts keys the rule classifier reads.
//
// These name entries in a seam's free-form Facts/Identifiers maps, NOT rows of
// the asset_facts table, so they are not in standards/fact-keys.yaml and do not
// need to be — a fact key is a thing we store about an asset, and these are the
// arguments to one call. Stated as constants so the caller that builds an
// AssetFacts and the adapter that reads it cannot disagree by a typo, which is
// the entire failure mode of a stringly-typed map.
const (
	// FactMACAddress is one MAC, in Identifiers. It matches the identifier
	// vocabulary's `mac_address` kind (shared/identity), which is what an
	// observation already carries.
	FactMACAddress = "mac_address"

	// FactMACAddresses is several MACs, in Facts, for a device with more than
	// one interface. Both are read; a device that supplies both gets the union.
	FactMACAddresses = "mac_addresses"

	FactSysObjectID       = "sysobjectid"
	FactENIPVendorID      = "enip_vendor_id"
	FactCloudResourceType = "cloud_resource_type"
	FactBanners           = "banners"
	FactOpenPorts         = "open_ports"
	FactVendor            = "vendor"
	FactModel             = "model"
	FactPlatform          = "platform"

	// FactMDNSServices is the DNS-SD service types the host advertises, in
	// Facts. It matches the `net.mdns_services` fact key the passive sensors
	// write, so an intake that already has that fact can pass it straight
	// through under a name that means the same thing on both sides.
	FactMDNSServices = "mdns_services"

	// FactLLDPCapabilities and FactCDPCapabilities are the capability names the
	// device advertised, in Facts. They are spelled as the `lldp_capabilities`
	// and `cdp_capabilities` attributes shared/hostobs emits, because that is
	// where they come from and a second spelling is a second thing to keep in
	// step.
	FactLLDPCapabilities = "lldp_capabilities"
	FactCDPCapabilities  = "cdp_capabilities"

	// FactOSName is the operating system the host named when asked, in Facts.
	// It is spelled to match the `os.name` fact key a host inventory writes,
	// so an intake holding that fact passes it straight through under a name
	// that means the same thing on both sides.
	FactOSName = "os_name"
)

// RuleClassifier answers the Classifier seam from the curated rule table
// (ADR-0004 D6) through [classify.Engine].
//
// # Why this lives here rather than in shared/classify
//
// Because of the direction of the dependency. shared/classify is imported by
// the sensor and the device agent, which cross-compile with CGO off and have no
// business carrying the AI seam vocabulary; and this package's [Default] has to
// hand back the rule engine, which it cannot do if classify imports it. So
// classify stays pure and seam-free, and the adapter — the one place that knows
// both vocabularies — lives on this side.
//
// # It still never guesses
//
// The engine proposes no class when the rules do not decide one, INCLUDING when
// they decide two (see classify.Engine.Classify's conflict rule). This type
// forwards that verbatim: Unknown true, empty Class, zero Confidence. The null
// classifier's contract is not weakened by having a default that can answer —
// it is the same contract, met by something with evidence.
type RuleClassifier struct {
	// Engine is the rule engine. Nil means [classify.Default] — the
	// compiled-in table, which is what a deployment that has not loaded the
	// curated rows from the database runs on.
	//
	// A service that HAS loaded them builds a RuleClassifier{Engine: loaded}
	// and registers it, or swaps the whole Set. It does not mutate this one:
	// an Engine is immutable, and reloading means replacing the pointer.
	Engine *classify.Engine
}

func (c RuleClassifier) engine() *classify.Engine {
	if c.Engine != nil {
		return c.Engine
	}
	return classify.Default()
}

// Classify maps the seam's AssetFacts onto the engine's input, runs it, and
// maps the result back.
//
// It returns no error: "the rules did not decide" is a normal outcome with a
// complete answer, not a failure, and a caller must not log it as one.
func (c RuleClassifier) Classify(ctx context.Context, facts AssetFacts) (ClassProposal, error) {
	out := c.engine().Classify(ctx, classifyInput(facts))

	return ClassProposal{
		Proposal: NewProposal(
			// No model id: no model was involved. A rule table is not a model,
			// and "" is not a model called unknown — the source_ref is what
			// says which producer answered, and it says "rules" rather than
			// "none", which is the distinction a stored proposal needs.
			"",
			string(ai.SeamClassifier)+":"+ImplRules,
			out.Confidence,
		),
		Class:   out.Class,
		Unknown: out.Unknown,
	}, nil
}

// Explain runs the engine and hands back its full answer — the matched rules,
// the citations, and any conflict — for a caller that has to SHOW why a class
// was proposed.
//
// The seam interface deliberately returns only a class and a confidence,
// because that is all a seam contract can promise across eight different
// implementations. But a rule-based proposal can be audited in a way a learned
// one cannot, and throwing that away at the seam boundary would make the
// approval queue show a class with no argument behind it. Workstream 2.10b's
// intake calls this, not Classify.
func (c RuleClassifier) Explain(ctx context.Context, facts AssetFacts) classify.ClassProposal {
	return c.engine().Classify(ctx, classifyInput(facts))
}

// classifyInput is the ONE mapping from the seam's free-form AssetFacts onto
// the engine's typed input.
//
// One function and not two identical literals: Classify and Explain must run
// the same evidence, and when they were two copies a field added to one was a
// field the approval queue's explanation silently did not consider.
func classifyInput(facts AssetFacts) classify.ClassifyInput {
	return classify.ClassifyInput{
		MACs:              factMACs(facts),
		SysObjectID:       factString(facts.Facts, FactSysObjectID),
		ENIPVendorID:      factInt(facts.Facts, FactENIPVendorID),
		CloudResourceType: factString(facts.Facts, FactCloudResourceType),
		Banners:           factStringMap(facts.Facts, FactBanners),
		OpenPorts:         factInts(facts.Facts, FactOpenPorts),
		Vendor:            factString(facts.Facts, FactVendor),
		Model:             factString(facts.Facts, FactModel),
		Platform:          factString(facts.Facts, FactPlatform),
		MDNSServices:      factStrings(facts.Facts, FactMDNSServices),
		LLDPCapabilities:  factStrings(facts.Facts, FactLLDPCapabilities),
		CDPCapabilities:   factStrings(facts.Facts, FactCDPCapabilities),
		OS:                factString(facts.Facts, FactOSName),
	}
}

// --- AssetFacts readers -----------------------------------------------------
//
// Facts is map[string]any, so everything here has to survive a round trip
// through JSON, where an int arrives as a float64 and a []string as a []any.
// These readers accept both the native and the decoded shape, and answer with
// the zero value for anything else — a fact of the wrong type is an absent
// fact, not an error, because the alternative is a classification that fails
// outright because one collector wrote a port list as strings.

func factMACs(facts AssetFacts) []string {
	var out []string
	if mac := strings.TrimSpace(facts.Identifiers[FactMACAddress]); mac != "" {
		out = append(out, mac)
	}
	for _, v := range anySlice(facts.Facts, FactMACAddresses) {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func factString(facts map[string]any, key string) string {
	if facts == nil {
		return ""
	}
	s, _ := facts[key].(string)
	return strings.TrimSpace(s)
}

func factInt(facts map[string]any, key string) int {
	if facts == nil {
		return 0
	}
	switch v := facts[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case uint16:
		return int(v)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

func factStrings(facts map[string]any, key string) []string {
	if facts == nil {
		return nil
	}
	if v, ok := facts[key].([]string); ok {
		return v
	}
	var out []string
	for _, item := range anySlice(facts, key) {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func factInts(facts map[string]any, key string) []int {
	if facts == nil {
		return nil
	}
	if v, ok := facts[key].([]int); ok {
		return v
	}
	var out []int
	for _, item := range anySlice(facts, key) {
		switch n := item.(type) {
		case int:
			out = append(out, n)
		case int64:
			out = append(out, int(n))
		case float64:
			out = append(out, int(n))
		}
	}
	return out
}

func factStringMap(facts map[string]any, key string) map[string]string {
	if facts == nil {
		return nil
	}
	if v, ok := facts[key].(map[string]string); ok {
		return v
	}
	raw, ok := facts[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func anySlice(facts map[string]any, key string) []any {
	if facts == nil {
		return nil
	}
	switch v := facts[key].(type) {
	case []any:
		return v
	case []string:
		out := make([]any, len(v))
		for i, s := range v {
			out[i] = s
		}
		return out
	default:
		return nil
	}
}
