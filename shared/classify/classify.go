// Package classify is the rule-based classifier: what a thing is, argued from
// evidence a collector actually gathered, with the rules held as DATA.
//
// ADR-0004 D6 (asset-inventory) makes fingerprinting rules a seeded table a
// platform admin curates rather than code, so the catalogue grows without a
// release and the learned classifier of workstream 4.2 has features to train
// on. This package is the engine over that table. standards/classification-
// rules.yaml is the source of truth; `make generate` writes both the compiled-in
// table here and the seeded rows in seed.sql from it.
//
// # What this package will not do
//
// It never guesses. Classify returns Unknown with no class whenever the rules
// do not decide one, which includes the case where they decide two — see the
// conflict rule on [Engine.Classify]. That is ADR-0008 D4.3, "not assessed
// stays not assessed", and it is the same honesty as the PQC `unclassified`
// bucket and the risk score's "0 means NOT ASSESSED": a plausible wrong answer
// is worse than an absent one, because an absent one invites someone to look
// and a wrong one gets approved.
//
// It also never DECIDES. Everything here is a proposal that goes through
// Approvals (ADR-0008 D3, ADR-0002 D5). Intake wiring — turning a ClassProposal
// into a row in the approval queue — is workstream 2.10b and lives in
// inventory-service, not here.
//
// # Pure Go, on purpose
//
// The sensor and the device agent cross-compile to several operating systems
// with CGO off, and both need to classify what they see. So this package has no
// database pool, no NATS, no tenant context and no CGO — just the rules and the
// matching. A service that wants the CURATED table loads it through
// [Repository]; a runtime with no database gets [Default], which is the same
// rules compiled in.
package classify

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

// ConflictEpsilon is how close two competing classes have to be before the
// engine refuses to choose between them.
//
// A tenth is wide on purpose. The confidence ladder in the YAML spaces its
// bands 0.05 apart, so two rules that disagree from DIFFERENT bands (a 0.85
// model rule against a 0.70 OUI rule) still resolve, while two rules from the
// same band disagreeing (two 0.80 rules proposing firewall and load_balancer)
// is exactly the case where the honest answer is "we do not know".
const ConflictEpsilon = 0.10

// ClassifyInput is everything a collector saw that a rule can key on.
//
// Every field is optional. An input with nothing populated is valid and
// produces Unknown — which is what a caller with no evidence should get, rather
// than an error it has to distinguish from a real one.
type ClassifyInput struct {
	// MACs are layer-2 addresses in any spelling (colon, hyphen, Cisco dotted,
	// bare). Only the first three octets are read.
	MACs []string

	// SysObjectID is the SNMP sysObjectID as walked, with or without a leading
	// dot.
	SysObjectID string

	// ENIPVendorID is the ODVA vendor id from an EtherNet/IP List Identity
	// response. Zero means absent — vendor id 0 is not assigned.
	ENIPVendorID int

	// CloudResourceType is the provider's own resource type, as the cloud
	// collectors spell it ("aws_s3_bucket").
	CloudResourceType string

	// Banners is what each probed service said about itself, keyed by probe.
	// Banner rules are matched against every VALUE; the key is not part of the
	// match, so a banner pattern has to be specific enough to stand alone.
	//
	// # The contract on a value
	//
	// Each value is ONE line exactly as the service sent it, INCLUDING the
	// header name where the protocol has one: `Server: nginx/1.2`, not
	// `nginx/1.2`; `SSH-2.0-OpenSSH_9.6`, which has no header name to include.
	// Not a whole response, not a status line, not several headers joined.
	//
	// This is load-bearing and it fails silently if a producer gets it wrong.
	// Every shipped banner rule anchors on `(?i)^server:\s*…`, because the
	// header name is the only thing that says WHICH header the value came from
	// — the map key is not matched. A producer that handed over the bare value
	// would match no rule, ever, and nothing would say so: the classifier would
	// simply stop proposing `web_application`. A producer that has only the
	// bare value (a JSON field named `server_header`) must render the line —
	// see bannersFromRawData in inventory-service, which does.
	Banners map[string]string

	// OpenPorts is the set of ports found listening. A port_profile rule fires
	// only when every port it names is in here.
	OpenPorts []int

	// Vendor is the manufacturer, where something already established it —
	// typically because the device named itself over an API. It is an ANSWER,
	// not a hypothesis, so it is returned as-is and no rule overrides it; it
	// also guards model rules, which fire only for the vendor they name.
	Vendor string

	// Model is the model or product id the device stated.
	Model string

	// Platform is the collector path's own identity for this device: the
	// management API it answered ("panos", "fortios", "icontrol"), or the
	// device profile it was registered under ("cisco_asa").
	//
	// It is not in ADR-0004 D6's original list of rule inputs and was added in
	// 2.10a, because it is the only honest home for the three class hints the
	// interrogators used to carry as constants. "A box that answered the
	// FortiOS API is a FortiGate, and a FortiGate is a firewall" is a strong,
	// earned conclusion. "Its MAC is in a Fortinet OUI" is not the same claim —
	// FortiSwitch and FortiAP share those assignments — and collapsing the two
	// would have classified every Fortinet switch as a firewall.
	Platform string

	// MDNSServices are the DNS-SD service types the subject advertises
	// ("_ipp._tcp"), as shared/hostobs' mDNS decoder collected them and as the
	// `net.mdns_services` fact stores them.
	//
	// Passive, and among the strongest evidence a LAN capture produces: a host
	// advertising `_ipp._tcp` is telling the segment it accepts print jobs,
	// which is a statement about the HOST. An SSH banner, by contrast, says
	// only that something on it accepts logins — which is why SSH is
	// deliberately not a rule and this is.
	MDNSServices []string

	// LLDPCapabilities are the IEEE 802.1AB system capabilities the subject
	// advertised — `bridge`, `router`, `wlan_access_point`, `telephone`,
	// `station_only` — spelled as shared/hostobs' decoder spells them.
	LLDPCapabilities []string

	// CDPCapabilities are the Cisco CDP capabilities the subject advertised —
	// `router`, `switch`, `host`, `voip_phone` — spelled as shared/hostobs'
	// decoder spells them.
	//
	// Kept apart from LLDPCapabilities because the two vocabularies use
	// different words for overlapping ideas: CDP's `switch` means the device
	// switches, while 802.1AB's `bridge` is the bridging FUNCTION, which an
	// access point and a desk phone also perform. A rule written for one
	// protocol firing on the other's advertisement is exactly the fabricated
	// fact this table exists to avoid.
	CDPCapabilities []string
}

// ClassProposal is what the engine concluded, and why.
//
// Unknown true with an empty Class is a complete, valid answer, and it is what
// the caller gets both when nothing matched and when the matches contradicted
// each other. Those two are distinguishable — Conflict says which — and they
// mean different things to a reviewer: nothing matched is a gap in the
// catalogue, a conflict is a rule that needs fixing.
type ClassProposal struct {
	Class      string  `json:"class,omitempty"`
	Vendor     string  `json:"vendor,omitempty"`
	Model      string  `json:"model,omitempty"`
	Confidence float64 `json:"confidence"`

	// Unknown is true whenever Class is empty. It is a field rather than a
	// derived answer for the same reason seams.ClassProposal has one: the value
	// is serialised into a stored proposal, and "" read back out of JSON is
	// indistinguishable from an absent key.
	Unknown bool `json:"unknown"`

	// Conflict is true when two or more classes matched at similar confidence
	// and the engine therefore proposed none. ConflictingClasses names them.
	Conflict bool `json:"conflict"`

	// ConflictingClasses are the classes that tied, in the order they scored.
	// They are the reviewer's diagnosis: two rules disagreeing about the same
	// device is a curation bug, and this is what names it.
	ConflictingClasses []string `json:"conflicting_classes,omitempty"`

	// MatchedRules is every rule that matched, highest confidence first —
	// INCLUDING the ones whose class lost, and including vendor-only rules that
	// never competed for a class at all. A proposal a reviewer cannot audit is
	// one they can only rubber-stamp.
	MatchedRules []RuleRef `json:"matched_rules,omitempty"`

	// ModelID names the LEARNED classifier when the class came from it rather
	// than from a rule (workstream 4.2). Empty for every proposal this package
	// produces: the engine here has no model and never will.
	//
	// It lives on this struct rather than on a wrapper because this is the type
	// the whole intake path already carries — seams.Explain returns it, the
	// approval writer stores it, the Approvals row renders it — and a second
	// shape for "the same proposal, from the other producer" would be a second
	// thing for every one of those to get right.
	//
	// It is what decides the stored provenance: a class from a rule is
	// `class_source_kind: rule` with `rule:<id>`, and a class from the model is
	// `inferred` with `model:<id>`. ADR-0008 D4.2 defines `inferred` as
	// "something a model proposed" and prices it accordingly, so the two must
	// not be collapsed.
	ModelID string `json:"model_id,omitempty"`

	// ModelProbability is the model's calibrated probability for Class, 0 when
	// no model was involved. Confidence carries the same number for a
	// model-derived proposal, so a caller reading only Confidence is not
	// misled; this field is what says the number came from a model rather than
	// from a rule's assertion, which are different KINDS of quantity.
	ModelProbability float64 `json:"model_probability,omitempty"`

	// ModelReasons are the model's top feature contributions, largest first —
	// the argument behind a class no rule can cite a URL for.
	ModelReasons []ModelReason `json:"model_reasons,omitempty"`
}

// ModelReason is one feature's signed contribution to a learned proposal.
//
// The Feature is a stable machine name and the Label is the phrase a reviewer
// reads, built from the evidence in that same input — a vendor name, a port
// number, a banner token, an advertised service. Never a host identifier: the
// learned classifier's whole input is [ClassifyInput], which carries no
// hostname and no address, and a MAC reaches it only as the manufacturer its
// prefix is registered to.
type ModelReason struct {
	Feature      string  `json:"feature"`
	Label        string  `json:"label"`
	Contribution float64 `json:"contribution"`
}

// Engine matches a ClassifyInput against a set of rules.
//
// Safe for concurrent use: an Engine is immutable once built. Reloading the
// curated table means building a NEW engine and swapping the pointer, not
// mutating this one.
type Engine struct {
	// byKind is the rule set, bucketed so a classification touches only the
	// rules for the evidence it actually has.
	byKind map[string][]Rule

	// count is the total, for Describe.
	count int
}

// SkippedRule is a rule an engine refused, kept with the reason.
//
// It is returned rather than logged inside this package for the same reason
// [Observation.Sanitize] returns its rejects: the caller is the one that knows
// whether a skipped rule is a curation mistake to surface or an offline
// bundle's known-bad row, and a library that logged it would make the decision
// invisible at the call site.
type SkippedRule struct {
	Rule Rule
	Err  error
}

// New builds an engine from rules, SKIPPING any rule that does not validate and
// returning the ones it skipped.
//
// # Why skip rather than refuse
//
// Until workstream 2.10b the rules only ever came from the generated table, and
// refusing the whole set was right: a generated table with a bad row is a build
// that should not have shipped. Now they come from `classification_rules`, which
// a platform admin writes into through Catalog ▸ Classification rules, and an
// admin's one bad row must not be able to switch the classifier off for the
// whole deployment. One unusable rule costs that rule; it does not cost the
// other five hundred.
//
// The skips are the caller's to report, and the runtime loader logs each one by
// kind and pattern. Nothing is lost quietly — which is the half of the original
// argument that still holds.
//
// [NewStrict] keeps the old contract, and is what the generated table is built
// and tested with: there, a bad row IS a reason to fail.
//
// The error return is retained and is always nil today. It is the seam for a set
// that cannot produce an engine at all, and keeping it means a future reason to
// refuse does not have to churn every call site.
func New(rules []Rule) (*Engine, []SkippedRule, error) {
	e := &Engine{byKind: make(map[string][]Rule, len(Kinds))}
	var skipped []SkippedRule
	for i := range rules {
		r := rules[i]
		if err := r.Validate(); err != nil {
			skipped = append(skipped, SkippedRule{Rule: r, Err: err})
			continue
		}
		e.byKind[r.Kind] = append(e.byKind[r.Kind], r)
		e.count++
	}
	return e, skipped, nil
}

// NewStrict builds an engine from rules, refusing the whole set if any one of
// them does not validate.
//
// This is what the GENERATED table is built with ([Default]) and what
// TestGeneratedRules_AreValid asserts: those rules passed the generator, so a
// bad one is a bug in the generator or a hand-edit of a generated file, and
// carrying on with 553 of 554 rules would hide it.
func NewStrict(rules []Rule) (*Engine, error) {
	e, skipped, err := New(rules)
	if err != nil {
		return nil, err
	}
	if len(skipped) > 0 {
		return nil, skipped[0].Err
	}
	return e, nil
}

var (
	defaultOnce   sync.Once
	defaultEngine *Engine
	defaultErr    error
)

// Default is the engine over the compiled-in rule table — the same rules
// seed.sql writes, generated from the same YAML.
//
// It is what a runtime with no database uses (the sensor, the device agent, a
// unit test), and what a service falls back to when the curated table cannot be
// read. It panics only if the GENERATED table is invalid, which a build cannot
// produce: the generator validates it and TestGeneratedRules_AreValid covers
// it. Panicking rather than returning a half-built engine is the right failure
// here — an engine missing rules classifies wrongly and silently.
func Default() *Engine {
	defaultOnce.Do(func() {
		defaultEngine, defaultErr = NewStrict(generatedRules)
	})
	if defaultErr != nil {
		panic(defaultErr)
	}
	return defaultEngine
}

// Rules returns the engine's rules, in no particular order. A copy: the engine
// is shared and a caller that mutated the slice would corrupt every later
// classification.
func (e *Engine) Rules() []Rule {
	out := make([]Rule, 0, e.count)
	for _, kind := range Kinds {
		out = append(out, e.byKind[kind]...)
	}
	return out
}

// Len is how many rules the engine holds.
func (e *Engine) Len() int { return e.count }

// ProposesClass reports whether any rule in THIS engine names the class.
//
// It is the vocabulary check the learned classifier of workstream 4.2 is held
// to: a model may only propose a class the curated table could itself have
// argued. The point is the word "this" — the model's targets are fixed at build
// time from the compiled-in table, but the engine a service runs is the CURATED
// one, and a platform admin who deleted the last rule naming a class has said
// that class is not something this deployment classifies. A model proposing it
// anyway would route around the catalogue an admin curates, which is the one
// control they have over what gets proposed.
//
// Linear over the rules, because it is called once per intake where a class was
// not decided and an engine holds a few hundred rules; a cached set would be a
// second thing to invalidate when the refresher swaps the engine.
func (e *Engine) ProposesClass(key string) bool {
	if key == "" {
		return false
	}
	for _, kind := range Kinds {
		for _, r := range e.byKind[kind] {
			if r.Class == key {
				return true
			}
		}
	}
	return false
}

// Classify proposes a class, a vendor and a model from the evidence in facts.
//
// # How the class is decided
//
//  1. Every rule of every kind is matched against the evidence present. A rule
//     whose evidence is absent cannot match; it is not a miss.
//  2. Rules that name a class are grouped by class, and each class scores the
//     HIGHEST confidence among its rules. One class supported by three rules
//     does not out-score one supported by a better rule — evidence is not
//     additive here, because two OUI rules and an SNMP rule naming Cisco are
//     three views of one fact, not three facts.
//  3. Any class that ANOTHER candidate refines — one is its descendant in the
//     taxonomy — is dropped. `switch` beating `network_device` is a refinement,
//     not a disagreement, and treating it as a conflict would throw away the
//     better answer. Dropping every such ancestor before step 4, rather than
//     comparing only the top two, is what stops a genuine third opinion from
//     hiding behind a refinement that happened to sort above it.
//  4. Then, if the top two remaining scores are within [ConflictEpsilon], NO class
//     is proposed and both are reported. This is the rule that matters: two
//     unrelated classes at similar confidence means the rules contradict each
//     other, and the honest answer is that we do not know.
//  5. Otherwise the top class wins, at its own confidence.
//
// # How the vendor is decided
//
// An input Vendor wins outright — the device named itself, and no rule
// out-argues that. Otherwise the highest-confidence matching rule that names a
// vendor supplies it, with the same epsilon rule: two rules naming DIFFERENT
// vendors at similar confidence yield no vendor. Model works the same way.
//
// Classify never returns an error. It takes a context so callers do not have to
// change shape when a future engine consults something remote, and so it drops
// straight into the seams.Classifier signature.
func (e *Engine) Classify(_ context.Context, facts ClassifyInput) ClassProposal {
	matched := e.match(facts)

	refs := make([]RuleRef, 0, len(matched))
	for _, r := range matched {
		refs = append(refs, r.ref())
	}
	sortRefs(refs)

	proposal := ClassProposal{MatchedRules: refs}

	// --- vendor and model -------------------------------------------------
	//
	// Taken from the input first. A device that answered its own management API
	// and stated a vendor has given us a measured fact; a rule keyed on an OUI
	// has given us an inference. The measured one wins, and this is the same
	// precedence snmpIdentity already applied before these rules existed.
	proposal.Vendor = strings.TrimSpace(facts.Vendor)
	if proposal.Vendor == "" {
		proposal.Vendor, _ = topString(refs, func(r RuleRef) string { return r.Vendor })
	}
	proposal.Model = strings.TrimSpace(facts.Model)
	if proposal.Model == "" {
		proposal.Model, _ = topString(refs, func(r RuleRef) string { return r.Model })
	}

	// --- class ------------------------------------------------------------
	class, confidence, conflicting := decideClass(refs)
	if len(conflicting) > 0 {
		proposal.Conflict = true
		proposal.ConflictingClasses = conflicting
	}
	proposal.Class = class
	proposal.Confidence = confidence
	proposal.Unknown = class == ""
	if proposal.Unknown {
		// A proposal with no class makes no class claim, so it carries no
		// confidence either. Leaving the winning rule's number here would read
		// as "we are 85% sure of something", which is not a thing this struct
		// can say.
		proposal.Confidence = 0
	}

	return proposal
}

// match collects every rule whose evidence is present and whose pattern fits.
func (e *Engine) match(facts ClassifyInput) []Rule {
	var out []Rule

	out = append(out, e.matchOUI(facts.MACs)...)
	out = append(out, e.matchSysObjectID(facts.SysObjectID)...)
	out = append(out, e.matchENIP(facts.ENIPVendorID)...)
	out = append(out, e.matchCloudType(facts.CloudResourceType)...)
	out = append(out, e.matchBanners(facts.Banners)...)
	out = append(out, e.matchPortProfile(facts.OpenPorts)...)
	out = append(out, e.matchModel(facts.Vendor, facts.Model)...)
	out = append(out, e.matchPlatform(facts.Platform)...)
	out = append(out, e.matchCapabilities(KindCDPCapabilities, facts.CDPCapabilities)...)
	out = append(out, e.matchCapabilities(KindLLDPCapability, facts.LLDPCapabilities)...)
	out = append(out, e.matchMDNSServices(facts.MDNSServices)...)

	return out
}

// matchCapabilities returns the MOST SPECIFIC rules that fit what a device
// advertised: every rule whose whole capability set is present, narrowed to the
// ones naming the most capabilities.
//
// Most-specific-wins, like matchSysObjectID and matchModel, and for the same
// reason: a rule for `bridge,router` is not arguing with a rule for `router`, it
// is REFINING it. Returning both would put the two classes into the arbitration
// as rivals, and since they sit one band apart the engine would answer "we do
// not know" for the commonest device on a corporate LAN.
//
// A tie — two rules naming one capability each, both advertised — IS returned
// as two, because that is a real disagreement about a real device and the
// arbitration is where it belongs.
func (e *Engine) matchCapabilities(kind string, advertised []string) []Rule {
	if len(advertised) == 0 {
		return nil
	}
	set := make(map[string]bool, len(advertised))
	for _, c := range advertised {
		if c := strings.ToLower(strings.TrimSpace(c)); c != "" {
			set[c] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	var out []Rule
	best := 0
	for _, r := range e.byKind[kind] {
		if len(r.capabilities) < best {
			continue
		}
		all := true
		for _, c := range r.capabilities {
			if !set[c] {
				all = false
				break
			}
		}
		if !all {
			continue
		}
		if len(r.capabilities) > best {
			best = len(r.capabilities)
			out = out[:0]
		}
		out = append(out, r)
	}
	return out
}

func (e *Engine) matchMDNSServices(services []string) []Rule {
	if len(services) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []Rule
	for _, s := range services {
		svc := strings.ToLower(strings.TrimSpace(s))
		// The wire form carries the instance and the domain around the type —
		// `Brother HL-L2350DW._ipp._tcp.local.` — and the decoder already
		// reduces it to the type. Trimming the trailing root dot here is the
		// one normalisation left, because a producer that kept it would match
		// nothing and say nothing.
		svc = strings.TrimSuffix(svc, ".")
		svc = strings.TrimSuffix(svc, ".local")
		if svc == "" || seen[svc] {
			continue
		}
		seen[svc] = true
		for _, r := range e.byKind[KindMDNSService] {
			if strings.EqualFold(r.Pattern, svc) {
				out = append(out, r)
			}
		}
	}
	return out
}

func (e *Engine) matchOUI(macs []string) []Rule {
	if len(macs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []Rule
	for _, mac := range macs {
		oui := ouiOf(mac)
		if oui == "" || seen[oui] {
			continue
		}
		seen[oui] = true
		for _, r := range e.byKind[KindOUI] {
			if r.Pattern == oui {
				out = append(out, r)
			}
		}
	}
	return out
}

// ouiOf extracts the 24-bit assignment from a MAC in any spelling, as 6
// uppercase hex digits. It returns "" for anything that is not 12 hex digits —
// including the all-zero and broadcast addresses, which are placeholders rather
// than identities and whose "OUI" would be a rule pattern somebody might
// plausibly add.
func ouiOf(mac string) string {
	var hex strings.Builder
	for _, r := range mac {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F':
			hex.WriteRune(r)
		case r >= 'a' && r <= 'f':
			hex.WriteRune(r - 'a' + 'A')
		case r == ':' || r == '-' || r == '.' || r == ' ':
			// separator
		default:
			return ""
		}
	}
	h := hex.String()
	if len(h) != 12 {
		return ""
	}
	if h == "000000000000" || h == "FFFFFFFFFFFF" {
		return ""
	}
	return h[:6]
}

// matchSysObjectID returns the LONGEST matching prefix rule, and only that one.
//
// Longest-prefix rather than every-prefix because the rules under one
// enterprise are refinements of each other, not independent evidence: a
// platform admin who adds 1.3.6.1.4.1.9.1.1745 (a specific Catalyst) means it
// to REPLACE the broad 1.3.6.1.4.1.9 answer, not to argue with it. Returning
// both would put `switch` and `network_device` into the arbitration as rivals.
func (e *Engine) matchSysObjectID(sysObjectID string) []Rule {
	oid := strings.TrimSpace(sysObjectID)
	oid = strings.TrimPrefix(oid, ".")
	if !strings.HasPrefix(oid, enterprisePrefix) {
		return nil
	}
	var best *Rule
	for i, r := range e.byKind[KindSysObjectID] {
		if !oidHasPrefix(oid, r.Pattern) {
			continue
		}
		if best == nil || len(r.Pattern) > len(best.Pattern) {
			best = &e.byKind[KindSysObjectID][i]
		}
	}
	if best == nil {
		return nil
	}
	return []Rule{*best}
}

// oidHasPrefix matches on ARC boundaries, so 1.3.6.1.4.1.9 does not match
// enterprise 99. A plain strings.HasPrefix here would have attributed every
// Netgear device (enterprise 4526) to a rule for enterprise 452, silently.
func oidHasPrefix(oid, prefix string) bool {
	if oid == prefix {
		return true
	}
	return strings.HasPrefix(oid, prefix+".")
}

func (e *Engine) matchENIP(vendorID int) []Rule {
	if vendorID <= 0 {
		return nil
	}
	want := fmt.Sprintf("%d", vendorID)
	var out []Rule
	for _, r := range e.byKind[KindENIP] {
		if r.Pattern == want {
			out = append(out, r)
		}
	}
	return out
}

func (e *Engine) matchCloudType(resourceType string) []Rule {
	rt := strings.ToLower(strings.TrimSpace(resourceType))
	if rt == "" {
		return nil
	}
	var out []Rule
	for _, r := range e.byKind[KindCloudType] {
		if strings.ToLower(r.Pattern) == rt {
			out = append(out, r)
		}
	}
	return out
}

func (e *Engine) matchBanners(banners map[string]string) []Rule {
	if len(banners) == 0 {
		return nil
	}
	var out []Rule
	for _, r := range e.byKind[KindBanner] {
		if r.compiled == nil {
			// Unreachable through New, which compiles every banner rule or
			// refuses the set. Stated rather than dereferenced: a nil regexp
			// here would panic inside a discovery, far from the bad rule.
			continue
		}
		for _, banner := range banners {
			if r.compiled.MatchString(banner) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

func (e *Engine) matchPortProfile(open []int) []Rule {
	if len(open) == 0 {
		return nil
	}
	set := make(map[int]bool, len(open))
	for _, p := range open {
		set[p] = true
	}
	var out []Rule
	for _, r := range e.byKind[KindPortProfile] {
		all := true
		for _, p := range r.ports {
			if !set[p] {
				all = false
				break
			}
		}
		if all {
			out = append(out, r)
		}
	}
	return out
}

// matchModel returns the LONGEST matching prefix, for the same reason
// matchSysObjectID does: C9800 and C9 are refinements of one another, and
// AIR-CT (a wireless controller) must not lose an argument with AIR- (an access
// point).
//
// A rule that names a vendor is skipped when the input names a DIFFERENT one.
// That guard is what lets short, generic prefixes live in the table at all: a
// UniFi device type of "usw" and some other manufacturer's "USW-" model line
// would otherwise be the same rule.
func (e *Engine) matchModel(vendor, model string) []Rule {
	m := strings.ToUpper(strings.TrimSpace(model))
	if m == "" {
		return nil
	}
	v := strings.TrimSpace(vendor)
	var best *Rule
	for i, r := range e.byKind[KindModel] {
		if r.Vendor != "" && v != "" && !vendorAgrees(r.Vendor, v) {
			continue
		}
		if !strings.HasPrefix(m, strings.ToUpper(r.Pattern)) {
			continue
		}
		if best == nil || len(r.Pattern) > len(best.Pattern) {
			best = &e.byKind[KindModel][i]
		}
	}
	if best == nil {
		return nil
	}
	return []Rule{*best}
}

func (e *Engine) matchPlatform(platform string) []Rule {
	p := strings.TrimSpace(platform)
	if p == "" {
		return nil
	}
	var out []Rule
	for _, r := range e.byKind[KindPlatform] {
		if strings.EqualFold(r.Pattern, p) {
			out = append(out, r)
		}
	}
	return out
}

// decideClass runs steps 2–5 of the arbitration documented on Classify.
//
// It returns the winning class and its confidence, or "" and the classes that
// tied. refs must already be sorted highest-confidence first.
func decideClass(refs []RuleRef) (class string, confidence float64, conflicting []string) {
	// Highest confidence per class, in first-seen (i.e. descending) order.
	best := map[string]float64{}
	var order []string
	for _, r := range refs {
		if r.Class == "" {
			continue
		}
		if _, seen := best[r.Class]; !seen {
			order = append(order, r.Class)
			best[r.Class] = r.Confidence
			continue
		}
		if r.Confidence > best[r.Class] {
			best[r.Class] = r.Confidence
		}
	}
	// A refinement is not a disagreement. `switch` under `network_device` is the
	// taxonomy working as designed, and the specific answer is strictly better
	// than the general one, whichever of the two scored higher — so drop every
	// candidate that some OTHER candidate refines, and arbitrate over what is
	// left.
	//
	// Dropping FIRST rather than comparing the top two is what makes this hold
	// with more than two candidates. `network_device` 0.80, `firewall` 0.78 and
	// `switch` 0.77 used to resolve to `firewall`: the top two were related, the
	// refinement rule returned the specific one, and `switch` — a real
	// disagreement, one hundredth away — was never looked at. Now
	// `network_device` drops as an ancestor of both and the surviving two tie, so
	// the answer is that we do not know, which is what two rules contradicting
	// each other means.
	order = dropRefinedAncestors(order)

	switch len(order) {
	case 0:
		return "", 0, nil
	case 1:
		return order[0], best[order[0]], nil
	}

	top, runnerUp := order[0], order[1]

	if best[top]-best[runnerUp] < ConflictEpsilon {
		// Report every class within epsilon of the leader, not just the top
		// two: three rules disagreeing is the same bug as two, and a reviewer
		// shown only two of them would fix half of it.
		tied := []string{top}
		for _, c := range order[1:] {
			if best[top]-best[c] < ConflictEpsilon {
				tied = append(tied, c)
			}
		}
		return "", 0, tied
	}
	return top, best[top], nil
}

// vendorAgrees reports whether two vendor strings name the same manufacturer.
//
// Exact-after-folding, OR one folded name a prefix of the other — "Dell" and
// "Dell Inc.", "Ubiquiti" and "Ubiquiti Networks", "NETGEAR" and "Netgear".
// Corporate suffixes are how one manufacturer acquires several spellings, and
// the two places this is used both FAIL SILENTLY on a mismatch: a `model` rule
// whose vendor does not agree with the input simply does not fire, and two rules
// naming "different" vendors inside the conflict epsilon cancel each other and
// produce no vendor at all. Neither logs anything. That is a bad shape for an
// exact string comparison to sit in when the strings come from a curated CSV, an
// SNMP walk and a vendor API that have never been introduced to each other.
//
// The generator holds the LINE — every vendor a shipped rule names is spelled as
// standards/oui-vendors.csv spells it, and `make audit` fails otherwise. This is
// the belt underneath, for the vendor strings that arrive from a collector or a
// stored fact rather than from the table.
//
// The prefix rule stops well short of fuzzy matching: it does not merge
// "Cisco Systems" with "Cisco Meraki" (neither is a prefix of the other), and it
// refuses to draw any conclusion from fewer than three characters, so "HP" is
// not a licence to match everything beginning with those letters.
func vendorAgrees(a, b string) bool {
	fa, fb := foldVendor(a), foldVendor(b)
	if fa == "" || fb == "" {
		return false
	}
	if fa == fb {
		return true
	}
	short, long := fa, fb
	if len(short) > len(long) {
		short, long = long, short
	}
	const minPrefix = 3
	return len(short) >= minPrefix && strings.HasPrefix(long, short)
}

// foldVendor reduces a vendor name to its letters and digits, lower-cased, so
// punctuation and spacing stop being part of a manufacturer's identity.
func foldVendor(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r - 'A' + 'a')
		}
	}
	return b.String()
}

// dropRefinedAncestors removes every candidate class that another candidate is a
// descendant of, preserving the order of what remains.
//
// `network_device` beside `switch` is one answer at two altitudes, not two
// answers, and the specific one is strictly better. Removing the general one
// before the conflict check means a third, UNRELATED candidate still gets
// compared against the winner rather than being hidden behind a refinement that
// happened to sort above it.
func dropRefinedAncestors(order []string) []string {
	out := make([]string, 0, len(order))
	for i, candidate := range order {
		refined := false
		for j, other := range order {
			if i != j && assetclass.IsAncestor(candidate, other) {
				refined = true
				break
			}
		}
		if !refined {
			out = append(out, candidate)
		}
	}
	return out
}

// topString picks the highest-confidence non-empty value of one field, applying
// the same epsilon rule the class arbitration uses: two rules asserting
// different vendors at similar confidence produce none.
//
// refs must already be sorted highest-confidence first. The bool says whether a
// value was refused for conflicting, which the caller does not currently
// surface — vendor disagreement is rarer and less consequential than class
// disagreement, and MatchedRules already carries both for a reviewer.
func topString(refs []RuleRef, get func(RuleRef) string) (string, bool) {
	var leader string
	var leaderConf float64
	found := false
	for _, r := range refs {
		v := strings.TrimSpace(get(r))
		if v == "" {
			continue
		}
		if !found {
			leader, leaderConf, found = v, r.Confidence, true
			continue
		}
		if vendorAgrees(v, leader) {
			continue
		}
		if leaderConf-r.Confidence < ConflictEpsilon {
			return "", true
		}
		// Sorted descending, so everything after this point scores lower still.
		break
	}
	return leader, false
}
