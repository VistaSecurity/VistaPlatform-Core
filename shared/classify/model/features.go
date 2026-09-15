package model

import (
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/classify"
)

// Input is everything the model looks at: the evidence a collector gathered,
// and what the RULES made of it.
//
// The rules' answer is an input rather than a wrapper around this call because
// the model's job is defined relative to it — it speaks only where the rules
// cannot, and "the rules could not decide between a printer and a network
// device" is itself strong evidence about what the thing is. A model that could
// not see that would re-derive it badly from the same MAC.
type Input struct {
	// Facts is the collector's evidence, in exactly the shape the rule engine
	// reads. The same value, not a copy in another vocabulary: one host seen
	// two ways must not be classified two ways, and two projections of one
	// struct is how that starts.
	Facts classify.ClassifyInput

	// Rules is what [classify.Engine.Classify] returned for Facts. The zero
	// value is valid and means "the rules were not consulted", which is
	// different from "the rules said nothing" — [FeatureRuleSilent] carries the
	// latter and is set only when the engine ran and matched no class-bearing
	// rule at all.
	Rules classify.ClassProposal
}

// ── The feature space ──────────────────────────────────────────────────────
//
// Everything below is a BUILD CONSTANT. The widths, the port list, the
// capability vocabularies and the two class vocabularies are fixed at compile
// time and derived from the COMPILED-IN rule table, never from the curated
// `classification_rules` rows a platform admin edits.
//
// That distinction is load-bearing and easy to get wrong in the opposite
// direction. The rules' OUTPUT (Input.Rules) comes from the live curated
// engine, which is right — it is the chain's first stage and an admin's rule
// must affect it. But the feature SPACE must not: a trained weight for
// `oui/7` means "whatever vendors hash to bucket 7 in this build", and an admin
// adding an OUI row that landed in bucket 7 would silently change what a
// committed weight refers to. A model whose features move under its weights is
// a model nobody can account for.

// Hash widths. Each is a power of two so the modulo is exact and a width change
// is visible as a whole-file diff of the weights rather than a drift.
//
// # Why hash at all, and what a collision costs
//
// The alternative is a one-hot over every value the catalogue can produce:
// roughly five hundred OUI vendors, every model prefix, every banner token. A
// feature NAME is part of the weights file, so that space would have to be
// enumerated in the schema whether or not any of it was ever observed, and the
// hashing trick collapses it to a fixed, stated width.
//
// Two values that hash to one bucket become one feature, and the model cannot
// tell them apart. The widths are set generously — the file is SPARSE, so a
// bucket nothing ever sets costs nothing at all, and widening is therefore free
// in everything except the schema fingerprint. At 256 OUI buckets the whole
// five-hundred-vendor table averages two vendors per bucket, and the handful
// that appear in any one tenant's population collide far less often than that.
//
// What makes a collision survivable when it does happen is that no bucket
// decides anything alone: a colliding pair is separated by the other evidence
// in the same input, and [ModelProposalFloor] means an input whose ONLY signal
// is a collided bucket cannot clear the floor. A collision costs precision on
// thin evidence, which is exactly where the model is meant to stay quiet.
//
// The EXPLANATION is not hashed. [Model.Predict] labels each contribution from
// the evidence in this very input — the vendor the OUI is registered to, the
// banner token, the port number — so a reviewer reads "the MAC prefix is
// registered to Brother", never "oui/7".
const (
	OUIBuckets       = 256
	SysOIDBuckets    = 64
	SysOIDSubBuckets = 64
	PIDBuckets       = 64
	PIDTokenBuckets  = 128
	BannerBuckets    = 128
	MDNSBuckets      = 64
	CloudBuckets     = 128
)

// Feature namespaces. A feature's name is `<namespace>/<bucket or token>`, and
// the names are what the weights file is keyed by — so renaming one invalidates
// every trained weight, and [Model.Validate] refuses a model whose namespaces
// this build does not know.
const (
	// FeatureBias is the intercept, always 1. Per class, so it carries each
	// class's base rate on the population the model is asked about — which is
	// NOT the population at large: the model only ever runs where the rules
	// could not decide, and those inputs are not a random sample of anything.
	FeatureBias = "bias"

	// NamespaceOUI is the manufacturer the MAC's 24-bit assignment belongs to,
	// per the compiled-in OUI table, hashed. The VENDOR and not the prefix: two
	// assignments held by one manufacturer are one fact, and hashing the hex
	// would scatter Cisco's sixty prefixes across sixty buckets.
	NamespaceOUI = "oui"

	// FeatureOUIUnknown is a MAC whose assignment the table does not name. It
	// is a feature rather than an absence because "a manufacturer we have never
	// catalogued" is evidence — it skews away from the enterprise classes the
	// catalogue is thickest in.
	FeatureOUIUnknown = "oui_unknown"

	// NamespaceSysOID is the IANA private-enterprise number from the SNMP
	// sysObjectID, hashed. NamespaceSysOIDSub adds the arc below it, which is
	// where a vendor separates its product lines.
	NamespaceSysOID    = "sysoid"
	NamespaceSysOIDSub = "sysoid_sub"

	// NamespacePID is the product-id FAMILY: the stated model's first token
	// with its trailing digits removed, so `C9300-48P`, `C9200L` and `C9500`
	// are one feature. NamespacePIDToken keeps the token whole, which separates
	// them again.
	NamespacePID      = "pid"
	NamespacePIDToken = "pid_token"

	// NamespaceBanner is a product token from a `Server:` line, hashed.
	NamespaceBanner = "banner"

	// NamespacePort is one of [WellKnownPorts] being open. Not hashed: the port
	// list is short, closed and meaningful on its own, and a collided port
	// would be the one feature a reviewer would certainly notice was wrong.
	NamespacePort = "port"

	// NamespaceMDNS is an advertised DNS-SD service type, hashed.
	NamespaceMDNS = "mdns"

	// NamespaceLLDP and NamespaceCDP are the advertised capability names, one
	// feature each over the two decoders' whole vocabularies. Two namespaces
	// and not one, for the reason classify keeps two rule kinds: CDP's `switch`
	// and 802.1AB's `bridge` are different claims, and a shared feature would
	// teach the model they are the same.
	NamespaceLLDP = "lldp"
	NamespaceCDP  = "cdp"

	// NamespaceCloud is the provider's own resource type, TOKENISED on its
	// underscores and hashed word by word.
	//
	// Token by token rather than whole, because the vocabulary is open and the
	// words generalise across it. `aws_kms`, `gcp_kms_crypto_key` and
	// `azure_managed_hsm` are three types the catalogue spells three ways; what
	// they share is `kms` and `hsm`, and a whole-type hash puts them in three
	// unrelated buckets so a type nobody has catalogued yet — which is
	// precisely the input the rules are silent on — could only ever score its
	// bias. Tokenising is what lets an unseen `gcp_kms_key_ring` be recognised
	// from `aws_kms`.
	NamespaceCloud = "cloud"

	// NamespaceRuleTop is the class the rules LED with — the one they decided,
	// or, on a conflict, the highest-scoring of the tied classes.
	// NamespaceRuleTied is every class a conflict named.
	NamespaceRuleTop  = "rule_top"
	NamespaceRuleTied = "rule_tied"

	// FeatureRuleConfidence is the highest confidence among the matched rules
	// that named ANY class, 0 when none did.
	//
	// Not [classify.ClassProposal.Confidence], which is zero on a conflict by
	// construction — a proposal with no class makes no claim, so it carries no
	// confidence. Reading that field here would have made this feature
	// identically zero on every input the chain actually gives the model, which
	// is a weight fitted on evidence the model never sees: the "check that
	// cannot fail" shape, pointed at a feature.
	FeatureRuleConfidence = "rule_confidence"

	// FeatureRuleConflict is the rules contradicting each other.
	FeatureRuleConflict = "rule_conflict"

	// FeatureRuleSilent is the rules matching no class-bearing rule at all. It
	// is a different state from a conflict and means a different thing: a gap
	// in the catalogue rather than a bug in it.
	FeatureRuleSilent = "rule_silent"
)

// WellKnownPorts is the fixed port vocabulary, ascending. Exactly 64: a closed
// list chosen for what it SEPARATES — 9100 and 631 for printers, 502/20000/4840
// /44818 for the OT protocols, 3306/5432/1433/1521/27017 for databases, 161 and
// 4786 for managed network gear — rather than the sixty-four most common ports
// on the internet, most of which every class has open.
var WellKnownPorts = []int{
	21, 22, 23, 25, 53, 67, 69, 80, 88, 102, 110, 111, 123, 135, 139, 143,
	161, 389, 443, 445, 465, 502, 515, 548, 554, 587, 623, 631, 636, 873, 902, 993,
	995, 1194, 1433, 1521, 1723, 1883, 1900, 2049, 2222, 3128, 3260, 3306, 3389, 4786, 4840, 5000,
	5060, 5432, 5900, 5985, 6379, 7547, 8000, 8080, 8443, 8883, 9100, 9200, 11211, 20000, 27017, 44818,
}

// lldpCapabilities and cdpCapabilities are the two decoders' vocabularies,
// restated here rather than imported from shared/hostobs.
//
// Restated for the same reason shared/identity/matcher restates the identifier
// kinds: this package must stay importable by the sensor and the device agent,
// which have no business carrying a packet decoder, and a feature NAME is part
// of the weights file — so it has to be a constant of this package even when
// the vocabulary it mirrors lives elsewhere. TestCapabilityVocabularyMatchesHostobs
// fails if the two drift, which is the half of the argument that matters.
var (
	lldpCapabilities = []string{
		"other", "repeater", "bridge", "wlan_access_point",
		"router", "telephone", "docsis_cable_device", "station_only",
		"c_vlan_component", "s_vlan_component", "two_port_mac_relay",
	}
	cdpCapabilities = []string{
		"router", "transparent_bridge", "source_route_bridge", "switch",
		"host", "igmp_capable", "repeater", "voip_phone",
		"remotely_managed", "cvta_phone", "two_port_mac_relay",
	}
)

// Vector is one extracted input: feature name → value, with the evidence that
// set each one.
type Vector struct {
	// Values is the sparse feature vector. A feature absent from the map is
	// zero, which for every feature here means "not observed" rather than "a
	// measurement of zero" — the "unknown is neither" rule of ADR-0008 D4.3 at
	// the feature level.
	Values map[string]float64

	// Evidence is feature name → the phrase that set it, for the explanation.
	// It never leaves this process except through [Model.Predict]'s
	// contributions, and it never contains a host identifier: see
	// [Features] for what is deliberately not put in it.
	Evidence map[string]string
}

func newVector() Vector {
	return Vector{Values: map[string]float64{}, Evidence: map[string]string{}}
}

func (v Vector) set(name, evidence string, value float64) {
	if value == 0 {
		return
	}
	if cur, ok := v.Values[name]; !ok || value > cur {
		v.Values[name] = value
	}
	if _, ok := v.Evidence[name]; !ok && evidence != "" {
		v.Evidence[name] = evidence
	}
}

// At reads one feature, 0 for one the vector does not carry.
func (v Vector) At(name string) float64 { return v.Values[name] }

// Names returns the vector's feature names, sorted, so a caller iterating it is
// deterministic.
func (v Vector) Names() []string {
	out := make([]string, 0, len(v.Values))
	for n := range v.Values {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Features is the model's whole view of an input, and the ONLY path from an
// [Input] into a score.
//
// # What cannot reach the model
//
// Not the MAC — only which manufacturer its 24-bit assignment belongs to.
// Not a hostname or an address: [classify.ClassifyInput] carries neither, and
// that is not an accident of this function, it is the shape of the struct.
// Not a serial number, a credential or a key: none is an input to
// classification and none has a feature here to land in.
//
// Every value is 0, 1, or a confidence in 0..1. There is no field into which a
// raw string could be carried through, which makes "the classifier never sees
// an identifier" a structural property rather than a promise —
// TestNoRawIdentifierReachesAnExplanation is the assertion that it stays one.
func Features(in Input) Vector {
	v := newVector()
	v.set(FeatureBias, "", 1)

	table := ouiTable()
	seenOUI := map[string]bool{}
	for _, mac := range in.Facts.MACs {
		oui := ouiOf(mac)
		if oui == "" || seenOUI[oui] {
			continue
		}
		seenOUI[oui] = true
		vendor, known := table[oui]
		if !known {
			v.set(FeatureOUIUnknown, "the MAC prefix is not one the vendor table names", 1)
			continue
		}
		v.set(bucket(NamespaceOUI, vendor, OUIBuckets),
			"the MAC prefix is registered to "+vendor, 1)
	}

	if ent, sub := enterpriseArcs(in.Facts.SysObjectID); ent != "" {
		v.set(bucket(NamespaceSysOID, ent, SysOIDBuckets),
			"the SNMP object id is under private enterprise "+ent, 1)
		if sub != "" {
			v.set(bucket(NamespaceSysOIDSub, sub, SysOIDSubBuckets),
				"the SNMP object id is under "+sub, 1)
		}
	}

	if token := pidToken(in.Facts.Model); token != "" {
		v.set(bucket(NamespacePIDToken, token, PIDTokenBuckets),
			"the stated model begins "+token, 1)
		if family := pidFamily(token); family != "" {
			v.set(bucket(NamespacePID, family, PIDBuckets),
				"the stated model is in the "+family+" family", 1)
		}
	}

	for _, token := range bannerTokens(in.Facts.Banners) {
		v.set(bucket(NamespaceBanner, token, BannerBuckets),
			"the service banner said “"+token+"”", 1)
	}

	open := map[int]bool{}
	for _, p := range in.Facts.OpenPorts {
		open[p] = true
	}
	for _, p := range WellKnownPorts {
		if open[p] {
			v.set(NamespacePort+"/"+strconv.Itoa(p), "port "+strconv.Itoa(p)+" is open", 1)
		}
	}

	for _, svc := range in.Facts.MDNSServices {
		s := normaliseMDNS(svc)
		if s == "" {
			continue
		}
		v.set(bucket(NamespaceMDNS, s, MDNSBuckets), "it advertises "+s, 1)
	}

	setCapabilities(v, NamespaceLLDP, lldpCapabilities, in.Facts.LLDPCapabilities, "LLDP")
	setCapabilities(v, NamespaceCDP, cdpCapabilities, in.Facts.CDPCapabilities, "CDP")

	if ct := strings.ToLower(strings.TrimSpace(in.Facts.CloudResourceType)); isResourceType(ct) {
		for _, tok := range cloudTokens(ct) {
			// The TOKEN, not the whole type. The type is a provider string this
			// package never validated and cannot bound — it arrives from a
			// finding's raw_data by way of `resource_type` — and the label is
			// stored in asset_history and rendered to a reviewer. The token is
			// what the feature is anyway, so echoing the type as well added
			// nothing and carried an arbitrary string along with it.
			v.set(bucket(NamespaceCloud, tok, CloudBuckets),
				"the cloud resource type contains “"+tok+"”", 1)
		}
	}

	setRuleFeatures(v, in.Rules)
	return v
}

// setRuleFeatures projects the rule engine's own answer.
//
// The three states are mutually exclusive and all three are meaningful: the
// rules decided (the chain does not call the model at all, but the TRAINER sees
// these — a class a reviewer accepted from a rule is a labelled example), the
// rules conflicted, or the rules said nothing.
func setRuleFeatures(v Vector, prop classify.ClassProposal) {
	top := prop.Class
	if top == "" && len(prop.ConflictingClasses) > 0 {
		// Descending, as decideClass reports them, so the first is the leader.
		top = prop.ConflictingClasses[0]
	}
	if top != "" {
		v.set(NamespaceRuleTop+"/"+top, "the rules led with "+labelOf(top), 1)
	}
	for _, c := range prop.ConflictingClasses {
		v.set(NamespaceRuleTied+"/"+c, "the rules argued "+labelOf(c), 1)
	}
	if prop.Conflict {
		v.set(FeatureRuleConflict, "the rules contradicted each other", 1)
	}
	if conf := topClassRuleConfidence(prop); conf > 0 {
		v.set(FeatureRuleConfidence, "the strongest rule asserts "+
			strconv.Itoa(int(conf*100+0.5))+"%", conf)
	}
	// `Unknown` is what says the engine RAN. Engine.Classify sets it on every
	// answer it produces, so a zero-value ClassProposal — the caller that did
	// not consult the rules at all — has it false and sets nothing here. "The
	// rules were not asked" and "the rules had nothing to say" are different
	// facts and only one of them is evidence.
	if top == "" && !prop.Conflict && prop.Unknown {
		v.set(FeatureRuleSilent, "no rule proposed any class", 1)
	}
}

// topClassRuleConfidence is the highest confidence among the matched rules that
// named a class. Zero when none did, which includes a vendor-only OUI hit.
func topClassRuleConfidence(prop classify.ClassProposal) float64 {
	var best float64
	for _, r := range prop.MatchedRules {
		if r.Class != "" && r.Confidence > best {
			best = r.Confidence
		}
	}
	return best
}

func setCapabilities(v Vector, namespace string, vocabulary, advertised []string, protocol string) {
	if len(advertised) == 0 {
		return
	}
	known := make(map[string]bool, len(vocabulary))
	for _, c := range vocabulary {
		known[c] = true
	}
	for _, raw := range advertised {
		c := strings.ToLower(strings.TrimSpace(raw))
		if c == "" || !known[c] {
			// A capability name outside the decoder's vocabulary is a producer
			// bug, not evidence. Bucketing it would give the model a feature
			// that means "somebody spelled something wrong".
			continue
		}
		v.set(namespace+"/"+c, "it advertises "+protocol+" "+strings.ReplaceAll(c, "_", " "), 1)
	}
}

// labelOf is a class key's display name, falling back to the key. Used only in
// explanations.
func labelOf(key string) string {
	if c, ok := assetclass.Get(key); ok && c.Label != "" {
		return c.Label
	}
	return key
}

// bucket is the hashed feature name for one token in one namespace.
//
// FNV-1a over the lower-cased token, masked to the width. FNV rather than
// maphash because it is stable across processes and architectures: a weights
// file trained on one machine has to mean the same thing on another, and Go's
// map hash is deliberately randomised per process.
func bucket(namespace, token string, width int) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.ToLower(token)))
	return namespace + "/" + strconv.Itoa(int(h.Sum64()%uint64(width))) //nolint:gosec // width is a small positive constant
}

// ouiOf extracts the 24-bit assignment from a MAC in any spelling, as six
// uppercase hex digits, or "" for anything that is not twelve hex digits.
//
// A verbatim copy of classify's unexported ouiOf rather than an import of it,
// because exporting it from classify to serve one caller would widen that
// package's surface for a five-line helper. TestOUIExtractionMatchesTheEngine
// holds the two together over the spellings that differ.
func ouiOf(mac string) string {
	var hex strings.Builder
	for _, r := range mac {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F':
			hex.WriteRune(r)
		case r >= 'a' && r <= 'f':
			hex.WriteRune(r - 'a' + 'A')
		case r == ':' || r == '-' || r == '.' || r == ' ':
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

// enterpriseArcs splits a sysObjectID into its private-enterprise number and
// the arc below it. Both empty for anything outside 1.3.6.1.4.1.
//
// Both arcs must be DIGITS, and that is a check rather than an assumption. An
// OID arc is a number; a "sysObjectID" whose arc is not one did not come from
// an SNMP walk, so it is a producer bug and not evidence — the same argument
// setCapabilities makes about a capability name outside the decoder's
// vocabulary. It also matters because the arc is echoed into the explanation a
// reviewer reads and that string is stored: without this, whatever a producer
// put after `1.3.6.1.4.1.` would be carried through verbatim and unbounded.
func enterpriseArcs(sysObjectID string) (enterprise, sub string) {
	oid := strings.TrimPrefix(strings.TrimSpace(sysObjectID), ".")
	const prefix = "1.3.6.1.4.1."
	if !strings.HasPrefix(oid, prefix) {
		return "", ""
	}
	rest := strings.Split(strings.TrimPrefix(oid, prefix), ".")
	if len(rest) == 0 || !isArc(rest[0]) {
		return "", ""
	}
	enterprise = rest[0]
	if len(rest) > 1 && isArc(rest[1]) {
		sub = enterprise + "." + rest[1]
	}
	return enterprise, sub
}

// maxArcDigits bounds one OID arc. IANA's private-enterprise numbers are 32-bit,
// so ten digits is every assignment that exists and then some.
const maxArcDigits = 10

func isArc(s string) bool {
	return s != "" && len(s) <= maxArcDigits && allDigits(s)
}

// pidToken is the first delimiter-separated token of a stated model, upper-cased.
// `C9300-48P` → `C9300`; `AIR-CT5508` → `AIR`; `HP LaserJet M404` → `HP`.
func pidToken(model string) string {
	m := strings.ToUpper(strings.TrimSpace(model))
	if m == "" {
		return ""
	}
	idx := strings.IndexFunc(m, func(r rune) bool {
		return r == '-' || r == '_' || r == '/' || r == ' ' || r == '.'
	})
	if idx > 0 {
		m = m[:idx]
	}
	if len(m) > 16 {
		m = m[:16]
	}
	return m
}

// pidFamily strips the trailing digits from a product token, so one vendor's
// numbered product line is one feature: `C9300`, `C9200` and `C9500` all give
// `C`. Empty when the token is all digits, which is not a family.
func pidFamily(token string) string {
	end := len(token)
	for end > 0 && token[end-1] >= '0' && token[end-1] <= '9' {
		end--
	}
	return token[:end]
}

// bannerTokens are the product words of every `Server:` line in the banner map.
//
// Only the `Server:` lines. The banner contract on [classify.ClassifyInput]
// says a value is one line INCLUDING its header name, which is what makes this
// decidable at all — and the other banners are deliberately out: an SSH banner
// says the host runs sshd, which every class from `server` to `plc` does, and
// CLASSIFICATION_RULES.md's "what is deliberately not a rule" makes the same
// point about the same string.
//
// Version numbers are dropped. `nginx/1.24.0` and `nginx/1.27.1` are one
// product, and keeping the version would scatter one vendor across as many
// buckets as they have releases.
func bannerTokens(banners map[string]string) []string {
	if len(banners) == 0 {
		return nil
	}
	// Sorted keys: the map iteration order is random, and the token CAP below
	// would otherwise keep a different subset per call.
	keys := make([]string, 0, len(banners))
	for k := range banners {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	seen := map[string]bool{}
	var out []string
	for _, k := range keys {
		// ONE line, enforced rather than assumed. ClassifyInput.Banners' own
		// contract says a value is one line — and its doc says the contract
		// "fails silently if a producer gets it wrong", which for the rule
		// engine means a pattern that does not match. Here it meant something
		// worse: a producer that handed over a whole HTTP response had every
		// word of every later header turned into a feature AND into an
		// explanation a reviewer reads, so `Host: ceo-laptop.corp.example`
		// rendered as "the service banner said “laptop”". The header a token is
		// claimed to come from has to be the header it came from.
		line := strings.TrimSpace(firstLine(banners[k]))
		if !strings.HasPrefix(strings.ToLower(line), "server:") {
			continue
		}
		value := strings.TrimSpace(line[len("server:"):])
		for _, tok := range splitProductTokens(value) {
			if seen[tok] {
				continue
			}
			seen[tok] = true
			out = append(out, tok)
			if len(out) >= maxBannerTokens {
				return out
			}
		}
	}
	return out
}

// firstLine is everything before the first CR or LF.
func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// maxBannerTokens caps how much one banner may contribute. A `Server:` line is
// usually two words; the ones that are not are embedded web servers listing
// their whole module set, and letting one line set a third of the vector would
// make the model's answer depend on a device's verbosity.
const maxBannerTokens = 8

// bannerStopWords are tokens that carry no product identity.
//
// Only one, and it earns its place: `Server: HP HTTP Server` yields `server`
// from the VALUE, which is the header's own name said twice. Keeping it gives
// the model a feature meaning "this line came from a Server header", which
// every banner it reads already does — and gives a reviewer the explanation
// "the service banner said “server”", which is not a reason.
var bannerStopWords = map[string]bool{"server": true}

// maxProductTokenLen bounds ONE token. No product name is longer, and the token
// is echoed into a stored explanation — so an unbounded one would let a service
// that answered with a hundred characters of anything put them in front of a
// reviewer under the words "the service banner said".
const maxProductTokenLen = 32

func splitProductTokens(value string) []string {
	fields := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '+'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if len(f) < 2 || len(f) > maxProductTokenLen || allDigits(f) || bannerStopWords[f] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// maxCloudTokens caps a resource type's contribution for the same reason
// [maxBannerTokens] caps a banner's.
const maxCloudTokens = 6

// maxResourceTypeLen bounds a provider resource type. Every one in the shipped
// catalogue is under 36 characters; 64 is generous for a provider nobody has
// catalogued yet, which is the input this feature exists to recognise.
const maxResourceTypeLen = 64

// isResourceType reports whether ct is shaped like a provider RESOURCE TYPE
// rather than a resource identifier.
//
// A type is a short snake-cased name — `aws_s3_bucket`, `gcp_kms_crypto_key`.
// An ARN, a resource path or a self-link is not, and the separators are what
// tell them apart: `:` `/` `.` and whitespace appear in identifiers and in no
// type the catalogue names.
//
// The distinction matters because the field is filled from a finding's raw_data
// (`resource_type`, falling back to `cloud_resource_type`) with nothing in
// between holding a producer to it — and [cloudTokens] splits whatever arrives
// into words, each of which becomes a feature AND an explanation label. Given
// `aws_ec2_instance/ceo-laptop.finance.corp.example` that produced "the cloud
// resource type contains “laptop”", which is a hostname in front of a reviewer
// and in `asset_history`, from a package whose doc says it can never see one.
//
// Refusing outright rather than salvaging the leading words: a type this
// package cannot recognise is not evidence about a class, and half of one is
// worse than none.
func isResourceType(ct string) bool {
	if ct == "" || len(ct) > maxResourceTypeLen {
		return false
	}
	for _, r := range ct {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// cloudTokens splits a provider's resource type into its words, keeping the
// order and dropping duplicates. `aws_rds_instance` → aws, rds, instance.
func cloudTokens(resourceType string) []string {
	fields := strings.FieldsFunc(resourceType, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		// Bounded for the same reason a banner token is: it is echoed into a
		// stored explanation, and the resource type it came from is a provider
		// string nothing here validated.
		if len(f) < 2 || len(f) > maxProductTokenLen || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
		if len(out) >= maxCloudTokens {
			break
		}
	}
	return out
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// normaliseMDNS reduces a DNS-SD advertisement to its service type, the same
// trimming classify's matchMDNSServices applies, so a producer that kept the
// trailing root dot is read identically on both sides.
//
// Then it REFUSES anything that is not a service type. shared/hostobs' decoder
// only ever emits `_service._tcp` / `_service._udp` (`dnsServiceType`, which
// bounds it the same way), but that is not the only producer: inventory-service
// reads `mdns_services` — and, failing that, a bare `services` key — straight
// out of a finding's raw_data, where nothing holds a sensor to that shape. A
// DNS-SD *instance* name begins with the host's own label, so an unchecked
// string here is the one place a hostname could reach an explanation the
// package doc promises carries none.
//
// Refusing rather than trimming, because a label like "it advertises
// office-printer-3" is not evidence about a class in the first place.
func normaliseMDNS(s string) string {
	svc := strings.ToLower(strings.TrimSpace(s))
	svc = strings.TrimSuffix(svc, ".")
	svc = strings.TrimSuffix(svc, ".local")
	if !isServiceType(svc) {
		return ""
	}
	return svc
}

// maxServiceTypeLen matches hostobs.MaxIdentifierLen's role for the same string.
const maxServiceTypeLen = 64

// isServiceType reports whether s is exactly `_service._tcp` or `_service._udp`.
func isServiceType(s string) bool {
	if len(s) > maxServiceTypeLen {
		return false
	}
	base, ok := strings.CutSuffix(s, "._tcp")
	if !ok {
		if base, ok = strings.CutSuffix(s, "._udp"); !ok {
			return false
		}
	}
	if len(base) < 2 || base[0] != '_' || strings.Contains(base, ".") {
		return false
	}
	for _, r := range base[1:] {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// ── Vocabularies derived from the compiled-in rule table ───────────────────

var (
	derivedOnce    sync.Once
	derivedOUI     map[string]string
	derivedClasses []string
	derivedTargets []string
)

func deriveFromRules() {
	derivedOnce.Do(func() {
		derivedOUI = map[string]string{}
		classSet := map[string]bool{}
		for _, r := range classify.Default().Rules() {
			if r.Kind == classify.KindOUI && r.Vendor != "" {
				derivedOUI[r.Pattern] = r.Vendor
			}
			if r.Class != "" {
				classSet[r.Class] = true
			}
		}
		for c := range classSet {
			derivedClasses = append(derivedClasses, c)
			if isTargetClass(c) {
				derivedTargets = append(derivedTargets, c)
			}
		}
		sort.Strings(derivedClasses)
		sort.Strings(derivedTargets)
	})
}

// isTargetClass reports whether a class may be a model TARGET.
//
// Three exclusions, and each is the same rule from a different angle:
//
//  1. `unknown_host` and `external` are not answers. "Unknown" is what the
//     chain returns when nothing clears the floor, and a model that could
//     PROPOSE unknown would be proposing to change nothing.
//  2. A class with children is a GROUP — `network_device`, `ot_device`. The
//     rules already reach those from an OUI; the model exists to say the
//     specific thing the rules could not, and proposing `network_device` to a
//     reviewer who is looking at an unclassified host adds a word, not an
//     answer.
//  3. A top-level class is the coarsest group of all.
func isTargetClass(key string) bool {
	switch key {
	case assetclass.KeyUnknownHost, assetclass.KeyExternal:
		return false
	}
	c, ok := assetclass.Get(key)
	if !ok || c.Parent == "" {
		return false
	}
	return len(assetclass.Children(key)) == 0
}

// ouiTable is the compiled-in OUI-to-vendor map.
func ouiTable() map[string]string {
	deriveFromRules()
	return derivedOUI
}

// RuleClassVocabulary is every class the compiled-in rules can name, sorted. It
// is the domain of the [NamespaceRuleTop] and [NamespaceRuleTied] features.
func RuleClassVocabulary() []string {
	deriveFromRules()
	return append([]string(nil), derivedClasses...)
}

// TargetClasses is what the model may propose, sorted — the leaf classes of the
// compiled-in rule vocabulary. See [isTargetClass] for the three exclusions.
func TargetClasses() []string {
	deriveFromRules()
	return append([]string(nil), derivedTargets...)
}

// FeatureNames is the whole feature space, sorted. It is the SCHEMA the weights
// file is validated against: a weight naming a feature outside this list is a
// file from a build whose features differ, and a namespace missing from a
// trained file is a namespace that was never trained.
func FeatureNames() []string {
	deriveFromRules()
	out := []string{FeatureBias, FeatureOUIUnknown, FeatureRuleConfidence, FeatureRuleConflict, FeatureRuleSilent}
	add := func(namespace string, width int) {
		for i := range width {
			out = append(out, namespace+"/"+strconv.Itoa(i))
		}
	}
	add(NamespaceOUI, OUIBuckets)
	add(NamespaceSysOID, SysOIDBuckets)
	add(NamespaceSysOIDSub, SysOIDSubBuckets)
	add(NamespacePID, PIDBuckets)
	add(NamespacePIDToken, PIDTokenBuckets)
	add(NamespaceBanner, BannerBuckets)
	add(NamespaceMDNS, MDNSBuckets)
	add(NamespaceCloud, CloudBuckets)
	for _, p := range WellKnownPorts {
		out = append(out, NamespacePort+"/"+strconv.Itoa(p))
	}
	for _, c := range lldpCapabilities {
		out = append(out, NamespaceLLDP+"/"+c)
	}
	for _, c := range cdpCapabilities {
		out = append(out, NamespaceCDP+"/"+c)
	}
	for _, c := range derivedClasses {
		out = append(out, NamespaceRuleTop+"/"+c, NamespaceRuleTied+"/"+c)
	}
	sort.Strings(out)
	return out
}
