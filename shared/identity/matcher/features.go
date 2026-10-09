package matcher

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
	"github.com/vistasecurity/vistaplatform/shared/ouiregistry"
)

// Side is one half of a comparison: an observation, or an existing asset.
//
// It is deliberately the SAME type for both. Everything the model looks at is a
// comparison of two like things, so a struct per side would be two struct
// definitions that must agree, and the pairwise extractor below would have to
// know which was which — which is exactly the asymmetry that makes a matcher
// score A-against-B differently from B-against-A for no stated reason.
//
// Nothing here is key material or raw metadata. Identifier VALUES are present
// so the extractor can compare them; they are never emitted in an explanation
// and never leave this package.
type Side struct {
	// Name is what a person calls this thing: the display name, else the
	// hostname. Compared for similarity, never for identity.
	Name string

	// Class is the asset class key (`server`, `network_device`, …). Empty when
	// the intake path had no opinion, which is not the same as a class that
	// disagrees — see [FeatureClassConflict].
	Class string

	// Identifiers is kind → values, with every value already normalised by the
	// identification engine.
	//
	// Several values per kind, because that is what an asset HAS: a machine
	// with two NICs has two MACs, a dual-stacked host two addresses, a record
	// seen under a short name and an mDNS name two hostnames. v1 carried one
	// value per kind, and the engine's conversion kept whichever it saw last —
	// so a candidate whose SECOND MAC was the one the observation carried
	// scored as though the MACs disagreed. A kind now counts as matched when
	// ANY value agrees ( Phase 5).
	Identifiers map[string][]string

	// Derived is the subset of Identifiers that was WORKED OUT from other
	// evidence rather than observed ( Phase 2: a MAC recovered from an
	// EUI-64 address or a serial). A kind whose only agreement runs through a
	// derived value sets [FeatureIDMatchDerived] as well as its strength
	// feature, so the model can discount an inference against an observation.
	Derived map[string][]string

	// GenericNames are names this side's intake judged GENERIC — carried by
	// many unrelated devices ( B2) — beyond what the built-in dictionary
	// already knows ([hostnamequality.IsGeneric]). The tenant-frequency half of
	// that rule needs a database, so the engine passes its verdict in rather
	// than this package guessing. A generic hostname never counts as an
	// identifier agreement, and a name similarity resting on one sets
	// [FeatureNameGeneric].
	GenericNames []string

	// Segment is the network segment (scope) this side belongs to, empty when
	// unknown.
	Segment string

	// Vendor and Model are the two class attributes worth comparing across a
	// pair: they are stable properties of the physical thing, so a
	// disagreement is real evidence of two things and an agreement is weak
	// evidence of one (a rack of identical switches agrees on both).
	Vendor string
	Model  string

	// SourceKind is the ADR-0005 provenance vocabulary — measured, imported,
	// declared, inferred. For a candidate it is the kind that supplied its
	// identifiers.
	SourceKind string

	// SeenAt is when this side was last seen. Zero means unknown, which is not
	// "seen at the epoch": [FeatureRecency] reads 0 for an unknown side rather
	// than a very large gap, because "we do not know" and "last seen in 1970"
	// are different facts and only one of them is evidence.
	SeenAt time.Time

	// Status is the asset status of an existing asset (`monitoring`,
	// `pending_approval`, …), empty for an observation. The MODEL does not read
	// it — an asset's place in the approval queue says nothing about whether it
	// is the same physical thing — but the engine's auto-accept guard does, so
	// it travels with the side rather than being fetched again.
	Status string
}

// Pair is one comparison: this observation against this candidate asset.
type Pair struct {
	Observation Side
	Candidate   Side
}

// The feature names, which are also the keys of the weights file and the
// machine-readable half of an explanation. They are stable: renaming one
// invalidates every trained weights file, so [Model.Validate] refuses a model
// whose names do not match this list exactly.
const (
	// FeatureBias is the intercept — the log-odds of a match before any
	// evidence. Trained, not fixed: on a conflict-path population most pairs
	// are NOT matches, and pretending otherwise would make the model
	// over-confident on thin evidence.
	FeatureBias = "bias"

	// FeatureIDMatchSingleton — the two sides agree on a kind an asset holds at
	// most one of (agent_id, cloud_resource_id, serial_number, cmdb_sys_id).
	// The strongest single piece of evidence there is.
	FeatureIDMatchSingleton = "id_match_singleton"
	// FeatureIDConflictSingleton — both sides carry the same singleton KIND
	// with DIFFERENT values. Two ARNs are two resources. The model learns a
	// large negative weight for it, and [Model.Score] additionally CAPS the
	// score, because ADR-0002 D3's singleton erratum says no score may override
	// a singleton disagreement.
	FeatureIDConflictSingleton = "id_conflict_singleton"
	// FeatureIDMatchStrong — agreement on a tenant-unique non-singleton kind
	// (ssh_host_key_fingerprint, mac_address, fqdn).
	FeatureIDMatchStrong = "id_match_strong"
	// FeatureIDMatchWeak — agreement on a scope-local kind (hostname,
	// ip_address, name). On its own this is what a DHCP lease looks like.
	FeatureIDMatchWeak = "id_match_weak"
	// FeatureIDMatchBreadth — how MANY kinds agree, capped at four and scaled
	// to 0..1. Breadth is separate from strength: one serial is strong and
	// narrow; a MAC, an FQDN and a hostname all agreeing is broad corroboration
	// from several angles.
	FeatureIDMatchBreadth = "id_match_breadth"

	// FeatureNameSimilarity — the larger of token Jaccard and Jaro-Winkler over
	// the two sides' names, including their name-like identifiers, 0..1.
	FeatureNameSimilarity = "name_similarity"
	// FeatureNameTrailingDigitsDiffer — the names differ ONLY in a trailing
	// number (`web01` / `web02`). The single commonest false positive an
	// inventory produces, and invisible to every string-similarity measure.
	FeatureNameTrailingDigitsDiffer = "name_sequential"

	// FeatureVendorMatch / FeatureVendorConflict — both known and equal, both
	// known and different. Absent-on-either-side is NEITHER, so an unknown
	// vendor contributes nothing rather than reading as agreement.
	FeatureVendorMatch    = "vendor_match"
	FeatureVendorConflict = "vendor_conflict"
	// FeatureModelMatch / FeatureModelConflict — the same, for the hardware
	// model.
	FeatureModelMatch    = "model_match"
	FeatureModelConflict = "model_conflict"

	// FeatureClassEqual — the same class key.
	FeatureClassEqual = "class_equal"
	// FeatureClassRelated — one class is an ancestor of the other. A `server`
	// observation landing on a `computer` asset is a refinement, not a
	// disagreement.
	FeatureClassRelated = "class_related"
	// FeatureClassConflict — both classes known, neither an ancestor of the
	// other. A printer is not a firewall.
	FeatureClassConflict = "class_conflict"

	// FeatureSegmentMatch / FeatureSegmentConflict — same network segment, or
	// two different known ones. A hostname agreeing ACROSS segments is the
	// second commonest false positive: every segment has a `db01`.
	FeatureSegmentMatch    = "segment_match"
	FeatureSegmentConflict = "segment_conflict"

	// FeatureRecency — how close in time the two sightings are, as
	// exp(-days/30): 1.0 for the same moment, ~0.37 a month apart, ~0 a year
	// apart. Zero when either side's time is unknown.
	FeatureRecency = "recency"

	// FeatureSourceSame / FeatureSourceCross — the two sides came from the same
	// provenance kind, or from two different ones. Both are features rather
	// than one signed value because they mean different things and the SIGN is
	// the model's to learn: corroboration from two independent sources is the
	// textbook positive, while one collector emitting two rows for one thing is
	// the textbook duplicate.
	FeatureSourceSame  = "source_same"
	FeatureSourceCross = "source_cross"

	// ── v2 ( Phase 5) ────────────────────────────────────────────────
	//
	// Each states its EXPECTED sign, which TestTrainedWeightSigns and
	// TestAgreeingIsNeverWorseEvidenceThanDisagreeing hold the trained weights
	// to. A retrain that flipped one would keep its accuracy and quietly stop
	// meaning what the label says.

	// FeatureVendorOUIMatch / FeatureVendorOUIConflict — the manufacturer
	// behind each side's MAC addresses (the IEEE OUI, [ouiregistry.VendorForMAC]),
	// falling back to the side's `vendor` attribute when none of its MACs has a
	// registered prefix. Match when the two sides share a vendor, conflict when
	// both are known and share none. Expected: NO SIGN — like vendor_match, a
	// rack of identical hardware agrees on its NIC vendor — but the ORDERING
	// conflict ≤ match holds. Weaker than the attribute pair by construction: a
	// laptop with a USB dongle has two NIC vendors, and a randomised phone MAC
	// has none.
	FeatureVendorOUIMatch    = "vendor_oui_match"
	FeatureVendorOUIConflict = "vendor_oui_conflict"

	// FeatureNameGeneric — every best-matching name pair involves a GENERIC
	// name (`iphone`, `printer`, or one the tenant sees on three or more
	// assets). The name similarity it rides on is then a coincidence of
	// factory defaults, not evidence. Expected sign: ≤ 0.
	FeatureNameGeneric = "name_generic"

	// FeatureNameSynthetic — every best-matching name pair involves a
	// SYNTHETIC name ([hostnamequality.IsIdentityName] false: a UUID-form
	// service instance, an address written as a name, `none-N`). Two records
	// both called `192-0-2-5.local` share a lease, not an identity. Expected
	// sign: ≤ 0.
	FeatureNameSynthetic = "name_synthetic"

	// FeatureIDMatchDerived — a kind agreed ONLY through a value one side
	// derived rather than observed ( Phase 2). It rides alongside the
	// kind's strength feature as a discount: a derivation is an inference, and
	// never better evidence than seeing the value. Expected sign: ≤ 0, and
	// id_match_strong + id_match_derived ≥ 0 — a derived MAC still VOTES
	// (owner decision D3), so the discount may not turn it into evidence of
	// two things.
	FeatureIDMatchDerived = "id_match_derived"

	// FeatureBindingConflict — the two sides share an address but not a MAC:
	// both carry hardware addresses, none in common, and an ip_address agrees.
	// That is the MAC↔IP binding of one side contradicting the other's — the
	// lease moved to a different NIC, which is the shape of the wrong merge
	// the address-only link rule ( C1) exists to refuse. Expected sign:
	// ≤ 0.
	FeatureBindingConflict = "binding_conflict"
)

// featureNames is the vector's order. The weights file is keyed by name rather
// than positional, so inserting a feature does not silently re-map an existing
// trained weight onto a different feature — but the ORDER still matters for
// reproducible training and for [Vector], so it is stated once here.
var featureNames = []string{
	FeatureBias,
	FeatureIDMatchSingleton,
	FeatureIDConflictSingleton,
	FeatureIDMatchStrong,
	FeatureIDMatchWeak,
	FeatureIDMatchBreadth,
	FeatureNameSimilarity,
	FeatureNameTrailingDigitsDiffer,
	FeatureVendorMatch,
	FeatureVendorConflict,
	FeatureModelMatch,
	FeatureModelConflict,
	FeatureClassEqual,
	FeatureClassRelated,
	FeatureClassConflict,
	FeatureSegmentMatch,
	FeatureSegmentConflict,
	FeatureRecency,
	FeatureSourceSame,
	FeatureSourceCross,
	// v2, appended so every v1 feature keeps its position.
	FeatureVendorOUIMatch,
	FeatureVendorOUIConflict,
	FeatureNameGeneric,
	FeatureNameSynthetic,
	FeatureIDMatchDerived,
	FeatureBindingConflict,
}

// FeatureNames returns the feature vector's names, in order.
func FeatureNames() []string {
	out := make([]string, len(featureNames))
	copy(out, featureNames)
	return out
}

// FeatureCount is how many features the model reads.
func FeatureCount() int { return len(featureNames) }

// Vector is one extracted feature vector, keyed by name.
type Vector map[string]float64

// At returns the value of one feature, 0 for a name the vector does not carry.
func (v Vector) At(name string) float64 { return v[name] }

// Slice returns the vector in [FeatureNames] order.
func (v Vector) Slice() []float64 {
	out := make([]float64, len(featureNames))
	for i, n := range featureNames {
		out[i] = v[n]
	}
	return out
}

// recencyHalfLife is the exponential decay constant of [FeatureRecency], in
// days. Thirty is a collector's monthly cycle: two sightings within a normal
// polling window score near 1, and two a quarter apart score near 0.
const recencyHalfLife = 30.0

// Features extracts the model's whole view of a pair.
//
// It is the allowlist: nothing reaches the model that is not computed here, and
// every value is a COMPARISON rather than a value carried over from either
// side. That is what makes "the model never sees key material or raw metadata"
// a structural property rather than a promise — there is no path from a Pair
// into the model except through this function's return value, and its return
// value is [FeatureCount] numbers.
//
// Every feature is symmetric: swapping the two sides gives the same vector
// (TestSymmetry). "Is this the same thing as that" does not depend on which was
// named first.
func Features(p Pair) Vector {
	v := Vector{FeatureBias: 1}
	obs, cand := p.Observation, p.Candidate
	generic := genericSet(obs, cand)

	// ── identifiers ────────────────────────────────────────────────────────
	matched := 0
	for _, kind := range allKinds {
		a := identityValues(obs, kind, generic)
		b := identityValues(cand, kind, generic)
		if len(a) == 0 || len(b) == 0 {
			continue
		}
		agreeing := intersect(a, b)
		if len(agreeing) > 0 {
			matched++
			switch {
			case IsSingleton(kind):
				v[FeatureIDMatchSingleton] = 1
			case strongKinds[kind]:
				v[FeatureIDMatchStrong] = 1
			case weakKinds[kind]:
				v[FeatureIDMatchWeak] = 1
			}
			if derivedOnly(obs, cand, kind, agreeing) {
				v[FeatureIDMatchDerived] = 1
			}
			continue
		}
		// No value agrees. Only a SINGLETON disagreement is evidence of two
		// things: a machine legitimately has several MACs, several addresses
		// and several names, so holding two of those says nothing.
		if IsSingleton(kind) {
			v[FeatureIDConflictSingleton] = 1
		}
	}
	if matched > 4 {
		matched = 4
	}
	v[FeatureIDMatchBreadth] = float64(matched) / 4

	// ── the MAC↔IP binding ─────────────────────────────────────────────────
	if bindingConflict(obs, cand) {
		v[FeatureBindingConflict] = 1
	}

	// ── names ──────────────────────────────────────────────────────────────
	names := nameSignals(obs, cand, generic)
	v[FeatureNameSimilarity] = names.similarity
	if names.sequential {
		v[FeatureNameTrailingDigitsDiffer] = 1
	}
	if names.generic {
		v[FeatureNameGeneric] = 1
	}
	if names.synthetic {
		v[FeatureNameSynthetic] = 1
	}

	// ── vendor and model ───────────────────────────────────────────────────
	setAgreement(v, FeatureVendorMatch, FeatureVendorConflict, obs.Vendor, cand.Vendor)
	setAgreement(v, FeatureModelMatch, FeatureModelConflict, obs.Model, cand.Model)
	setSetAgreement(v, FeatureVendorOUIMatch, FeatureVendorOUIConflict, hardwareVendors(obs), hardwareVendors(cand))

	// ── class ──────────────────────────────────────────────────────────────
	oc, cc := strings.TrimSpace(obs.Class), strings.TrimSpace(cand.Class)
	switch {
	case oc == "" || cc == "":
		// One side has no opinion. Nothing set: an absent class is not
		// agreement and it is not disagreement.
	case oc == cc:
		v[FeatureClassEqual] = 1
	case assetclass.IsAncestor(oc, cc) || assetclass.IsAncestor(cc, oc):
		v[FeatureClassRelated] = 1
	default:
		v[FeatureClassConflict] = 1
	}

	// ── segment ────────────────────────────────────────────────────────────
	setAgreement(v, FeatureSegmentMatch, FeatureSegmentConflict, obs.Segment, cand.Segment)

	// ── time ───────────────────────────────────────────────────────────────
	if !obs.SeenAt.IsZero() && !cand.SeenAt.IsZero() {
		days := math.Abs(obs.SeenAt.Sub(cand.SeenAt).Hours()) / 24
		v[FeatureRecency] = math.Exp(-days / recencyHalfLife)
	}

	// ── provenance ─────────────────────────────────────────────────────────
	setAgreement(v, FeatureSourceSame, FeatureSourceCross, obs.SourceKind, cand.SourceKind)

	return v
}

// setAgreement writes the match/conflict pair for one comparable attribute.
// Both empty or either empty sets NEITHER: an unknown value is not agreement,
// which is the "not assessed stays not assessed" rule of ADR-0008 D4.3 applied
// to a feature.
func setAgreement(v Vector, matchName, conflictName, a, b string) {
	a, b = strings.ToLower(strings.TrimSpace(a)), strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" {
		return
	}
	if a == b {
		v[matchName] = 1
		return
	}
	v[conflictName] = 1
}

// setSetAgreement is [setAgreement] over two SETS of values: agreement when they
// share one, conflict when both are known and share none, neither when either
// is empty.
func setSetAgreement(v Vector, matchName, conflictName string, a, b []string) {
	if len(a) == 0 || len(b) == 0 {
		return
	}
	if len(intersect(a, b)) > 0 {
		v[matchName] = 1
		return
	}
	v[conflictName] = 1
}

// values reads one kind's values: trimmed, empties dropped, deduplicated and
// SORTED. Sorted because the name comparison walks them in order, and an order
// that followed however the caller built its slice would let the same pair
// score differently on two runs.
func values(ids map[string][]string, kind string) []string {
	raw := ids[kind]
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// identityValues is [values] minus the values that are recorded but prove
// nothing about WHICH device this is: a generic hostname ( B2 — the engine
// never lets one decide, link or corroborate, and the model does not either),
// and a synthetic hostname or FQDN ([hostnamequality.IsIdentityName]: ingest no
// longer mints those as identifiers, but records written before it still carry
// them).
func identityValues(s Side, kind string, generic map[string]bool) []string {
	vs := values(s.Identifiers, kind)
	if kind != KindHostname && kind != KindFQDN {
		return vs
	}
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if kind == KindHostname && isGenericName(v, generic) {
			continue
		}
		if !hostnamequality.IsIdentityName(v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

// intersect returns the values of b also present in a, compared
// case-insensitively (the engine has normalised identifier values already; a
// vendor name has not been).
func intersect(a, b []string) []string {
	in := make(map[string]bool, len(a))
	for _, x := range a {
		in[strings.ToLower(x)] = true
	}
	var out []string
	for _, y := range b {
		if in[strings.ToLower(y)] {
			out = append(out, y)
		}
	}
	return out
}

// derivedOnly reports that every agreeing value of a kind is DERIVED on at
// least one of the two sides — the kind agreed, but only through an inference.
// One agreeing value observed on both sides is an observed match, and the
// discount does not apply.
func derivedOnly(a, b Side, kind string, agreeing []string) bool {
	da, db := lowerSet(a.Derived[kind]), lowerSet(b.Derived[kind])
	for _, v := range agreeing {
		k := strings.ToLower(strings.TrimSpace(v))
		if !da[k] && !db[k] {
			return false
		}
	}
	return true
}

func lowerSet(vs []string) map[string]bool {
	out := make(map[string]bool, len(vs))
	for _, v := range vs {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out[v] = true
		}
	}
	return out
}

// bindingConflict reports that the two sides share an address and not a NIC:
// both carry MAC addresses, none of them in common, and an ip_address agrees.
//
// Derived MACs count as MACs here: a MAC recovered from an EUI-64 address is a
// statement about which interface built that address, which is exactly the
// binding being compared. Symmetric by construction.
//
// It is the pair-level shadow of the engine's address-only link rule (
// C1): the engine refuses to link on such a lease; the model learns what the
// address agreeing is worth in this shape.
//
// The candidate side is a whole asset, not one interface: the model cannot see
// WHICH of the candidate's MACs held the address, only that none of them is the
// observation's. A machine with a second NIC nobody has recorded yet produces
// the same shape — which is why this is a feature with a learned weight and
// not a rule.
func bindingConflict(a, b Side) bool {
	ma, mb := values(a.Identifiers, KindMACAddress), values(b.Identifiers, KindMACAddress)
	if len(ma) == 0 || len(mb) == 0 || len(intersect(ma, mb)) > 0 {
		return false
	}
	return len(intersect(values(a.Identifiers, KindIPAddress), values(b.Identifiers, KindIPAddress))) > 0
}

// hardwareVendors is the set of manufacturers a side's MAC addresses are
// registered to, as vendor keys ([vendorKey]); when none of its MACs has a
// registered prefix — a randomised or locally administered address, or no MAC
// at all — it falls back to the side's `vendor` attribute. Empty means not
// known, and sets neither feature.
func hardwareVendors(s Side) []string {
	var out []string
	seen := map[string]bool{}
	for _, mac := range values(s.Identifiers, KindMACAddress) {
		if k := vendorKey(ouiregistry.VendorForMAC(mac)); k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		if k := vendorKey(s.Vendor); k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// vendorKey reduces a manufacturer name to the one token two spellings of it
// share: its first word, lower-cased, letters and digits only. The OUI table
// says `Dell` where an attribute says `Dell Inc.`, and `TP-Link Technologies`
// where another source says `TP-LINK`; comparing whole strings would turn every
// such pair into a vendor CONFLICT — evidence of two things the data does not
// contain. The cost runs the other way (two vendors sharing a first word
// agree), and that is the cheaper error: agreement on vendor is weak evidence
// either way.
func vendorKey(vendor string) string {
	for _, field := range strings.Fields(strings.ToLower(vendor)) {
		var b strings.Builder
		for _, r := range field {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				b.WriteRune(r)
			}
		}
		if b.Len() > 0 {
			return b.String()
		}
	}
	return ""
}

// genericSet is the union of both sides' GenericNames, normalised. A name one
// intake judged generic is generic on the other side too: the verdict is about
// the VALUE (many devices announce it), not about which record carries it.
func genericSet(a, b Side) map[string]bool {
	out := map[string]bool{}
	for _, s := range []Side{a, b} {
		for _, n := range s.GenericNames {
			if n = normaliseName(n); n != "" {
				out[n] = true
			}
		}
	}
	return out
}

func isGenericName(name string, generic map[string]bool) bool {
	return generic[normaliseName(name)] || hostnamequality.IsGeneric(name)
}

// nameCandidates is every string on one side that is a name: its own, plus the
// values of its name-like identifiers.
//
// All of them, rather than "the best one", because the two sides disagree about
// which they carry far more often than they disagree about the name itself. A
// cloud collector supplies a display name and no hostname; a sensor supplies an
// FQDN and no display name. Picking one per side and comparing those two
// compares a display name against an FQDN and scores a perfect match low.
//
// Generic and synthetic names are INCLUDED: they are names, and the similarity
// they produce is real. [FeatureNameGeneric] and [FeatureNameSynthetic] are how
// the model learns what that similarity is worth.
func nameCandidates(s Side) []string {
	out := make([]string, 0, 1+len(nameLikeKinds))
	if n := strings.TrimSpace(s.Name); n != "" {
		out = append(out, n)
	}
	for _, kind := range nameLikeKinds {
		out = append(out, values(s.Identifiers, kind)...)
	}
	return out
}

// nameResult is what the name comparison measured.
type nameResult struct {
	similarity float64
	sequential bool
	generic    bool
	synthetic  bool
}

// nameSignals returns the best name similarity across the two sides' name
// candidates, and three properties of the BEST-MATCHING pairs.
//
// Each property holds only when it holds for EVERY pair that reaches the best
// similarity. Two reasons. It is symmetric — which of several equally good
// pairs a loop meets first depends on which side is named first, and a feature
// that flipped with the order would score A-against-B differently from
// B-against-A. And it is the honest reading: if any equally strong pair is an
// ordinary, real name, the similarity is not resting on a default or a lease.
//
// The properties read the best pairs specifically. Checking every pair would
// fire on any coincidental `…01`/`…02` among unrelated names, and checking a
// fixed pair would miss the case entirely when the two sides spell their names
// differently — which is the case they exist for.
func nameSignals(obs, cand Side, generic map[string]bool) nameResult {
	as, bs := nameCandidates(obs), nameCandidates(cand)
	type namePair struct{ a, b string }
	var (
		r    nameResult
		best []namePair
	)
	for _, a := range as {
		for _, b := range bs {
			s := NameSimilarity(a, b)
			switch {
			case s > r.similarity:
				r.similarity, best = s, []namePair{{a, b}}
			case s == r.similarity && s > 0:
				best = append(best, namePair{a, b})
			}
		}
	}
	if r.similarity == 0 {
		return nameResult{}
	}
	r.sequential, r.generic, r.synthetic = true, true, true
	for _, p := range best {
		if !sequentialNames(p.a, p.b) {
			r.sequential = false
		}
		if !isGenericName(p.a, generic) && !isGenericName(p.b, generic) {
			r.generic = false
		}
		if hostnamequality.IsIdentityName(p.a) && hostnamequality.IsIdentityName(p.b) {
			r.synthetic = false
		}
	}
	return r
}
