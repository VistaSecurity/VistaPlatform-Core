package matcher

import (
	"math"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
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

	// Identifiers is kind → value, with every value already normalised by the
	// identification engine.
	Identifiers map[string]string

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
// value is twenty numbers.
func Features(p Pair) Vector {
	v := Vector{FeatureBias: 1}

	// ── identifiers ────────────────────────────────────────────────────────
	matched := 0
	for _, kind := range allKinds {
		a, okA := lookup(p.Observation.Identifiers, kind)
		b, okB := lookup(p.Candidate.Identifiers, kind)
		if !okA || !okB {
			continue
		}
		if a == b {
			matched++
			switch {
			case IsSingleton(kind):
				v[FeatureIDMatchSingleton] = 1
			case strongKinds[kind]:
				v[FeatureIDMatchStrong] = 1
			case weakKinds[kind]:
				v[FeatureIDMatchWeak] = 1
			}
			continue
		}
		// Values differ. Only a SINGLETON disagreement is evidence of two
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

	// ── names ──────────────────────────────────────────────────────────────
	similarity, sequential := nameSignals(p.Observation, p.Candidate)
	v[FeatureNameSimilarity] = similarity
	if sequential {
		v[FeatureNameTrailingDigitsDiffer] = 1
	}

	// ── vendor and model ───────────────────────────────────────────────────
	setAgreement(v, FeatureVendorMatch, FeatureVendorConflict, p.Observation.Vendor, p.Candidate.Vendor)
	setAgreement(v, FeatureModelMatch, FeatureModelConflict, p.Observation.Model, p.Candidate.Model)

	// ── class ──────────────────────────────────────────────────────────────
	oc, cc := strings.TrimSpace(p.Observation.Class), strings.TrimSpace(p.Candidate.Class)
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
	setAgreement(v, FeatureSegmentMatch, FeatureSegmentConflict, p.Observation.Segment, p.Candidate.Segment)

	// ── time ───────────────────────────────────────────────────────────────
	if !p.Observation.SeenAt.IsZero() && !p.Candidate.SeenAt.IsZero() {
		days := math.Abs(p.Observation.SeenAt.Sub(p.Candidate.SeenAt).Hours()) / 24
		v[FeatureRecency] = math.Exp(-days / recencyHalfLife)
	}

	// ── provenance ─────────────────────────────────────────────────────────
	setAgreement(v, FeatureSourceSame, FeatureSourceCross, p.Observation.SourceKind, p.Candidate.SourceKind)

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

// lookup reads an identifier value, treating an empty string as absent.
func lookup(ids map[string]string, kind string) (string, bool) {
	v, ok := ids[kind]
	v = strings.TrimSpace(v)
	return v, ok && v != ""
}

// nameCandidates is every string on one side that is a name: its own, plus the
// values of its name-like identifiers.
//
// All of them, rather than "the best one", because the two sides disagree about
// which they carry far more often than they disagree about the name itself. A
// cloud collector supplies a display name and no hostname; a sensor supplies an
// FQDN and no display name. Picking one per side and comparing those two
// compares a display name against an FQDN and scores a perfect match low.
func nameCandidates(s Side) []string {
	out := make([]string, 0, 1+len(nameLikeKinds))
	if n := strings.TrimSpace(s.Name); n != "" {
		out = append(out, n)
	}
	for _, kind := range nameLikeKinds {
		if v, ok := lookup(s.Identifiers, kind); ok {
			out = append(out, v)
		}
	}
	return out
}

// nameSignals returns the best name similarity across the two sides' name
// candidates, and whether THAT pair is two sequentially-numbered names.
//
// The sequential check reads the best-matching pair specifically. Checking
// every pair would fire on any coincidental `…01`/`…02` among unrelated names,
// and checking a fixed pair would miss the case entirely when the two sides
// spell their names differently — which is the case it exists for.
func nameSignals(obs, cand Side) (similarity float64, sequential bool) {
	as, bs := nameCandidates(obs), nameCandidates(cand)
	var bestA, bestB string
	for _, a := range as {
		for _, b := range bs {
			if s := NameSimilarity(a, b); s > similarity {
				similarity, bestA, bestB = s, a, b
			}
		}
	}
	if similarity == 0 {
		return 0, false
	}
	return similarity, sequentialNames(bestA, bestB)
}
