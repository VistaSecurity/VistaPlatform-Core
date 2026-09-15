package relationships_test

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

// The vocabulary is the ADR-0003 D2 table, spelled out here so that changing it
// is a deliberate edit in two places rather than a quiet widening in one.
func TestVocabularyMatchesTheADRTable(t *testing.T) {
	want := []struct {
		canonical string
		reverse   string
	}{
		{"runs_on", "runs"},
		{"hosted_on", "hosts"},
		{"virtualized_by", "virtualizes"},
		{"depends_on", "used_by"},
		{"connects_to", "connected_from"},
		{"member_of", "members"},
		{"contains", "contained_by"},
		{"manages", "managed_by"},
		{"sends_data_to", "receives_data_from"},
		{"impacts", "impacted_by"},
	}

	all := relationships.All()
	if len(all) != len(want) {
		t.Fatalf("vocabulary has %d types, the ADR-0003 D2 table has %d: %v", len(all), len(want), all)
	}
	for i, expected := range want {
		if string(all[i]) != expected.canonical {
			t.Errorf("type %d is %q, the table says %q (order is the table's order)", i, all[i], expected.canonical)
		}
		if all[i].Reverse() != expected.reverse {
			t.Errorf("%q reverses to %q, the table says %q", all[i], all[i].Reverse(), expected.reverse)
		}
		if !all[i].Valid() {
			t.Errorf("%q does not validate", all[i])
		}
	}
}

func TestValid_RejectsAnythingElse(t *testing.T) {
	for _, invented := range []string{
		"", "uplinks_to", "RUNS_ON", "runs-on", "connected_from", "members",
	} {
		if relationships.Type(invented).Valid() {
			t.Errorf("%q validated; only the ten canonical types may", invented)
		}
		if label := relationships.Type(invented).Reverse(); label != "" {
			t.Errorf("%q has reverse label %q; an unknown type has none", invented, label)
		}
	}
	// A reverse LABEL is not a type: storing an edge in the reverse direction
	// is the asymmetry the model exists to prevent.
	if relationships.Type("connected_from").Valid() {
		t.Error("a reverse label validated as a type")
	}
}

// A collector may not claim to have measured a business consequence or a
// declared data flow.
func TestMeasurable_ExcludesTheDeclaredAndDerivedTypes(t *testing.T) {
	if relationships.Impacts.Measurable() {
		t.Error("impacts is derived by traversal or declared by a user (ADR-0003 D5); no collector measures one")
	}
	if relationships.SendsDataTo.Measurable() {
		t.Error("sends_data_to is a declared data flow")
	}
	for _, measurable := range []relationships.Type{
		relationships.RunsOn, relationships.HostedOn, relationships.VirtualizedBy,
		relationships.DependsOn, relationships.ConnectsTo, relationships.MemberOf,
		relationships.Contains, relationships.Manages,
	} {
		if !measurable.Measurable() {
			t.Errorf("%q is measurable by some collector (ADR-0004 D1) but was rejected", measurable)
		}
	}
	if relationships.Type("uplinks_to").Measurable() {
		t.Error("an unknown type is not measurable")
	}
}

func TestStrings_IsASortedCopy(t *testing.T) {
	got := relationships.Strings()
	if len(got) != len(relationships.All()) {
		t.Fatalf("Strings() has %d entries, All() has %d", len(got), len(relationships.All()))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("Strings() is not sorted: %q before %q", got[i-1], got[i])
		}
	}
	got[0] = "mutated"
	if relationships.Strings()[0] == "mutated" {
		t.Error("Strings() handed out the package's own slice")
	}
	all := relationships.All()
	all[0] = relationships.Type("mutated")
	if relationships.All()[0] == relationships.Type("mutated") {
		t.Error("All() handed out the package's own slice")
	}
}

// The impact direction map (ADR-0003 D5 as amended, spelled out
// here rather than derived, so flipping one is a deliberate edit in two places.
//
// The two FORWARD types are the whole reason this table exists: the original D5
// walked every type in reverse, which inverted them and made "what breaks if
// this controller dies" answer nothing.
func TestImpactDirection_IsPerTypeAndMatchesTheAmendedADR(t *testing.T) {
	want := map[string]relationships.ImpactDirection{
		"runs_on":        relationships.ImpactReverse,
		"hosted_on":      relationships.ImpactReverse,
		"virtualized_by": relationships.ImpactReverse,
		"depends_on":     relationships.ImpactReverse,
		"member_of":      relationships.ImpactReverse,
		"sends_data_to":  relationships.ImpactReverse,
		"contains":       relationships.ImpactForward,
		"manages":        relationships.ImpactForward,
		"impacts":        relationships.ImpactForward,
	}
	for _, typ := range relationships.All() {
		dir, bearing := typ.ImpactDirectionOf()
		expected, shouldBear := want[string(typ)]
		if bearing != shouldBear {
			t.Errorf("%s: ImpactBearing = %v, want %v", typ, bearing, shouldBear)
			continue
		}
		if bearing && dir != expected {
			t.Errorf("%s: direction = %q, want %q — a wrong direction inverts "+
				"'what breaks if this dies' for every asset of that shape", typ, dir, expected)
		}
	}
	// `connects_to` is the one exclusion, and it is deliberate: an observed
	// flow is not a dependency, and it is the highest-volume measured type.
	if relationships.ConnectsTo.ImpactBearing() {
		t.Error("connects_to must not be impact-bearing — including the highest-volume " +
			"measured type makes almost every closure the whole tenant")
	}
}

// Every impact-bearing type must have a DECLARED direction, and no type may
// have a direction without being impact-bearing. A type in one half and not the
// other is a type the CTE's CASE and its JOIN arm disagree about, which is a
// whole column of wrong answers with no error anywhere.
func TestImpactDirection_EveryBearingTypeIsInExactlyOneHalf(t *testing.T) {
	reverse := map[string]bool{}
	for _, s := range relationships.ImpactReverseStrings() {
		reverse[s] = true
	}
	forward := map[string]bool{}
	for _, s := range relationships.ImpactForwardStrings() {
		forward[s] = true
	}
	bearing := relationships.ImpactBearingStrings()
	if len(bearing) != len(reverse)+len(forward) {
		t.Fatalf("%d impact-bearing types split into %d reverse + %d forward",
			len(bearing), len(reverse), len(forward))
	}
	for _, s := range bearing {
		if reverse[s] == forward[s] {
			t.Errorf("%q is in %s — it must be in exactly one half", s,
				map[bool]string{true: "BOTH halves", false: "NEITHER half"}[reverse[s]])
		}
	}
	for _, typ := range relationships.All() {
		if !typ.ImpactBearing() && (reverse[string(typ)] || forward[string(typ)]) {
			t.Errorf("%s has a walk direction but is not impact-bearing", typ)
		}
	}
}

// Upstream is the exact mirror of downstream. The service expresses that by
// passing the two halves SWAPPED, so the property that makes the mirror true is
// "the halves are disjoint and together cover the vocabulary" — asserted above —
// plus nothing else about the walk being direction-aware. This pins the swap.
func TestImpactDirection_UpstreamIsTheMirror(t *testing.T) {
	down := [2][]string{relationships.ImpactReverseStrings(), relationships.ImpactForwardStrings()}
	up := [2][]string{relationships.ImpactForwardStrings(), relationships.ImpactReverseStrings()}
	if len(down[0]) != len(up[1]) || len(down[1]) != len(up[0]) {
		t.Fatal("the swapped halves are not the same two sets")
	}
	for i := range down[0] {
		if down[0][i] != up[1][i] {
			t.Errorf("mirror broken: downstream-reverse %q vs upstream-forward %q", down[0][i], up[1][i])
		}
	}
	for i := range down[1] {
		if down[1][i] != up[0][i] {
			t.Errorf("mirror broken: downstream-forward %q vs upstream-reverse %q", down[1][i], up[0][i])
		}
	}
}

// `impacts` is crossed once and not continued through: it names a business
// service, which is the end of the sentence a blast-radius answer finishes.
func TestImpactTerminal_IsOnlyImpacts(t *testing.T) {
	for _, typ := range relationships.All() {
		want := typ == relationships.Impacts
		if got := typ.ImpactTerminal(); got != want {
			t.Errorf("%s: ImpactTerminal = %v, want %v", typ, got, want)
		}
	}
	terminal := relationships.ImpactTerminalStrings()
	if len(terminal) != 1 || terminal[0] != "impacts" {
		t.Errorf("ImpactTerminalStrings() = %v, want [impacts]", terminal)
	}
	// A terminal type that is not impact-bearing would never be reached, and a
	// rule nothing reaches is a rule that cannot fail.
	if !relationships.Impacts.ImpactBearing() {
		t.Error("impacts is terminal but not impact-bearing, so the terminal rule is unreachable")
	}
}

func TestImpactStrings_AreSortedCopies(t *testing.T) {
	for name, got := range map[string][]string{
		"ImpactBearingStrings":  relationships.ImpactBearingStrings(),
		"ImpactReverseStrings":  relationships.ImpactReverseStrings(),
		"ImpactForwardStrings":  relationships.ImpactForwardStrings(),
		"ImpactTerminalStrings": relationships.ImpactTerminalStrings(),
	} {
		for i := 1; i < len(got); i++ {
			if got[i-1] >= got[i] {
				t.Errorf("%s() is not sorted: %q before %q", name, got[i-1], got[i])
			}
		}
	}
	mutate := relationships.ImpactBearingStrings()
	mutate[0] = "mutated"
	if relationships.ImpactBearingStrings()[0] == "mutated" {
		t.Error("ImpactBearingStrings() handed out the package's own slice")
	}
}
