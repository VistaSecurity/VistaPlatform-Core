package seams

import (
	"reflect"
	"testing"
)

// The plan-citation grammar ([ev:key] and [guide]), tested here in Core because
// this is where it lives. Its only producer is the Enterprise remediator, whose
// own tests drive it end to end; these pin the grammar itself, including the
// shapes a model can write that must NOT parse as a citation.

func TestEvidenceRefsIn(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"one", "Disable it [ev:protocol_version].", []string{"protocol_version"}},
		{"several, in order, with duplicates", "[ev:b] and [ev:a] and [ev:b]", []string{"b", "a", "b"}},
		{"dotted and hyphenated keys", "[ev:cvss_v3.base_score] [ev:cert-chain]",
			[]string{"cvss_v3.base_score", "cert-chain"}},
		{"none", "Disable it.", nil},

		// Shapes that must not parse. Each is a way a model could try to put
		// something other than an evidence key where a UI renders a label.
		{"a markdown link is not a citation", "[see the docs](https://example.test)", nil},
		{"a row citation is not an evidence citation", "[row:r1]", nil},
		{"a space is not in the class", "[ev:protocol version]", nil},
		{"markup is not in the class", "[ev:<script>]", nil},
		{"a quote is not in the class", `[ev:"key"]`, nil},
		{"an empty key does not match", "[ev:]", nil},
		{"a slash is not in the class", "[ev:a/b]", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EvidenceRefsIn(tc.in)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("EvidenceRefsIn(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCitesGuidance(t *testing.T) {
	if !CitesGuidance("Do the usual thing [guide].") {
		t.Error("the guidance marker was not recognised")
	}
	if CitesGuidance("Do the usual thing [guidance].") {
		t.Error("[guidance] was read as the guidance marker; the marker is exactly [guide]")
	}
	if CitesGuidance("no citation here") {
		t.Error("guidance cited in text that cites nothing")
	}
}

func TestPlanCitationsResolve(t *testing.T) {
	keys := map[string]bool{"protocol_version": true, "cipher_suite": true}

	tests := []struct {
		name        string
		text        string
		hasGuidance bool
		want        bool
	}{
		{"a known evidence key", "Disable it [ev:protocol_version].", true, true},
		{"the guidance, where there is guidance", "Apply the standard fix [guide].", true, true},
		{"several known keys", "[ev:protocol_version] and [ev:cipher_suite]", true, true},

		// Cite or refuse: nothing cited is refuse.
		{"nothing cited", "Disable TLS 1.0.", true, false},

		// One bad citation condemns the step, even beside a good one. An
		// unresolvable reference is the model asserting something about a
		// measurement it was never shown.
		{"an unknown key", "Rotate it [ev:admin_password].", true, false},
		{"one good, one unknown", "[ev:protocol_version] then [ev:admin_password]", true, false},

		// A citation pointing at nothing is worse than no citation, because it
		// reads as checked.
		{"the guidance, where there is none", "Apply the standard fix [guide].", false, false},
		{"a known key while there is no guidance", "Disable it [ev:protocol_version].", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PlanCitationsResolve(tc.text, keys, tc.hasGuidance); got != tc.want {
				t.Errorf("PlanCitationsResolve(%q, hasGuidance=%v) = %v, want %v",
					tc.text, tc.hasGuidance, got, tc.want)
			}
		})
	}
}

// The list is DERIVED from the text, so the two cannot disagree: each distinct
// key once, in order of first appearance, with the guidance last.
func TestCollectPlanCitations(t *testing.T) {
	got := CollectPlanCitations("[ev:b] then [guide] then [ev:a] then [ev:b] again")
	want := []Citation{
		{Kind: CitationKindEvidence, Ref: "b"},
		{Kind: CitationKindEvidence, Ref: "a"},
		{Kind: CitationKindGuidance},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CollectPlanCitations = %+v, want %+v", got, want)
	}
	if CollectPlanCitations("nothing here") != nil {
		t.Error("citations collected from text that cites nothing")
	}
}

// The two grammars do not read each other's markers. A remediation step citing
// [row:r1] resolves nothing, and a narrative citing [ev:x] resolves nothing —
// which is what keeps one seam's output from validating against another's rows.
func TestTheTwoGrammarsAreDisjoint(t *testing.T) {
	if len(RefsIn("[ev:protocol_version]")) != 0 {
		t.Error("the row grammar matched an evidence citation")
	}
	if len(EvidenceRefsIn("[row:r1]")) != 0 {
		t.Error("the evidence grammar matched a row citation")
	}
	if StripCitations("[ev:a] kept") != "[ev:a] kept" {
		t.Error("StripCitations removed an evidence marker")
	}
}

func TestEvidenceCiteMarker(t *testing.T) {
	m := EvidenceCiteMarker("protocol_version")
	if m != "[ev:protocol_version]" {
		t.Fatalf("EvidenceCiteMarker = %q", m)
	}
	// Round trip: what the prompt shows the model is what the parser reads back.
	if refs := EvidenceRefsIn(m); len(refs) != 1 || refs[0] != "protocol_version" {
		t.Errorf("the marker this package renders does not parse back: %v", refs)
	}
}
