package seams

import (
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
)

func learned(t *testing.T) LearnedMatcher {
	t.Helper()
	m, ok := NewLearnedMatcher().(LearnedMatcher)
	if !ok {
		t.Fatal("the learned matcher failed to load its weights; the seam degraded to proposing nothing")
	}
	return m
}

var sighting = time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)

func TestLearnedMatcher_IsTheRegistryDefault(t *testing.T) {
	set := Default()
	if _, ok := set.Matcher.(LearnedMatcher); !ok {
		t.Fatalf("the default matcher is %T, want LearnedMatcher", set.Matcher)
	}
	if got := MatcherModelID(set.Matcher); got == "" {
		t.Error("the default matcher cannot name its model; a proposal it scores would carry no provenance")
	}
	if got := MatcherModelID(NullMatcher{}); got != "" {
		t.Errorf("the null matcher named a model (%q); \"\" is not a model called unknown", got)
	}
}

func TestLearnedMatcher_ScoresExplainsAndCarriesProvenance(t *testing.T) {
	m := learned(t)
	scores, err := m.Match(t.Context(),
		Observation{
			Kind:        "server",
			Name:        "db01.corp.example.com",
			Segment:     "seg-a",
			SourceKind:  SourceKindMeasured,
			ObservedAt:  sighting,
			Identifiers: map[string]string{"serial_number": "sn-1", "hostname": "db01"},
			Attributes:  map[string]any{"vendor": "Dell", "model": "R650"},
		},
		[]AssetSummary{
			{
				ID: "match", Class: "server", Name: "db01", Segment: "seg-a",
				SourceKind: SourceKindImported, LastSeenAt: sighting.Add(-time.Hour),
				Identifiers: map[string]string{"serial_number": "sn-1", "hostname": "db01"},
				Attributes:  map[string]any{"vendor": "Dell", "model": "R650"},
				Status:      "monitoring",
			},
			{
				ID: "other", Class: "printer", Name: "lobby-printer", Segment: "seg-b",
				SourceKind: SourceKindMeasured, LastSeenAt: sighting.Add(-200 * 24 * time.Hour),
				Identifiers: map[string]string{"ip_address": "198.51.100.9"},
				Status:      "monitoring",
			},
		})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(scores) != 2 {
		t.Fatalf("scored %d candidates, want 2", len(scores))
	}

	byID := map[string]MatchScore{}
	for _, s := range scores {
		byID[s.AssetID] = s
	}
	good, bad := byID["match"], byID["other"]

	if good.Score <= 0.5 {
		t.Errorf("a pair agreeing on a serial, a hostname, the segment and the hardware scored %.4f", good.Score)
	}
	if bad.Score >= 0.5 {
		t.Errorf("a printer in another segment sharing nothing scored %.4f", bad.Score)
	}
	if good.Score <= bad.Score {
		t.Error("the candidates are not separated")
	}

	// Provenance (ADR-0008 D4.1): source_kind, source_ref, model_id, and a
	// confidence that is the score rather than a second number.
	p := good.Provenance()
	if p.SourceKind != SourceKindInferred {
		t.Errorf("source_kind = %q, want %q", p.SourceKind, SourceKindInferred)
	}
	if p.ModelID == "" || p.ModelID != m.ModelID() {
		t.Errorf("model_id = %q, want %q", p.ModelID, m.ModelID())
	}
	if want := string(ai.SeamMatcher) + ":" + ImplLearned; p.SourceRef != want {
		t.Errorf("source_ref = %q, want %q", p.SourceRef, want)
	}
	if p.Confidence != good.Score {
		t.Errorf("confidence %v and score %v disagree; a reader would have to ask which is real", p.Confidence, good.Score)
	}

	if len(good.Explanation) == 0 {
		t.Fatal("a score arrived with no explanation")
	}
	if good.Reason == "" {
		t.Error("a score arrived with no reason; a proposal with a number and no phrase can only be rubber-stamped")
	}
	for _, f := range good.Explanation {
		if f.Label == "" || f.Feature == "" {
			t.Errorf("unlabelled factor: %+v", f)
		}
	}
}

// The seam's Observation and AssetSummary are the model's whole window onto the
// pair. A field the adapter forgets to carry is a feature that silently reads
// zero forever, which is invisible — the model keeps working and simply stops
// knowing something.
func TestLearnedMatcher_CarriesEveryComparableField(t *testing.T) {
	m := learned(t)
	base := func() (Observation, AssetSummary) {
		return Observation{
				Kind: "server", Name: "host-a", Segment: "seg-a",
				SourceKind: SourceKindMeasured, ObservedAt: sighting,
				Identifiers: map[string]string{"hostname": "host-a"},
				Attributes:  map[string]any{"vendor": "Dell", "model": "R650"},
			}, AssetSummary{
				ID: "c", Class: "server", Name: "host-a", Segment: "seg-a",
				SourceKind: SourceKindMeasured, LastSeenAt: sighting,
				Identifiers: map[string]string{"hostname": "host-a"},
				Attributes:  map[string]any{"vendor": "Dell", "model": "R650"},
			}
	}
	scoreOf := func(t *testing.T, o Observation, a AssetSummary) float64 {
		t.Helper()
		scores, err := m.Match(t.Context(), o, []AssetSummary{a})
		if err != nil || len(scores) != 1 {
			t.Fatalf("Match: %v (%d scores)", err, len(scores))
		}
		return scores[0].Score
	}

	o, a := base()
	agreed := scoreOf(t, o, a)

	cases := []struct {
		name    string
		mutate  func(*Observation, *AssetSummary)
		feature string
	}{
		{"segment", func(_ *Observation, a *AssetSummary) { a.Segment = "seg-z" }, matcher.FeatureSegmentConflict},
		{"vendor", func(_ *Observation, a *AssetSummary) { a.Attributes = map[string]any{"vendor": "HPE", "model": "R650"} }, matcher.FeatureVendorConflict},
		{"model", func(_ *Observation, a *AssetSummary) {
			a.Attributes = map[string]any{"vendor": "Dell", "model": "DL380"}
		}, matcher.FeatureModelConflict},
		{"class", func(_ *Observation, a *AssetSummary) { a.Class = "printer" }, matcher.FeatureClassConflict},
		{"last seen", func(_ *Observation, a *AssetSummary) { a.LastSeenAt = sighting.Add(-365 * 24 * time.Hour) }, matcher.FeatureRecency},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, a := base()
			tc.mutate(&o, &a)
			if got := scoreOf(t, o, a); got >= agreed {
				t.Errorf("changing the %s did not lower the score (%.6f vs %.6f); "+
					"the adapter is not carrying it through to %s", tc.name, got, agreed, tc.feature)
			}
		})
	}
}

// The model must not read an asset's approval status. Where an asset sits in the
// approval queue says nothing about whether it is the same physical thing, and a
// model that learned to favour approved assets would be laundering an approval
// decision into an identity one (ADR-0008 D5). Status travels on the summary for
// the ENGINE's auto-accept guard, which is a different job.
func TestLearnedMatcher_IgnoresApprovalStatus(t *testing.T) {
	m := learned(t)
	score := func(status string) float64 {
		scores, err := m.Match(t.Context(),
			Observation{Kind: "server", Name: "h", Segment: "s", ObservedAt: sighting,
				Identifiers: map[string]string{"hostname": "h"}},
			[]AssetSummary{{ID: "c", Class: "server", Name: "h", Segment: "s", LastSeenAt: sighting,
				Identifiers: map[string]string{"hostname": "h"}, Status: status}})
		if err != nil || len(scores) != 1 {
			t.Fatalf("Match: %v", err)
		}
		return scores[0].Score
	}
	if a, b := score("monitoring"), score("pending_approval"); a != b {
		t.Errorf("the status moved the score: monitoring %.6f, pending %.6f", a, b)
	}
}

// A non-string attribute reads as UNKNOWN, not as a value that disagrees with
// everything. A best-effort stringification would turn an absent vendor into
// evidence of two different things.
func TestLearnedMatcher_NonStringAttributeIsUnknown(t *testing.T) {
	m := learned(t)
	score := func(vendor any) float64 {
		scores, err := m.Match(t.Context(),
			Observation{Kind: "server", Name: "h", Segment: "s", ObservedAt: sighting,
				Identifiers: map[string]string{"hostname": "h"},
				Attributes:  map[string]any{"vendor": vendor}},
			[]AssetSummary{{ID: "c", Class: "server", Name: "h", Segment: "s", LastSeenAt: sighting,
				Identifiers: map[string]string{"hostname": "h"},
				Attributes:  map[string]any{"vendor": "Dell"}}})
		if err != nil || len(scores) != 1 {
			t.Fatalf("Match: %v", err)
		}
		return scores[0].Score
	}
	absent := score(nil)
	for _, junk := range []any{42, map[string]any{"nested": true}, []any{"a"}, true} {
		if got := score(junk); got != absent {
			t.Errorf("a %T vendor scored %.6f, an absent one %.6f: a non-string attribute must read as unknown",
				junk, got, absent)
		}
	}
}

func TestLearnedMatcher_NoCandidatesIsNoProposal(t *testing.T) {
	scores, err := learned(t).Match(t.Context(), Observation{Kind: "server"}, nil)
	if err != nil || scores != nil {
		t.Fatalf("Match with no candidates = %v, %v; want no proposal and no error", scores, err)
	}
}

// The explanation travels to the UI, into logs and into asset_history. It must
// not repeat an identifier VALUE — those are on the proposal's matched-identifier
// list, under the tenant's own access control, and a second copy in a model's
// reasoning is one nobody asked for.
func TestLearnedMatcher_ExplanationRepeatsNoValues(t *testing.T) {
	secrets := map[string]string{
		"serial_number":            "sn-secret-9911",
		"cloud_resource_id":        "arn:aws:ec2:us-east-1:1:instance/i-0secret",
		"ssh_host_key_fingerprint": "SHA256:donotleak",
		"hostname":                 "secret-host",
	}
	scores, err := learned(t).Match(t.Context(),
		Observation{Kind: "server", Name: "secret-host", Segment: "seg", ObservedAt: sighting, Identifiers: secrets},
		[]AssetSummary{{ID: "c", Class: "server", Name: "secret-host", Segment: "seg",
			LastSeenAt: sighting, Identifiers: secrets}})
	if err != nil || len(scores) != 1 {
		t.Fatalf("Match: %v", err)
	}
	rendered := scores[0].Reason
	for _, f := range scores[0].Explanation {
		rendered += " " + f.Feature + " " + f.Label
	}
	for _, v := range secrets {
		if strings.Contains(strings.ToLower(rendered), strings.ToLower(v)) {
			t.Errorf("the explanation repeats %q:\n%s", v, rendered)
		}
	}
}
