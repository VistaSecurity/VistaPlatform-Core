package seams

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/ai"
)

// Every null default returns its DOCUMENTED answer. These read as trivial and
// are not: the documented answer is the contract the whole "AI-native, never
// AI-dependent" posture rests on, and the tempting "improvements" to each one
// — a most-likely class, an empty-but-present narrative, a silent nil instead
// of ErrUnavailable — are each a way of pretending something was checked.
func TestNullDefaults_ReturnTheirDocumentedAnswers(t *testing.T) {
	ctx := context.Background()

	t.Run("Matcher proposes nothing, without erroring", func(t *testing.T) {
		got, err := NullMatcher{}.Match(ctx, Observation{Kind: "host"}, []AssetSummary{{ID: "a1"}})
		if err != nil {
			t.Fatalf("err = %v; 'no proposal' is a normal outcome, not a failure", err)
		}
		if got != nil {
			t.Errorf("got %#v, want nil", got)
		}
	})

	t.Run("Classifier says unknown, never guesses", func(t *testing.T) {
		got, err := NullClassifier{}.Classify(ctx, AssetFacts{Facts: map[string]any{"banner": "OpenSSH_9.6"}})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if !got.Unknown {
			t.Error("Unknown = false; not assessed must stay not assessed (ADR-0008 D4.3)")
		}
		if got.Class != "" {
			t.Errorf("Class = %q; the null classifier guessed", got.Class)
		}
		if got.Confidence != 0 {
			t.Errorf("Confidence = %v; it made no claim, so it must claim nothing", got.Confidence)
		}
	})

	t.Run("DriftDetector proposes no anomalies", func(t *testing.T) {
		got, err := NullDriftDetector{}.Detect(ctx, PopulationWindow{TenantID: "t1"})
		if err != nil || got != nil {
			t.Errorf("got %#v, %v; want nil, nil", got, err)
		}
	})

	t.Run("Enricher adds no facts", func(t *testing.T) {
		got, err := NullEnricher{}.Enrich(ctx, EnrichmentSubject{Vendor: "Cisco"})
		if err != nil || got != nil {
			t.Errorf("got %#v, %v; want nil, nil", got, err)
		}
	})

	t.Run("Narrator is unavailable, not empty", func(t *testing.T) {
		got, err := NullNarrator{}.Narrate(ctx, NarrationInput{Subject: "cbom diff"})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if got.Available {
			t.Error("Available = true from the null narrator")
		}
		if got.Text != "" {
			t.Errorf("Text = %q; the null narrator fabricated prose", got.Text)
		}
	})

	t.Run("Query refuses", func(t *testing.T) {
		got, err := NullQuery{}.Answer(ctx, "how many expired certs?", nil)
		if !errors.Is(err, ai.ErrUnavailable) {
			t.Errorf("err = %v, want ai.ErrUnavailable", err)
		}
		if got.Text != "" {
			t.Errorf("Text = %q; there is no honest empty answer to a question", got.Text)
		}
	})

	t.Run("Author refuses", func(t *testing.T) {
		got, err := NullAuthor{}.Draft(ctx, "PCI-DSS 4.0 requirement 4.2.1")
		if !errors.Is(err, ai.ErrUnavailable) {
			t.Errorf("err = %v, want ai.ErrUnavailable", err)
		}
		if got != nil {
			t.Errorf("got %#v, want nil", got)
		}
	})

	t.Run("Remediator refuses", func(t *testing.T) {
		got, err := NullRemediator{}.Propose(ctx, FindingRef{FindingID: "f1"})
		if !errors.Is(err, ai.ErrUnavailable) {
			t.Errorf("err = %v, want ai.ErrUnavailable", err)
		}
		if got.Summary != "" || len(got.Steps) != 0 {
			t.Errorf("got %#v; the null remediator drafted a plan", got)
		}
	})
}

// A seam's RULE-BASED default produces real values with real provenance, and
// saying "inferred" about a date read out of a catalogue would understate it as
// badly as the reverse overstates. D4.1 cuts both ways.
//
// ADR-0008 D1 gives several seams a null/rule-based default that answers — the
// enricher's "static catalogue lookups", the matcher's deterministic identifier
// rules — and [NewLookupProposal] is the only way to build provenance for one.
func TestNewLookupProposal(t *testing.T) {
	p := NewLookupProposal(SourceKindImported, "catalog:eol:row-1")
	if p.SourceKind != SourceKindImported {
		t.Errorf("SourceKind = %q, want %q", p.SourceKind, SourceKindImported)
	}
	if p.SourceRef != "catalog:eol:row-1" {
		t.Errorf("SourceRef = %q", p.SourceRef)
	}
	// No model and no estimate. "" is not a model called unknown, and a lookup
	// made no estimate — a confidence we invented would read as a measurement.
	if p.ModelID != "" || p.Confidence != 0 {
		t.Errorf("a lookup claimed a model or a confidence: %+v", p)
	}

	// It survives serialisation as what it is, which is the half D4.1 is
	// actually about.
	blob, err := json.Marshal(Fact{Proposal: p, Key: "eol.os.date", Value: "2029-05-31",
		SourceURL: "https://endoflife.date/ubuntu"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["source_kind"] != SourceKindImported {
		t.Errorf("serialised source_kind = %v, want %q:\n%s", decoded["source_kind"], SourceKindImported, blob)
	}

	// It cannot be used to launder an inferred value as something else, and it
	// cannot invent a fifth source_kind nothing reports on.
	for _, bad := range []string{SourceKindInferred, "guessed", ""} {
		if got := NewLookupProposal(bad, "x").SourceKind; got != SourceKindImported {
			t.Errorf("NewLookupProposal(%q) kept SourceKind %q; it must normalise to %q",
				bad, got, SourceKindImported)
		}
	}
	// And the three legitimate kinds pass through, which is the inverse
	// polarity: a normaliser that flattened everything to "imported" would pass
	// the loop above and lose the distinction it exists to keep.
	for _, ok := range []string{SourceKindMeasured, SourceKindImported, SourceKindDeclared} {
		if got := NewLookupProposal(ok, "x").SourceKind; got != ok {
			t.Errorf("NewLookupProposal(%q) = %q, want it preserved", ok, got)
		}
	}
}

// D4.1: every output carrying an inferred value carries source_kind,
// source_ref, confidence and model id — and carries them THROUGH
// SERIALISATION, which is the half that was missing. source_kind was a method,
// so json.Marshal dropped it and source_ref did not exist at all: a proposal
// crossing a service boundary or landing in a jsonb column arrived looking
// exactly like a measured fact.
func TestEveryInferredOutputCarriesProvenance(t *testing.T) {
	const modelID = "onnx-v1"

	outputs := map[string]Proposed{
		"MatchScore":    MatchScore{Proposal: NewProposal(modelID, "matcher:"+modelID, 0.8)},
		"ClassProposal": ClassProposal{Proposal: NewProposal(modelID, "classifier:"+modelID, 0.8)},
		"Anomaly":       Anomaly{Proposal: NewProposal(modelID, "drift_detector:"+modelID, 0.8)},
		"Fact":          Fact{Proposal: NewProposal(modelID, "enricher:"+modelID, 0.8)},
		"Narrative":     Narrative{Proposal: NewProposal(modelID, "narrator:"+modelID, 0.8)},
		"Answer":        Answer{Proposal: NewProposal(modelID, "query:"+modelID, 0.8)},
		"ControlDraft":  ControlDraft{Proposal: NewProposal(modelID, "author:"+modelID, 0.8)},
		"PlanDraft":     PlanDraft{Proposal: NewProposal(modelID, "remediator:"+modelID, 0.8)},
	}

	for name, out := range outputs {
		t.Run(name, func(t *testing.T) {
			p := ProposalOf(out)
			if p.SourceKind != SourceKindInferred {
				t.Errorf("SourceKind = %q, want %q", p.SourceKind, SourceKindInferred)
			}
			if p.SourceRef == "" {
				t.Error("SourceRef is empty; D4.1 requires it alongside source_kind")
			}
			if p.Confidence != 0.8 || p.ModelID != modelID {
				t.Errorf("provenance lost: %+v", p)
			}

			// The serialised form is what a consumer actually sees.
			blob, err := json.Marshal(out)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(blob, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if decoded["source_kind"] != SourceKindInferred {
				t.Errorf("serialised %s has source_kind %v, want %q:\n%s",
					name, decoded["source_kind"], SourceKindInferred, blob)
			}
			if ref, _ := decoded["source_ref"].(string); ref == "" {
				t.Errorf("serialised %s has no source_ref:\n%s", name, blob)
			}
			if decoded["model_id"] != modelID {
				t.Errorf("serialised %s has model_id %v:\n%s", name, decoded["model_id"], blob)
			}
		})
	}
}

// A null default's answer carries provenance too — with no model id, because no
// model was involved, and a source_ref naming the null producer. "The null
// classifier said unknown" and "a model said unknown" are different facts about
// a deployment and a stored proposal has to be able to tell them apart.
func TestNullDefaults_CarryTheirOwnProvenance(t *testing.T) {
	ctx := context.Background()

	cls, _ := NullClassifier{}.Classify(ctx, AssetFacts{})
	narrative, _ := NullNarrator{}.Narrate(ctx, NarrationInput{})
	answer, _ := NullQuery{}.Answer(ctx, "?", nil)
	plan, _ := NullRemediator{}.Propose(ctx, FindingRef{})

	for name, out := range map[string]Proposed{
		"NullClassifier": cls,
		"NullNarrator":   narrative,
		"NullQuery":      answer,
		"NullRemediator": plan,
	} {
		t.Run(name, func(t *testing.T) {
			p := ProposalOf(out)
			if p.SourceKind != SourceKindInferred {
				t.Errorf("SourceKind = %q", p.SourceKind)
			}
			if !strings.HasSuffix(p.SourceRef, ":"+ImplNone) {
				t.Errorf("SourceRef = %q, want it to name the null producer", p.SourceRef)
			}
			if p.ModelID != "" {
				t.Errorf("ModelID = %q; no model produced this and \"\" is not a model called unknown", p.ModelID)
			}
			if p.Confidence != 0 {
				t.Errorf("Confidence = %v; it made no claim", p.Confidence)
			}
		})
	}
}
