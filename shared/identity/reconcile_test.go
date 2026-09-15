package identity

import (
	"fmt"
	"testing"
)

// tiers are the distinct provenance tiers each group's table ranks, in the
// order the ADR lists them (strongest first). The cell-by-cell test below
// asserts that for EVERY ordered pair, the stronger one wins whichever way
// round it arrives — which is the property a precedence table actually makes,
// and is what a per-row spot check would miss.
type tier struct {
	name string
	v    ValueWithSource
}

func val(text string, kind SourceKind, mode MeasurementMode, conf float64) ValueWithSource {
	return ValueWithSource{
		Value:      text,
		Source:     Source{Kind: kind, Ref: "test:" + string(kind), Mode: mode},
		Confidence: conf,
	}
}

func tiersFor(group AttributeGroup) []tier {
	switch group {
	case GroupIdentity:
		return []tier{
			{"declared", val("declared", SourceDeclared, "", 0)},
			{"measured-active", val("measured-active", SourceMeasured, ModeActive, 1)},
			{"measured-passive", val("measured-passive", SourceMeasured, ModePassive, 1)},
			{"imported", val("imported", SourceImported, "", 0)},
			{"inferred", val("inferred", SourceInferred, "", 0.99)},
		}
	case GroupContext:
		return []tier{
			{"declared", val("declared", SourceDeclared, "", 0)},
			{"imported", val("imported", SourceImported, "", 0)},
			{"measured", val("measured", SourceMeasured, ModeActive, 1)},
			{"inferred", val("inferred", SourceInferred, "", 0.99)},
		}
	case GroupClass:
		return []tier{
			{"declared", val("declared", SourceDeclared, "", 0)},
			{"measured-high-confidence", val("measured-high", SourceMeasured, ModeActive, HighConfidence)},
			{"imported", val("imported", SourceImported, "", 0)},
			{"measured-low-confidence", val("measured-low", SourceMeasured, ModeActive, HighConfidence-0.01)},
			{"inferred", val("inferred", SourceInferred, "", 0.99)},
		}
	}
	return nil
}

// TestReconcileEveryCell walks every ordered pair of tiers in every group.
func TestReconcileEveryCell(t *testing.T) {
	for _, group := range []AttributeGroup{GroupIdentity, GroupContext, GroupClass} {
		tiers := tiersFor(group)
		if len(tiers) == 0 {
			t.Fatalf("no tier table for group %s", group)
		}
		for i, stronger := range tiers {
			for j, weaker := range tiers {
				if i >= j {
					continue
				}
				name := fmt.Sprintf("%s/%s beats %s", group, stronger.name, weaker.name)
				t.Run(name, func(t *testing.T) {
					// The stronger value arriving second must win.
					if got := Reconcile(group, weaker.v, stronger.v); got.Value != stronger.v.Value {
						t.Errorf("incoming %s did not overwrite existing %s: got %v", stronger.name, weaker.name, got.Value)
					}
					// And arriving first, it must survive.
					if got := Reconcile(group, stronger.v, weaker.v); got.Value != stronger.v.Value {
						t.Errorf("incoming %s overwrote existing %s: got %v", weaker.name, stronger.name, got.Value)
					}
				})
			}
		}
		// A tier against itself: the newer observation of equal authority wins.
		for _, same := range tiers {
			t.Run(fmt.Sprintf("%s/%s ties to the incoming value", group, same.name), func(t *testing.T) {
				existing := same.v
				existing.Value = "older"
				if got := Reconcile(group, existing, same.v); got.Value != same.v.Value {
					t.Errorf("a tie kept the older value %v, want the incoming %v", got.Value, same.v.Value)
				}
			})
		}
	}
}

func TestReconcileEmptyNeverWins(t *testing.T) {
	populated := val("something", SourceImported, "", 0)

	empties := []struct {
		name string
		v    any
	}{
		{"nil", nil},
		{"empty string", ""},
		{"zero int", 0},
		{"zero float", 0.0},
		{"empty slice", []string{}},
		{"nil slice", []string(nil)},
		{"empty map", map[string]any{}},
		{"nil pointer", (*string)(nil)},
	}

	for _, group := range []AttributeGroup{GroupIdentity, GroupContext, GroupClass} {
		for _, e := range empties {
			t.Run(string(group)+"/"+e.name, func(t *testing.T) {
				// An empty value from the STRONGEST source still loses.
				incoming := val("", SourceDeclared, "", 1)
				incoming.Value = e.v
				got := Reconcile(group, populated, incoming)
				if got.Value != populated.Value {
					t.Fatalf("an empty declared value overwrote a populated imported one: got %#v", got.Value)
				}
			})
		}
	}

	t.Run("false is not empty", func(t *testing.T) {
		// The load-bearing exception. An explicit false is an answer —
		// cert_has_sct, mtls_detected — and demoting it is the jq `//` mistake
		// that silently inverts a security flag.
		existing := ValueWithSource{Value: true, Source: Source{Kind: SourceMeasured, Ref: "test:sensor", Mode: ModePassive}}
		incoming := ValueWithSource{Value: false, Source: Source{Kind: SourceMeasured, Ref: "test:agent", Mode: ModeActive}}
		got := Reconcile(GroupIdentity, existing, incoming)
		if got.Value != false {
			t.Fatalf("an explicit false was treated as empty and did not overwrite true")
		}
		if IsEmptyValue(false) {
			t.Error("IsEmptyValue(false) = true; false is an answer, not an absence")
		}
	})
}

func TestReconcileInferredNeverOverwritesMeasuredOrDeclared(t *testing.T) {
	// ADR-0008 D4.2, at ANY confidence, in EVERY group — including the
	// context group, where a measured value is otherwise weak.
	confident := val("model says", SourceInferred, "", 1.0)

	for _, group := range []AttributeGroup{GroupIdentity, GroupContext, GroupClass} {
		for _, existing := range []ValueWithSource{
			val("measured", SourceMeasured, ModePassive, 0.1),
			val("declared", SourceDeclared, "", 0),
		} {
			t.Run(string(group)+"/"+string(existing.Source.Kind), func(t *testing.T) {
				if got := Reconcile(group, existing, confident); got.Value != existing.Value {
					t.Fatalf("an inferred value at confidence 1.0 overwrote a %s one: got %v", existing.Source.Kind, got.Value)
				}
			})
		}
	}

	t.Run("inferred may fill a gap", func(t *testing.T) {
		// D4.2 permits exactly this and nothing more.
		empty := ValueWithSource{Source: Source{Kind: SourceMeasured, Ref: "test:sensor"}}
		if got := Reconcile(GroupIdentity, empty, confident); got.Value != confident.Value {
			t.Fatalf("an inferred value did not fill an empty slot: got %v", got.Value)
		}
	})

	t.Run("inferred may overwrite inferred and imported", func(t *testing.T) {
		for _, existing := range []ValueWithSource{
			val("older guess", SourceInferred, "", 0.2),
			val("cmdb", SourceImported, "", 0),
		} {
			got := Reconcile(GroupIdentity, existing, confident)
			want := confident.Value
			if existing.Source.Kind == SourceImported {
				// imported outranks inferred in every table, so it holds.
				want = existing.Value
			}
			if got.Value != want {
				t.Errorf("existing %s vs incoming inferred: got %v, want %v", existing.Source.Kind, got.Value, want)
			}
		}
	})
}

func TestReconcileUnspecifiedMeasurementModeDoesNotOutrankPassive(t *testing.T) {
	// "Did not say how it measured" must not be promoted to active. An
	// unspecified-mode value must lose to an active one and tie with passive.
	unspecified := val("unspecified", SourceMeasured, ModeUnspecified, 1)
	active := val("active", SourceMeasured, ModeActive, 1)
	passive := val("passive", SourceMeasured, ModePassive, 1)

	if got := Reconcile(GroupIdentity, active, unspecified); got.Value != active.Value {
		t.Errorf("an unspecified-mode measurement overwrote an active one: got %v", got.Value)
	}
	if got := Reconcile(GroupIdentity, passive, unspecified); got.Value != unspecified.Value {
		t.Errorf("an unspecified-mode measurement lost to a passive one: got %v (they are the same tier, so the incoming value wins)", got.Value)
	}
}

// TestReconcileInferredFloorHoldsUnderAnUnknownGroup is what makes the
// explicit D4.2 guard in Reconcile load-bearing rather than redundant: with an
// unrecognised group every source ranks equal, and without the guard the tie
// would hand the write to the model.
func TestReconcileInferredFloorHoldsUnderAnUnknownGroup(t *testing.T) {
	inferred := val("model says", SourceInferred, "", 1.0)
	for _, existing := range []ValueWithSource{
		val("measured", SourceMeasured, ModePassive, 1),
		val("declared", SourceDeclared, "", 0),
	} {
		got := Reconcile(AttributeGroup("a group nobody declared"), existing, inferred)
		if got.Value != existing.Value {
			t.Errorf("an inferred value overwrote a %s one under an unknown group: got %v", existing.Source.Kind, got.Value)
		}
	}
}

func TestReconcileUnknownGroupAndSourceRankLast(t *testing.T) {
	known := val("known", SourceInferred, "", 0)
	unknown := ValueWithSource{Value: "unknown", Source: Source{Kind: SourceKind("telepathy"), Ref: "test:???"}}

	if got := Reconcile(GroupIdentity, known, unknown); got.Value != known.Value {
		t.Errorf("a value with an unreadable source kind beat an inferred one: got %v", got.Value)
	}
	if got := Reconcile(AttributeGroup("vibes"), known, known); got.Value != known.Value {
		t.Errorf("an unknown group broke reconciliation entirely: got %v", got.Value)
	}
}

func TestAttributeGroupValid(t *testing.T) {
	for _, g := range []AttributeGroup{GroupIdentity, GroupContext, GroupClass} {
		if !g.Valid() {
			t.Errorf("%s.Valid() = false", g)
		}
	}
	if AttributeGroup("posture").Valid() {
		t.Error("an invented group reported itself valid")
	}
}
