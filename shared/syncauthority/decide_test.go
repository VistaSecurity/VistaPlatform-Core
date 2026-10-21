package syncauthority

import (
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func TestDecide(t *testing.T) {
	hour := time.Hour
	cases := []struct {
		name string
		in   Input
		want Action
		val  any
	}{
		{"equal values do nothing", Input{Authority: DeclaredHere, Ours: Side{Value: "a"}, Theirs: Side{Value: "a"}}, ActionNone, nil},
		{"empty string equals null", Input{Authority: Newest, Ours: Side{Value: nil}, Theirs: Side{Value: ""}}, ActionNone, nil},
		{"numbers compare across types", Input{Authority: Peer, Ours: Side{Value: int64(1500)}, Theirs: Side{Value: float64(1500)}}, ActionNone, nil},

		// SYNC_MODEL §7.1: an observed field is not overwritten by a stale peer value.
		{"observed inside the window pushes ours over a different peer value",
			Input{Authority: Observed, Ours: Side{Value: float64(1000000)}, Theirs: Side{Value: float64(100000), Changed: true, ChangedAt: t0}, Baseline: true,
				ObservedAt: t0.Add(-10 * time.Minute), StaleWindow: hour, Now: t0}, ActionPush, float64(1000000)},
		{"observed but stale is a conflict, not a pull",
			Input{Authority: Observed, Ours: Side{Value: float64(1000000)}, Theirs: Side{Value: float64(100000)},
				ObservedAt: t0.Add(-2 * hour), StaleWindow: hour, Now: t0}, ActionConflict, nil},
		// Row 2.6: an empty field on an observed object is not a measurement.
		{"observed and fresh but empty here takes the peer's value",
			Input{Authority: Observed, Ours: Side{Value: nil}, Theirs: Side{Value: "junos"},
				ObservedAt: t0.Add(-time.Minute), StaleWindow: hour, Now: t0}, ActionPull, "junos"},
		{"observed and cleared here since the last sync pushes the clear",
			Input{Authority: Observed, Ours: Side{Value: nil, Changed: true}, Theirs: Side{Value: "junos"}, Baseline: true,
				ObservedAt: t0.Add(-time.Minute), StaleWindow: hour, Now: t0}, ActionPush, nil},
		{"observed but never observed here: peer-only change pulls",
			Input{Authority: Observed, Ours: Side{Value: float64(1)}, Theirs: Side{Value: float64(2), Changed: true}, Baseline: true, Now: t0}, ActionPull, float64(2)},

		{"peer authority pulls", Input{Authority: Peer, Ours: Side{Value: "x", Changed: true}, Theirs: Side{Value: "y"}, Baseline: true}, ActionPull, "y"},

		// SYNC_MODEL §7.2: declared_here changed on both sides → conflict, never a write.
		{"declared_here changed on both sides is a conflict",
			Input{Authority: DeclaredHere, Ours: Side{Value: "ours", Changed: true, ChangedAt: t0}, Theirs: Side{Value: "theirs", Changed: true, ChangedAt: t0.Add(hour)}, Baseline: true}, ActionConflict, nil},
		{"declared_here changed here only pushes", Input{Authority: DeclaredHere, Ours: Side{Value: "ours", Changed: true}, Theirs: Side{Value: "theirs"}, Baseline: true}, ActionPush, "ours"},
		{"declared_here changed in the peer only still pushes ours", Input{Authority: DeclaredHere, Ours: Side{Value: "ours"}, Theirs: Side{Value: "theirs", Changed: true}, Baseline: true}, ActionPush, "ours"},
		{"declared_here never set here fills from the peer", Input{Authority: DeclaredHere, Ours: Side{Value: nil}, Theirs: Side{Value: "theirs"}}, ActionPull, "theirs"},
		{"declared_here cleared here is pushed as cleared", Input{Authority: DeclaredHere, Ours: Side{Value: nil, Changed: true}, Theirs: Side{Value: "theirs"}, Baseline: true}, ActionPush, nil},

		{"merge unions", Input{Authority: Merge, Ours: Side{Value: []any{"a", "b"}}, Theirs: Side{Value: []any{"c", "a"}}}, ActionMerge, []any{"a", "b", "c"}},

		{"newest: only ours changed pushes", Input{Authority: Newest, Ours: Side{Value: "a", Changed: true}, Theirs: Side{Value: "b"}, Baseline: true}, ActionPush, "a"},
		{"newest: only theirs changed pulls", Input{Authority: Newest, Ours: Side{Value: "a"}, Theirs: Side{Value: "b", Changed: true}, Baseline: true}, ActionPull, "b"},
		{"newest: both changed, ours an hour newer, pushes",
			Input{Authority: Newest, Ours: Side{Value: "a", Changed: true, ChangedAt: t0.Add(hour)}, Theirs: Side{Value: "b", Changed: true, ChangedAt: t0}, Baseline: true}, ActionPush, "a"},
		{"newest: both changed, theirs an hour newer, pulls",
			Input{Authority: Newest, Ours: Side{Value: "a", Changed: true, ChangedAt: t0}, Theirs: Side{Value: "b", Changed: true, ChangedAt: t0.Add(hour)}, Baseline: true}, ActionPull, "b"},
		{"newest: both changed within five minutes is a conflict",
			Input{Authority: Newest, Ours: Side{Value: "a", Changed: true, ChangedAt: t0}, Theirs: Side{Value: "b", Changed: true, ChangedAt: t0.Add(4 * time.Minute)}, Baseline: true}, ActionConflict, nil},
		{"newest: exactly at the window edge is a conflict",
			Input{Authority: Newest, Ours: Side{Value: "a", ChangedAt: t0}, Theirs: Side{Value: "b", ChangedAt: t0.Add(NewestWindow)}}, ActionConflict, nil},
		{"newest: just past the window, the newer wins",
			Input{Authority: Newest, Ours: Side{Value: "a", ChangedAt: t0}, Theirs: Side{Value: "b", ChangedAt: t0.Add(NewestWindow + time.Second)}}, ActionPull, "b"},
		{"newest: unknown change time is a conflict", Input{Authority: Newest, Ours: Side{Value: "a"}, Theirs: Side{Value: "b", ChangedAt: t0}}, ActionConflict, nil},

		{"unknown authority is a conflict", Input{Authority: "whatever", Ours: Side{Value: "a"}, Theirs: Side{Value: "b"}}, ActionConflict, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(tc.in)
			if got.Action != tc.want {
				t.Fatalf("action = %s (%s), want %s", got.Action, got.Reason, tc.want)
			}
			if got.Reason == "" {
				t.Error("a decision carries a reason for the plan")
			}
			if tc.want != ActionNone && tc.want != ActionConflict && !Equal(got.Value, tc.val) {
				t.Errorf("value = %#v, want %#v", got.Value, tc.val)
			}
			if tc.want == ActionConflict && got.Value != nil {
				t.Errorf("a conflict writes nothing, but carried %#v", got.Value)
			}
		})
	}
}

func TestCanonicalAndFingerprint(t *testing.T) {
	if !Equal([]any{"b", "a"}, []string{"a", "b"}) {
		t.Error("sets compare unordered")
	}
	if Equal("a", "A") {
		t.Error("strings compare exactly")
	}
	if Equal(false, nil) {
		t.Error("an explicit false is an answer, not an absence")
	}
	if !IsEmpty([]any{}) || !IsEmpty("") || IsEmpty(false) || IsEmpty(float64(0)) {
		t.Error("IsEmpty: empty set and empty string are empty; false and 0 are values")
	}
	if Fingerprint("") != Fingerprint(nil) || Fingerprint("a") == Fingerprint("b") {
		t.Error("fingerprints follow canonical equality")
	}
}

func TestKindsAreOrderedAndValid(t *testing.T) {
	ks := Kinds()
	if len(ks) == 0 {
		t.Fatal("no synced kinds")
	}
	for i, k := range ks {
		// A sync kind (Object set) is not a vocabulary kind; its rows are.
		if _, isKind := dcim.ParseObjectKind(string(k.Kind)); k.Object == "" && !isKind {
			t.Errorf("%s is not an ObjectKind", k.Kind)
		} else if k.Object != "" {
			if isKind {
				t.Errorf("%s is a vocabulary ObjectKind and a sync kind over %s", k.Kind, k.Object)
			}
			if _, ok := dcim.ParseObjectKind(string(k.Object)); !ok || k.Object.Table() == "" {
				t.Errorf("%s: object %s is not an ObjectKind with a table", k.Kind, k.Object)
			}
		}
		if i > 0 && ks[i-1].Order > k.Order {
			t.Errorf("%s (order %d) listed after %s (order %d)", k.Kind, k.Order, ks[i-1].Kind, ks[i-1].Order)
		}
		for _, f := range k.Fields {
			if !f.Authority.Valid() {
				t.Errorf("%s.%s: invalid authority %q", k.Kind, f.Field, f.Authority)
			}
		}
	}
	// Business units precede everything that references them.
	if ks[0].Kind != dcim.ObjectKindBusinessUnit {
		t.Errorf("first kind = %s, want business_unit", ks[0].Kind)
	}
	if a, ok := Default(dcim.ObjectKindPrefix, "business_unit_id"); !ok || a != DeclaredHere {
		t.Errorf("prefix.business_unit_id default = %q, want declared_here (ADR-0010 D7 example)", a)
	}
	if a, ok := Default(dcim.ObjectKindInterface, "mac_address"); !ok || a != Observed {
		t.Errorf("interface.mac_address default = %q, want observed", a)
	}
}

func TestOverrides(t *testing.T) {
	o := Overrides{"prefix": {"description": DeclaredHere}}
	if err := o.Validate(); err != nil {
		t.Fatalf("a valid override refused: %v", err)
	}
	if a, _ := o.Resolve(dcim.ObjectKindPrefix, "description"); a != DeclaredHere {
		t.Errorf("override not applied: %q", a)
	}
	if a, _ := o.Resolve(dcim.ObjectKindPrefix, "is_pool"); a != DeclaredHere {
		t.Errorf("an unnamed field keeps its default, got %q", a)
	}
	if _, ok := o.Resolve(dcim.ObjectKindPrefix, "prefix"); ok {
		t.Error("an identity column is not a synced field")
	}
	for name, bad := range map[string]Overrides{
		"unknown kind":      {"rack": {"name": Peer}},
		"unknown field":     {"prefix": {"prefixx": Peer}},
		"unknown authority": {"prefix": {"description": "theirs"}},
	} {
		err := bad.Validate()
		if err == nil {
			t.Errorf("%s accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "field authority") {
			t.Errorf("%s: error does not name the setting: %v", name, err)
		}
	}
}
