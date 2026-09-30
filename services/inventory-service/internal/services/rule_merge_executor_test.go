package services

import (
	"database/sql"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// The survivor order, one rule per case. Each case differs from its control by
// the one fact the rule reads.
//
// Mutation checks: drop any one comparison in ruleMergeSurvivor → its case
// picks the other record.
func TestRuleMergeSurvivor_Order(t *testing.T) {
	a, b := uuid.MustParse("00000000-0000-4000-8000-00000000000a"), uuid.MustParse("00000000-0000-4000-8000-00000000000b")
	early := sql.NullTime{Time: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true}
	late := sql.NullTime{Time: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), Valid: true}
	base := func(id uuid.UUID) ruleSurvivorFacts {
		return ruleSurvivorFacts{ID: id, Status: identity.StatusMonitoring, FirstDiscovered: early, IdentifierCount: 2}
	}
	for _, tt := range []struct {
		name string
		edit func(x, y *ruleSurvivorFacts) // x is the record that must survive
	}{
		{"in service beats awaiting approval", func(x, y *ruleSurvivorFacts) {
			y.Status = identity.StatusPendingApproval
			y.Declared = true // even a declared one: its status is what the merged record keeps
		}},
		{"declared beats discovered", func(x, y *ruleSurvivorFacts) {
			x.Declared = true
			x.FirstDiscovered = late // seen later, still the survivor
		}},
		{"established beats provisional", func(x, y *ruleSurvivorFacts) {
			y.Provisional = true
			x.FirstDiscovered = late
		}},
		{"earlier first discovery", func(x, y *ruleSurvivorFacts) {
			y.FirstDiscovered = late
			y.IdentifierCount = 9
		}},
		{"a known first discovery beats an unknown one", func(x, y *ruleSurvivorFacts) {
			y.FirstDiscovered = sql.NullTime{}
		}},
		{"more identifiers", func(x, y *ruleSurvivorFacts) {
			x.IdentifierCount = 5
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Both orders, so the answer is about the facts and not the input
			// order; and the survivor is b in half of them, so the id
			// tie-break cannot be what passes it.
			for _, want := range []uuid.UUID{a, b} {
				other := a
				if want == a {
					other = b
				}
				x, y := base(want), base(other)
				tt.edit(&x, &y)
				for _, in := range [][]ruleSurvivorFacts{{x, y}, {y, x}} {
					if got := ruleMergeSurvivor(in); got != want {
						t.Fatalf("survivor %s, want %s", got, want)
					}
				}
			}
		})
	}
	t.Run("full tie breaks on the id", func(t *testing.T) {
		if got := ruleMergeSurvivor([]ruleSurvivorFacts{base(b), base(a)}); got != a {
			t.Fatalf("survivor %s, want the lower id %s", got, a)
		}
	})
}

// Declared values are never overwritten by measured ones (guard rail 5).
//
// Mutation checks: always choose the survivor → "declared value on the other
// record" fails; always choose the declared one → "both declared" fails.
func TestRuleFieldResolutions_DeclaredWins(t *testing.T) {
	survivor, other := uuid.New(), uuid.New()
	conflict := func(field string, survivorDeclared, otherDeclared bool) MergeFieldConflict {
		// The survivor's value is listed FIRST, so a resolution that fell back
		// to "the first value" would pick it — only the declared-wins rule can
		// pick the other record.
		return MergeFieldConflict{Field: field, RequiresResolution: survivorDeclared || otherDeclared, Values: []MergeFieldValue{
			{AssetID: survivor, Value: "s", Declared: survivorDeclared},
			{AssetID: other, Value: "o", Declared: otherDeclared},
		}}
	}
	for _, tt := range []struct {
		name string
		c    MergeFieldConflict
		want uuid.UUID
	}{
		{"declared value on the survivor", conflict("display_name", true, false), survivor},
		{"declared value on the other record", conflict("display_name", false, true), other},
		{"both declared: the survivor's", conflict("environment", true, true), survivor},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleFieldResolutions(&AssetMergePreview{Conflicts: []MergeFieldConflict{tt.c}}, survivor)
			if got[tt.c.Field] != tt.want {
				t.Fatalf("%s resolved to %s, want %s", tt.c.Field, got[tt.c.Field], tt.want)
			}
		})
	}
	t.Run("a conflict needing no decision is left to the merge", func(t *testing.T) {
		got := ruleFieldResolutions(&AssetMergePreview{Conflicts: []MergeFieldConflict{conflict("primary_address", false, false)}}, survivor)
		if got != nil {
			t.Fatalf("resolved %v, want nothing", got)
		}
	})
	t.Run("survivor holds no value", func(t *testing.T) {
		c := MergeFieldConflict{Field: "site", RequiresResolution: true, Values: []MergeFieldValue{
			{AssetID: other, Value: "x", Declared: true}, {AssetID: uuid.New(), Value: "y", Declared: true}}}
		if got := ruleFieldResolutions(&AssetMergePreview{Conflicts: []MergeFieldConflict{c}}, survivor); got["site"] != other {
			t.Fatalf("site resolved to %s, want the first declared value's record %s", got["site"], other)
		}
	})
}

func TestRuleMergeReason(t *testing.T) {
	if got := ruleMergeReason([]string{"a", "b"}); got != "rule: same_device — a; b" {
		t.Errorf("reason %q", got)
	}
	long := ruleMergeReason([]string{strings.Repeat("é", 1500)})
	if len(long) > 2000 || !utf8.ValidString(long) || !strings.HasPrefix(long, ruleMergeReasonPrefix) {
		t.Errorf("long reason: %d bytes, valid UTF-8 %v", len(long), utf8.ValidString(long))
	}
}
