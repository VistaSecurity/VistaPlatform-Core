package approval

import (
	"net/netip"
	"testing"

	"github.com/google/uuid"
)

// TestEvaluator_ReadsPrefixFirst is the prefix precedence (rows 1.4, 1.6):
// when the observation's address is in a prefix with rules of its own, those
// rules decide and an unscoped rule gets no second vote.
//
// Mutation: delete the prefixFirst call in EvaluateAutoApprovalWithRules and
// the first case goes red — the unscoped rule approves an observation the
// prefix's own rule declined.
func TestEvaluator_ReadsPrefixFirst(t *testing.T) {
	svc := NewService(nil)
	tenant := uuid.New()
	prefix := uuid.New()
	broad := &Rule{ID: uuid.New(), TenantID: tenant, Name: "broad", IsActive: true,
		Query: "network.ownership:internal"}
	prefixRule := &Rule{ID: uuid.New(), TenantID: tenant, Name: "prefix", IsActive: true,
		Query: "network.prefix_id = " + prefix.String() + " and confidence >= 0.9"}
	rules := []*Rule{broad, prefixRule}

	cls := func(p *uuid.UUID) *Classification {
		return &Classification{Ownership: "internal", Type: "private", PrefixID: p}
	}
	obs := func(conf float64) Discovery {
		return Discovery{TenantID: tenant, Address: "10.70.0.5"}.WithConfidence(conf)
	}

	ok, id, err := svc.EvaluateAutoApprovalWithRules(rules, obs(0.5), cls(&prefix))
	if err != nil || ok {
		t.Fatalf("in a prefix whose rule declines: approved=%v by %v (err %v); want the prefix rule to decide no", ok, id, err)
	}
	ok, id, err = svc.EvaluateAutoApprovalWithRules(rules, obs(0.95), cls(&prefix))
	if err != nil || !ok || id == nil || *id != prefixRule.ID {
		t.Fatalf("in a prefix whose rule accepts: approved=%v by %v (err %v); want the prefix rule", ok, id, err)
	}
	// No prefix on the observation: the other rules answer.
	ok, id, err = svc.EvaluateAutoApprovalWithRules(rules, obs(0.5), cls(nil))
	if err != nil || !ok || id == nil || *id != broad.ID {
		t.Fatalf("outside any prefix: approved=%v by %v (err %v); want the broad rule", ok, id, err)
	}
	// A prefix with no rule of its own leaves the decision to the rest.
	other := uuid.New()
	ok, id, err = svc.EvaluateAutoApprovalWithRules(rules, obs(0.5), cls(&other))
	if err != nil || !ok || id == nil || *id != broad.ID {
		t.Fatalf("in a prefix with no rule: approved=%v by %v (err %v); want the broad rule", ok, id, err)
	}
}

// TestObservationFields_PrefixVRFInterface: the three row-1.4 fields read what
// the classification and discovery carry, and are ABSENT (no match) when they
// carry nothing.
func TestObservationFields_PrefixVRFInterface(t *testing.T) {
	svc := NewService(nil)
	tenant := uuid.New()
	prefix, vrf, iface := uuid.New(), uuid.New(), uuid.New()
	for _, c := range []struct {
		query string
	}{
		{"network.prefix_id = " + prefix.String()},
		{"network.vrf_id = " + vrf.String()},
		{"interface_id = " + iface.String()},
	} {
		rule := &Rule{ID: uuid.New(), TenantID: tenant, IsActive: true, Query: c.query}
		d := Discovery{TenantID: tenant, InterfaceID: &iface}
		ok, _, err := svc.EvaluateAutoApprovalWithRules([]*Rule{rule}, d,
			&Classification{Ownership: "internal", PrefixID: &prefix, VRFID: &vrf})
		if err != nil || !ok {
			t.Errorf("%s: approved=%v err=%v, want a match", c.query, ok, err)
		}
		ok, _, err = svc.EvaluateAutoApprovalWithRules([]*Rule{rule}, Discovery{TenantID: tenant},
			&Classification{Ownership: "internal"})
		if err != nil || ok {
			t.Errorf("%s with nothing carried: approved=%v err=%v, want no match", c.query, ok, err)
		}
	}
}

func TestPrefixSet_LongestMatchAndAmbiguity(t *testing.T) {
	outer, inner, twinA, twinB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	s := NewPrefixSet([]Prefix{
		{ID: outer, Prefix: netip.MustParsePrefix("10.71.0.0/16")},
		{ID: inner, Prefix: netip.MustParsePrefix("10.71.4.0/24")},
		{ID: twinA, Prefix: netip.MustParsePrefix("10.72.0.0/24")},
		{ID: twinB, Prefix: netip.MustParsePrefix("10.72.0.0/24")},
	})
	if p := s.Match("10.71.4.9"); p == nil || p.ID != inner {
		t.Errorf("10.71.4.9 matched %+v, want the /24", p)
	}
	if p := s.Match("10.71.9.9"); p == nil || p.ID != outer {
		t.Errorf("10.71.9.9 matched %+v, want the /16", p)
	}
	if p := s.Match("10.72.0.1"); p != nil {
		t.Errorf("an ambiguous longest match chose %+v, want none", p)
	}
	if p := s.Match("192.0.2.1"); p != nil {
		t.Errorf("an address in no prefix matched %+v", p)
	}
	if p := s.Match("not-an-address"); p != nil {
		t.Errorf("a non-address matched %+v", p)
	}
	var c Classification
	c.Apply(s.Match("10.71.4.9"))
	if c.PrefixID == nil || *c.PrefixID != inner {
		t.Errorf("Apply recorded %v, want %s", c.PrefixID, inner)
	}
}
