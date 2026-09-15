package producers

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/findings"
)

// The configuration rule table's PRECEDENCE contract.
//
// `matchConfigurationRules` returns at most one match per kind, and the rule
// that wins is the FIRST one in the table. That is a decision, not an accident
// of iteration, and until now it was only a comment.
//
// The findings table forces at-most-one: `findings_open_subject_uniq` permits
// one open row per (producer, kind, subject), so a second match on the same
// endpoint could not be stored anyway. What is NOT forced is WHICH one — and a
// map-order winner would make the surviving finding change between passes on a
// host nothing changed about, rewriting its summary and its evidence every
// night and making the history unreadable.
//
// First-match-wins is kept over "most specific wins" because "most specific"
// has no definition over this table: the rules match on different axes (a name
// run, a port, a transport) and there is no ordering between "matched the name
// redis" and "matched port 11211". A hand-ordered table is a decision a
// reviewer can see in a diff; a specificity metric is one they would have to
// re-derive on every change.

func TestMatchConfigurationRules_FirstRuleInTheTableWins(t *testing.T) {
	// A service string carrying the needles of TWO insecure-exposure rules.
	// Contrived — no real banner says this — which is the point: the ordering
	// must be decided by the table, not by whichever case happens to occur.
	ep := endpointFacts{ServiceName: "redis memcached", Port: 6379, Transport: "tcp"}

	got := matchConfigurationRules(ep)
	if len(got) != 1 {
		t.Fatalf("%d matches for one kind on one endpoint, want 1: %+v", len(got), got)
	}
	if got[0].Rule.ID != "expose-redis" {
		t.Errorf("rule %q won, want expose-redis — it is first in the table for its kind, and the "+
			"table's order IS the precedence", got[0].Rule.ID)
	}

	// Reversing the endpoint's word order must not reverse the winner.
	ep.ServiceName = "memcached redis"
	got = matchConfigurationRules(ep)
	if len(got) != 1 || got[0].Rule.ID != "expose-redis" {
		t.Errorf("the winner followed the ENDPOINT's word order (%+v); precedence belongs to the "+
			"table", got)
	}
}

// The table's order within each kind IS the precedence, so a reorder is a
// behaviour change and has to look like one in review.
//
// Pinned as the exact ID sequence rather than as a property, because the
// property ("the first match wins") is pinned above and says nothing about
// which rule that is. Moving expose-redis below expose-memcached is a
// legitimate decision; making it silently is not.
func TestConfigurationRules_TableOrderIsTheContract(t *testing.T) {
	want := map[string][]string{
		findings.KindPlaintextManagement: {
			"mgmt-telnet", "mgmt-ftp", "mgmt-snmp-v1", "mgmt-snmp-v2c",
		},
		findings.KindInsecureServiceExposed: {
			"expose-redis", "expose-memcached", "expose-mongodb", "expose-elasticsearch",
			"expose-etcd", "expose-couchdb", "expose-docker-api", "expose-kubelet-readonly",
			"expose-rsh", "expose-tftp", "expose-nfs", "expose-rpcbind",
		},
	}
	got := map[string][]string{}
	for _, r := range configurationRules {
		got[r.Kind] = append(got[r.Kind], r.ID)
	}
	if len(got) != len(want) {
		t.Fatalf("the table covers %d kinds, this test pins %d", len(got), len(want))
	}
	for kind, wantIDs := range want {
		gotIDs := got[kind]
		if len(gotIDs) != len(wantIDs) {
			t.Errorf("%s: %d rules, want %d\n got %v\nwant %v", kind, len(gotIDs), len(wantIDs), gotIDs, wantIDs)
			continue
		}
		for i := range wantIDs {
			if gotIDs[i] != wantIDs[i] {
				t.Errorf("%s rule %d is %q, want %q — the order is the precedence",
					kind, i, gotIDs[i], wantIDs[i])
			}
		}
	}
}

// Why first-match-wins is unreachable from the PORT signal today: no two
// PortAlone rules of one kind claim the same (port, transport).
//
// Scoped to PortAlone deliberately. `mgmt-snmp-v1` and `mgmt-snmp-v2c` both
// list 161/udp and neither may fire on it — the port cannot tell v1 from v2c
// from v3, and v3 with authPriv is the fix this finding asks for, so both carry
// `PortAlone: false` and only a measured name fires them. Their shared port is
// documentation of what the rule is about, not a claim on the socket, and a
// check that counted it would be the over-strict polarity: it would reject a
// correct table.
//
// This is the invariant a reviewer leans on when adding a rule, so it is
// checked rather than asserted in prose. If it breaks, the precedence test
// above stops being theoretical — which is fine, and this failing is how
// anybody would find out.
func TestConfigurationRules_NoTwoPortRulesOfOneKindClaimTheSameSocket(t *testing.T) {
	type claim struct {
		port      int
		transport string
	}
	seen := map[string]map[claim]string{}
	for _, r := range configurationRules {
		if !r.PortAlone {
			continue
		}
		if seen[r.Kind] == nil {
			seen[r.Kind] = map[claim]string{}
		}
		for _, p := range r.Ports {
			for _, tr := range []string{"tcp", "udp"} {
				if r.Transport != "" && r.Transport != tr {
					continue
				}
				c := claim{port: p, transport: tr}
				if other, taken := seen[r.Kind][c]; taken {
					t.Errorf("%s and %s both claim %s/%d for kind %s — the table's order now decides "+
						"which finding a real endpoint gets", other, r.ID, tr, p, r.Kind)
				}
				seen[r.Kind][c] = r.ID
			}
		}
	}
}
