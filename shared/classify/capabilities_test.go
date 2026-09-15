package classify

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The three kinds workstream 2.10b added, tested for the properties that are
// easy to lose and impossible to notice: a set rule that fires on a partial
// match, a combination rule that argues with the rules it refines, and a
// protocol's vocabulary leaking into the other protocol's rules.

func capabilityEngine(t *testing.T) *Engine {
	t.Helper()
	return mustEngine(t,
		Rule{Kind: KindCDPCapabilities, Pattern: "router", Class: "router", Confidence: 0.65, SourceURL: "https://x"},
		Rule{Kind: KindCDPCapabilities, Pattern: "switch", Class: "switch", Confidence: 0.65, SourceURL: "https://x"},
		Rule{Kind: KindCDPCapabilities, Pattern: "router,switch", Class: "network_device", Confidence: 0.70, SourceURL: "https://x"},
		Rule{Kind: KindLLDPCapability, Pattern: "router", Class: "router", Confidence: 0.65, SourceURL: "https://x"},
		Rule{Kind: KindLLDPCapability, Pattern: "bridge,router", Class: "network_device", Confidence: 0.70, SourceURL: "https://x"},
		Rule{Kind: KindLLDPCapability, Pattern: "wlan_access_point", Class: "access_point", Confidence: 0.75, SourceURL: "https://x"},
	)
}

// A combination REFINES the single-capability rules under it. Without
// most-specific-wins the three CDP rules would all match a layer-3 switch, the
// top two would sit 0.05 apart, and the engine would answer "we do not know"
// for the commonest device on a corporate LAN.
func TestCapabilities_MostSpecificSetWins(t *testing.T) {
	ctx := context.Background()
	e := capabilityEngine(t)

	for _, tc := range []struct {
		name  string
		in    ClassifyInput
		class string
		rules int
	}{
		{"cdp switch only", ClassifyInput{CDPCapabilities: []string{"switch", "igmp_capable"}}, "switch", 1},
		{"cdp router only", ClassifyInput{CDPCapabilities: []string{"router"}}, "router", 1},
		// Both protocols answer the SAME thing for a device that both forwards
		// and routes: their common ancestor, because `switch` is only probably
		// right (a router with a switch module advertises the same two bits)
		// and the broad answer is certainly right. Two opposite answers for one
		// evidence shape would be a curation bug in the table itself.
		{"cdp both bits", ClassifyInput{CDPCapabilities: []string{"router", "switch", "igmp_capable"}}, "network_device", 1},
		{"lldp both bits", ClassifyInput{LLDPCapabilities: []string{"bridge", "router"}}, "network_device", 1},
		{"lldp access point", ClassifyInput{LLDPCapabilities: []string{"bridge", "wlan_access_point"}}, "access_point", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Classify(ctx, tc.in)
			if got.Class != tc.class {
				t.Errorf("Class = %q, want %q (matched %+v, conflict=%v %v)",
					got.Class, tc.class, got.MatchedRules, got.Conflict, got.ConflictingClasses)
			}
			if len(got.MatchedRules) != tc.rules {
				t.Errorf("matched %d rules, want %d: %+v", len(got.MatchedRules), tc.rules, got.MatchedRules)
			}
		})
	}
}

// CDP and 802.1AB are two views of ONE device, so the shipped table has to give
// one answer for "it forwards and it routes" — CDP `router,switch`, 802.1AB
// `bridge,router`. It gave two for a while: `switch` from CDP (transcribed from
// the Go switch statement the rules replaced) and `network_device` from LLDP,
// which meant the same Catalyst classified differently depending on which
// protocol we happened to capture.
//
// Over Default(), the SHIPPED table, because a fixture cannot catch a divergence
// somebody introduces in the YAML.
func TestCapabilities_TheTwoProtocolsAgree(t *testing.T) {
	ctx := context.Background()
	cdp := Default().Classify(ctx, ClassifyInput{CDPCapabilities: []string{"router", "switch"}})
	lldp := Default().Classify(ctx, ClassifyInput{LLDPCapabilities: []string{"bridge", "router"}})
	if cdp.Class != lldp.Class {
		t.Fatalf("a device that forwards and routes is %q over CDP and %q over 802.1AB; "+
			"one device, one answer", cdp.Class, lldp.Class)
	}
	// And the answer is the ancestor rather than either leaf: `switch` is right
	// for a layer-3 Catalyst and wrong for an ISR with a switch module, and both
	// advertise exactly these bits.
	if cdp.Class != "network_device" {
		t.Errorf("both bits classified as %q, want network_device — the broad class that is "+
			"certainly right, not the narrow one that is probably right", cdp.Class)
	}
	// A recognised product id still refines it back to the leaf; the broad
	// answer costs nothing where better evidence exists.
	refined := Default().Classify(ctx, ClassifyInput{
		Vendor: "Cisco Systems", Model: "WS-C3750X-48P",
		CDPCapabilities: []string{"router", "switch"},
	})
	if refined.Class != "switch" {
		t.Errorf("a Catalyst PID with both bits classified as %q, want switch", refined.Class)
	}
}

// `bridge` on its own means the device bridges. A switch bridges; so does an
// access point, so does a desk phone's built-in two-port switch, and so does a
// hypervisor's vSwitch. This is the single easiest wrong rule to write in the
// table, so the absence of one is pinned.
func TestLLDPCapability_BridgeAloneProposesNothing(t *testing.T) {
	got := capabilityEngine(t).Classify(context.Background(),
		ClassifyInput{LLDPCapabilities: []string{"bridge", "station_only"}})
	if !got.Unknown || got.Class != "" {
		t.Fatalf("a bare `bridge` advertisement produced %+v; it must produce no class", got)
	}
	if got.Conflict {
		t.Error("reported a conflict; nothing matched at all, which is a different answer")
	}
}

// The two protocols use different words for overlapping ideas. A rule written
// for one must not fire on the other's advertisement — CDP's `switch` and
// 802.1AB's `bridge` are not the same claim.
func TestCapabilities_OneProtocolsRulesNeverFireOnTheOthers(t *testing.T) {
	ctx := context.Background()
	e := capabilityEngine(t)

	// `switch` exists only as a CDP rule. Advertised over LLDP (which has no
	// such capability), it must match nothing.
	if got := e.Classify(ctx, ClassifyInput{LLDPCapabilities: []string{"switch"}}); !got.Unknown {
		t.Errorf("a CDP rule fired on an LLDP advertisement: %+v", got)
	}
	// `wlan_access_point` exists only as an LLDP rule.
	if got := e.Classify(ctx, ClassifyInput{CDPCapabilities: []string{"wlan_access_point"}}); !got.Unknown {
		t.Errorf("an LLDP rule fired on a CDP advertisement: %+v", got)
	}
}

// Two single-capability rules proposing unrelated classes for one device is a
// real disagreement, and the arbitration — not the matcher — is where it
// belongs. The matcher returns both; the engine then refuses to choose.
func TestCapabilities_ATieIsLeftToTheArbitration(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindLLDPCapability, Pattern: "router", Class: "router", Confidence: 0.65, SourceURL: "https://x"},
		Rule{Kind: KindLLDPCapability, Pattern: "telephone", Class: "printer", Confidence: 0.65, SourceURL: "https://x"},
	)
	got := e.Classify(context.Background(), ClassifyInput{LLDPCapabilities: []string{"router", "telephone"}})
	if !got.Conflict || got.Class != "" {
		t.Fatalf("got %+v, want no class and a reported conflict", got)
	}
	if len(got.ConflictingClasses) != 2 {
		t.Errorf("ConflictingClasses = %v, want both", got.ConflictingClasses)
	}
}

// The engine takes the service type as the decoder files it. The normalisations
// it does apply are the ones a producer could plausibly get wrong in a way that
// would match NOTHING and say nothing.
func TestMDNSService_NormalisesWhatTheWireCarries(t *testing.T) {
	ctx := context.Background()
	e := mustEngine(t,
		Rule{Kind: KindMDNSService, Pattern: "_ipp._tcp", Class: "printer", Confidence: 0.75, SourceURL: "https://x"},
	)
	for _, advertised := range []string{"_ipp._tcp", "_IPP._TCP", "_ipp._tcp.", "_ipp._tcp.local.", " _ipp._tcp "} {
		if got := e.Classify(ctx, ClassifyInput{MDNSServices: []string{advertised}}); got.Class != "printer" {
			t.Errorf("%q classified as %+v, want printer", advertised, got)
		}
	}
	// And it does not reach for a prefix: `_ipp-tls._tcp` is a different
	// service and must not match the IPP rule.
	if got := e.Classify(ctx, ClassifyInput{MDNSServices: []string{"_ipp-tls._tcp"}}); !got.Unknown {
		t.Errorf("_ipp-tls._tcp matched the _ipp._tcp rule: %+v", got)
	}
}

// --- the lenient load contract ---------------------------------------------

// One bad row from the admin console must cost that row and nothing else. The
// classifier going silent for a whole deployment because somebody typed a
// pattern wrong is the failure this contract exists to prevent.
func TestNew_SkipsABadRuleAndKeepsTheRest(t *testing.T) {
	good := Rule{Kind: KindMDNSService, Pattern: "_ipp._tcp", Class: "printer", Confidence: 0.75, SourceURL: "https://x"}
	bad := Rule{Kind: KindMDNSService, Pattern: "IPP", Class: "printer", Confidence: 0.75, SourceURL: "https://x", ID: "row-42"}

	e, skipped, err := New([]Rule{good, bad})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.Len() != 1 {
		t.Errorf("engine holds %d rules, want 1 — the good rule must survive its neighbour", e.Len())
	}
	if len(skipped) != 1 {
		t.Fatalf("skipped %d rules, want 1", len(skipped))
	}
	if skipped[0].Rule.ID != "row-42" {
		t.Errorf("skipped rule id = %q, want row-42 — the report has to NAME the row an admin must fix", skipped[0].Rule.ID)
	}
	if skipped[0].Err == nil || !strings.Contains(skipped[0].Err.Error(), "mdns_service") {
		t.Errorf("skip reason = %v, want it to say what was wrong", skipped[0].Err)
	}
	// And it still classifies, against the rule that was fine.
	if got := e.Classify(context.Background(), ClassifyInput{MDNSServices: []string{"_ipp._tcp"}}); got.Class != "printer" {
		t.Errorf("after skipping a bad row the engine answered %+v", got)
	}
}

// NewStrict keeps the old contract, and it is what the GENERATED table is built
// with: there a bad row is a bug in the generator, and carrying on with 563 of
// 564 rules would hide it.
func TestNewStrict_StillRefusesTheWholeSet(t *testing.T) {
	bad := Rule{Kind: KindMDNSService, Pattern: "IPP", Class: "printer", Confidence: 0.75, SourceURL: "https://x"}
	good := Rule{Kind: KindMDNSService, Pattern: "_ipp._tcp", Class: "printer", Confidence: 0.75, SourceURL: "https://x"}
	if _, err := NewStrict([]Rule{good, bad}); err == nil {
		t.Fatal("NewStrict accepted a set containing an invalid rule")
	}
}

// --- the runtime loader -----------------------------------------------------

type stubRepo struct {
	rules []Rule
	err   error
	calls int
}

func (s *stubRepo) ListRules(context.Context) ([]Rule, error) {
	s.calls++
	return s.rules, s.err
}

// A curated table that cannot be read leaves the compiled-in rules in place and
// SAYS SO. Falling silently back would un-apply every rule an admin ever added
// at the moment the database is least able to explain itself.
func TestRefresher_UnreadableTableFallsBackLoudly(t *testing.T) {
	var lines []string
	r := NewRefresher(context.Background(), &stubRepo{err: errors.New("connection refused")},
		DefaultRefreshInterval, func(f string, _ ...any) { lines = append(lines, f) })

	if r.Engine() != Default() {
		t.Error("a failed first load must leave the compiled-in engine in place")
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "compiled-in") {
		t.Errorf("logged %v, want one line naming the fallback", lines)
	}
}

// A LATER failure keeps the engine already loaded, and does NOT drop back to the
// compiled-in table.
//
// This is the half of the contract the first-load test cannot reach, and it is
// the half that matters in a running deployment: dropping to Default() here would
// silently un-apply every rule an admin ever added, at the moment the database is
// least able to explain itself. It would also be invisible — the classifier goes
// on classifying, just against different rules.
func TestRefresher_ALaterFailureKeepsWhatItHas(t *testing.T) {
	var lines []string
	repo := &stubRepo{rules: []Rule{
		{Kind: KindMDNSService, Pattern: "_ipp._tcp", Class: "printer", Confidence: 0.75, SourceURL: "https://x"},
	}}
	r := NewRefresher(context.Background(), repo, DefaultRefreshInterval,
		func(f string, _ ...any) { lines = append(lines, f) })
	curated := r.Engine()
	if curated.Len() != 1 {
		t.Fatalf("first load holds %d rules, want the curated 1", curated.Len())
	}

	repo.err = errors.New("connection refused")
	r.reload(context.Background(), false)

	if got := r.Engine(); got != curated {
		t.Errorf("a failed reload swapped the engine (%d rules, curated had %d); the curated "+
			"table must stay in force", got.Len(), curated.Len())
	}
	if r.Engine() == Default() {
		t.Error("a failed reload fell back to the compiled-in table, un-applying every rule an admin added")
	}
	if len(lines) != 1 || !strings.Contains(lines[len(lines)-1], "keeping") {
		t.Errorf("logged %v, want a line saying the loaded rules were kept", lines)
	}
	// And it still classifies against the curated rules.
	if got := r.Engine().Classify(context.Background(),
		ClassifyInput{MDNSServices: []string{"_ipp._tcp"}}); got.Class != "printer" {
		t.Errorf("after a failed reload the engine answered %+v", got)
	}
}

// The skips are reported per row, by kind and pattern. "3 rules were skipped"
// is not something an admin can act on.
func TestRefresher_NamesEverySkippedRow(t *testing.T) {
	var lines []string
	repo := &stubRepo{rules: []Rule{
		{Kind: KindMDNSService, Pattern: "_ipp._tcp", Class: "printer", Confidence: 0.75, SourceURL: "https://x"},
		{Kind: KindOUI, Pattern: "nothex", Vendor: "Nobody", Confidence: 0.85, SourceURL: "https://x"},
	}}
	r := NewRefresher(context.Background(), repo, DefaultRefreshInterval,
		func(f string, _ ...any) { lines = append(lines, f) })

	if r.Engine().Len() != 1 {
		t.Errorf("engine holds %d rules, want 1", r.Engine().Len())
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "skipping classification rule") {
		t.Fatalf("logged %v, want one per-row skip line", lines)
	}
}

func TestRefreshIntervalFromEnv(t *testing.T) {
	for _, tc := range []struct {
		set     string
		want    string
		fromEnv bool
	}{
		{"", DefaultRefreshInterval.String(), false},
		{"30s", "30s", true},
		{"2h0m0s", "2h0m0s", true},
		// An operator who typed a bare number meant a duration and did not get
		// one. The fallback is the same as unset, and `false` is what lets the
		// caller say so rather than leaving them to infer it from behaviour.
		{"5", DefaultRefreshInterval.String(), false},
		{"-1m", DefaultRefreshInterval.String(), false},
		{"nonsense", DefaultRefreshInterval.String(), false},
	} {
		t.Run(tc.set, func(t *testing.T) {
			t.Setenv(RefreshEnvVar, tc.set)
			got, fromEnv := RefreshIntervalFromEnv()
			if got.String() != tc.want || fromEnv != tc.fromEnv {
				t.Errorf("got %v/%v, want %v/%v", got, fromEnv, tc.want, tc.fromEnv)
			}
		})
	}
}
