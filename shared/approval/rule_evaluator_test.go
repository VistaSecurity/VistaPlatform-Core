package approval

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// segmentRule builds the rule inventory-service's ManageAutoApprovalRules writes
// for a network segment whose auto-approve toggle is ON. Keep this in step with
// that writer — it is the only producer of these rows.
//
// The query is written out here rather than generated, on purpose: if the
// writer's shape changes, these tests should stop describing it loudly rather
// than quietly follow it.
func segmentRule(segmentID uuid.UUID, active bool) *Rule {
	return ruleWithQuery(
		"source:sensor and network.ownership:internal and network.type:private and network.segment_id="+segmentID.String(),
		active)
}

func ruleWithQuery(q string, active bool) *Rule {
	return &Rule{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Name:     "Auto-approve sensor discoveries: 203.0.113.0/24",
		Query:    q,
		IsActive: active,
	}
}

// onSegment is the classification a discovery gets when its address falls
// inside a registered tenant segment.
func onSegment(segmentID uuid.UUID) *Classification {
	return &Classification{
		Ownership: "internal",
		Type:      "private",
		SegmentID: &segmentID,
	}
}

// TestSegmentRuleQueryValidates is the write-time half, and the thing the jsonb
// shape could not have: the rule the writer produces must be a legal query. A
// misspelled field is now a refusal instead of a condition that silently
// evaporates.
func TestSegmentRuleQueryValidates(t *testing.T) {
	canonical, err := ValidateRuleQuery(segmentRule(uuid.New(), true).Query)
	if err != nil {
		t.Fatalf("the generated segment rule does not validate: %v", err)
	}
	if canonical == "" {
		t.Fatal("a non-empty rule must canonicalize to non-empty text")
	}

	if _, err := ValidateRuleQuery("network_ownershp:internal"); err == nil {
		t.Fatal("a misspelled field must be refused; the jsonb form ignored it and produced a WIDER rule")
	}
	if _, err := ValidateRuleQuery(""); err != nil {
		t.Fatalf("an empty rule matches everything and is legal, got %v", err)
	}
}

// TestSegmentAutoApprovalContract pins the one gate on auto-approval: the
// discovery is on a user-defined segment whose auto-approve toggle is on.
// Both polarities, because a guard that can only pass is not a guard.
func TestSegmentAutoApprovalContract(t *testing.T) {
	svc := NewService(nil) // the WithRules path never touches the DB
	segmentID := uuid.New()
	otherSegmentID := uuid.New()
	discovery := Discovery{TenantID: uuid.New()}.WithConfidence(0.9)

	t.Run("auto-approve on, discovery on that segment → approved", func(t *testing.T) {
		rule := segmentRule(segmentID, true)
		approved, ruleID, err := svc.EvaluateAutoApprovalWithRules(
			[]*Rule{rule}, discovery, onSegment(segmentID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !approved {
			t.Fatal("expected auto-approval for a discovery on an auto-approve segment")
		}
		if ruleID == nil || *ruleID != rule.ID {
			t.Fatalf("expected the matching rule id %s, got %v", rule.ID, ruleID)
		}
	})

	t.Run("no rule at all → not approved", func(t *testing.T) {
		approved, ruleID, err := svc.EvaluateAutoApprovalWithRules(
			nil, discovery, onSegment(segmentID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if approved || ruleID != nil {
			t.Fatalf("expected default-deny with no rules, got approved=%v ruleID=%v", approved, ruleID)
		}
	})

	t.Run("rule inactive → not approved", func(t *testing.T) {
		approved, _, err := svc.EvaluateAutoApprovalWithRules(
			[]*Rule{segmentRule(segmentID, false)}, discovery, onSegment(segmentID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if approved {
			t.Fatal("an inactive rule must not auto-approve")
		}
	})

	t.Run("rule for a different segment → not approved", func(t *testing.T) {
		approved, _, err := svc.EvaluateAutoApprovalWithRules(
			[]*Rule{segmentRule(otherSegmentID, true)}, discovery, onSegment(segmentID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if approved {
			t.Fatal("a rule scoped to another segment must not auto-approve")
		}
	})

	t.Run("discovery on no segment → not approved", func(t *testing.T) {
		approved, _, err := svc.EvaluateAutoApprovalWithRules(
			[]*Rule{segmentRule(segmentID, true)}, discovery,
			&Classification{Ownership: "unknown", Type: "private"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if approved {
			t.Fatal("a discovery matching no segment must not auto-approve")
		}
	})

	t.Run("third-party ownership is never approved", func(t *testing.T) {
		approved, _, err := svc.EvaluateAutoApprovalWithRules(
			[]*Rule{segmentRule(segmentID, true)}, discovery,
			&Classification{Ownership: "third_party", Type: "public", SegmentID: &segmentID})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if approved {
			t.Fatal("third-party discoveries must never enter the asset approval pipeline")
		}
	})
}

func TestEvaluateRuleSourceAndConfidence(t *testing.T) {
	e := NewRuleEvaluator()
	segmentID := uuid.New()

	cloudDiscovery := Discovery{
		TenantID: uuid.New(),
		Metadata: []byte(`{"discovery_method":"cloud_api","cloud_provider":"aws","cloud_region":"us-east-1"}`),
	}
	sensorDiscovery := Discovery{TenantID: uuid.New()}.WithConfidence(0.9)

	t.Run("a sensor rule skips a cloud discovery", func(t *testing.T) {
		matched, err := e.EvaluateRule(segmentRule(segmentID, true), cloudDiscovery, onSegment(segmentID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if matched {
			t.Fatal("a source:sensor rule must not match a cloud discovery")
		}
	})

	// The cloud and any-source forms were unreachable until the segment rule
	// gained a per-source setting: both writers hard-coded the sensor form and
	// nothing else could author a rule. These pin them as live code, in both
	// polarities.
	cloudRule := func() *Rule {
		return ruleWithQuery("source:cloud and network.ownership:internal and network.segment_id="+segmentID.String(), true)
	}

	t.Run("a cloud rule matches a cloud discovery", func(t *testing.T) {
		matched, err := e.EvaluateRule(cloudRule(), cloudDiscovery, onSegment(segmentID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !matched {
			t.Fatal("a cloud rule did not match a cloud discovery — the branch is dead code again")
		}
	})

	t.Run("a cloud rule skips a sensor discovery", func(t *testing.T) {
		matched, err := e.EvaluateRule(cloudRule(), sensorDiscovery, onSegment(segmentID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if matched {
			t.Fatal("a cloud-only rule matched a sensor discovery")
		}
	})

	t.Run("no source term matches both sources", func(t *testing.T) {
		// §8: `source: all` has no equivalent term, because "any source" is the
		// ABSENCE of a constraint. This is what the writer emits for a segment
		// covering both.
		anySource := ruleWithQuery("network.ownership:internal and network.segment_id="+segmentID.String(), true)
		for name, d := range map[string]Discovery{"cloud": cloudDiscovery, "sensor": sensorDiscovery} {
			matched, err := e.EvaluateRule(anySource, d, onSegment(segmentID))
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", name, err)
			}
			if !matched {
				t.Fatalf("a rule with no source term did not match the %s discovery", name)
			}
		}
	})

	t.Run("a confidence floor is enforced", func(t *testing.T) {
		rule := ruleWithQuery(
			"network.ownership:internal and network.segment_id="+segmentID.String()+" and confidence >= 0.8", true)

		low, err := e.EvaluateRule(rule, Discovery{}.WithConfidence(0.5), onSegment(segmentID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if low {
			t.Fatal("a discovery below the floor must not match")
		}

		high, err := e.EvaluateRule(rule, Discovery{}.WithConfidence(0.9), onSegment(segmentID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !high {
			t.Fatal("a discovery above the floor must match")
		}
	})

	// §5.2, and the reason Confidence is a pointer: a rule about something
	// nobody measured is UNKNOWN, and Unknown does not match. A `float64` zero
	// value would have made this indistinguishable from a measured 0.0, and the
	// answer would have been "definitely below the floor" — right by accident
	// here, and wrong the moment the predicate is `confidence < 0.5`.
	t.Run("an unmeasured confidence matches NEITHER the floor nor its negation", func(t *testing.T) {
		unscored := Discovery{TenantID: uuid.New()}
		for _, q := range []string{"confidence >= 0.8", "not confidence >= 0.8", "confidence < 0.8"} {
			rule := ruleWithQuery("network.segment_id="+segmentID.String()+" and "+q, true)
			matched, err := e.EvaluateRule(rule, unscored, onSegment(segmentID))
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", q, err)
			}
			if matched {
				t.Fatalf("%q matched a discovery whose confidence nobody recorded", q)
			}
		}
	})
}

// TestRuleThatDoesNotValidateNeverMatches is the fail-closed direction: a rule
// whose query the language refuses must never approve anything, and the caller
// must be told rather than left with a silent no.
func TestRuleThatDoesNotValidateNeverMatches(t *testing.T) {
	e := NewRuleEvaluator()
	rule := ruleWithQuery("hostnaem:web-1", true)

	matched, err := e.EvaluateRule(rule, Discovery{}, onSegment(uuid.New()))
	if matched {
		t.Fatal("a rule that does not validate must not match")
	}
	if err == nil {
		t.Fatal("a rule that does not validate must report why, not just decline")
	}
	if !strings.Contains(err.Error(), "unknown_field") {
		t.Fatalf("the error should name the language diagnostic, got %v", err)
	}

	// Compiled once: the second call returns the SAME cached failure rather
	// than re-parsing per discovery in a batch of a thousand.
	if _, err2 := e.EvaluateRule(rule, Discovery{}, onSegment(uuid.New())); err2 == nil {
		t.Fatal("the cached failure must survive a second evaluation")
	}
}

// TestEmptyRuleMatchesEverything: a rule with no conditions auto-approves every
// observation. That is deliberately expressible — and deliberately something a
// person has to write — so it is pinned rather than left to be discovered.
func TestEmptyRuleMatchesEverything(t *testing.T) {
	e := NewRuleEvaluator()
	matched, err := e.EvaluateRule(ruleWithQuery("", true), Discovery{}, &Classification{Ownership: "internal"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Fatal("an empty rule matches every observation")
	}
}

// TestSegmentIDFromQuery pins the lookup inventory-service uses to find the
// rule it owns for a segment — including the spellings a text match would miss.
func TestSegmentIDFromQuery(t *testing.T) {
	id := uuid.New()
	for _, q := range []string{
		"network.segment_id=" + id.String(),
		"source:sensor and network.segment_id = " + id.String(),
		`network.segment_id="` + id.String() + `"`,
		"network.segment_id:" + id.String(),
	} {
		got, ok := SegmentIDFromQuery(q)
		if !ok || got != id {
			t.Fatalf("%q: got (%v, %v), want (%v, true)", q, got, ok, id)
		}
	}
	for _, q := range []string{"", "source:sensor", "network.segment_id=not-a-uuid", "((("} {
		if _, ok := SegmentIDFromQuery(q); ok {
			t.Fatalf("%q should name no segment", q)
		}
	}
}

// The kind vocabulary this package spells and the catalogue's closed value set
// are the same two strings.
//
// [rule_evaluator.go]'s doc comment on KindCrypto/KindHostObservation has
// promised this test by name since the constants landed, and it did not exist —
// which is the "a check that cannot fail" shape twice over: a named guard that
// is not there reads, to anyone grepping, exactly like one that is.
//
// The drift it guards is silent in both directions. Widen the catalogue's enum
// and nothing here refuses the new value, so a rule can be written about a kind
// no producer ever states — Unknown for every finding, an auto-approval rule
// that can never fire. Rename a constant and the rules a tenant already stored
// keep validating (the catalogue still knows the old spelling) while
// [observationSource.Field] now hands back the new one, so every
// `kind:host_observation` rule silently stops matching the rows it names.
//
// Mutation check: change either constant, or add a value to
// observationKindValues, and this fails.
func TestObservationKindVocabularyMatchesCatalogue(t *testing.T) {
	var enum []string
	for _, f := range ruleCatalog().Fields(ObservationTarget) {
		if f.Name == "kind" {
			enum = f.Enum
			break
		}
	}
	if enum == nil {
		t.Fatal("the observation target publishes no `kind` field; a rule cannot name what an observation IS")
	}

	want := map[string]bool{KindCrypto: false, KindHostObservation: false}
	for _, v := range enum {
		seen, known := want[v]
		if !known {
			t.Errorf("the catalogue publishes kind %q, which no constant in this package spells — a rule could name a kind nothing states", v)
			continue
		}
		if seen {
			t.Errorf("the catalogue publishes kind %q twice", v)
		}
		want[v] = true
	}
	for v, seen := range want {
		if !seen {
			t.Errorf("this package spells kind %q and the catalogue does not publish it — rules naming it are refused at write time", v)
		}
	}
}

// A rule can be written about either kind, and about neither by accident.
//
// TestObservationKindVocabularyMatchesCatalogue pins the two vocabularies to
// each other; this pins them to the thing that actually reads them, which is a
// rule going through the real validator and the real evaluator.
func TestObservationKindIsAPredicateARuleCanWrite(t *testing.T) {
	for _, kind := range []string{KindCrypto, KindHostObservation} {
		t.Run(kind, func(t *testing.T) {
			if _, err := ValidateRuleQuery("kind:" + kind); err != nil {
				t.Fatalf("a rule naming kind %q was refused at write time: %v", kind, err)
			}
		})
	}

	// The value set is closed, so a kind nobody states is a refusal with a
	// span rather than a rule that silently never fires.
	if _, err := ValidateRuleQuery("kind:spreadsheet"); err == nil {
		t.Error("a rule naming a kind no producer states was accepted; it would never match anything")
	}

	ev := NewRuleEvaluator()
	rule := ruleWithQuery("kind:"+KindHostObservation, true)
	cls := &Classification{Ownership: "unknown", Type: "private"}

	match, err := ev.EvaluateRule(rule, Discovery{}.WithKind(KindHostObservation), cls)
	if err != nil {
		t.Fatalf("evaluating a kind rule: %v", err)
	}
	if !match {
		t.Error("a kind:host_observation rule did not match a host observation")
	}

	match, err = ev.EvaluateRule(rule, Discovery{}.WithKind(KindCrypto), cls)
	if err != nil {
		t.Fatalf("evaluating a kind rule against a crypto finding: %v", err)
	}
	if match {
		t.Error("a kind:host_observation rule matched a crypto finding — `kind` is the only thing that separates them, since both are source:sensor")
	}

	// Absent is Unknown, not false (QUERY_LANGUAGE §5.2): the declared and
	// imported intake paths state no kind, and a rule about kinds must not fire
	// on them.
	match, err = ev.EvaluateRule(rule, Discovery{}, cls)
	if err != nil {
		t.Fatalf("evaluating a kind rule against an unstated kind: %v", err)
	}
	if match {
		t.Error("a kind rule matched an observation whose kind nobody stated")
	}

	// And the NEGATED form does not match it either, which is the assertion
	// that tells Unknown apart from false. A positive predicate fails to match
	// under both readings, so it cannot see the difference; `not kind:X` can —
	// NOT Unknown is Unknown and still does not fire, where NOT false would.
	//
	// Mutation check: make [observationSource.Field] report `kind` as PRESENT
	// for the empty string (`return s.d.Kind, true`) and this fails, because a
	// spreadsheet row would start auto-approving on "everything that is not a
	// host observation".
	negated := ruleWithQuery("not kind:"+KindHostObservation, true)
	match, err = ev.EvaluateRule(negated, Discovery{}, cls)
	if err != nil {
		t.Fatalf("evaluating a negated kind rule against an unstated kind: %v", err)
	}
	if match {
		t.Error("`not kind:host_observation` matched an observation whose kind nobody stated; absent must stay Unknown under negation (§5.2), not become true")
	}
	// The same negation DOES fire on a stated, different kind — otherwise the
	// assertion above would be satisfied by a rule that can never match.
	match, err = ev.EvaluateRule(negated, Discovery{}.WithKind(KindCrypto), cls)
	if err != nil {
		t.Fatalf("evaluating a negated kind rule against a crypto finding: %v", err)
	}
	if !match {
		t.Error("`not kind:host_observation` did not match a finding stated as crypto")
	}
}

// A passive host observation is `source:sensor`, so the rules a tenant already
// has keep firing.
//
// The envelope for one of these carries `discovery_method:
// "passive_host_observation"` — the sensor's own method string, and a value
// normaliseSource did not know until workstream 2.5. An unrecognised method
// yields the EMPTY string, which is absent, not a fallback: `source` is then
// Unknown, and every segment rule a tenant had written (`source:sensor and
// network.segment_id=…`) would have silently stopped auto-approving the moment
// these rows started arriving, with nothing anywhere reporting it.
//
// Silent is the operative word and is why this is worth a test of its own. The
// symptom is the ABSENCE of approvals — a queue that fills instead of draining
// — which looks like "the sensor found more things" rather than like a bug.
//
// Mutation check: remove "passive_host_observation" from normaliseSource's
// sensor case and this fails.
func TestPassiveHostObservationIsASensorSource(t *testing.T) {
	rule := ruleWithQuery("source:sensor", true)
	ev := NewRuleEvaluator()
	cls := &Classification{Ownership: "unknown", Type: "private"}

	obs := Discovery{
		Metadata: []byte(`{"discovery_method":"passive_host_observation"}`),
	}.WithKind(KindHostObservation)

	match, err := ev.EvaluateRule(rule, obs, cls)
	if err != nil {
		t.Fatalf("evaluating a source rule against a host observation: %v", err)
	}
	if !match {
		t.Error("a `source:sensor` rule did not match a passive host observation; every existing segment rule would stop auto-approving the moment these rows arrive")
	}

	// Directly, too, so the failure names the mapping rather than the rule.
	if got, known := normaliseSource("passive_host_observation"); !known || got != "sensor" {
		t.Errorf("normaliseSource(passive_host_observation) = %q (known=%v), want sensor", got, known)
	}

	// And `source` alone still cannot single host observations out — which is
	// the whole reason `kind` had to exist. Both are sensor.
	crypto := Discovery{
		Metadata: []byte(`{"discovery_method":"sensor_discovery"}`),
	}.WithKind(KindCrypto)
	match, err = ev.EvaluateRule(rule, crypto, cls)
	if err != nil {
		t.Fatalf("evaluating a source rule against a crypto finding: %v", err)
	}
	if !match {
		t.Error("a `source:sensor` rule did not match a sensor crypto finding")
	}
}
