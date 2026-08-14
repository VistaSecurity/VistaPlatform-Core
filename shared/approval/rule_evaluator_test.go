package approval

import (
	"testing"

	"github.com/google/uuid"
)

// segmentRule builds the rule shape inventory-service's ManageAutoApprovalRules
// writes for a network segment whose auto-approve toggle is ON. Keep this in
// step with that writer — it is the only producer of these rows.
func segmentRule(segmentID uuid.UUID, active bool) *Rule {
	return &Rule{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Name:     "Auto-approve sensor discoveries: 203.0.113.0/24",
		Conditions: map[string]interface{}{
			"source":                        "sensor_discoveries",
			"network_ownership":             "internal",
			"network_type":                  "private",
			"require_network_segment_match": true,
			"network_segment_id":            segmentID.String(),
		},
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

// TestSegmentAutoApprovalContract pins the one gate on auto-approval: the
// discovery is on a user-defined segment whose auto-approve toggle is on.
// Both polarities, because a guard that can only pass is not a guard.
func TestSegmentAutoApprovalContract(t *testing.T) {
	svc := NewService(nil) // the WithRules path never touches the DB
	segmentID := uuid.New()
	otherSegmentID := uuid.New()
	discovery := Discovery{TenantID: uuid.New(), Confidence: 0.9}

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

	t.Run("sensor_discoveries rule skips a cloud discovery", func(t *testing.T) {
		d := Discovery{
			TenantID: uuid.New(),
			Metadata: []byte(`{"discovery_method":"cloud_api"}`),
		}
		matched, err := e.EvaluateRule(segmentRule(segmentID, true), d, onSegment(segmentID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if matched {
			t.Fatal("a sensor_discoveries rule must not match a cloud discovery")
		}
	})

	t.Run("min_confidence is enforced", func(t *testing.T) {
		rule := segmentRule(segmentID, true)
		rule.Conditions["min_confidence"] = 0.8

		low, err := e.EvaluateRule(rule, Discovery{Confidence: 0.5}, onSegment(segmentID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if low {
			t.Fatal("a discovery below min_confidence must not match")
		}

		high, err := e.EvaluateRule(rule, Discovery{Confidence: 0.9}, onSegment(segmentID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !high {
			t.Fatal("a discovery above min_confidence must match")
		}
	})
}
