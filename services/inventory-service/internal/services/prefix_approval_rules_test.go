package services

// Unit coverage for the per-prefix auto-approval rule generator (DCIM row 1.6).
// Since ADR-0009 D5 the rule covers SENSOR discoveries only: cloud
// resources are auto-approved per account, on the cloud integration.

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/approval"
)

// TestPrefixRuleGenerator_ValidSensorOnlyRule pins the generator: whatever the
// prefix's network type — including none and one the rules do not know — the
// rule it writes is a valid `source:sensor` rule scoped to the prefix id.
// Re-adding a cloud source makes the query fail validation (shared/approval
// refuses a prefix rule naming the cloud source), so this goes red.
func TestPrefixRuleGenerator_ValidSensorOnlyRule(t *testing.T) {
	id := uuid.NewString()
	for _, networkType := range []string{"private", "public", "vpn", "cloud", "", "corporate"} {
		t.Run("network type "+networkType, func(t *testing.T) {
			q := prefixApprovalQuery(networkType, id)
			if _, err := approval.ValidateRuleQuery(q); err != nil {
				t.Fatalf("generated prefix rule %q does not validate: %v", q, err)
			}
			if !strings.Contains(q, "source:sensor") || strings.Contains(q, "source:cloud") {
				t.Fatalf("generated prefix rule %q must say source:sensor and never source:cloud", q)
			}
			if got, ok := approval.PrefixIDFromQuery(q); !ok || got.String() != id {
				t.Fatalf("generated prefix rule %q does not name its prefix (got %v, %v)", q, got, ok)
			}
			if networkType == "corporate" && strings.Contains(q, "network.type") {
				t.Fatalf("a network type the rules do not know must not become a term: %q", q)
			}
		})
	}
}

// The generator never touches the rules table for a prefix that neither had
// nor has auto-approve: the common case, and every intake write.
func TestSyncPrefixApprovalRule_NoAutoApproveIsANoOp(t *testing.T) {
	// A nil transaction would panic if it were used.
	if err := syncPrefixApprovalRule(t.Context(), nil, uuid.New(),
		map[string]any{"id": uuid.NewString(), "auto_approve_discoveries": false},
		map[string]any{"id": uuid.NewString(), "auto_approve_discoveries": false}); err != nil {
		t.Fatalf("no-op sync: %v", err)
	}
	if err := syncPrefixApprovalRule(t.Context(), nil, uuid.New(), nil,
		map[string]any{"id": uuid.NewString()}); err != nil {
		t.Fatalf("no-op sync on create: %v", err)
	}
}
