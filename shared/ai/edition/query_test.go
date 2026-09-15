package edition

import (
	"context"
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	ql "github.com/vistasecurity/vistaplatform/shared/query"
)

// These tests run in BOTH builds and assert what is true of both. The
// ee-specific claims live in query_ee_test.go, which only the Enterprise build
// compiles.

// TestNewQuery_AlwaysUsable is the property that makes shipping a seam before a
// model safe: whatever the edition and whatever the configuration, a caller
// gets a non-nil seam and a description saying what it is.
func TestNewQuery_AlwaysUsable(t *testing.T) {
	t.Setenv("AI_PROVIDER", "none")

	q, desc := NewQuery(ql.DefaultCatalog(), nil)
	if q == nil {
		t.Fatal("NewQuery returned a nil seam; a caller would panic on first use")
	}
	if desc.Seam != ai.SeamQuery {
		t.Errorf("description names seam %q, want %q", desc.Seam, ai.SeamQuery)
	}
	if desc.Family != seams.FamilyGenerative {
		t.Errorf("family = %q, want %q", desc.Family, seams.FamilyGenerative)
	}

	// With AI_PROVIDER=none nothing can answer, in either edition.
	_, err := q.Answer(context.Background(), "what is in production?", nil)
	if !errors.Is(err, ai.ErrUnavailable) {
		t.Errorf("Answer with no provider returned %v, want ai.ErrUnavailable", err)
	}
	if desc.Active {
		t.Error("the seam reports itself active with AI_PROVIDER=none")
	}
}

// TestNewQuery_NilCatalogueDoesNotPanic. A service that has not built its
// catalogue yet must degrade, not crash: a nil-pointer panic at wiring time
// takes the whole service down for a capability nobody asked for yet.
func TestNewQuery_NilCatalogueDoesNotPanic(t *testing.T) {
	t.Setenv("AI_PROVIDER", "none")

	q, desc := NewQuery(nil, nil)
	if q == nil {
		t.Fatal("NewQuery(nil, nil) returned a nil seam")
	}
	if desc.State != seams.StateInactive {
		t.Errorf("state = %q with no catalogue, want %q", desc.State, seams.StateInactive)
	}
}

// TestNewQuery_UnknownProviderDegradesRatherThanFailing. A typo in AI_PROVIDER
// must not be able to take a service down — and must not be able to silently
// disable a capability an operator believes they turned on, which is what the
// three-valued State is for.
func TestNewQuery_UnknownProviderDegradesRatherThanFailing(t *testing.T) {
	t.Setenv("AI_PROVIDER", "anthropicc")

	q, desc := NewQuery(ql.DefaultCatalog(), nil)
	if q == nil {
		t.Fatal("a typo in AI_PROVIDER produced a nil seam")
	}
	if desc.Active {
		t.Error("a typo in AI_PROVIDER produced an active seam")
	}
	if _, err := q.Answer(context.Background(), "anything?", nil); !errors.Is(err, ai.ErrUnavailable) {
		t.Errorf("Answer = %v, want ai.ErrUnavailable", err)
	}
}
