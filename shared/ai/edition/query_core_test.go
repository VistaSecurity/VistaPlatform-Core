//go:build !ee

package edition

import (
	"context"
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	ql "github.com/vistasecurity/vistaplatform/shared/query"
)

// The Core polarity of the edition boundary. Both directions are pinned
// because a guard that only ever sees one side is a guard that cannot fail in
// the direction that matters: this file is what catches the ee tree becoming
// reachable from a Core build, and query_ee_test.go is what catches it
// becoming unreachable from an Enterprise one.

// TestQueryLinked_IsFalseInACoreBuild.
func TestQueryLinked_IsFalseInACoreBuild(t *testing.T) {
	if QueryLinked() {
		t.Fatal("QueryLinked() is true without the ee tag; Core has linked an Enterprise tree")
	}
}

// TestNewQuery_IsTheNullSeamInCore, whatever AI_PROVIDER says.
//
// Not merely "it returns an error": it returns THE null default, so a Core
// deployment runs the same code path every deployment runs, and a caller that
// handles the null default correctly handles the real one.
func TestNewQuery_IsTheNullSeamInCore(t *testing.T) {
	for _, kind := range []string{"none", "anthropic", "openai_compat"} {
		t.Run(kind, func(t *testing.T) {
			t.Setenv("AI_PROVIDER", kind)

			q, desc := NewQuery(ql.DefaultCatalog(), nil)
			if _, isNull := q.(seams.NullQuery); !isNull {
				t.Fatalf("Core resolved AI_PROVIDER=%s to %T, want seams.NullQuery", kind, q)
			}
			if desc.Implementation != seams.ImplNone || desc.State != seams.StateInactive {
				t.Errorf("description = %+v, want the null implementation, inactive", desc)
			}
			if _, err := q.Answer(context.Background(), "anything?", nil); !errors.Is(err, ai.ErrUnavailable) {
				t.Errorf("Answer = %v, want ai.ErrUnavailable", err)
			}
		})
	}
}
