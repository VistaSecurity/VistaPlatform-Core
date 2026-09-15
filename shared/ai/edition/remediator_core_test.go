//go:build !ee

package edition

import (
	"context"
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

// The Core polarity of the remediator's edition boundary. Both directions are
// pinned, for the reason query_core_test.go gives: this file catches the ee tree
// becoming reachable from a Core build, and remediator_ee_test.go catches it
// becoming unreachable from an Enterprise one.

func TestRemediatorLinked_IsFalseInACoreBuild(t *testing.T) {
	if RemediatorLinked() {
		t.Fatal("RemediatorLinked() is true without the ee tag; Core has linked an Enterprise tree")
	}
}

// Core resolves to THE null default, whatever AI_PROVIDER says — not merely to
// something that errors. That is what makes the endpoint's 402 honest: there is
// no remediator in this build to configure.
func TestNewRemediator_IsTheNullSeamInCore(t *testing.T) {
	for _, kind := range []string{"none", "anthropic", "openai_compat"} {
		t.Run(kind, func(t *testing.T) {
			t.Setenv("AI_PROVIDER", kind)

			rem, desc := NewRemediator(nil)
			if _, isNull := rem.(seams.NullRemediator); !isNull {
				t.Fatalf("Core resolved AI_PROVIDER=%s to %T, want seams.NullRemediator", kind, rem)
			}
			if desc.Implementation != seams.ImplNone || desc.State != seams.StateInactive {
				t.Errorf("description = %+v, want the null implementation, inactive", desc)
			}
			_, err := rem.Propose(context.Background(), seams.FindingRef{FindingID: "f1", Kind: "weak_configuration"})
			if !errors.Is(err, ai.ErrUnavailable) {
				t.Errorf("Propose = %v, want ai.ErrUnavailable", err)
			}
		})
	}
}
