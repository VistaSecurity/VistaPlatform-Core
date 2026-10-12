package middleware

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

func resetInternalVerifierState() { SetInternalVerifier(nil) }

func TestGetInternalVerifier_InitializesOnlyOnceWhenSecretMissing(t *testing.T) {
	t.Setenv("INTERNAL_AUTH_SECRET", "")
	resetInternalVerifierState()

	if got := getInternalVerifier(); got != nil {
		t.Fatal("expected nil verifier when INTERNAL_AUTH_SECRET is unset")
	}

	// Changing env vars at runtime should not trigger re-initialization.
	t.Setenv("INTERNAL_AUTH_SECRET", "late-secret")
	if got := getInternalVerifier(); got != nil {
		t.Fatal("expected verifier to remain nil after first initialization attempt")
	}
}

func TestGetInternalVerifier_InitializesWhenSecretPresent(t *testing.T) {
	t.Setenv("INTERNAL_AUTH_SECRET", "test-secret")
	resetInternalVerifierState()

	if got := getInternalVerifier(); got == nil {
		t.Fatal("expected verifier when INTERNAL_AUTH_SECRET is set")
	}
}

func TestSetInternalVerifier_OverridesCachedAndNilRestoresLazy(t *testing.T) {
	t.Setenv("INTERNAL_AUTH_SECRET", "")
	resetInternalVerifierState()
	t.Cleanup(resetInternalVerifierState)
	if getInternalVerifier() != nil {
		t.Fatal("expected nil verifier with no secret")
	}

	v := serviceauth.NewVerifier("injected")
	SetInternalVerifier(v)
	if getInternalVerifier() != v {
		t.Fatal("injected verifier was not returned")
	}

	t.Setenv("INTERNAL_AUTH_SECRET", "from-env")
	SetInternalVerifier(nil)
	if got := getInternalVerifier(); got == nil || got == v {
		t.Fatal("nil must clear the cache so the verifier re-resolves from the environment")
	}
}
