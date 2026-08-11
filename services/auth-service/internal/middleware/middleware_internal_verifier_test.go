package middleware

import (
	"sync"
	"testing"
)

func resetInternalVerifierState() {
	internalVerifier = nil
	internalVerifierOnce = sync.Once{}
}

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
