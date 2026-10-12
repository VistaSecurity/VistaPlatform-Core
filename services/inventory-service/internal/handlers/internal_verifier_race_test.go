package handlers

import (
	"sync"
	"testing"
)

// getInternalVerifier is first called lazily from request goroutines. Run under
// -race this fails on an unsynchronised nil-check-then-assign.
func TestGetInternalVerifier_ConcurrentFirstUse(t *testing.T) {
	t.Setenv("INTERNAL_AUTH_SECRET", "race-test-secret")
	internalVerifier = nil
	internalVerifierOnce = sync.Once{}
	t.Cleanup(func() {
		internalVerifier = nil
		internalVerifierOnce = sync.Once{}
	})

	var wg sync.WaitGroup
	results := make([]any, 32)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = getInternalVerifier()
		}()
	}
	wg.Wait()
	for i, v := range results {
		if v == nil {
			t.Fatalf("goroutine %d saw a nil verifier", i)
		}
		if v != results[0] {
			t.Fatalf("goroutine %d saw a different verifier instance", i)
		}
	}
}
