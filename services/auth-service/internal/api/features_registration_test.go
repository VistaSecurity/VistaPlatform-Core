package api

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// A feature flag is only useful if it is registered on EVERY surface. This file
// pins the one link in that chain that is checkable from Go: the tenant feature
// map must publish every edition-gated key.
//
// Why it matters, concretely: the frontend gates paid surfaces purely on
// GET /tenant/features (see the note on knownFeatures). A key that is
// edition-gated in shared/entitlements but missing from knownFeatures is
// therefore absent from the response, reads as `undefined` in the client, and
// the surface it was supposed to gate stays visible on a Core build — where its
// routes do not exist and every call 404s. That is exactly the class of bug
// this test exists to prevent, and it cannot be caught by any test that only
// looks at one of the two lists.
//
// The other two registrations (the `FeatureName` union in
// packages/primitives/src/features/types.ts and the OpenAPI `FeatureFlags`
// closed shape) are pinned on the TypeScript side, in
// packages/primitives/src/features/registration.test.ts.
func TestKnownFeatures_publishesEveryEditionGatedKey(t *testing.T) {
	published := make(map[string]bool, len(knownFeatures))
	for _, k := range knownFeatures {
		if published[k] {
			t.Errorf("knownFeatures lists %q twice", k)
		}
		published[k] = true
	}

	for _, key := range entitlements.EditionGatedKeys() {
		if !published[key] {
			t.Errorf("edition-gated item %q is missing from knownFeatures — the frontend "+
				"cannot gate on it, so its Enterprise-only surface stays visible on Core", key)
		}
	}
}

// The inverse direction is deliberately NOT an error: a Core capability may
// legitimately be flag-controlled without being paid. This test only records
// which keys those are, so an accidental one is visible in the test output
// rather than silent.
func TestKnownFeatures_ungatedKeysAreIntentional(t *testing.T) {
	gated := make(map[string]bool)
	for _, k := range entitlements.EditionGatedKeys() {
		gated[k] = true
	}
	for _, k := range knownFeatures {
		if !gated[k] {
			t.Logf("note: %q is published to tenants but is NOT edition-gated (free in Core)", k)
		}
	}
}
