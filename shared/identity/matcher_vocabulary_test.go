package identity_test

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
)

// The learned matcher restates the identifier-kind vocabulary as plain strings,
// because it cannot import this package: shared/identity imports
// shared/ai/seams, and the seam adapter that registers the model as the
// matcher's default lives in seams — so a matcher package importing seams would
// close the cycle.
//
// This test is what makes the restatement a copy rather than a second opinion.
// It lives HERE and not there because the dependency runs this way: identity may
// import matcher, matcher may not import identity.
//
// The consequence of drift is quiet and specific. A kind missing from
// matcher.AllKinds is a kind the extractor never compares, so a pair agreeing on
// it scores as if they agreed on nothing; a kind wrongly marked singleton makes
// a machine's second MAC read as evidence of two machines; a singleton kind
// MISSING from the list is one a high score could auto-merge past, which is the
// exact hole ADR-0002 D3's singleton erratum was written to close.
func TestMatcherKindVocabularyMatchesIdentity(t *testing.T) {
	want := identity.AllKinds()
	got := matcher.AllKinds()

	if len(got) != len(want) {
		t.Fatalf("matcher knows %d kinds, identity has %d:\n  matcher %v\n  identity %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != string(want[i]) {
			t.Errorf("kind %d: matcher says %q, identity says %q", i, got[i], want[i])
		}
	}
}

func TestMatcherSingletonKindsMatchIdentity(t *testing.T) {
	var want []string
	for _, k := range identity.AllKinds() {
		if k.Singleton() {
			want = append(want, string(k))
		}
	}
	got := matcher.SingletonKinds()

	if len(got) != len(want) {
		t.Fatalf("matcher has %d singleton kinds, identity has %d:\n  matcher %v\n  identity %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("singleton %d: matcher says %q, identity says %q", i, got[i], want[i])
		}
	}
	// And per-kind, both ways: a kind identity calls multi-valued must not be a
	// singleton to the matcher, and vice versa.
	for _, k := range identity.AllKinds() {
		if matcher.IsSingleton(string(k)) != k.Singleton() {
			t.Errorf("%s: matcher singleton=%v, identity singleton=%v",
				k, matcher.IsSingleton(string(k)), k.Singleton())
		}
	}
}
