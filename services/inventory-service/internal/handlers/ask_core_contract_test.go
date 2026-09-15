//go:build !ee

package handlers

// The CORE polarity of the ask endpoint.
//
// A Core build has no query seam at all — the implementation is
// shared/ai/ee/query, which the open-source export deletes — so the route
// answers 402 Payment Required and nothing downstream of the edition check
// runs.
//
// Mounted rather than absent, on purpose. A 404 would be indistinguishable from
// a broken route, would put one in every Core user's console, and would leave a
// client unable to tell "this is not in your edition" from "this deployment is
// misconfigured". Same reasoning as the remediator's drafting routes
// (AI_SEAMS §14) and as §10 and §12's own endpoints.
//
// The Enterprise polarity is in ask_ee_contract_test.go, which only a
// `-tags ee` build compiles. Neither file can see the other's side.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	aiedition "github.com/vistasecurity/vistaplatform/shared/ai/edition"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

// The claim the tests below rest on, stated once so a reader does not have to
// infer it from the absence of a build tag.
func TestQuerySeamIsNotLinkedInACoreBuild(t *testing.T) {
	if aiedition.QueryLinked() {
		t.Fatal("QueryLinked() is true without the ee tag; this file's assertions are meaningless")
	}
}

func TestContract_Ask_402_inCore(t *testing.T) {
	sv := loadSpec(t)
	seam := &stubQuerySeam{}
	store := &stubAskStore{rows: askSeededAssets()}
	eng := newAskEngine(seam, store, &stubAskClasses{}, uuid.New(), uuid.New())

	w := askDo(eng, strings.NewReader(`{"question":"which production servers are there"}`))
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())

	// Nothing downstream ran. The edition check is FIRST so a Core deployment
	// spends no query on a route it cannot serve — and so a reader can see that
	// the 402 is not being produced somewhere further in by accident.
	if seam.calls != 0 {
		t.Errorf("the seam was called %d times in a Core build", seam.calls)
	}
	if got := store.queries(); len(got) != 0 {
		t.Errorf("the inventory was read %d times on a route that cannot answer: %v", len(got), got)
	}

	// The message tells the reader what they still have, rather than only what
	// they do not: the query language searches the same inventory in every
	// edition, and it is the thing they should reach for next.
	body := w.Body.String()
	if !strings.Contains(body, "query language") {
		t.Errorf("the 402 does not name the deterministic path that still works: %s", body)
	}
}

// A Core build refuses BEFORE it looks at the body, so a malformed request on a
// route this edition cannot serve still reads as "not in your edition" rather
// than as the user's mistake. The reverse order would send a Core user to fix a
// question that was never going to be asked.
func TestContract_Ask_402_beatsABadBody_inCore(t *testing.T) {
	seam := &stubQuerySeam{}
	eng := newAskEngine(seam, &stubAskStore{}, &stubAskClasses{}, uuid.New(), uuid.New())

	w := askDo(eng, strings.NewReader(`not json at all`))
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
	}
	if seam.calls != 0 {
		t.Error("the seam was called")
	}
}

// No tenant on the context is 401 in every edition: the edition check needs a
// tenant to be about.
func TestContract_Ask_401_noTenant(t *testing.T) {
	sv := loadSpec(t)
	eng := newAskEngine(&stubQuerySeam{}, &stubAskStore{}, &stubAskClasses{}, uuid.Nil, uuid.New())

	w := askDo(eng, strings.NewReader(`{"question":"anything"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- a fixture only the Core cases use --------------------------------------
//
// It lives here rather than in the shared harness because the `-tags ee` build
// does not compile this file, so a fixture only these cases touch reads to the
// linter as dead code — correctly, in that build. The ee contract file keeps its
// own for the same reason.

// stubQuerySeam stands in for the seam where the case under test is about the
// HANDLER rather than about the loop — the Core 402, the RBAC gate, the
// bad-body cases. The ee contract file drives the REAL seam over a mocked
// provider instead.
type stubQuerySeam struct {
	answer seams.Answer
	err    error
	calls  int
	asked  string
}

func (s *stubQuerySeam) Answer(_ context.Context, question string, _ seams.ToolSet) (seams.Answer, error) {
	s.calls++
	s.asked = question
	return s.answer, s.err
}
