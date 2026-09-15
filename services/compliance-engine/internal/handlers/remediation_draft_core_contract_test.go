//go:build !ee

package handlers

// The CORE polarity of the remediation-drafting endpoints.
//
// A Core build has no remediator at all — the implementation is
// shared/ai/ee/remediator, which the open-source export deletes — so both routes
// answer 402 Payment Required and nothing downstream of the edition check runs.
//
// Mounted rather than absent, on purpose. A 404 would be indistinguishable from
// a broken route, would put one in every Core user's console, and would leave a
// client unable to tell "this is not in your edition" from "this deployment is
// misconfigured". The same reasoning AI_SEAMS §10 and §12 give for their own
// endpoints.
//
// The Enterprise polarity is in remediation_draft_ee_contract_test.go, which
// only a `-tags ee` build compiles. Neither file can see the other's side, which
// is why there are two.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	aiedition "github.com/vistasecurity/vistaplatform/shared/ai/edition"
)

func TestContract_RemediationDraft_402_inCore(t *testing.T) {
	sv := loadSpec(t)
	seam := &stubRemediator{draft: sampleModelDraft()}
	resolver := &stubFindingResolver{ref: sampleFindingRef()}
	plans := &stubDraftPlanStore{}
	eng := newRemediationDraftEngine(seam, resolver, plans, uuid.New(), uuid.New())

	w := do(eng, http.MethodPost, cBase+"/findings/"+rdFinding+"/remediation/draft", strings.NewReader(`{}`))
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())

	// Nothing downstream ran. The edition check is FIRST so a Core deployment
	// spends no query on a route it cannot serve — and so a reader of the test
	// can see that "402" is not being produced somewhere further in by accident.
	if seam.calls != 0 {
		t.Errorf("the seam was called %d times in a Core build", seam.calls)
	}
	if len(plans.addCalls) != 0 {
		t.Errorf("a plan item was written in a Core build")
	}

	// The message tells the reader what they still have, rather than only what
	// they do not. The guidance is on the page in every edition.
	if !strings.Contains(w.Body.String(), "guidance") {
		t.Errorf("the 402 does not mention the standard guidance: %s", w.Body.String())
	}
}

func TestContract_RemediationAccept_402_inCore(t *testing.T) {
	sv := loadSpec(t)
	plans := &stubDraftPlanStore{}
	eng := newRemediationDraftEngine(
		&stubRemediator{draft: sampleModelDraft()},
		&stubFindingResolver{ref: sampleFindingRef()}, plans, uuid.New(), uuid.New())

	body := `{"title":"TLS cleanup","model_id":"m1","steps":[{"action":"Disable TLSv1.0 [ev:protocol_version].","manual":true}]}`
	w := do(eng, http.MethodPost, cBase+"/findings/"+rdFinding+"/remediation/accept", strings.NewReader(body))
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())

	// The important half: a Core build does not write an AI-provenance row on
	// its way to refusing. A 402 AFTER the write would be worse than no check.
	if len(plans.addCalls) != 0 {
		t.Errorf("accept persisted %d items in a Core build", len(plans.addCalls))
	}
}

// The claim the two tests above rest on, stated once so a reader does not have
// to infer it from the absence of a build tag.
func TestRemediatorIsNotLinkedInACoreBuild(t *testing.T) {
	if aiedition.RemediatorLinked() {
		t.Fatal("RemediatorLinked() is true without the ee tag; this file's assertions are meaningless")
	}
}
