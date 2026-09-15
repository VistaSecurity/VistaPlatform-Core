//go:build !ee

package api

// The CORE polarity of Settings → AI assistant's edition report.
//
// # Why this is its own build-tagged file
//
// It used to live in ai_settings_contract_test.go, untagged, opening with the
// comment "this test binary is a CORE build (no `-tags ee`)". That sentence was
// an assumption about how the suite is invoked, not a fact the compiler
// enforced — and `Dockerfile.dist` and `Dockerfile.licensed` build this service
// WITH `-tags ee`, so the Enterprise image line is a build whose tests the claim
// was false for. `go test -tags ee ./...` failed on the very first assertion
// ("a Core build must not report the Enterprise providers as linked") because in
// that build they ARE linked, correctly.
//
// Nothing caught it: no CI leg runs the tagged build's suite, so the only red
// was in a build nobody ran. The fix is the same one the ask and remediation
// contract tests already use — one file per polarity, each naming the build it
// is about — and it buys the half that was missing entirely: ai_settings_ee_test.go
// asserts what an ENTERPRISE build reports, which is where "no provider
// configured ⇒ no AI UI" is a question with two possible answers rather than a
// foregone one.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	aiedition "github.com/vistasecurity/vistaplatform/shared/ai/edition"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

// A Core build reports every generative seam unavailable, and says which
// edition would have it — never "misconfigured", never blank.
func TestContract_GetTenantAISettings_coreReportsGenerativeSeamsUnavailable(t *testing.T) {
	eng, mock := newAISettingsEngine(t, true)
	expectControlsRead(t, mock, nil)

	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/ai", nil)
	var got aiStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.EditionLinked {
		t.Fatal("a Core build must not report the Enterprise providers as linked")
	}
	var classicalLive int
	for _, s := range got.Seams {
		switch s.Family {
		case seams.FamilyGenerative:
			if s.Live {
				t.Errorf("seam %q reports live in a Core build", s.Key)
			}
			if s.EditionRequired != seams.EditionEnterprise {
				t.Errorf("seam %q: edition_required = %q, want enterprise", s.Key, s.EditionRequired)
			}
		case seams.FamilyClassical:
			if s.EditionRequired != seams.EditionCore {
				t.Errorf("seam %q: edition_required = %q, want core", s.Key, s.EditionRequired)
			}
			if s.Live {
				classicalLive++
			}
		default:
			t.Errorf("seam %q has family %q", s.Key, s.Family)
		}
	}
	// The classifier's default is the rule engine and the matcher's is the
	// logistic scorer — neither is null, and a Core deployment with no provider
	// still classifies and still ranks merge candidates. If this ever reaches
	// zero the page is telling Core users they have nothing, which is the claim
	// the whole design exists to avoid.
	if classicalLive == 0 {
		t.Error("no classical seam reports live in Core; at least the rule classifier does")
	}
}

// The build-tag fact this file's polarity rests on, asserted directly. Without
// it a future edit that linked the providers into Core would make every
// assertion above vacuously true rather than red.
func TestEditionIsNotLinkedInACoreBuild(t *testing.T) {
	if aiedition.Linked() {
		t.Fatal("edition.Linked() is true in an untagged build; the Core polarity above proves nothing")
	}
}

// Naming a provider this build cannot construct must not be reported as
// configured. `AI_PROVIDER=openai_compat` on a Core install is an operator
// misconfiguration — the providers are Enterprise — and the honest answer is
// "not configured", not "configured and live".
//
// `openai_compat` rather than `anthropic` deliberately: a sibling test in this
// package registers a stub under `anthropic` so it can exercise the CONFIGURED
// state, and a test whose meaning depends on which file ran first is a test
// that will one day pass for the wrong reason.
func TestContract_GetTenantAISettings_coreIgnoresAProviderItCannotBuild(t *testing.T) {
	t.Setenv("AI_PROVIDER", ai.ProviderOpenAICompat)
	t.Setenv("AI_BASE_URL", "https://model.example.com/v1")
	t.Setenv("AI_MODEL", "some-model")

	eng, mock := newAISettingsEngine(t, true)
	expectControlsRead(t, mock, nil)

	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/ai", nil)
	var got aiStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ProviderConfigured {
		t.Error("a Core build reported a provider it has no implementation for as configured")
	}
	for _, s := range got.Seams {
		if s.Family == seams.FamilyGenerative && s.Live {
			t.Errorf("seam %q went live on a Core build because AI_PROVIDER named something", s.Key)
		}
	}
}
