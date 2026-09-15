package server

// The grounded ask tool (`vistaplatform_ask`, build-plan 4.4b).
//
// It is a FORWARDER: inventory-service holds the seam, the tool layer, the
// tenant kill switch and the audit rail, and this tool hands the answer back
// unchanged. These tests are therefore about the hop — what survives it, what
// must not, and the four non-2xx answers that are not failures.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestAskToolReturnsTheGroundedAnswer proves the tool is a forwarder and not a
// second implementation: what inventory-service composed — the canonical query,
// the rows, the cited summary and the provenance — reaches the agent unchanged,
// minus the heavy fields every tool prunes.
func TestAskToolReturnsTheGroundedAnswer(t *testing.T) {
	f := newFixture(t)
	result := callTool(t, f, f.validPAT, "vistaplatform_ask",
		map[string]any{"question": "which production servers are there"})

	if result["isError"] == true {
		t.Fatalf("tool errored: %v", result)
	}
	text := toolText(t, result)

	// The CANONICAL query, not the question: the platform AND-s its default
	// scope in, and an agent repeating the answer must show what ran.
	if !strings.Contains(text, "status:monitoring") {
		t.Errorf("the canonical query did not reach the agent: %s", text)
	}
	if !strings.Contains(text, "[row:a1]") {
		t.Errorf("the citation marker was stripped; the summary is no longer checkable: %s", text)
	}
	if !strings.Contains(text, "mock-model-1") {
		t.Errorf("provenance lost: %s", text)
	}
	// The tool inherits the surface-wide pruning, so a PEM in a row does not
	// reach an agent through this path either.
	if strings.Contains(text, "SECRETPEM") || strings.Contains(text, "certificate_pem") {
		t.Errorf("heavy fields not pruned on the ask path: %s", text)
	}
	// It POSTs, because a question does not belong in a URL where proxies and
	// access logs keep it.
	if got := f.last(t).Path; !strings.HasSuffix(got, "/ask") {
		t.Errorf("called %s, want the /ask endpoint", got)
	}
}

// TestAskToolAnswersUnavailableRatherThanErroring is the honesty rule of this
// tool.
//
// Four non-2xx answers are not failures to retry: none can succeed on a second
// attempt, and a tool error invites exactly that. They come back as a
// structured fact naming the reason and an alternative that works in every
// edition — and never as an empty answer, which an agent would report as a
// clean inventory nobody measured.
func TestAskToolAnswersUnavailableRatherThanErroring(t *testing.T) {
	for _, tc := range []struct {
		name     string
		question string
		reason   string
	}{
		{"core build", "core-build please", "edition"},
		{"no provider", "no-provider please", "no_provider"},
		{"tenant switched it off", "switched-off please", "tenant_off"},
		{"model could not write a valid query", "untranslatable please", "not_grounded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			result := callTool(t, f, f.validPAT, "vistaplatform_ask",
				map[string]any{"question": tc.question})

			if result["isError"] == true {
				t.Fatalf("%s came back as a tool error; an agent will retry something that cannot succeed: %v",
					tc.name, result)
			}
			text := toolText(t, result)

			var got struct {
				Available bool   `json:"available"`
				Reason    string `json:"reason"`
				Message   string `json:"message"`
				Instead   string `json:"instead"`
			}
			if err := json.Unmarshal([]byte(text), &got); err != nil {
				t.Fatalf("result was not the unavailable shape: %v (%s)", err, text)
			}
			if got.Available {
				t.Error("available is true on a refusal")
			}
			if got.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", got.Reason, tc.reason)
			}
			if got.Message == "" {
				t.Error("the platform's own sentence was dropped; the agent cannot say why")
			}
			if !strings.Contains(got.Instead, "vistaplatform_query_assets") {
				t.Errorf("no working alternative named: %q", got.Instead)
			}
			// Nothing an agent could read as an answer.
			if strings.Contains(text, `"rows"`) {
				t.Errorf("a refusal carried answer-shaped keys: %s", text)
			}
		})
	}
}

// The 422's diagnostics are the one thing a person or an agent can act on, so
// they must survive the hop verbatim rather than being flattened.
func TestAskToolCarriesTheValidatorDiagnostics(t *testing.T) {
	f := newFixture(t)
	result := callTool(t, f, f.validPAT, "vistaplatform_ask",
		map[string]any{"question": "untranslatable please"})

	text := toolText(t, result)
	for _, want := range []string{"unknown_field", "hostnaem", "did you mean"} {
		if !strings.Contains(text, want) {
			t.Errorf("diagnostic %q lost on the way to the agent: %s", want, text)
		}
	}
}

// Every 403 that is NOT the tenant kill switch is a REAL error, and must not be
// dressed as "this capability is not available".
//
// This is the other polarity of the 403 arm, and it has three spellings rather
// than one because the route really can answer 403 four ways. The tenant kill
// switch identifies ITSELF with a machine-readable `reason`; everything else
// falls through to an error carrying the platform's own sentence.
//
// The middle case is the regression. `Permission outside token scope` is what
// the same middleware writes for a scope-narrowed PAT — capital P, and the
// `required_permission` key is a sibling of `error`, not part of it — so a
// client sniffing the MESSAGE for the word "permission" matched neither and
// reported the tenant as having switched the assistant off. That sends an
// operator to a settings page that is already correct while the real fix is a
// differently scoped token. Deleting the `reason` check turns all three red.
func TestAskToolReportsAPermissionFailureAsAnError(t *testing.T) {
	for _, tc := range []struct {
		name     string
		question string
		want     string
	}{
		{"role lacks assets.read", "no-read please", "Insufficient permissions"},
		{"scope-narrowed API token", "scoped-token please", "Permission outside token scope"},
		{"session must change its password", "stale-session please", "Password change required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			status, out := f.rpc(t, f.validPAT, "tools/call",
				map[string]any{"name": "vistaplatform_ask", "arguments": map[string]any{"question": tc.question}})
			if status != http.StatusOK {
				t.Fatalf("status = %d body %v", status, out)
			}
			result, _ := out["result"].(map[string]any)
			if result["isError"] != true {
				t.Fatalf("%s came back as a normal result: %v", tc.name, result)
			}
			text := toolText(t, result)
			if strings.Contains(text, `"available"`) {
				t.Errorf("%s was dressed as an availability answer: %s", tc.name, text)
			}
			// And the platform's own sentence survives, so the caller can act
			// on the real cause rather than on our classification of it.
			if !strings.Contains(text, tc.want) {
				t.Errorf("the platform's sentence was lost: %s", text)
			}
		})
	}
}

// A blank question is refused before any backend call: an empty prompt cannot
// produce an answer, and spending a round trip to learn that is a round trip
// spent on nothing.
func TestAskToolRefusesABlankQuestion(t *testing.T) {
	f := newFixture(t)
	before := len(f.backendURLs)
	status, out := f.rpc(t, f.validPAT, "tools/call",
		map[string]any{"name": "vistaplatform_ask", "arguments": map[string]any{"question": "   "}})
	if status != http.StatusOK {
		t.Fatalf("status = %d body %v", status, out)
	}
	result, _ := out["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("a blank question was accepted: %v", result)
	}
	if len(f.backendURLs) != before {
		t.Error("a blank question still reached the platform")
	}
}

// The question is a PROMPT (ADR-0008 D4.7) and this rail never asked the tenant
// whether it may store one. The record still says a call happened, by whom, and
// how much came back.
func TestAskToolDoesNotRecordTheQuestion(t *testing.T) {
	f := newFixture(t)
	const asked = "which production servers nobody owns have an expiring certificate"
	callTool(t, f, f.validPAT, "vistaplatform_ask", map[string]any{"question": asked})

	found := false
	for _, ev := range f.audit.all() {
		blob, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal audit event: %v", err)
		}
		if !strings.Contains(string(blob), "vistaplatform_ask") {
			continue
		}
		found = true
		if strings.Contains(string(blob), "production servers nobody owns") {
			t.Errorf("the question was written to the audit rail: %s", blob)
		}
	}
	if !found {
		t.Fatal("no audit record for the ask call at all; this test proved nothing")
	}
}
