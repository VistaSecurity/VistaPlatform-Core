package auditlog

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProjectArgsIsAnAllowlist(t *testing.T) {
	// A future tool input carrying something it should not. The point of the
	// allowlist is that this needs no maintenance to stay safe: the unknown
	// field is dropped because it was never listed, not because someone
	// remembered to exclude it.
	in := struct {
		Search      string `json:"search"`
		Environment string `json:"environment"`
		APIKey      string `json:"api_key"`
		Password    string `json:"password"`
		PrivateKey  string `json:"private_key"`
		Whatever    string `json:"some_field_invented_next_year"`
	}{
		Search:      "web",
		Environment: "production",
		APIKey:      "sk-live-must-not-be-recorded",
		Password:    "hunter2",
		PrivateKey:  "-----BEGIN PRIVATE KEY-----",
		Whatever:    "unknown",
	}

	got := projectArgs(in)

	if got["environment"] != "production" {
		t.Errorf("allowed filter dropped: %v", got)
	}
	if got["search_preview"] != "web" {
		t.Errorf("search preview missing: %v", got)
	}
	for _, banned := range []string{"api_key", "password", "private_key", "some_field_invented_next_year", "search"} {
		if _, present := got[banned]; present {
			t.Errorf("%q was recorded; the projection is not fail-closed", banned)
		}
	}
	// Belt and braces: no recorded value may contain the secrets either.
	blob, _ := json.Marshal(got)
	for _, secret := range []string{"sk-live", "hunter2", "BEGIN PRIVATE KEY"} {
		if strings.Contains(string(blob), secret) {
			t.Errorf("secret %q reached the audit record: %s", secret, blob)
		}
	}
}

func TestProjectArgsTruncatesFreeText(t *testing.T) {
	long := strings.Repeat("x", 5000)
	got := projectArgs(struct {
		Search string `json:"search"`
		Issuer string `json:"issuer"`
		Text   string `json:"text"`
		Query  string `json:"query"`
	}{Search: long, Issuer: long, Text: long, Query: long})

	for k, cap := range map[string]int{
		"search_preview": 64, "issuer_preview": 64, "text_preview": 64, "query_preview": 256,
	} {
		s, ok := got[k].(string)
		if !ok {
			t.Fatalf("%s missing: %v", k, got)
		}
		// +3 for the ellipsis truncate appends.
		if len(s) > cap+3 {
			t.Errorf("%s not truncated to its own cap: %d chars, cap %d", k, len(s), cap)
		}
		// Each cap is the one the argument declares, not a shared constant: a
		// query truncated to 64 would lose the half that says what it selected.
		if len(s) < cap {
			t.Errorf("%s truncated below its cap: %d chars, cap %d", k, len(s), cap)
		}
	}
}

// The query language is the "run this query" argument args.go's allowlist
// comment anticipated. It must be recorded (which query an agent ran is the
// point of the record) and it must be recorded as a PREVIEW — verbatim would
// mean an unbounded caller-composed string, possibly carrying values the agent
// read out of the tenant's own inventory, stored in full.
func TestProjectArgsRecordsTheQueryAsAPreview(t *testing.T) {
	got := projectArgs(struct {
		Query  string `json:"query"`
		Cursor string `json:"cursor"`
	}{Query: `environment:production and owner_email:"alice@example.com"`, Cursor: "cGFnZTox"})

	if got["query_preview"] != `environment:production and owner_email:"alice@example.com"` {
		t.Errorf("query not recorded: %v", got)
	}
	if _, verbatim := got["query"]; verbatim {
		t.Error("query recorded verbatim under its own key; it must be a bounded preview")
	}
	// An opaque continuation token says nothing about what was read.
	if _, present := got["cursor"]; present {
		t.Errorf("cursor recorded: %v", got)
	}
}

func TestProjectArgsOmitsEmpty(t *testing.T) {
	if got := projectArgs(struct{}{}); got != nil {
		t.Errorf("empty input produced %v, want nil", got)
	}
	if got := projectArgs(nil); got != nil {
		t.Errorf("nil input produced %v, want nil", got)
	}
}

func TestCountRecords(t *testing.T) {
	decode := func(s string) any {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			t.Fatalf("bad fixture: %v", err)
		}
		return v
	}

	cases := []struct {
		name    string
		body    string
		want    int
		counted bool
	}{
		{"envelope key wins", `{"assets":[{"a":1},{"b":2}],"pagination":{"total":99}}`, 2, true},
		{"bare array", `[1,2,3]`, 3, true},
		{"empty collection is a real answer", `{"assets":[]}`, 0, true},
		{"single unnamed array", `{"widgets":[1,2]}`, 2, true},
		// A summary object has no collection; reporting 0 would read as "the
		// agent got nothing", which is the opposite of the truth.
		{"scalar summary is not counted", `{"total_assets":12,"high_risk":3}`, 0, false},
		{"ambiguous multi-array declines", `{"a":[1],"b":[2,3]}`, 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, counted := CountRecords(decode(tc.body))
			if n != tc.want || counted != tc.counted {
				t.Errorf("CountRecords = (%d, %v), want (%d, %v)", n, counted, tc.want, tc.counted)
			}
		})
	}
}

func TestCategoryForPermissionStaysWithinTheCheckConstraint(t *testing.T) {
	// audit.activity_logs has a valid_event_category CHECK; a category outside
	// it makes the insert fail, which is how an audit trail stops recording
	// while everything upstream still reports success.
	valid := map[string]bool{
		"asset": true, "discovery": true, "compliance": true, "user": true,
		"tenant": true, "system": true, "report": true, "certificate": true,
		"data": true, "config": true, "job": true, "authentication": true,
	}
	for _, perm := range []string{"assets.read", "compliance.read", "reports.read", "something.new"} {
		if got := CategoryForPermission(perm); !valid[got] {
			t.Errorf("CategoryForPermission(%q) = %q, which violates valid_event_category", perm, got)
		}
	}
}

// TestAskQuestionIsNeverRecorded pins the one argument on this surface that is
// a PROMPT.
//
// ADR-0008 D4.7: prompts are not stored unless the tenant opts in, and that
// opt-in is enforced one layer down, inside ai.WithAudit, where the question
// actually crosses the provider boundary. A copy written here would be an
// opt-in honoured in one place and bypassed in another.
//
// It is deliberately asserted against BOTH maps and against the projection's
// output, because `question` could be admitted three ways — allowlisted,
// previewed, or by someone widening the projection — and only the last of those
// is visible in the output alone.
func TestAskQuestionIsNeverRecorded(t *testing.T) {
	if allowedArgs[AskQuestionArg] {
		t.Error("`question` is on the allowlist; ADR-0008 D4.7's opt-in lives at the provider boundary, not here")
	}
	if _, previewed := previewArgs[AskQuestionArg]; previewed {
		t.Error("`question` is recorded as a preview; a truncated prompt is still a stored prompt")
	}

	const asked = "which production servers nobody owns are running an expiring certificate"
	got := projectArgs(struct {
		Question string `json:"question"`
	}{Question: asked})

	if got != nil {
		t.Fatalf("a call carrying only a question recorded %v, want no arguments at all", got)
	}

	// The other polarity, so this test is known to be doing work rather than
	// known to pass because projectArgs returns nil for everything: an input
	// carrying a question AND an allowlisted field records the second and not
	// the first.
	mixed := projectArgs(struct {
		Question string `json:"question"`
		AssetID  string `json:"asset_id"`
	}{Question: asked, AssetID: "1ffb4ff8-0000-4000-8000-000000000001"})

	if mixed["asset_id"] != "1ffb4ff8-0000-4000-8000-000000000001" {
		t.Errorf("the allowlisted identifier was dropped: %v", mixed)
	}
	blob, _ := json.Marshal(mixed)
	if strings.Contains(string(blob), "production servers") {
		t.Errorf("the question reached the audit record: %s", blob)
	}
	for _, key := range []string{AskQuestionArg, AskQuestionArg + "_preview"} {
		if _, present := mixed[key]; present {
			t.Errorf("%q was recorded", key)
		}
	}
}
