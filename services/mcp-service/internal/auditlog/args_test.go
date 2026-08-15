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
	long := strings.Repeat("x", 500)
	got := projectArgs(struct {
		Search string `json:"search"`
		Issuer string `json:"issuer"`
	}{Search: long, Issuer: long})

	for _, k := range []string{"search_preview", "issuer_preview"} {
		s, ok := got[k].(string)
		if !ok {
			t.Fatalf("%s missing: %v", k, got)
		}
		if len(s) > previewLen+3 {
			t.Errorf("%s not truncated: %d chars", k, len(s))
		}
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
