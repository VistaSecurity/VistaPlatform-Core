package models

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The seeded shape (scripts/database/seed.sql) round-trips field for field.
func TestParseComponentRemediationGuidance_SeededShape(t *testing.T) {
	raw := []byte(`{
		"summary": "DH 512-bit modulus was crackable in 1999 and is critically broken.",
		"impact": "CRITICAL - An attacker can passively decrypt all traffic.",
		"steps": ["1. Identify all servers", "2. Reconfigure servers to use ECDHE"],
		"timeline": "Immediate - within 7 days",
		"cve_references": ["CVE-2015-4000"],
		"resources": ["https://weakdh.org/"]
	}`)
	got := ParseComponentRemediationGuidance(raw)
	want := &ComponentRemediationGuidance{
		Summary:       "DH 512-bit modulus was crackable in 1999 and is critically broken.",
		Impact:        "CRITICAL - An attacker can passively decrypt all traffic.",
		Steps:         []string{"1. Identify all servers", "2. Reconfigure servers to use ECDHE"},
		Timeline:      "Immediate - within 7 days",
		CVEReferences: []string{"CVE-2015-4000"},
		Resources:     []string{"https://weakdh.org/"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

// The column default is '{}', and NULL/garbage must not surface as an empty
// guidance object a consumer would render as a blank "How to fix" section.
func TestParseComponentRemediationGuidance_NothingUsableIsNil(t *testing.T) {
	for _, raw := range []string{``, `{}`, `null`, `[]`, `not json`, `{"summary":"   ","steps":[]}`, `{"steps":[1,2],"resources":[" "]}`} {
		if got := ParseComponentRemediationGuidance([]byte(raw)); got != nil {
			t.Errorf("%q: got %+v, want nil", raw, got)
		}
	}
}

// Admins edit this column free-form. One mistyped field must not throw away the
// rest of the row's advice, and a non-string list item is dropped on its own.
func TestParseComponentRemediationGuidance_WrongTypedFieldIsDroppedAlone(t *testing.T) {
	got := ParseComponentRemediationGuidance([]byte(`{"summary": 7, "steps": "not a list", "timeline": "Within 30 days", "resources": ["https://a.example", 3, ""]}`))
	if got == nil {
		t.Fatal("usable fields were discarded because a sibling field had the wrong type")
	}
	if got.Summary != "" || len(got.Steps) != 0 {
		t.Errorf("wrong-typed fields leaked through: %+v", got)
	}
	if got.Timeline != "Within 30 days" {
		t.Errorf("timeline = %q", got.Timeline)
	}
	if !reflect.DeepEqual(got.Resources, []string{"https://a.example"}) {
		t.Errorf("resources = %v, want only the string item", got.Resources)
	}
}

// List fields serialize as [] (never null) and absent text fields are omitted,
// matching the OpenAPI schema's required/optional split.
func TestComponentRemediationGuidance_JSONShape(t *testing.T) {
	g := ParseComponentRemediationGuidance([]byte(`{"summary":"Weak."}`))
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"summary":"Weak.","steps":[],"cve_references":[],"resources":[]}`; got != want {
		t.Errorf("json = %s, want %s", got, want)
	}
}
