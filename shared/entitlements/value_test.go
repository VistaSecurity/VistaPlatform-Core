package entitlements_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// ValidateValue is the one shape rule for every entitlement value column.
// These cases are the report's acceptance list for ED-06: missing property,
// empty object, wrong type, negative quantity and invalid kind all fail with
// an actionable reason, while explicit zero and explicit unlimited stay
// distinct and valid.
func TestValidateValue(t *testing.T) {
	cases := []struct {
		name    string
		kind    entitlements.Kind
		raw     string
		wantErr string // substring of the reason; "" = valid
	}{
		// boolean
		{"bool true", entitlements.KindBoolean, `{"enabled": true}`, ""},
		{"bool false", entitlements.KindBoolean, `{"enabled": false}`, ""},
		{"bool empty object", entitlements.KindBoolean, `{}`, `missing "enabled"`},
		{"bool empty string", entitlements.KindBoolean, ``, "value is required"},
		{"bool whitespace", entitlements.KindBoolean, `   `, "value is required"},
		{"bool null literal", entitlements.KindBoolean, `null`, "not null"},
		{"bool not an object", entitlements.KindBoolean, `true`, "must be a JSON object"},
		{"bool string payload", entitlements.KindBoolean, `{"enabled": "true"}`, "must be true or false"},
		{"bool null payload", entitlements.KindBoolean, `{"enabled": null}`, "must be true or false"},
		{"bool wrong field", entitlements.KindBoolean, `{"quantity": 5}`, `missing "enabled"`},
		{"bool extra field", entitlements.KindBoolean, `{"enabled": true, "quantity": 5}`, "unexpected field(s) quantity"},

		// numeric_cap
		{"cap zero", entitlements.KindNumericCap, `{"quantity": 0}`, ""},
		{"cap positive", entitlements.KindNumericCap, `{"quantity": 250}`, ""},
		{"cap unlimited", entitlements.KindNumericCap, `{"quantity": null}`, ""},
		{"cap empty object", entitlements.KindNumericCap, `{}`, `missing "quantity"`},
		{"cap negative", entitlements.KindNumericCap, `{"quantity": -5}`, "must not be negative"},
		{"cap fraction", entitlements.KindNumericCap, `{"quantity": 2.5}`, "whole number"},
		{"cap string", entitlements.KindNumericCap, `{"quantity": "10"}`, "must be an integer or null"},
		{"cap bool", entitlements.KindNumericCap, `{"quantity": true}`, "must be an integer or null"},
		{"cap huge", entitlements.KindNumericCap, `{"quantity": 1e12}`, "at most"},
		{"cap extra field", entitlements.KindNumericCap, `{"quantity": 5, "enabled": true}`, "unexpected field(s) enabled"},
		{"cap array", entitlements.KindNumericCap, `[5]`, "must be a JSON object"},

		// numeric_metered shares the numeric rule
		{"meter zero", entitlements.KindNumericMetered, `{"quantity": 0}`, ""},
		{"meter unlimited", entitlements.KindNumericMetered, `{"quantity": null}`, ""},
		{"meter empty object", entitlements.KindNumericMetered, `{}`, `missing "quantity"`},

		// enum_choice
		{"enum value", entitlements.KindEnumChoice, `{"value": "premium"}`, ""},
		{"enum empty object", entitlements.KindEnumChoice, `{}`, `missing "value"`},
		{"enum empty string", entitlements.KindEnumChoice, `{"value": ""}`, "non-empty string"},
		{"enum blank string", entitlements.KindEnumChoice, `{"value": "   "}`, "non-empty string"},
		{"enum null", entitlements.KindEnumChoice, `{"value": null}`, "non-empty string"},
		{"enum number", entitlements.KindEnumChoice, `{"value": 3}`, "non-empty string"},

		// kind itself
		{"unknown kind", entitlements.Kind("limit"), `{"quantity": 1}`, `unknown item kind "limit"`},
		{"empty kind", entitlements.Kind(""), `{"quantity": 1}`, "unknown item kind"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := entitlements.ValidateValue(tc.kind, json.RawMessage(tc.raw))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateValue(%s, %q) = %v, want nil", tc.kind, tc.raw, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateValue(%s, %q) = nil, want error containing %q", tc.kind, tc.raw, tc.wantErr)
			}
			var ive *entitlements.InvalidValueError
			if !errors.As(err, &ive) {
				t.Fatalf("error is %T, want *InvalidValueError", err)
			}
			if ive.Kind != tc.kind {
				t.Errorf("InvalidValueError.Kind = %q, want %q", ive.Kind, tc.kind)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// Every reason must tell the operator what shape was expected, not just that
// the value was wrong — that is what makes the 400 actionable from a form.
func TestValidateValue_ReasonsNameTheExpectedShape(t *testing.T) {
	for _, kind := range entitlements.KnownKinds() {
		err := entitlements.ValidateValue(kind, json.RawMessage(`{}`))
		if err == nil || !strings.Contains(err.Error(), "expected {") {
			t.Errorf("%s: reason for {} = %v, want it to spell out the expected shape", kind, err)
		}
	}
}

func TestIsKnownKind(t *testing.T) {
	for _, k := range entitlements.KnownKinds() {
		if !entitlements.IsKnownKind(k) {
			t.Errorf("IsKnownKind(%q) = false", k)
		}
	}
	for _, k := range []entitlements.Kind{"", "limit", "Boolean", "numeric"} {
		if entitlements.IsKnownKind(k) {
			t.Errorf("IsKnownKind(%q) = true", k)
		}
	}
}

// QuantityValue is the read-side half of the same rule. An explicit null is
// unlimited; a missing key is malformed. Both used to return (nil, true), which
// is how `{}` became unlimited capacity.
func TestQuantityValue_MissingKeyIsMalformed(t *testing.T) {
	ent := func(raw string) *entitlements.EffectiveEntitlement {
		return &entitlements.EffectiveEntitlement{
			Item:  entitlements.BillableItem{Key: "max_assets", Kind: entitlements.KindNumericCap},
			Value: json.RawMessage(raw),
		}
	}

	if qty, ok := ent(`{"quantity": null}`).QuantityValue(); !ok || qty != nil {
		t.Errorf(`{"quantity": null} = (%v, %v), want (nil, true) — explicit null is unlimited`, qty, ok)
	}
	if qty, ok := ent(`{"quantity": 7}`).QuantityValue(); !ok || qty == nil || *qty != 7 {
		t.Errorf(`{"quantity": 7} = (%v, %v), want (7, true)`, qty, ok)
	}
	if qty, ok := ent(`{"quantity": 0}`).QuantityValue(); !ok || qty == nil || *qty != 0 {
		t.Errorf(`{"quantity": 0} = (%v, %v), want (0, true) — zero is a real cap, not unlimited`, qty, ok)
	}
	for _, raw := range []string{`{}`, `{"enabled": true}`, `null`, `[]`, `"5"`} {
		if qty, ok := ent(raw).QuantityValue(); ok {
			t.Errorf("%s = (%v, %v), want ok=false — a missing quantity key must not read as unlimited", raw, qty, ok)
		}
	}
}
