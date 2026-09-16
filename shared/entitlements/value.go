package entitlements

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

// InvalidValueError reports an entitlement value that does not have the shape
// its item kind requires. Handlers map it to 400; the Reason is safe to echo
// to an operator because it describes the request, not the database.
type InvalidValueError struct {
	Kind   Kind
	Reason string
}

func (e *InvalidValueError) Error() string {
	return fmt.Sprintf("entitlements: invalid %s value: %s", e.Kind, e.Reason)
}

// KnownKinds lists every value kind the catalog supports, in a stable order.
func KnownKinds() []Kind {
	return []Kind{KindBoolean, KindNumericCap, KindNumericMetered, KindEnumChoice}
}

// IsKnownKind reports whether kind is one the catalog supports.
func IsKnownKind(kind Kind) bool {
	for _, k := range KnownKinds() {
		if k == kind {
			return true
		}
	}
	return false
}

// ValidateValue checks that raw is a well-formed value for an item of the given
// kind. It is the single shape rule for billable_items.default_value,
// tier_entitlements.included_value and tenant_entitlements.override_value, and
// every write path is expected to call it before persisting.
//
// The shapes are exact, not "at least":
//
//	boolean          {"enabled": true|false}
//	numeric_cap      {"quantity": N}       N a non-negative integer
//	numeric_metered  {"quantity": null}    null is the explicit "unlimited"
//	enum_choice      {"value": "..."}      a non-empty string
//
// Why exact: the resolver COALESCEs override > tier > default, and an empty
// object is non-NULL JSON, so `{}` stored anywhere in that chain WINS the
// coalesce and then has to be interpreted. Before this rule existed, `{}`
// parsed as quantity=nil and was honoured as unlimited — a form left blank, or
// a PUT that omitted the value, silently granted unlimited capacity, and did
// so from the layer that outranks the operator's own tier. Missing is not
// unlimited; unlimited is spelled out.
//
// Unknown keys are rejected for the same reason: {"quantity": 5, "enabled":
// true} is a request whose meaning depends on which accessor happens to read
// it. A negative quantity is rejected because no gate can satisfy it — the
// cap check compares current+additional <= quantity, so -1 denies everything
// while displaying as a real number.
//
// enum_choice membership is NOT checked: the catalog carries no allowed-values
// list for an enum item, so the most this can assert is "a non-empty string".
func ValidateValue(kind Kind, raw json.RawMessage) error {
	if !IsKnownKind(kind) {
		return &InvalidValueError{Kind: kind, Reason: fmt.Sprintf("unknown item kind %q (want one of %s)", kind, kindList())}
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return &InvalidValueError{Kind: kind, Reason: "value is required (" + shapeHint(kind) + ")"}
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return &InvalidValueError{Kind: kind, Reason: "value must be a JSON object (" + shapeHint(kind) + ")"}
	}
	if obj == nil {
		// json.Unmarshal of the literal `null` into a map leaves it nil
		// without an error.
		return &InvalidValueError{Kind: kind, Reason: "value must be a JSON object, not null (" + shapeHint(kind) + ")"}
	}

	field := shapeField(kind)
	inner, present := obj[field]
	if !present {
		return &InvalidValueError{Kind: kind, Reason: fmt.Sprintf("missing %q (%s)", field, shapeHint(kind))}
	}
	if len(obj) != 1 {
		extra := make([]string, 0, len(obj)-1)
		for k := range obj {
			if k != field {
				extra = append(extra, k)
			}
		}
		sort.Strings(extra)
		return &InvalidValueError{Kind: kind, Reason: fmt.Sprintf("unexpected field(s) %s (%s)", strings.Join(extra, ", "), shapeHint(kind))}
	}

	switch kind {
	case KindBoolean:
		var b *bool
		if err := json.Unmarshal(inner, &b); err != nil || b == nil {
			return &InvalidValueError{Kind: kind, Reason: `"enabled" must be true or false`}
		}
	case KindNumericCap, KindNumericMetered:
		if string(inner) == "null" {
			return nil // explicit unlimited
		}
		var f float64
		if err := json.Unmarshal(inner, &f); err != nil {
			return &InvalidValueError{Kind: kind, Reason: `"quantity" must be an integer or null (null = unlimited)`}
		}
		if f != math.Trunc(f) || math.IsInf(f, 0) || math.IsNaN(f) {
			return &InvalidValueError{Kind: kind, Reason: `"quantity" must be a whole number`}
		}
		if f < 0 {
			return &InvalidValueError{Kind: kind, Reason: `"quantity" must not be negative (use null for unlimited)`}
		}
		if f > math.MaxInt32 {
			return &InvalidValueError{Kind: kind, Reason: fmt.Sprintf(`"quantity" must be at most %d (use null for unlimited)`, math.MaxInt32)}
		}
	case KindEnumChoice:
		var s *string
		if err := json.Unmarshal(inner, &s); err != nil || s == nil || strings.TrimSpace(*s) == "" {
			return &InvalidValueError{Kind: kind, Reason: `"value" must be a non-empty string`}
		}
	}
	return nil
}

func shapeField(kind Kind) string {
	switch kind {
	case KindBoolean:
		return "enabled"
	case KindNumericCap, KindNumericMetered:
		return "quantity"
	default:
		return "value"
	}
}

func shapeHint(kind Kind) string {
	switch kind {
	case KindBoolean:
		return `expected {"enabled": true|false}`
	case KindNumericCap, KindNumericMetered:
		return `expected {"quantity": N} or {"quantity": null} for unlimited`
	default:
		return `expected {"value": "..."}`
	}
}

func kindList() string {
	names := make([]string, 0, 4)
	for _, k := range KnownKinds() {
		names = append(names, string(k))
	}
	return strings.Join(names, ", ")
}
