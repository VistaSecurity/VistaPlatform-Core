package facts

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"
)

// dateLayouts are the forms a `date` fact may arrive in. A fact usually
// crosses a JSON boundary before it is stored, so a date is a string far more
// often than it is a time.Time.
var dateLayouts = []string{
	time.RFC3339,
	"2006-01-02",
}

// ValidateValue reports whether v is an acceptable value for the registered
// fact key. It is the enforcement point for asset_facts writes: the key column
// has no CHECK constraint and the value column is jsonb, so nothing else
// stands between a producer and a fact nobody can read back.
//
// It type-checks the value against the key's declared type and, for scalar
// keys that declare one, against the enum. It deliberately does NOT validate
// the inside of an array or object against ItemSchema — that fragment is
// vocabulary for consumers, and the producer owns the shape of what it puts
// inside. Validating it here would mean a schema edit could reject facts a
// deployed collector is still sending.
func ValidateValue(key string, v any) error {
	k, ok := Get(key)
	if !ok {
		return fmt.Errorf("facts: unknown fact key %q", key)
	}
	// A nil value is the absence of a fact, not a fact with no value. Writing
	// one would make "not collected" and "collected as nothing" the same row,
	// which is the three-valued mistake this codebase keeps paying for.
	if v == nil {
		return fmt.Errorf("facts: %s: value is nil; omit the fact instead of storing an empty one", key)
	}

	switch k.Type {
	case "string":
		s, ok := v.(string)
		if !ok {
			return typeErr(key, k.Type, v)
		}
		if len(k.Enum) > 0 && !slices.Contains(k.Enum, s) {
			return fmt.Errorf("facts: %s: value %q is not one of [%s]", key, s, strings.Join(k.Enum, ", "))
		}
		return nil

	case "integer":
		if !isInteger(v) {
			return typeErr(key, k.Type, v)
		}
		return nil

	case "boolean":
		if _, ok := v.(bool); !ok {
			return typeErr(key, k.Type, v)
		}
		return nil

	case "date":
		return validateDate(key, v)

	case "array":
		if !isArray(v) {
			return typeErr(key, k.Type, v)
		}
		return nil

	case "object":
		if !isObject(v) {
			return typeErr(key, k.Type, v)
		}
		return nil

	default:
		// Unreachable while the generator validates the type vocabulary, but a
		// silent pass here would let a bad generated file through unnoticed.
		return fmt.Errorf("facts: %s: registry declares unsupported type %q", key, k.Type)
	}
}

func typeErr(key, want string, v any) error {
	return fmt.Errorf("facts: %s: want %s, got %T", key, want, v)
}

func isInteger(v any) bool {
	switch n := v.(type) {
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return true
	case float32:
		return isIntegral(float64(n))
	case float64:
		// JSON numbers decode to float64, so a whole number that arrived as
		// 42.0 is an integer as far as a fact is concerned. 42.5 is not.
		return isIntegral(n)
	case json.Number:
		_, err := n.Int64()
		return err == nil
	default:
		return false
	}
}

func isIntegral(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Trunc(f)
}

func validateDate(key string, v any) error {
	if _, ok := v.(time.Time); ok {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return typeErr(key, "date", v)
	}
	for _, layout := range dateLayouts {
		if _, err := time.Parse(layout, s); err == nil {
			return nil
		}
	}
	return fmt.Errorf("facts: %s: %q is not an RFC 3339 timestamp or a YYYY-MM-DD date", key, s)
}

func isArray(v any) bool {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice:
		// A nil slice marshals to JSON `null`, so storing one writes the empty
		// fact the nil check above exists to refuse. An empty-but-allocated
		// slice is a different statement — "nothing here" — and is allowed.
		if rv.IsNil() {
			return false
		}
		// []byte is raw bytes, not a list of facts. Accepting it would let an
		// encoded blob masquerade as an array and read back as gibberish.
		return rv.Type().Elem().Kind() != reflect.Uint8
	case reflect.Array:
		return rv.Type().Elem().Kind() != reflect.Uint8
	default:
		return false
	}
}

func isObject(v any) bool {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		// A nil map marshals to JSON `null`, the same empty fact a nil slice
		// would write. A non-nil empty map is a value and is allowed.
		if rv.IsNil() {
			return false
		}
		return rv.Type().Key().Kind() == reflect.String
	case reflect.Struct:
		// A typed producer may hand over its own struct; it marshals to a JSON
		// object like any map. time.Time is a struct too, and is not one.
		return rv.Type() != reflect.TypeOf(time.Time{})
	case reflect.Pointer:
		if rv.IsNil() {
			return false
		}
		return isObject(rv.Elem().Interface())
	default:
		return false
	}
}

// MayWrite reports whether a producer is permitted to write a fact key. A
// collector writing a key it is not registered for means two subsystems
// disagree about who owns a fact, which is how one key ends up with two
// meanings.
func MayWrite(producer, key string) bool {
	k, ok := Get(key)
	return ok && slices.Contains(k.Producers, producer)
}
