package database

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// JSONSlice and JSONStringSlice are the array companions to [JSONMap], for
// json/jsonb columns holding an array rather than an object.
//
// The same database/sql gap applies: a struct field declared
//
//	Operators []string `db:"valid_operators"`
//
// fails at runtime with "unsupported Scan, storing driver.Value type []uint8
// into type *[]string", and only against a real database — compilation and
// any test using a fake say nothing. compliance-engine's measurement_types
// read was dead this way: three jsonb array columns and two jsonb object
// columns scanned into plain Go slices and maps, so the platform-admin
// "add / edit a measurement rule" endpoints could never succeed.
//
// Unlike JSONMap, a nil slice is written as SQL NULL rather than an empty
// array, because the columns these serve are nullable with no default and an
// absent list is meaningfully different from an empty one: "no restriction on
// which operators are allowed" is not "no operator is allowed".
//
// JSON marshalling is unaffected — a named slice type encodes exactly as its
// underlying slice — so swapping a field to one of these does not change any
// API response shape.
type JSONSlice []interface{}

// JSONStringSlice is [JSONSlice] for an array known to hold only strings.
type JSONStringSlice []string

// Scan implements sql.Scanner. A SQL NULL, or an empty value, yields a nil
// slice (distinguishable from an empty one, which is what "[]" gives).
func (s *JSONSlice) Scan(src interface{}) error {
	return scanJSONArray(src, (*[]interface{})(s), "JSONSlice")
}

// Value implements driver.Valuer.
func (s JSONSlice) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal([]interface{}(s))
}

// Scan implements sql.Scanner. See [JSONSlice.Scan].
func (s *JSONStringSlice) Scan(src interface{}) error {
	return scanJSONArray(src, (*[]string)(s), "JSONStringSlice")
}

// Value implements driver.Valuer. See [JSONSlice.Value].
func (s JSONStringSlice) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal([]string(s))
}

// scanJSONArray holds the shared NULL/empty/type handling so the two slice
// types cannot drift apart on it.
func scanJSONArray(src interface{}, dst interface{}, typeName string) error {
	var b []byte
	switch v := src.(type) {
	case nil:
		b = nil
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return fmt.Errorf("database.%s: cannot scan %T", typeName, src)
	}
	if len(b) == 0 {
		// Zero the destination: Scan may be reusing a struct across rows.
		switch d := dst.(type) {
		case *[]interface{}:
			*d = nil
		case *[]string:
			*d = nil
		}
		return nil
	}
	return json.Unmarshal(b, dst)
}
