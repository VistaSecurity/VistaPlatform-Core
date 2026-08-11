package database

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// JSONMap is a map[string]interface{} that can be scanned directly out of, and
// written directly into, a json/jsonb column.
//
// It exists because database/sql has no conversion between []byte and a Go
// map, in either direction. A struct field declared
//
//	Config map[string]interface{} `db:"config"`
//
// therefore fails at runtime with "unsupported Scan, storing driver.Value type
// []uint8 into type *map[string]interface {}" on read, and "unsupported type
// map[string]interface {}, a map" on write — but only when a real database is
// involved, so unit tests and compilation say nothing. Two such fields were
// found dead this way while adding the credential-encryption integration
// tests (inventory-service's integrations.auth_config and
// cluster-sensor-service's discovery_alert_configs.conditions): both endpoints
// had never worked against Postgres.
//
// JSON marshalling is unaffected — a named map type encodes exactly as its
// underlying map — so swapping a field to JSONMap does not change any API
// response shape.
type JSONMap map[string]interface{}

// Scan implements sql.Scanner. A SQL NULL, or an empty value, yields a nil map
// (distinguishable from an empty one, which is what "{}" gives).
func (m *JSONMap) Scan(src interface{}) error {
	if src == nil {
		*m = nil
		return nil
	}
	var b []byte
	switch v := src.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return fmt.Errorf("database.JSONMap: cannot scan %T", src)
	}
	if len(b) == 0 {
		*m = nil
		return nil
	}
	return json.Unmarshal(b, (*map[string]interface{})(m))
}

// Value implements driver.Valuer. A nil map is written as an empty JSON object
// rather than SQL NULL, because every column this type serves is a
// NOT NULL DEFAULT '{}' config blob.
func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(map[string]interface{}(m))
}
