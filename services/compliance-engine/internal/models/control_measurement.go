package models

import (
	"time"

	"github.com/google/uuid"
	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
)

// MeasurementType represents a type of measurement that can be evaluated.
//
// The five jsonb-backed fields use the shared JSON scanner types rather than
// plain maps and slices: database/sql cannot scan jsonb into either, so a
// plain declaration compiles, passes every test that does not touch Postgres,
// and then fails on every real row. Read this row through
// [MeasurementTypeColumns], which also COALESCEs the nullable text columns —
// every seeded measurement type has a NULL extraction_query, and NULL does not
// scan into a string either.
type MeasurementType struct {
	ID               uuid.UUID                `json:"id" db:"id"`
	Code             string                   `json:"code" db:"code"`
	Name             string                   `json:"name" db:"name"`
	Description      string                   `json:"description" db:"description"`
	DataType         string                   `json:"data_type" db:"data_type"` // integer, string, enum, date, boolean
	ExtractionQuery  string                   `json:"extraction_query,omitempty" db:"extraction_query"`
	Units            string                   `json:"units,omitempty" db:"units"`
	ValidRange       shareddb.JSONMap         `json:"valid_range,omitempty" db:"valid_range"`
	AllowedRuleTypes shareddb.JSONStringSlice `json:"allowed_rule_types,omitempty" db:"allowed_rule_types"` // Array of allowed rule types
	EnumValues       shareddb.JSONSlice       `json:"enum_values,omitempty" db:"enum_values"`               // Array of valid enum values
	ValidOperators   shareddb.JSONStringSlice `json:"valid_operators,omitempty" db:"valid_operators"`       // Array of valid operators for threshold
	PredicateSchema  shareddb.JSONMap         `json:"predicate_schema,omitempty" db:"predicate_schema"`     // JSON schema for predicate validation
	Category         string                   `json:"category,omitempty" db:"category"`                     // Grouping category
	CreatedAt        time.Time                `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time                `json:"updated_at" db:"updated_at"`
}

// MeasurementTypeColumns is the canonical SELECT list for a [MeasurementType],
// shared by every read so they cannot drift apart on which columns need a
// COALESCE. description / extraction_query / units / category are all nullable
// and land in plain string fields.
const MeasurementTypeColumns = `id, code, name,
	       COALESCE(description, '') AS description,
	       data_type,
	       COALESCE(extraction_query, '') AS extraction_query,
	       COALESCE(units, '') AS units,
	       valid_range, allowed_rule_types, enum_values, valid_operators, predicate_schema,
	       COALESCE(category, '') AS category,
	       created_at, updated_at`

// ControlMeasurement represents a mapping between a control and a measurement type with rule logic
type ControlMeasurement struct {
	ID                uuid.UUID              `json:"id" db:"id"`
	ControlID         uuid.UUID              `json:"control_id" db:"control_id"`
	FrameworkType     string                 `json:"framework_type" db:"framework_type"` // platform or tenant
	MeasurementTypeID uuid.UUID              `json:"measurement_type_id" db:"measurement_type_id"`
	RuleType          string                 `json:"rule_type" db:"rule_type"` // threshold, presence, pattern, range
	Predicate         map[string]interface{} `json:"predicate" db:"predicate"` // Rule logic JSON
	SeverityOverride  string                 `json:"severity_override,omitempty" db:"severity_override"`
	Weight            int                    `json:"weight" db:"weight"`
	CreatedAt         time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at" db:"updated_at"`

	// Joined fields
	MeasurementType *MeasurementType `json:"measurement_type,omitempty" db:"-"`
}

// RulePredicate represents the structure of a rule predicate
type RulePredicate struct {
	Type     string      `json:"type"`               // threshold, presence, pattern, range
	Operator string      `json:"operator,omitempty"` // <=, >=, <, >, ==, != (for threshold)
	Value    interface{} `json:"value,omitempty"`    // Value for threshold or pattern
	Field    string      `json:"field,omitempty"`    // Field name for threshold
	Pattern  string      `json:"pattern,omitempty"`  // Regex pattern for pattern type
	Min      interface{} `json:"min,omitempty"`      // Min value for range
	Max      interface{} `json:"max,omitempty"`      // Max value for range
	Exists   bool        `json:"exists,omitempty"`   // Boolean for presence type
}

// ControlMeasurementInput represents input for creating/updating a control measurement
type ControlMeasurementInput struct {
	MeasurementTypeID uuid.UUID              `json:"measurement_type_id" binding:"required"`
	RuleType          string                 `json:"rule_type" binding:"required,oneof=threshold presence pattern range"`
	Predicate         map[string]interface{} `json:"predicate" binding:"required"`
	SeverityOverride  string                 `json:"severity_override,omitempty" binding:"omitempty,oneof=Low Med High Critical"`
	Weight            int                    `json:"weight" binding:"omitempty,min=1,max=10"`
}
