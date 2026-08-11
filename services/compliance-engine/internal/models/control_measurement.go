package models

import (
	"time"

	"github.com/google/uuid"
)

// MeasurementType represents a type of measurement that can be evaluated
type MeasurementType struct {
	ID               uuid.UUID              `json:"id" db:"id"`
	Code             string                 `json:"code" db:"code"`
	Name             string                 `json:"name" db:"name"`
	Description      string                 `json:"description" db:"description"`
	DataType         string                 `json:"data_type" db:"data_type"` // integer, string, enum, date, boolean
	ExtractionQuery  string                 `json:"extraction_query,omitempty" db:"extraction_query"`
	Units            string                 `json:"units,omitempty" db:"units"`
	ValidRange       map[string]interface{} `json:"valid_range,omitempty" db:"valid_range"`
	AllowedRuleTypes []string               `json:"allowed_rule_types,omitempty" db:"allowed_rule_types"` // Array of allowed rule types
	EnumValues       []interface{}          `json:"enum_values,omitempty" db:"enum_values"`               // Array of valid enum values
	ValidOperators   []string               `json:"valid_operators,omitempty" db:"valid_operators"`       // Array of valid operators for threshold
	PredicateSchema  map[string]interface{} `json:"predicate_schema,omitempty" db:"predicate_schema"`     // JSON schema for predicate validation
	Category         string                 `json:"category,omitempty" db:"category"`                     // Grouping category
	CreatedAt        time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at" db:"updated_at"`
}

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
