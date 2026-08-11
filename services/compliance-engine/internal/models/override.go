package models

import (
	"time"

	"github.com/google/uuid"
)

// Override represents a compliance override (disregard or severity change)
type Override struct {
	ID            uuid.UUID    `json:"id" db:"id"`
	TenantID      uuid.UUID    `json:"tenant_id" db:"tenant_id"`
	ScenarioID    *uuid.UUID   `json:"scenario_id" db:"scenario_id"` // NULL for global overrides
	ControlID     uuid.UUID    `json:"control_id" db:"control_id"`
	OverrideType  OverrideType `json:"override_type" db:"override_type"`
	SeverityFrom  *string      `json:"severity_from" db:"severity_from"`
	SeverityTo    *string      `json:"severity_to" db:"severity_to"`
	Rationale     string       `json:"rationale" db:"rationale"`
	FrameworkType string       `json:"framework_type" db:"framework_type"` // "platform" or "tenant"
	CreatedBy     uuid.UUID    `json:"created_by" db:"created_by"`
	CreatedAt     time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at" db:"updated_at"`

	// Joined fields
	Control  *Control  `json:"control,omitempty" db:"-"`
	Scenario *Scenario `json:"scenario,omitempty" db:"-"`
}

// OverrideType represents the type of override
type OverrideType string

const (
	OverrideTypeDisregard OverrideType = "disregard"
	OverrideTypeSeverity  OverrideType = "severity"
)

// Valid override types
var ValidOverrideTypes = []OverrideType{
	OverrideTypeDisregard,
	OverrideTypeSeverity,
}

// IsValid checks if the override type is valid
func (ot OverrideType) IsValid() bool {
	for _, valid := range ValidOverrideTypes {
		if ot == valid {
			return true
		}
	}
	return false
}
