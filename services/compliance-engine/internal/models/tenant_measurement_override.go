package models

import (
	"time"

	"github.com/google/uuid"
)

// TenantMeasurementOverride allows tenants to customize measurement predicates
// on licensed platform framework controls without copying the framework.
// For example, a tenant might override cert_expiration_days threshold from 30 to 60.
type TenantMeasurementOverride struct {
	ID                   uuid.UUID              `json:"id" db:"id"`
	TenantID             uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	ControlMeasurementID uuid.UUID              `json:"control_measurement_id" db:"control_measurement_id"`
	PredicateOverride    map[string]interface{} `json:"predicate_override" db:"predicate_override"`
	SeverityOverride     *string                `json:"severity_override,omitempty" db:"severity_override"`
	Rationale            string                 `json:"rationale" db:"rationale"`
	CreatedBy            uuid.UUID              `json:"created_by" db:"created_by"`
	CreatedAt            time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at" db:"updated_at"`

	// Joined fields
	ControlMeasurement *ControlMeasurement `json:"control_measurement,omitempty" db:"-"`
}

// TenantMeasurementOverrideInput represents the input for creating/updating a threshold override
type TenantMeasurementOverrideInput struct {
	ControlMeasurementID string                 `json:"control_measurement_id" binding:"required"`
	PredicateOverride    map[string]interface{} `json:"predicate_override" binding:"required"`
	SeverityOverride     *string                `json:"severity_override,omitempty"`
	Rationale            string                 `json:"rationale" binding:"required"`
}
