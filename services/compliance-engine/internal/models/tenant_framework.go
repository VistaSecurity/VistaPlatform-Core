package models

import (
	"time"

	"github.com/google/uuid"
)

// TenantFramework represents a tenant-created or copied compliance framework
type TenantFramework struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	TenantID          uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Name              string     `json:"name" db:"name"`
	Version           string     `json:"version" db:"version"`
	Description       string     `json:"description" db:"description"`
	SourceFrameworkID *uuid.UUID `json:"source_framework_id,omitempty" db:"source_framework_id"` // If copied from platform framework
	CreatedBy         uuid.UUID  `json:"created_by" db:"created_by"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`

	// Computed fields
	ControlsCount int `json:"controls_count" db:"controls_count"`

	// Joined fields
	Controls []TenantFrameworkControl `json:"controls,omitempty" db:"-"`
}

// TenantFrameworkControl represents a control within a tenant framework
type TenantFrameworkControl struct {
	ID               uuid.UUID  `json:"id" db:"id"`
	FrameworkID      uuid.UUID  `json:"framework_id" db:"framework_id"`
	FamilyID         *uuid.UUID `json:"family_id,omitempty" db:"family_id"`
	ControlID        string     `json:"control_id" db:"control_id"`
	Title            string     `json:"title" db:"title"`
	Description      string     `json:"description" db:"description"`
	BaselineSeverity string     `json:"baseline_severity" db:"baseline_severity"`
	CryptoRelevant   bool       `json:"crypto_relevant" db:"crypto_relevant"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at" db:"updated_at"`

	// Joined fields
	Family       *Family              `json:"family,omitempty" db:"-"`
	Measurements []ControlMeasurement `json:"measurements,omitempty" db:"-"`
}

// TenantFrameworkInput represents input for creating/updating a tenant framework
type TenantFrameworkInput struct {
	Name        string `json:"name" binding:"required"`
	Version     string `json:"version" binding:"required"`
	Description string `json:"description"`
}

// TenantFrameworkControlInput represents input for creating/updating a tenant framework control
type TenantFrameworkControlInput struct {
	FamilyID         *uuid.UUID `json:"family_id"`
	ControlID        string     `json:"control_id" binding:"required"`
	Title            string     `json:"title" binding:"required"`
	Description      string     `json:"description"`
	BaselineSeverity string     `json:"baseline_severity" binding:"required,oneof=Low Med High Critical"`
	CryptoRelevant   bool       `json:"crypto_relevant"`
}
