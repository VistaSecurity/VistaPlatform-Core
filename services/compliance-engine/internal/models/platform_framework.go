package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// PlatformFrameworkVersion represents a version snapshot of a platform framework
type PlatformFrameworkVersion struct {
	ID            uuid.UUID       `json:"id" db:"id"`
	FrameworkID   uuid.UUID       `json:"framework_id" db:"framework_id"`
	Version       string          `json:"version" db:"version"`
	Snapshot      json.RawMessage `json:"snapshot" db:"snapshot"`
	ChangeSummary *string         `json:"change_summary,omitempty" db:"change_summary"`
	ChangedBy     *uuid.UUID      `json:"changed_by,omitempty" db:"changed_by"`
	CreatedAt     time.Time       `json:"created_at" db:"created_at"`
}

// PlatformFrameworkVersionSummary is a version entry without the full snapshot
type PlatformFrameworkVersionSummary struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	Version       string     `json:"version" db:"version"`
	ChangeSummary *string    `json:"change_summary,omitempty" db:"change_summary"`
	ChangedBy     *uuid.UUID `json:"changed_by,omitempty" db:"changed_by"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
}

// PlatformFramework represents a platform admin-created compliance framework template
type PlatformFramework struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	Code              string     `json:"code" db:"code"`
	Name              string     `json:"name" db:"name"`
	Version           string     `json:"version" db:"version"`
	Description       string     `json:"description" db:"description"`
	Organization      string     `json:"organization" db:"organization"`
	Status            string     `json:"status" db:"status"` // draft, published, archived
	IsPlatformDefault bool       `json:"is_platform_default" db:"is_platform_default"`
	PublishedAt       *time.Time `json:"published_at,omitempty" db:"published_at"`
	PublishedBy       *uuid.UUID `json:"published_by,omitempty" db:"published_by"`
	CreatedBy         uuid.UUID  `json:"created_by" db:"created_by"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`

	// Computed fields
	ControlsCount int `json:"controls_count" db:"controls_count"`

	// Joined fields
	Controls []PlatformFrameworkControl `json:"controls,omitempty" db:"-"`
}

// PlatformFrameworkControl represents a control within a platform framework
type PlatformFrameworkControl struct {
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

// PlatformFrameworkInput represents input for creating/updating a platform framework
type PlatformFrameworkInput struct {
	Code              string `json:"code" binding:"required"`
	Name              string `json:"name" binding:"required"`
	Version           string `json:"version" binding:"required"`
	Description       string `json:"description"`
	Organization      string `json:"organization"`
	IsPlatformDefault bool   `json:"is_platform_default"`
}

// PublishFrameworkInput represents input for publishing a framework
type PublishFrameworkInput struct {
	Status string `json:"status" binding:"required,oneof=published archived"` // Can publish or archive
}

// PlatformFrameworkControlInput represents input for creating/updating a platform framework control
type PlatformFrameworkControlInput struct {
	FamilyID         *uuid.UUID `json:"family_id"`
	ControlID        string     `json:"control_id" binding:"required"`
	Title            string     `json:"title" binding:"required"`
	Description      string     `json:"description"`
	BaselineSeverity string     `json:"baseline_severity" binding:"required,oneof=Low Med High Critical"`
	CryptoRelevant   bool       `json:"crypto_relevant"`
}

// PublishedFrameworkWithLicense represents a published framework with license status for a tenant
type PublishedFrameworkWithLicense struct {
	PlatformFramework
	IsLicensed bool `json:"is_licensed" db:"is_licensed"`
}
