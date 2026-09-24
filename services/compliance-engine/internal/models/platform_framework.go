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

	// Seeded-content ownership (decision 4, RC-12); set by the admin catalogue reads.
	SeededContent

	// Joined fields
	Controls []PlatformFrameworkControl `json:"controls,omitempty" db:"-"`
}

// FrameworkControlColumns is the canonical SELECT list for a framework control
// row. The platform and tenant control tables have identical shapes, so both
// reads use it and cannot drift apart on which columns are COALESCEd.
//
// source_kind / source_ref are NULL on every row created before those columns
// existed, and NULL does not scan into a string — so they are COALESCEd to "",
// which is also how the API reports "this control carries no provenance".
const FrameworkControlColumns = `id, framework_id, family_id, control_id, title,
	       COALESCE(description, '') AS description,
	       baseline_severity, crypto_relevant,
	       COALESCE(source_kind, '') AS source_kind,
	       COALESCE(source_ref, '') AS source_ref,
	       created_at, updated_at`

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

	// SourceKind / SourceRef are ADR-0008 D4.1 provenance: where this control
	// came from. Empty means the row predates the columns — NOT that a person
	// wrote it. See the schema comment; the distinction is the point.
	SourceKind string `json:"source_kind,omitempty" db:"source_kind"`
	SourceRef  string `json:"source_ref,omitempty" db:"source_ref"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Seeded-content ownership (decision 4, RC-12); set by the admin catalogue reads.
	SeededContent

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
	BaselineSeverity string     `json:"baseline_severity" binding:"required,oneof=low medium high critical"`
	CryptoRelevant   bool       `json:"crypto_relevant"`

	// SourceKind / SourceRef record where this control came from, and are read
	// ON CREATE ONLY. Omitted, they default to "declared" — a person filled in
	// the authoring form. A client accepting a draft from the Author seam sends
	// "inferred" and the model that drafted it.
	//
	// Update ignores them deliberately: provenance says where a row CAME FROM,
	// which editing does not change. `updated_at` is what records the edit, and
	// a reviewer who tightens a drafted predicate has not turned it into a
	// control they wrote from scratch.
	//
	// Only the two values an authoring API can honestly produce are accepted.
	// "measured" and "imported" are in the column's CHECK because they are in
	// the shared vocabulary, but nothing here can legitimately claim either.
	SourceKind string `json:"source_kind,omitempty" binding:"omitempty,oneof=declared inferred"`
	SourceRef  string `json:"source_ref,omitempty" binding:"omitempty,max=200"`
}

// PublishedFrameworkWithLicense represents a published framework with license status for a tenant
type PublishedFrameworkWithLicense struct {
	PlatformFramework
	IsLicensed bool `json:"is_licensed" db:"is_licensed"`
}
