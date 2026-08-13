package models

import (
	"time"

	"github.com/google/uuid"
)

// Finding represents an evidence item discovered by scanners/sensors or services
type Finding struct {
	ID        uuid.UUID      `json:"id" db:"id"`
	TenantID  uuid.UUID      `json:"tenant_id" db:"tenant_id"`
	Type      string         `json:"type" db:"type"` // e.g., tls_protocol, weak_cipher
	Severity  string         `json:"severity" db:"severity"`
	AssetID   *uuid.UUID     `json:"asset_id" db:"asset_id"`
	Evidence  map[string]any `json:"evidence" db:"evidence"`
	FirstSeen time.Time      `json:"first_seen" db:"first_seen"`
	LastSeen  time.Time      `json:"last_seen" db:"last_seen"`
	CreatedAt time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt time.Time      `json:"updated_at" db:"updated_at"`
}

// RuleVulnerabilityMapping links a compliance rule to a class of findings
type RuleVulnerabilityMapping struct {
	ID               uuid.UUID      `json:"id" db:"id"`
	RuleID           uuid.UUID      `json:"rule_id" db:"rule_id"`
	FindingType      string         `json:"finding_type" db:"finding_type"`
	Predicate        map[string]any `json:"predicate" db:"predicate"` // JSON logic-style filter
	Weight           int            `json:"weight" db:"weight"`
	FrameworkID      string         `json:"framework_id" db:"framework_id"`
	FrameworkVersion string         `json:"framework_version" db:"framework_version"`
	CreatedAt        time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at" db:"updated_at"`
}

// ComplianceFinding represents a finding linked to a specific compliance control
type ComplianceFinding struct {
	ID               uuid.UUID      `json:"id" db:"id"`
	TenantID         uuid.UUID      `json:"tenant_id" db:"tenant_id"`
	ControlID        uuid.UUID      `json:"control_id" db:"control_id"`
	AssetID          uuid.UUID      `json:"asset_id" db:"asset_id"`
	AssetType        string         `json:"asset_type" db:"asset_type"` // network_asset, certificate, crypto_implementation
	Severity         string         `json:"severity" db:"severity"`
	Summary          string         `json:"summary" db:"summary"`
	Evidence         map[string]any `json:"evidence" db:"evidence"`
	FirstSeen        time.Time      `json:"first_seen" db:"first_seen"`
	LastSeen         time.Time      `json:"last_seen" db:"last_seen"`
	AssignedTo       *uuid.UUID     `json:"assigned_to,omitempty" db:"assigned_to"`
	AssignedAt       *time.Time     `json:"assigned_at,omitempty" db:"assigned_at"`
	AssignedBy       *uuid.UUID     `json:"assigned_by,omitempty" db:"assigned_by"`
	RemediationNotes *string        `json:"remediation_notes,omitempty" db:"remediation_notes"`
	// Event-driven findings fields
	DetectionState    string     `json:"detection_state" db:"detection_state"` // ACTIVE, INACTIVE, ARCHIVED
	WorkflowStatus    string     `json:"workflow_status" db:"workflow_status"` // NEW, NOTIFIED, RESOLVED, SUPPRESSED
	OccurrenceCount   int        `json:"occurrence_count" db:"occurrence_count"`
	ResurfacedAt      *time.Time `json:"resurfaced_at,omitempty" db:"resurfaced_at"`
	SuppressedUntil   *time.Time `json:"suppressed_until,omitempty" db:"suppressed_until"`
	SuppressionReason *string    `json:"suppression_reason,omitempty" db:"suppression_reason"`
	// Stale detection fields
	IsStale           bool       `json:"is_stale" db:"is_stale"`
	LastEvaluatedAt   *time.Time `json:"last_evaluated_at,omitempty" db:"last_evaluated_at"`
	EvaluationVersion int        `json:"evaluation_version" db:"evaluation_version"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`

	// Computed fields
	TicketCount int `json:"ticket_count,omitempty" db:"-"`

	// Joined fields
	Control *Control `json:"control,omitempty" db:"-"`
	Asset   *Asset   `json:"asset,omitempty" db:"-"`
}

// ComplianceTicket represents a ticket for tracking remediation work
type ComplianceTicket struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	TenantID        uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	FindingID       *uuid.UUID `json:"finding_id,omitempty" db:"finding_id"`
	ControlID       uuid.UUID  `json:"control_id" db:"control_id"`
	Title           string     `json:"title" db:"title"`
	Description     *string    `json:"description,omitempty" db:"description"`
	Status          string     `json:"status" db:"status"`
	Priority        string     `json:"priority" db:"priority"`
	AssignedTo      *uuid.UUID `json:"assigned_to,omitempty" db:"assigned_to"`
	CreatedBy       uuid.UUID  `json:"created_by" db:"created_by"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolutionNotes *string    `json:"resolution_notes,omitempty" db:"resolution_notes"`

	// Joined fields
	Finding *ComplianceFinding `json:"finding,omitempty" db:"-"`
	Control *Control           `json:"control,omitempty" db:"-"`
}

// ComplianceFindingHistory represents a history entry for a compliance finding
type ComplianceFindingHistory struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	FindingID    uuid.UUID  `json:"finding_id" db:"finding_id"`
	ChangedBy    *uuid.UUID `json:"changed_by,omitempty" db:"changed_by"`
	ChangedAt    time.Time  `json:"changed_at" db:"changed_at"`
	FieldName    string     `json:"field_name" db:"field_name"`
	OldValue     *string    `json:"old_value,omitempty" db:"old_value"`
	NewValue     *string    `json:"new_value,omitempty" db:"new_value"`
	ChangeReason *string    `json:"change_reason,omitempty" db:"change_reason"`
}

// Asset represents an infrastructure asset (from inventory service)
type Asset struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	TenantID    uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Hostname    *string                `json:"hostname" db:"hostname"`
	IPAddress   *string                `json:"ip_address" db:"ip_address"`
	Port        *int                   `json:"port" db:"port"`
	AssetType   string                 `json:"asset_type" db:"asset_type"`
	Environment *string                `json:"environment" db:"environment"`
	Tags        map[string]interface{} `json:"tags" db:"tags"`
	// DisplayName is set when the finding's target isn't a network asset (a
	// certificate's common name, or a crypto-configuration's protocol/version
	// label) — the object has no hostname/IP of its own to fall back on.
	DisplayName *string `json:"display_name,omitempty" db:"-"`
}
