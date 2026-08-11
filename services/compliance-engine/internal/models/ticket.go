package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Ticket represents a unified ticket in the tickets table
type Ticket struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	TenantID    uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Category    string     `json:"category" db:"category"`
	Title       string     `json:"title" db:"title"`
	Description *string    `json:"description,omitempty" db:"description"`
	Status      string     `json:"status" db:"status"`
	Priority    string     `json:"priority" db:"priority"`
	Severity    *string    `json:"severity,omitempty" db:"severity"`
	DueDate     *time.Time `json:"due_date,omitempty" db:"due_date"`

	// Inventory links
	FindingID              *uuid.UUID `json:"finding_id,omitempty" db:"finding_id"`
	ControlID              *uuid.UUID `json:"control_id,omitempty" db:"control_id"`
	AssetID                *uuid.UUID `json:"asset_id,omitempty" db:"asset_id"`
	CertificateID          *uuid.UUID `json:"certificate_id,omitempty" db:"certificate_id"`
	CryptoImplementationID *uuid.UUID `json:"crypto_implementation_id,omitempty" db:"crypto_implementation_id"`

	// External ticket system integration
	ExternalTicketSystem *string `json:"external_ticket_system,omitempty" db:"external_ticket_system"`
	ExternalTicketID     *string `json:"external_ticket_id,omitempty" db:"external_ticket_id"`
	ExternalTicketURL    *string `json:"external_ticket_url,omitempty" db:"external_ticket_url"`
	ExternalSyncStatus   string  `json:"external_sync_status" db:"external_sync_status"`

	// Metadata
	Source string         `json:"source" db:"source"`
	Tags   pq.StringArray `json:"tags,omitempty" db:"tags"`

	// People
	AssignedTo *uuid.UUID `json:"assigned_to,omitempty" db:"assigned_to"`
	CreatedBy  uuid.UUID  `json:"created_by" db:"created_by"`

	// Timestamps
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolutionNotes *string    `json:"resolution_notes,omitempty" db:"resolution_notes"`

	// Alert bridge: set when the ticket was created from an alert.
	AlertID *uuid.UUID `json:"alert_id,omitempty" db:"alert_id"`

	// Computed/joined
	CommentCount int `json:"comment_count,omitempty" db:"-"`
}

// TicketComment represents a comment on a ticket
type TicketComment struct {
	ID       uuid.UUID `json:"id" db:"id"`
	TicketID uuid.UUID `json:"ticket_id" db:"ticket_id"`
	// AuthorID is nil for system-authored comments (alert-event echoes).
	AuthorID  *uuid.UUID `json:"author_id,omitempty" db:"author_id"`
	Content   string     `json:"content" db:"content"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

// CreateTicketInput is the input for creating a new ticket
type CreateTicketInput struct {
	Category    string  `json:"category"`
	Title       string  `json:"title" binding:"required"`
	Description *string `json:"description"`
	Priority    string  `json:"priority"`
	Severity    *string `json:"severity"`
	DueDate     *string `json:"due_date"` // ISO 8601

	// Inventory links
	FindingID              *string `json:"finding_id"`
	ControlID              *string `json:"control_id"`
	AssetID                *string `json:"asset_id"`
	CertificateID          *string `json:"certificate_id"`
	CryptoImplementationID *string `json:"crypto_implementation_id"`

	// External ticket system
	ExternalTicketSystem *string `json:"external_ticket_system"`
	ExternalTicketID     *string `json:"external_ticket_id"`
	ExternalTicketURL    *string `json:"external_ticket_url"`

	// Metadata
	Source *string  `json:"source"`
	Tags   []string `json:"tags"`

	// Assignment
	AssignedTo *string `json:"assigned_to"`
}

// UpdateTicketInput is the input for updating a ticket
type UpdateTicketInput struct {
	Status          *string  `json:"status"`
	Priority        *string  `json:"priority"`
	Severity        *string  `json:"severity"`
	DueDate         *string  `json:"due_date"` // ISO 8601 or empty string to clear
	AssignedTo      *string  `json:"assigned_to"`
	ResolutionNotes *string  `json:"resolution_notes"`
	Tags            []string `json:"tags"`
	Category        *string  `json:"category"`
	Description     *string  `json:"description"`

	// External ticket system
	ExternalTicketSystem *string `json:"external_ticket_system"`
	ExternalTicketID     *string `json:"external_ticket_id"`
	ExternalTicketURL    *string `json:"external_ticket_url"`
	ExternalSyncStatus   *string `json:"external_sync_status"`
}

// TicketFilters defines the query filters for listing tickets
type TicketFilters struct {
	Category      string `json:"category"`
	Status        string `json:"status"`
	Priority      string `json:"priority"`
	Severity      string `json:"severity"`
	AssignedTo    string `json:"assigned_to"`
	AssetID       string `json:"asset_id"`
	CertificateID string `json:"certificate_id"`
	FindingID     string `json:"finding_id"`
	Source        string `json:"source"`
	Search        string `json:"search"`
	Overdue       bool   `json:"overdue"`
	Page          int    `json:"page"`
	PageSize      int    `json:"page_size"`
}

// TicketStats holds aggregate ticket counts
type TicketStats struct {
	ByStatus   map[string]int `json:"by_status"`
	ByCategory map[string]int `json:"by_category"`
	Overdue    int            `json:"overdue"`
	Total      int            `json:"total"`
}

// TicketProgress holds time-series remediation progress data
type TicketProgress struct {
	PeriodDays         int                       `json:"period_days"`
	Summary            map[string]int            `json:"summary"`
	AvgResolutionHours float64                   `json:"avg_resolution_hours"`
	Trend              []TicketTrendPoint        `json:"trend"`
	ByCategory         map[string]map[string]int `json:"by_category"`
}

// TicketTrendPoint represents a single day's ticket activity
type TicketTrendPoint struct {
	Date     string `json:"date"`
	Opened   int    `json:"opened"`
	Resolved int    `json:"resolved"`
}
