package models

import (
	"time"

	"github.com/google/uuid"
)

// RemediationPlan represents a remediation initiative that groups related findings
type RemediationPlan struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	TenantID    uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Title       string     `json:"title" db:"title"`
	Description *string    `json:"description,omitempty" db:"description"`
	PlanType    string     `json:"plan_type" db:"plan_type"`
	Status      string     `json:"status" db:"status"`
	Priority    string     `json:"priority" db:"priority"`
	OwnerID     *uuid.UUID `json:"owner_id,omitempty" db:"owner_id"`
	TargetDate  *time.Time `json:"target_date,omitempty" db:"target_date"`
	FrameworkID *uuid.UUID `json:"framework_id,omitempty" db:"framework_id"`
	CompletedAt *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	CreatedBy   uuid.UUID  `json:"created_by" db:"created_by"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`

	// Computed fields (not stored in DB)
	ItemCount     int `json:"item_count" db:"-"`
	ResolvedCount int `json:"resolved_count" db:"-"`
	Progress      int `json:"progress" db:"-"`
}

// RemediationPlanItem represents a finding linked to a plan
type RemediationPlanItem struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	PlanID    uuid.UUID  `json:"plan_id" db:"plan_id"`
	FindingID uuid.UUID  `json:"finding_id" db:"finding_id"`
	TicketID  *uuid.UUID `json:"ticket_id,omitempty" db:"ticket_id"`
	Notes     *string    `json:"notes,omitempty" db:"notes"`
	AddedAt   time.Time  `json:"added_at" db:"added_at"`
	AddedBy   uuid.UUID  `json:"added_by" db:"added_by"`

	// Joined from compliance_findings
	FindingSeverity       *string    `json:"finding_severity,omitempty" db:"finding_severity"`
	FindingSummary        *string    `json:"finding_summary,omitempty" db:"finding_summary"`
	FindingWorkflowStatus *string    `json:"finding_workflow_status,omitempty" db:"finding_workflow_status"`
	FindingAssetType      *string    `json:"finding_asset_type,omitempty" db:"finding_asset_type"`
	FindingAssetID        *uuid.UUID `json:"finding_asset_id,omitempty" db:"finding_asset_id"`

	// Joined from tickets (if linked)
	TicketStatus *string `json:"ticket_status,omitempty" db:"ticket_status"`
	TicketTitle  *string `json:"ticket_title,omitempty" db:"ticket_title"`
}

// CreatePlanInput is the input for creating a new remediation plan
type CreatePlanInput struct {
	Title       string  `json:"title" binding:"required"`
	Description *string `json:"description"`
	PlanType    string  `json:"plan_type"`
	Priority    string  `json:"priority"`
	OwnerID     *string `json:"owner_id"`
	TargetDate  *string `json:"target_date"`
	FrameworkID *string `json:"framework_id"`
}

// UpdatePlanInput is the input for updating a remediation plan
type UpdatePlanInput struct {
	Title       *string `json:"title"`
	Description *string `json:"description"`
	Status      *string `json:"status"`
	Priority    *string `json:"priority"`
	OwnerID     *string `json:"owner_id"`
	TargetDate  *string `json:"target_date"`
}

// AddPlanItemInput is the input for adding a finding to a plan
type AddPlanItemInput struct {
	FindingID string  `json:"finding_id" binding:"required"`
	TicketID  *string `json:"ticket_id"`
	Notes     *string `json:"notes"`
}

// AddPlanItemsBulkInput is the input for adding multiple findings to a plan
type AddPlanItemsBulkInput struct {
	FindingIDs []string `json:"finding_ids" binding:"required"`
}

// LinkTicketInput is the input for linking a ticket to a plan item
type LinkTicketInput struct {
	TicketID string `json:"ticket_id" binding:"required"`
}

// PlanFilters defines query filters for listing plans
type PlanFilters struct {
	Status   string `json:"status"`
	PlanType string `json:"plan_type"`
	Priority string `json:"priority"`
	OwnerID  string `json:"owner_id"`
	Search   string `json:"search"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

// PlanProgress is a detailed progress breakdown for a remediation plan
type PlanProgress struct {
	TotalItems       int            `json:"total_items"`
	ByWorkflowStatus map[string]int `json:"by_workflow_status"`
	ByTicketStatus   map[string]int `json:"by_ticket_status"`
	BySeverity       map[string]int `json:"by_severity"`
	PercentResolved  int            `json:"percent_resolved"`
	AllResolved      bool           `json:"all_resolved"`
}

// PlanRef is a lightweight plan reference used for ticket -> plan back-links.
// Carries only the fields needed to render a badge and navigate back to the plan.
type PlanRef struct {
	ID     uuid.UUID `json:"id" db:"id"`
	Title  string    `json:"title" db:"title"`
	Status string    `json:"status" db:"status"`
}
