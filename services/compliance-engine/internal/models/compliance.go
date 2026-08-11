package models

import (
	"github.com/google/uuid"
	"time"
)

// ComplianceRule represents a compliance rule
type ComplianceRule struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	TenantID    uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Name        string                 `json:"name" db:"name"`
	Description string                 `json:"description" db:"description"`
	Category    string                 `json:"category" db:"category"`
	Severity    string                 `json:"severity" db:"severity"` // "critical", "high", "medium", "low"
	Status      string                 `json:"status" db:"status"`     // "active", "inactive", "draft"
	IsActive    bool                   `json:"is_active" db:"is_active"`
	Query       string                 `json:"query" db:"query"`
	Parameters  map[string]interface{} `json:"parameters" db:"parameters"`
	Tags        []string               `json:"tags" db:"tags"`
	CreatedBy   uuid.UUID              `json:"created_by" db:"created_by"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt   *time.Time             `json:"deleted_at" db:"deleted_at"`
}

// ComplianceRuleInput represents input for creating/updating a compliance rule
type ComplianceRuleInput struct {
	Name        string                 `json:"name" binding:"required"`
	Description string                 `json:"description"`
	Category    string                 `json:"category" binding:"required"`
	Severity    string                 `json:"severity" binding:"required"`
	Status      string                 `json:"status"`
	IsActive    bool                   `json:"is_active"`
	Query       string                 `json:"query" binding:"required"`
	Parameters  map[string]interface{} `json:"parameters"`
	Tags        []string               `json:"tags"`
}

// ComplianceCheck represents a compliance check execution
type ComplianceCheck struct {
	ID         uuid.UUID              `json:"id" db:"id"`
	TenantID   uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	RuleID     uuid.UUID              `json:"rule_id" db:"rule_id"`
	Rule       *ComplianceRule        `json:"rule" db:"rule"`
	Status     string                 `json:"status" db:"status"` // "passed", "failed", "error", "skipped"
	Message    string                 `json:"message" db:"message"`
	Details    map[string]interface{} `json:"details" db:"details"`
	ExecutedAt time.Time              `json:"executed_at" db:"executed_at"`
	CheckedAt  time.Time              `json:"checked_at" db:"checked_at"`
	Duration   int64                  `json:"duration_ms" db:"duration_ms"`
	CreatedAt  time.Time              `json:"created_at" db:"created_at"`
}

// ComplianceReport represents a compliance report
type ComplianceReport struct {
	ID          uuid.UUID         `json:"id" db:"id"`
	TenantID    uuid.UUID         `json:"tenant_id" db:"tenant_id"`
	Title       string            `json:"title" db:"title"`
	Description string            `json:"description" db:"description"`
	ReportType  string            `json:"report_type" db:"report_type"` // "scheduled", "on_demand", "incident"
	Status      string            `json:"status" db:"status"`           // "running", "completed", "failed"
	Summary     ComplianceSummary `json:"summary" db:"summary"`
	Checks      []ComplianceCheck `json:"checks" db:"checks"`
	GeneratedAt time.Time         `json:"generated_at" db:"generated_at"`
	CompletedAt *time.Time        `json:"completed_at" db:"completed_at"`
	GeneratedBy uuid.UUID         `json:"generated_by" db:"generated_by"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
}

// ComplianceReportInput represents input for creating a compliance report
type ComplianceReportInput struct {
	Title       string   `json:"title" binding:"required"`
	Description string   `json:"description"`
	ReportType  string   `json:"report_type" binding:"required"`
	RuleIDs     []string `json:"rule_ids"`
}

// ComplianceSummary represents a summary of compliance results
type ComplianceSummary struct {
	TotalChecks    int     `json:"total_checks"`
	PassedChecks   int     `json:"passed_checks"`
	FailedChecks   int     `json:"failed_checks"`
	ErrorChecks    int     `json:"error_checks"`
	SkippedChecks  int     `json:"skipped_checks"`
	WarningChecks  int     `json:"warning_checks"`
	CriticalIssues int     `json:"critical_issues"`
	HighIssues     int     `json:"high_issues"`
	MediumIssues   int     `json:"medium_issues"`
	LowIssues      int     `json:"low_issues"`
	ComplianceRate float64 `json:"compliance_rate"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	TenantID    uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	RuleID      uuid.UUID              `json:"rule_id" db:"rule_id"`
	AssetID     *uuid.UUID             `json:"asset_id" db:"asset_id"`
	Severity    string                 `json:"severity" db:"severity"`
	Title       string                 `json:"title" db:"title"`
	Description string                 `json:"description" db:"description"`
	Details     map[string]interface{} `json:"details" db:"details"`
	Status      string                 `json:"status" db:"status"` // "open", "acknowledged", "resolved", "false_positive"
	AssignedTo  *uuid.UUID             `json:"assigned_to" db:"assigned_to"`
	ResolvedAt  *time.Time             `json:"resolved_at" db:"resolved_at"`
	ResolvedBy  *uuid.UUID             `json:"resolved_by" db:"resolved_by"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
}

// ComplianceRequirement represents a requirement within a framework
type ComplianceRequirement struct {
	ID          uuid.UUID `json:"id" db:"id"`
	FrameworkID uuid.UUID `json:"framework_id" db:"framework_id"`
	Code        string    `json:"code" db:"code"`
	Title       string    `json:"title" db:"title"`
	Description string    `json:"description" db:"description"`
	Category    string    `json:"category" db:"category"`
	Priority    string    `json:"priority" db:"priority"`
	IsRequired  bool      `json:"is_required" db:"is_required"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}
