package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ActivityLog represents an audit log entry
type ActivityLog struct {
	ID                uuid.UUID              `json:"id" db:"id"`
	TenantID          *uuid.UUID             `json:"tenant_id,omitempty" db:"tenant_id"`
	UserID            *uuid.UUID             `json:"user_id,omitempty" db:"user_id"`
	UserType          string                 `json:"user_type" db:"user_type"`
	UserEmail         *string                `json:"user_email,omitempty" db:"user_email"`
	EventType         string                 `json:"event_type" db:"event_type"`
	EventCategory     string                 `json:"event_category" db:"event_category"`
	Action            string                 `json:"action" db:"action"`
	ResourceType      *string                `json:"resource_type,omitempty" db:"resource_type"`
	ResourceID        *uuid.UUID             `json:"resource_id,omitempty" db:"resource_id"`
	OldValues         JSONB                  `json:"old_values,omitempty" db:"old_values"`
	NewValues         JSONB                  `json:"new_values,omitempty" db:"new_values"`
	ChangedFields     []string               `json:"changed_fields,omitempty" db:"changed_fields"`
	IPAddress         *string                `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent         *string                `json:"user_agent,omitempty" db:"user_agent"`
	RequestID         *string                `json:"request_id,omitempty" db:"request_id"`
	SessionID         *string                `json:"session_id,omitempty" db:"session_id"`
	Success           bool                   `json:"success" db:"success"`
	ErrorMessage      *string                `json:"error_message,omitempty" db:"error_message"`
	ErrorCode         *string                `json:"error_code,omitempty" db:"error_code"`
	ComplianceTags    []string               `json:"compliance_tags,omitempty" db:"compliance_tags"`
	RequiresAttention bool                   `json:"requires_attention" db:"requires_attention"`
	Metadata          map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	Tags              []string               `json:"tags,omitempty" db:"tags"`
	OccurredAt        time.Time              `json:"occurred_at" db:"occurred_at"`
	CreatedAt         time.Time              `json:"created_at" db:"created_at"`
}

// ActivityLogFilters carries query filters. The json tags (snake_case) let the
// POST /activity-logs/query handler bind a `filters` body directly; the GET list
// handler still populates the fields from query params. Tags must stay in sync
// with the QueryActivityLogsRequest.filters schema in audit-service.openapi.yaml.
type ActivityLogFilters struct {
	TenantID          *uuid.UUID `json:"tenant_id,omitempty"`
	UserID            *uuid.UUID `json:"user_id,omitempty"`
	UserType          *string    `json:"user_type,omitempty"`
	EventType         []string   `json:"event_type,omitempty"`
	EventCategory     []string   `json:"event_category,omitempty"`
	Action            []string   `json:"action,omitempty"`
	ResourceType      *string    `json:"resource_type,omitempty"`
	ResourceID        *uuid.UUID `json:"resource_id,omitempty"`
	ComplianceTags    []string   `json:"compliance_tags,omitempty"`
	Tags              []string   `json:"tags,omitempty"`          // Filter by tags (e.g., "impersonated_action")
	Impersonation     *bool      `json:"impersonation,omitempty"` // Filter for impersonated actions (uses admin_impersonation compliance tag)
	Success           *bool      `json:"success,omitempty"`
	RequiresAttention *bool      `json:"requires_attention,omitempty"`
	StartDate         *time.Time `json:"start_date,omitempty"`
	EndDate           *time.Time `json:"end_date,omitempty"`
	Search            *string    `json:"search,omitempty"` // Full-text search on metadata
	Page              int        `json:"page,omitempty"`
	PageSize          int        `json:"page_size,omitempty"`
	SortBy            string     `json:"sort_by,omitempty"`
	SortOrder         string     `json:"sort_order,omitempty"`
}

// JSONB is a helper type for JSONB database columns
type JSONB map[string]interface{}

// Value implements driver.Valuer interface
func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan implements sql.Scanner interface
func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}

	return json.Unmarshal(bytes, j)
}
