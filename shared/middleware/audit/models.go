package audit

import (
	"time"

	"github.com/google/uuid"
)

// ActivityLogRequest represents an audit log entry to be sent to audit-service
type ActivityLogRequest struct {
	TenantID          *uuid.UUID             `json:"tenant_id,omitempty"`
	UserID            *uuid.UUID             `json:"user_id,omitempty"`
	UserType          string                 `json:"user_type"`
	UserEmail         *string                `json:"user_email,omitempty"`
	EventType         string                 `json:"event_type"`
	EventCategory     string                 `json:"event_category"`
	Action            string                 `json:"action"`
	ResourceType      *string                `json:"resource_type,omitempty"`
	ResourceID        *uuid.UUID             `json:"resource_id,omitempty"`
	OldValues         map[string]interface{} `json:"old_values,omitempty"`
	NewValues         map[string]interface{} `json:"new_values,omitempty"`
	ChangedFields     []string               `json:"changed_fields,omitempty"`
	IPAddress         *string                `json:"ip_address,omitempty"`
	UserAgent         *string                `json:"user_agent,omitempty"`
	RequestID         *string                `json:"request_id,omitempty"`
	SessionID         *string                `json:"session_id,omitempty"`
	Success           bool                   `json:"success"`
	ErrorMessage      *string                `json:"error_message,omitempty"`
	ErrorCode         *string                `json:"error_code,omitempty"`
	ComplianceTags    []string               `json:"compliance_tags,omitempty"`
	RequiresAttention bool                   `json:"requires_attention"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	Tags              []string               `json:"tags,omitempty"`
	OccurredAt        time.Time              `json:"occurred_at"`
}

// LogActivityResponse represents the response from audit-service
type LogActivityResponse struct {
	ID      uuid.UUID `json:"id"`
	Message string    `json:"message,omitempty"`
	Error   string    `json:"error,omitempty"`
}
