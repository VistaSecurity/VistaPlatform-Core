package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AlertRule represents a custom alert rule configuration
type AlertRule struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	TenantID    *uuid.UUID      `json:"tenant_id,omitempty" db:"tenant_id"` // NULL for platform rules
	Name        string          `json:"name" db:"name"`
	Description string          `json:"description" db:"description"`
	RuleType    string          `json:"rule_type" db:"rule_type"` // "threshold", "pattern", "anomaly"
	IsEnabled   bool            `json:"is_enabled" db:"is_enabled"`
	Severity    string          `json:"severity" db:"severity"` // "critical", "high", "medium", "low"
	Conditions  AlertConditions `json:"conditions" db:"conditions"`
	Actions     AlertActions    `json:"actions" db:"actions"`
	CreatedBy   uuid.UUID       `json:"created_by" db:"created_by"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at" db:"updated_at"`
}

// AlertConditions defines when an alert should trigger
type AlertConditions struct {
	EventTypes     []string               `json:"event_types,omitempty"`     // Match these event types
	EventCategory  string                 `json:"event_category,omitempty"`  // Match this category
	UserTypes      []string               `json:"user_types,omitempty"`      // Match these user types
	SuccessStatus  *bool                  `json:"success_status,omitempty"`  // Match success/failure
	TimeWindow     string                 `json:"time_window,omitempty"`     // e.g., "5m", "1h", "24h"
	Threshold      int                    `json:"threshold,omitempty"`       // Number of events to trigger
	FieldMatches   map[string]interface{} `json:"field_matches,omitempty"`   // Specific field values
	ResourceTypes  []string               `json:"resource_types,omitempty"`  // Match these resource types
	ComplianceTags []string               `json:"compliance_tags,omitempty"` // Match these compliance tags
}

// Scan implements sql.Scanner for AlertConditions
func (c *AlertConditions) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, c)
}

// Value implements driver.Valuer for AlertConditions
func (c AlertConditions) Value() (driver.Value, error) {
	return json.Marshal(c)
}

// AlertActions defines what happens when an alert triggers
type AlertActions struct {
	SendEmail       bool     `json:"send_email"`
	EmailRecipients []string `json:"email_recipients,omitempty"`
	SendWebhook     bool     `json:"send_webhook"`
	WebhookURL      string   `json:"webhook_url,omitempty"`
	CreateIncident  bool     `json:"create_incident"`
	SendSIEM        bool     `json:"send_siem"`
	NotifyAdmins    bool     `json:"notify_admins"`
}

// Scan implements sql.Scanner for AlertActions
func (a *AlertActions) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, a)
}

// Value implements driver.Valuer for AlertActions
func (a AlertActions) Value() (driver.Value, error) {
	return json.Marshal(a)
}

// AlertRuleFilters for querying alert rules
type AlertRuleFilters struct {
	TenantID  *uuid.UUID
	IsEnabled *bool
	Severity  string
	RuleType  string
	Page      int
	PageSize  int
}
