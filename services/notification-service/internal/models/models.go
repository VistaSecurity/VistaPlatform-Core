package models

import (
	"time"

	"github.com/google/uuid"
)

// TenantNotificationChannel represents a notification channel for a tenant
type TenantNotificationChannel struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	TenantID    uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	ChannelName string                 `json:"channel_name" db:"channel_name"`
	ChannelType string                 `json:"channel_type" db:"channel_type"`
	Config      map[string]interface{} `json:"config" db:"config"`
	Enabled     bool                   `json:"enabled" db:"enabled"`
	TestStatus  *string                `json:"test_status,omitempty" db:"test_status"`
	LastTestAt  *time.Time             `json:"last_test_at,omitempty" db:"last_test_at"`
	LastUsedAt  *time.Time             `json:"last_used_at,omitempty" db:"last_used_at"`
	Description *string                `json:"description,omitempty" db:"description"`
	CreatedBy   *uuid.UUID             `json:"created_by,omitempty" db:"created_by"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
}

// PlatformNotificationChannel represents a platform-wide notification channel
type PlatformNotificationChannel struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	ChannelName string                 `json:"channel_name" db:"channel_name"`
	ChannelType string                 `json:"channel_type" db:"channel_type"`
	Config      map[string]interface{} `json:"config" db:"config"`
	Enabled     bool                   `json:"enabled" db:"enabled"`
	TestStatus  *string                `json:"test_status,omitempty" db:"test_status"`
	LastTestAt  *time.Time             `json:"last_test_at,omitempty" db:"last_test_at"`
	LastUsedAt  *time.Time             `json:"last_used_at,omitempty" db:"last_used_at"`
	Description *string                `json:"description,omitempty" db:"description"`
	CreatedBy   *uuid.UUID             `json:"created_by,omitempty" db:"created_by"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	UpdatedBy   *uuid.UUID             `json:"updated_by,omitempty" db:"updated_by"`
}

// TenantNotificationRule represents a notification rule for a tenant
type TenantNotificationRule struct {
	ID             uuid.UUID   `json:"id" db:"id"`
	TenantID       uuid.UUID   `json:"tenant_id" db:"tenant_id"`
	RuleName       string      `json:"rule_name" db:"rule_name"`
	AlertSource    string      `json:"alert_source" db:"alert_source"`
	AlertType      *string     `json:"alert_type,omitempty" db:"alert_type"`
	ChannelIDs     []uuid.UUID `json:"channel_ids" db:"channel_ids"`
	SeverityFilter []string    `json:"severity_filter,omitempty" db:"severity_filter"`
	CategoryFilter []string    `json:"category_filter,omitempty" db:"category_filter"`
	Frequency      string      `json:"frequency" db:"frequency"`
	DigestWindow   *int        `json:"digest_window,omitempty" db:"digest_window"`
	Enabled        bool        `json:"enabled" db:"enabled"`
	Priority       int         `json:"priority" db:"priority"`
	CreatedAt      time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at" db:"updated_at"`
}

// PlatformNotificationRule represents a platform-wide notification rule
type PlatformNotificationRule struct {
	ID             uuid.UUID   `json:"id" db:"id"`
	RuleName       string      `json:"rule_name" db:"rule_name"`
	AlertSource    string      `json:"alert_source" db:"alert_source"`
	AlertType      *string     `json:"alert_type,omitempty" db:"alert_type"`
	ChannelIDs     []uuid.UUID `json:"channel_ids" db:"channel_ids"`
	SeverityFilter []string    `json:"severity_filter,omitempty" db:"severity_filter"`
	CategoryFilter []string    `json:"category_filter,omitempty" db:"category_filter"`
	Frequency      string      `json:"frequency" db:"frequency"`
	DigestWindow   *int        `json:"digest_window,omitempty" db:"digest_window"`
	Enabled        bool        `json:"enabled" db:"enabled"`
	Priority       int         `json:"priority" db:"priority"`
	CreatedAt      time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at" db:"updated_at"`
}

// NotificationHistory represents a sent notification
type NotificationHistory struct {
	ID               uuid.UUID              `json:"id" db:"id"`
	TenantID         *uuid.UUID             `json:"tenant_id,omitempty" db:"tenant_id"`
	NotificationType string                 `json:"notification_type" db:"notification_type"`
	AlertSource      string                 `json:"alert_source" db:"alert_source"`
	AlertType        string                 `json:"alert_type" db:"alert_type"`
	Severity         string                 `json:"severity" db:"severity"`
	Message          string                 `json:"message" db:"message"`
	ChannelsUsed     []string               `json:"channels_used" db:"channels_used"`
	Status           string                 `json:"status" db:"status"`
	Metadata         map[string]interface{} `json:"metadata" db:"metadata"`
	CreatedAt        time.Time              `json:"created_at" db:"created_at"`
}

// InAppNotification represents a tenant in-app notification (in_app_notifications).
type InAppNotification struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	TenantID  uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Type      string     `json:"type" db:"type"`
	Title     string     `json:"title" db:"title"`
	Message   string     `json:"message" db:"message"`
	JobID     *uuid.UUID `json:"job_id,omitempty" db:"job_id"`
	FindingID *uuid.UUID `json:"finding_id,omitempty" db:"finding_id"`
	ReadAt    *time.Time `json:"read_at,omitempty" db:"read_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

// PlatformInAppNotification represents a platform-scoped in-app notification
// (platform_in_app_notifications) — the admin-ui bell feed. No tenant column:
// these rows are the operator inbox for platform-scoped alerts.
type PlatformInAppNotification struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	Type      string     `json:"type" db:"type"`
	Title     string     `json:"title" db:"title"`
	Message   string     `json:"message" db:"message"`
	ReadAt    *time.Time `json:"read_at,omitempty" db:"read_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

// NotificationDeliveryQueue represents a queued notification delivery
type NotificationDeliveryQueue struct {
	ID             uuid.UUID              `json:"id" db:"id"`
	TenantID       *uuid.UUID             `json:"tenant_id,omitempty" db:"tenant_id"`
	NotificationID uuid.UUID              `json:"notification_id" db:"notification_id"`
	ChannelID      uuid.UUID              `json:"channel_id" db:"channel_id"`
	ChannelType    string                 `json:"channel_type" db:"channel_type"`
	Payload        map[string]interface{} `json:"payload" db:"payload"`
	Status         string                 `json:"status" db:"status"`
	RetryCount     int                    `json:"retry_count" db:"retry_count"`
	NextRetryAt    *time.Time             `json:"next_retry_at,omitempty" db:"next_retry_at"`
	DeliveredAt    *time.Time             `json:"delivered_at,omitempty" db:"delivered_at"`
	ErrorMessage   *string                `json:"error_message,omitempty" db:"error_message"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
}

// CreateChannelRequest represents a request to create a notification channel
type CreateChannelRequest struct {
	ChannelName string                 `json:"channel_name" binding:"required"`
	ChannelType string                 `json:"channel_type" binding:"required"`
	Config      map[string]interface{} `json:"config" binding:"required"`
	Enabled     bool                   `json:"enabled"`
	Description *string                `json:"description,omitempty"`
}

// UpdateChannelRequest represents a request to update a notification channel
type UpdateChannelRequest struct {
	ChannelName *string                `json:"channel_name,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Enabled     *bool                  `json:"enabled,omitempty"`
	Description *string                `json:"description,omitempty"`
}

// CreateRuleRequest represents a request to create a notification rule
type CreateRuleRequest struct {
	RuleName       string      `json:"rule_name" binding:"required"`
	AlertSource    string      `json:"alert_source" binding:"required"`
	AlertType      *string     `json:"alert_type,omitempty"`
	ChannelIDs     []uuid.UUID `json:"channel_ids" binding:"required"`
	SeverityFilter []string    `json:"severity_filter,omitempty"`
	CategoryFilter []string    `json:"category_filter,omitempty"`
	Frequency      string      `json:"frequency"`
	DigestWindow   *int        `json:"digest_window,omitempty"`
	Enabled        bool        `json:"enabled"`
	Priority       int         `json:"priority"`
}

// UpdateRuleRequest represents a request to update a notification rule
type UpdateRuleRequest struct {
	RuleName       *string     `json:"rule_name,omitempty"`
	AlertType      *string     `json:"alert_type,omitempty"`
	ChannelIDs     []uuid.UUID `json:"channel_ids,omitempty"`
	SeverityFilter []string    `json:"severity_filter,omitempty"`
	CategoryFilter []string    `json:"category_filter,omitempty"`
	Frequency      *string     `json:"frequency,omitempty"`
	DigestWindow   *int        `json:"digest_window,omitempty"`
	Enabled        *bool       `json:"enabled,omitempty"`
	Priority       *int        `json:"priority,omitempty"`
}

// SendNotificationRequest represents a request to send a notification (internal API)
type SendNotificationRequest struct {
	TenantID         *uuid.UUID             `json:"tenant_id,omitempty"` // NULL for platform notifications
	AlertSource      string                 `json:"alert_source" binding:"required"`
	AlertType        string                 `json:"alert_type" binding:"required"`
	Severity         string                 `json:"severity" binding:"required"`
	Message          string                 `json:"message" binding:"required"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	NotificationType string                 `json:"notification_type,omitempty"` // Defaults to 'alert' if not provided
}
