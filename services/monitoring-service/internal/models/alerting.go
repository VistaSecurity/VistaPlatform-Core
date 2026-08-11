package models

import (
	"time"

	"github.com/google/uuid"
)

// AlertThreshold represents a configurable alerting threshold
type AlertThreshold struct {
	ID                 uuid.UUID  `json:"id" db:"id"`
	ThresholdName      string     `json:"threshold_name" db:"threshold_name"`
	MetricType         string     `json:"metric_type" db:"metric_type"`
	ServiceName        *string    `json:"service_name,omitempty" db:"service_name"`
	WarningThreshold   *float64   `json:"warning_threshold,omitempty" db:"warning_threshold"`
	CriticalThreshold  *float64   `json:"critical_threshold,omitempty" db:"critical_threshold"`
	Severity           string     `json:"severity" db:"severity"`
	Enabled            bool       `json:"enabled" db:"enabled"`
	NotifyEmail        bool       `json:"notify_email" db:"notify_email"`
	NotifySlack        bool       `json:"notify_slack" db:"notify_slack"`
	NotifyWebhook      bool       `json:"notify_webhook" db:"notify_webhook"`
	NotifyInApp        bool       `json:"notify_in_app" db:"notify_in_app"`
	ComparisonOperator string     `json:"comparison_operator" db:"comparison_operator"`
	DurationMinutes    int        `json:"duration_minutes" db:"duration_minutes"`
	Description        *string    `json:"description,omitempty" db:"description"`
	CreatedBy          *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`
	UpdatedBy          *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
}

// AlertHistory represents a triggered alert
type AlertHistory struct {
	ID                uuid.UUID                `json:"id" db:"id"`
	ThresholdID       *uuid.UUID               `json:"threshold_id,omitempty" db:"threshold_id"`
	ThresholdName     string                   `json:"threshold_name" db:"threshold_name"`
	MetricType        string                   `json:"metric_type" db:"metric_type"`
	ServiceName       *string                  `json:"service_name,omitempty" db:"service_name"`
	ThresholdValue    float64                  `json:"threshold_value" db:"threshold_value"`
	ActualValue       float64                  `json:"actual_value" db:"actual_value"`
	Severity          string                   `json:"severity" db:"severity"`
	Status            string                   `json:"status" db:"status"`
	AcknowledgedBy    *uuid.UUID               `json:"acknowledged_by,omitempty" db:"acknowledged_by"`
	AcknowledgedAt    *time.Time               `json:"acknowledged_at,omitempty" db:"acknowledged_at"`
	ResolvedAt        *time.Time               `json:"resolved_at,omitempty" db:"resolved_at"`
	NotificationsSent []map[string]interface{} `json:"notifications_sent" db:"notifications_sent"`
	Message           *string                  `json:"message,omitempty" db:"message"`
	Metadata          map[string]interface{}   `json:"metadata" db:"metadata"`
	TriggeredAt       time.Time                `json:"triggered_at" db:"triggered_at"`
}

// NotificationChannel represents a notification channel configuration
type NotificationChannel struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	ChannelName string                 `json:"channel_name" db:"channel_name"`
	ChannelType string                 `json:"channel_type" db:"channel_type"`
	Config      map[string]interface{} `json:"config" db:"config"`
	Enabled     bool                   `json:"enabled" db:"enabled"`
	TestStatus  *string                `json:"test_status,omitempty" db:"test_status"`
	LastTestAt  *time.Time             `json:"last_test_at,omitempty" db:"last_test_at"`
	Description *string                `json:"description,omitempty" db:"description"`
	CreatedBy   *uuid.UUID             `json:"created_by,omitempty" db:"created_by"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	UpdatedBy   *uuid.UUID             `json:"updated_by,omitempty" db:"updated_by"`
}

// CreateAlertThresholdRequest represents a request to create an alert threshold
type CreateAlertThresholdRequest struct {
	ThresholdName      string   `json:"threshold_name" binding:"required"`
	MetricType         string   `json:"metric_type" binding:"required"`
	ServiceName        *string  `json:"service_name,omitempty"`
	WarningThreshold   *float64 `json:"warning_threshold,omitempty"`
	CriticalThreshold  *float64 `json:"critical_threshold,omitempty"`
	Severity           string   `json:"severity"`
	Enabled            bool     `json:"enabled"`
	NotifyEmail        bool     `json:"notify_email"`
	NotifySlack        bool     `json:"notify_slack"`
	NotifyWebhook      bool     `json:"notify_webhook"`
	NotifyInApp        bool     `json:"notify_in_app"`
	ComparisonOperator string   `json:"comparison_operator"`
	DurationMinutes    int      `json:"duration_minutes"`
	Description        string   `json:"description"`
}

// UpdateAlertThresholdRequest represents a request to update an alert threshold
type UpdateAlertThresholdRequest struct {
	WarningThreshold   *float64 `json:"warning_threshold,omitempty"`
	CriticalThreshold  *float64 `json:"critical_threshold,omitempty"`
	Severity           *string  `json:"severity,omitempty"`
	Enabled            *bool    `json:"enabled,omitempty"`
	NotifyEmail        *bool    `json:"notify_email,omitempty"`
	NotifySlack        *bool    `json:"notify_slack,omitempty"`
	NotifyWebhook      *bool    `json:"notify_webhook,omitempty"`
	NotifyInApp        *bool    `json:"notify_in_app,omitempty"`
	ComparisonOperator *string  `json:"comparison_operator,omitempty"`
	DurationMinutes    *int     `json:"duration_minutes,omitempty"`
	Description        *string  `json:"description,omitempty"`
}
