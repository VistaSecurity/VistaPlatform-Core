package models

import (
	"time"

	"github.com/google/uuid"
)

// Alert is a stateful condition demanding attention (): severity +
// lifecycle active → acknowledged → snoozed → resolved. One open alert exists
// per (tenant, alert_type, subject); repeated raises escalate it. The full
// custody chain lives in alert_events, append-only.
type Alert struct {
	ID           uuid.UUID              `json:"id" db:"id"`
	TenantID     uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	AlertType    string                 `json:"alert_type" db:"alert_type"`
	Source       string                 `json:"source" db:"source"`
	SubjectType  *string                `json:"subject_type,omitempty" db:"subject_type"`
	SubjectID    *uuid.UUID             `json:"subject_id,omitempty" db:"subject_id"`
	SubjectLabel *string                `json:"subject_label,omitempty" db:"subject_label"`
	Severity     string                 `json:"severity" db:"severity"`
	Status       string                 `json:"status" db:"status"`
	Title        string                 `json:"title" db:"title"`
	Message      *string                `json:"message,omitempty" db:"message"`
	Metadata     map[string]interface{} `json:"metadata,omitempty" db:"-"`

	AcknowledgedBy *uuid.UUID `json:"acknowledged_by,omitempty" db:"acknowledged_by"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty" db:"acknowledged_at"`

	SnoozedBy    *uuid.UUID `json:"snoozed_by,omitempty" db:"snoozed_by"`
	SnoozedUntil *time.Time `json:"snoozed_until,omitempty" db:"snoozed_until"`
	SnoozeReason *string    `json:"snooze_reason,omitempty" db:"snooze_reason"`

	ResolvedAt            *time.Time             `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolvedBy            *uuid.UUID             `json:"resolved_by,omitempty" db:"resolved_by"`
	Resolution            *string                `json:"resolution,omitempty" db:"resolution"`
	ResolutionNote        *string                `json:"resolution_note,omitempty" db:"resolution_note"`
	ResolutionObservation map[string]interface{} `json:"resolution_observation,omitempty" db:"-"`

	TicketID *uuid.UUID `json:"ticket_id,omitempty" db:"ticket_id"`

	FirstRaisedAt time.Time `json:"first_raised_at" db:"first_raised_at"`
	LastEventAt   time.Time `json:"last_event_at" db:"last_event_at"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

// AlertEvent is one append-only entry in an alert's evidence chain. Rows are
// never updated or deleted — that is what makes the chain audit evidence
// rather than workflow state.
type AlertEvent struct {
	ID        uuid.UUID              `json:"id" db:"id"`
	AlertID   uuid.UUID              `json:"alert_id" db:"alert_id"`
	TenantID  uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	EventType string                 `json:"event_type" db:"event_type"`
	ActorType string                 `json:"actor_type" db:"actor_type"`
	ActorID   *uuid.UUID             `json:"actor_id,omitempty" db:"actor_id"`
	Details   map[string]interface{} `json:"details,omitempty" db:"-"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
}

// AlertFilters narrows the alert list.
type AlertFilters struct {
	Status    string
	Severity  string
	AlertType string
	Limit     int
}

// AlertStats is the Alerts page summary card payload.
type AlertStats struct {
	Active       int `json:"active"`
	Acknowledged int `json:"acknowledged"`
	Snoozed      int `json:"snoozed"`
	Resolved     int `json:"resolved"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
}
