package models

import (
	"time"

	"github.com/google/uuid"
)

// JobExecutionLog represents a background job execution log entry
type JobExecutionLog struct {
	ID             uuid.UUID              `json:"id" db:"id"`
	JobID          uuid.UUID              `json:"job_id" db:"job_id"`
	JobType        string                 `json:"job_type" db:"job_type"`
	JobName        *string                `json:"job_name,omitempty" db:"job_name"`
	TenantID       *uuid.UUID             `json:"tenant_id,omitempty" db:"tenant_id"`
	InitiatedBy    *uuid.UUID             `json:"initiated_by,omitempty" db:"initiated_by"`
	Status         string                 `json:"status" db:"status"`
	StartedAt      *time.Time             `json:"started_at,omitempty" db:"started_at"`
	CompletedAt    *time.Time             `json:"completed_at,omitempty" db:"completed_at"`
	DurationMs     *int                   `json:"duration_ms,omitempty" db:"duration_ms"`
	ItemsProcessed int                    `json:"items_processed" db:"items_processed"`
	ItemsSucceeded int                    `json:"items_succeeded" db:"items_succeeded"`
	ItemsFailed    int                    `json:"items_failed" db:"items_failed"`
	ErrorMessage   *string                `json:"error_message,omitempty" db:"error_message"`
	ErrorDetails   JSONB                  `json:"error_details,omitempty" db:"error_details"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
}

// JobExecutionLogFilters represents filtering options for querying job execution logs
type JobExecutionLogFilters struct {
	JobID       *uuid.UUID
	JobType     []string
	TenantID    *uuid.UUID
	InitiatedBy *uuid.UUID
	Status      []string
	StartDate   *time.Time
	EndDate     *time.Time
	Page        int
	PageSize    int
	SortBy      string
	SortOrder   string
}
