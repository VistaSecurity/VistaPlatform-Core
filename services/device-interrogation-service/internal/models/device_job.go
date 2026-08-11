package models

import (
	"time"

	"github.com/google/uuid"
)

// DeviceJobType represents the type of device job
type DeviceJobType string

const (
	JobTypeDeviceInterrogation DeviceJobType = "device_interrogation"
	JobTypeCloudDiscovery      DeviceJobType = "cloud_discovery"
)

// DeviceJobStatus represents the status of a device job
type DeviceJobStatus string

const (
	JobStatusPending    DeviceJobStatus = "pending"
	JobStatusAssigned   DeviceJobStatus = "assigned"
	JobStatusInProgress DeviceJobStatus = "in_progress"
	JobStatusCompleted  DeviceJobStatus = "completed"
	JobStatusFailed     DeviceJobStatus = "failed"
	JobStatusCancelled  DeviceJobStatus = "cancelled"
)

// DeviceJob represents a device interrogation or cloud discovery job
type DeviceJob struct {
	ID            uuid.UUID       `json:"id" db:"id"`
	TenantID      uuid.UUID       `json:"tenant_id" db:"tenant_id"`
	JobType       DeviceJobType   `json:"job_type" db:"job_type"`
	DeviceID      *uuid.UUID      `json:"device_id,omitempty" db:"device_id"`
	IntegrationID *uuid.UUID      `json:"integration_id,omitempty" db:"integration_id"` // Cloud integration reference
	AgentID       *uuid.UUID      `json:"agent_id,omitempty" db:"agent_id"`
	Status        DeviceJobStatus `json:"status" db:"status"`
	Credentials   JSONB           `json:"credentials,omitempty" db:"credentials"` // Encrypted credentials
	Parameters    JSONB           `json:"parameters" db:"parameters"`
	Results       JSONB           `json:"results,omitempty" db:"results"`
	ErrorMessage  *string         `json:"error_message,omitempty" db:"error_message"`
	CreatedAt     time.Time       `json:"created_at" db:"created_at"`
	AssignedAt    *time.Time      `json:"assigned_at,omitempty" db:"assigned_at"`
	StartedAt     *time.Time      `json:"started_at,omitempty" db:"started_at"`
	CompletedAt   *time.Time      `json:"completed_at,omitempty" db:"completed_at"`
	ExpiresAt     *time.Time      `json:"expires_at,omitempty" db:"expires_at"`
	DeletedAt     *time.Time      `json:"deleted_at,omitempty" db:"deleted_at"`
}

// CreateDeviceJobRequest represents a request to create a device job
type CreateDeviceJobRequest struct {
	TenantID      uuid.UUID              `json:"tenant_id" binding:"required"`
	JobType       DeviceJobType          `json:"job_type" binding:"required"`
	DeviceID      *uuid.UUID             `json:"device_id,omitempty"`
	IntegrationID *uuid.UUID             `json:"integration_id,omitempty"` // Cloud integration reference
	AgentID       *uuid.UUID             `json:"agent_id,omitempty"`
	Credentials   map[string]interface{} `json:"credentials,omitempty"` // Will be encrypted
	Parameters    map[string]interface{} `json:"parameters"`
	ExpiresAt     *time.Time             `json:"expires_at,omitempty"`
}

// ToJob converts DeviceJob to the Job model used by agents
func (dj *DeviceJob) ToJob() *Job {
	job := &Job{
		ID:         dj.ID,
		Type:       string(dj.JobType),
		DeviceID:   dj.DeviceID,
		CreatedAt:  dj.CreatedAt,
		ExpiresAt:  dj.ExpiresAt,
		Parameters: dj.Parameters,
	}

	// Extract device type from parameters if available
	if deviceType, ok := dj.Parameters["device_type"].(string); ok {
		job.DeviceType = deviceType
	}

	// Convert credentials JSONB to map
	if dj.Credentials != nil {
		job.Credentials = map[string]interface{}(dj.Credentials)
	}

	return job
}
