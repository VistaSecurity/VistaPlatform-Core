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
	// JobTypeHostInventory is a general host inventory — OS, hardware
	// identity, packages, listening sockets and trust stores (asset-inventory
	// ADR-0004 D3).
	//
	// It covers the REMOTE mode only. A local collection is agent-originated:
	// the agent posts it to /agents/host-inventory, which writes the completed
	// row itself, because there is nothing for the platform to have queued.
	// Both are the same job_type in the database — the `mode` parameter is what
	// tells them apart, and it is on the row either way.
	JobTypeHostInventory DeviceJobType = "host_inventory"
)

// Valid reports whether t is one of the job types the database enum accepts.
//
// Spelled once, here, because the enum, the CHECK constraint and the tenant
// API all have to agree, and a job type accepted by an API and refused by the
// enum fails at INSERT with a message no operator can act on.
func (t DeviceJobType) Valid() bool {
	switch t {
	case JobTypeDeviceInterrogation, JobTypeCloudDiscovery, JobTypeHostInventory:
		return true
	default:
		return false
	}
}

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
	ID       uuid.UUID     `json:"id" db:"id"`
	TenantID uuid.UUID     `json:"tenant_id" db:"tenant_id"`
	JobType  DeviceJobType `json:"job_type" db:"job_type"`
	// AssetID is the asset the job targets. It was `device_id` until phase 1;
	// `devices` is gone and an interrogated device is an asset with an
	// asset_management row (ADR-0002 D5), so the column and the field are named
	// for what they point at.
	AssetID       *uuid.UUID      `json:"asset_id,omitempty" db:"asset_id"`
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
	AssetID       *uuid.UUID             `json:"asset_id,omitempty"`
	IntegrationID *uuid.UUID             `json:"integration_id,omitempty"` // Cloud integration reference
	AgentID       *uuid.UUID             `json:"agent_id,omitempty"`
	Credentials   map[string]interface{} `json:"credentials,omitempty"` // Will be encrypted
	Parameters    map[string]interface{} `json:"parameters"`
	ExpiresAt     *time.Time             `json:"expires_at,omitempty"`
}

// ToJob converts DeviceJob to the Job model used by agents.
//
// Both AssetID and the deprecated DeviceID are set, and they carry the same
// value. The device-agent is a SEPARATELY SHIPPED BINARY: a customer running
// last release's agent against this release's platform reads `device_id` and
// nothing else, so emitting only `asset_id` would hand every such agent a job
// with no target. The wire keeps both for one release; see Job.DeviceID.
func (dj *DeviceJob) ToJob() *Job {
	job := &Job{
		ID:         dj.ID,
		Type:       string(dj.JobType),
		AssetID:    dj.AssetID,
		DeviceID:   dj.AssetID,
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
