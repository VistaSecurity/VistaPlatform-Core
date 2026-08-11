package models

import (
	"time"
)

// CreateDiscoveryJobInput represents input for creating a discovery job
type CreateDiscoveryJobInput struct {
	Targets            []string               `json:"targets" binding:"required"`
	ExecutionMode      string                 `json:"execution_mode"`
	PreferredSensorIDs []string               `json:"preferred_sensor_ids"`
	RetentionCapMB     *int                   `json:"retention_cap_mb"`
	RetentionTTLHours  *int                   `json:"retention_ttl_hours"`
	Ports              []int                  `json:"ports"`
	Protocols          []string               `json:"protocols"`
	Options            map[string]interface{} `json:"options,omitempty"`
	Tags               map[string]interface{} `json:"tags,omitempty"`
	Owner              *string                `json:"owner,omitempty"`
	Environment        *string                `json:"environment,omitempty"`
}

// DiscoveryJob represents a discovery job
type DiscoveryJob struct {
	ID                 string    `json:"id" db:"id"`
	TenantID           string    `json:"tenant_id" db:"tenant_id"`
	CreatedBy          string    `json:"created_by" db:"created_by"`
	Status             string    `json:"status" db:"status"`
	Targets            []string  `json:"targets" db:"targets"`
	ExecutionMode      string    `json:"execution_mode" db:"execution_mode"`
	RequestedSensorIDs []string  `json:"requested_sensor_ids" db:"requested_sensor_ids"`
	Fanout             bool      `json:"fanout" db:"fanout"`
	RetentionCapMB     int       `json:"retention_cap_mb" db:"retention_cap_mb"`
	RetentionTTLHours  int       `json:"retention_ttl_hours" db:"retention_ttl_hours"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
}
