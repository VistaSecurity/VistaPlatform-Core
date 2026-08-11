package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Device represents a network device or cloud resource
type Device struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	TenantID        uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	DeviceType      string     `json:"device_type" db:"device_type"`
	Vendor          *string    `json:"vendor" db:"vendor"`
	Model           *string    `json:"model" db:"model"`
	Hostname        *string    `json:"hostname" db:"hostname"`
	IPAddress       *string    `json:"ip_address" db:"ip_address"`
	ManagementURL   *string    `json:"management_url" db:"management_url"`
	SerialNumber    *string    `json:"serial_number" db:"serial_number"`
	FirmwareVersion *string    `json:"firmware_version" db:"firmware_version"`
	DiscoveryMethod string     `json:"discovery_method" db:"discovery_method"`
	CredentialID    *uuid.UUID `json:"credential_id,omitempty" db:"credential_id"` // Optional, deprecated for network devices
	Username        *string    `json:"username,omitempty" db:"username"`           // For network devices
	Password        *string    `json:"password,omitempty" db:"password"`           // Encrypted, for network devices
	// TLSInsecureSkipVerify is an explicit per-device opt-in to skip TLS
	// verification when calling the device's management API. Defaults to
	// false; operators flip it to true only for devices whose management
	// endpoints present self-signed certs.
	TLSInsecureSkipVerify bool       `json:"tls_insecure_skip_verify" db:"tls_insecure_skip_verify"`
	ConnectionStatus      string     `json:"connection_status" db:"connection_status"`
	LastInterrogatedAt    *time.Time `json:"last_interrogated_at" db:"last_interrogated_at"`
	InterrogationError    *string    `json:"interrogation_error" db:"interrogation_error"`
	Metadata              JSONB      `json:"metadata" db:"metadata"`
	Tags                  JSONB      `json:"tags" db:"tags"`
	CreatedAt             time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt             *time.Time `json:"deleted_at" db:"deleted_at"`
}

// JSONB is a helper type for PostgreSQL JSONB columns
type JSONB map[string]interface{}

// Value implements the driver.Valuer interface
func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan implements the sql.Scanner interface
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

// CreateDeviceRequest represents a request to create a device
type CreateDeviceRequest struct {
	DeviceType      string     `json:"device_type" binding:"required"`
	Vendor          *string    `json:"vendor"`
	Model           *string    `json:"model"`
	Hostname        *string    `json:"hostname"`
	IPAddress       *string    `json:"ip_address"`
	ManagementURL   *string    `json:"management_url"`
	SerialNumber    *string    `json:"serial_number"`
	FirmwareVersion *string    `json:"firmware_version"`
	DiscoveryMethod string     `json:"discovery_method"`
	CredentialID    *uuid.UUID `json:"credential_id"` // Optional, deprecated for network devices
	Username        *string    `json:"username"`      // For network devices
	Password        *string    `json:"password"`      // For network devices, will be encrypted
	// Optional. Defaults to false (verify) if omitted. Opt-in per device.
	TLSInsecureSkipVerify *bool                  `json:"tls_insecure_skip_verify,omitempty"`
	Metadata              map[string]interface{} `json:"metadata"`
	Tags                  map[string]interface{} `json:"tags"`
}

// UpdateDeviceRequest represents a request to update a device
type UpdateDeviceRequest struct {
	Vendor          *string    `json:"vendor"`
	Model           *string    `json:"model"`
	Hostname        *string    `json:"hostname"`
	IPAddress       *string    `json:"ip_address"`
	ManagementURL   *string    `json:"management_url"`
	SerialNumber    *string    `json:"serial_number"`
	FirmwareVersion *string    `json:"firmware_version"`
	CredentialID    *uuid.UUID `json:"credential_id"` // Optional
	Username        *string    `json:"username"`      // For network devices
	Password        *string    `json:"password"`      // For network devices, will be encrypted
	// Optional. Set to flip the per-device TLS verification posture.
	TLSInsecureSkipVerify *bool                  `json:"tls_insecure_skip_verify,omitempty"`
	ConnectionStatus      *string                `json:"connection_status"`
	Metadata              map[string]interface{} `json:"metadata"`
	Tags                  map[string]interface{} `json:"tags"`
}

// InterrogateDeviceRequest represents a request to interrogate a device
type InterrogateDeviceRequest struct {
	DeviceID uuid.UUID `json:"device_id" binding:"required"`
}
