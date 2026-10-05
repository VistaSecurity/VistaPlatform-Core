package models

import (
	"database/sql/driver"
	"encoding/json"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Device is the API projection of an ASSET WITH MANAGEMENT CONFIGURED
// (ADR-0002 D5). The `devices` table it used to mirror is gone; the fields come
// from `assets`, `asset_management`, `asset_credentials`, `asset_facts` and
// `asset_identifiers` — see internal/services/managed_asset.go for the map.
//
// The shape is kept for the clients that read it, with two additions: `id` is
// now the asset id and `asset_id` says so explicitly rather than making a
// client infer it, and `class` is the asset class the device_type resolved to.
type Device struct {
	ID uuid.UUID `json:"id" db:"id"`
	// AssetID is the same value as ID, spelled so a client migrating to the
	// asset API does not have to guess which id it is holding. Both are the
	// asset's id; there is no separate device id any more.
	AssetID  uuid.UUID `json:"asset_id" db:"asset_id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`
	// ClassKey is the asset class (shared/assetclass) — what the device IS.
	// DeviceType names the interrogation DRIVER, which is a different question
	// and is why both are present.
	ClassKey        string     `json:"class,omitempty" db:"class_key"`
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
	TLSInsecureSkipVerify bool   `json:"tls_insecure_skip_verify" db:"tls_insecure_skip_verify"`
	ConnectionStatus      string `json:"connection_status" db:"connection_status"`
	// SSHHostKeyFingerprint is the host key pinned for this device, in
	// ssh.FingerprintSHA256 form. nil means "never pinned" — the enrolment
	// case. Once set, an interrogation that meets a different key aborts before
	// sending a credential. SSHHostKeyType is its algorithm, carried so the UI
	// can show what was pinned rather than an opaque hash.
	SSHHostKeyFingerprint *string    `json:"ssh_host_key_fingerprint,omitempty" db:"ssh_host_key_fingerprint"`
	SSHHostKeyType        *string    `json:"ssh_host_key_type,omitempty" db:"ssh_host_key_type"`
	SSHHostKeyPinnedAt    *time.Time `json:"ssh_host_key_pinned_at,omitempty" db:"ssh_host_key_pinned_at"`
	LastInterrogatedAt    *time.Time `json:"last_interrogated_at" db:"last_interrogated_at"`
	InterrogationError    *string    `json:"interrogation_error" db:"interrogation_error"`
	Metadata              JSONB      `json:"metadata" db:"metadata"`
	Tags                  JSONB      `json:"tags" db:"tags"`
	// PlatformReinterrogationAllowed is the operator's consent for the platform
	// to re-run this device's interrogation on its own when identity enrichment
	// needs fresh evidence from it (the rule). Stored as the device
	// metadata key identity_enrichment_executor = "platform"; absent means off.
	// Only the explicit request field of the same name writes it — a client's
	// free-form `metadata` cannot (see services.PlatformReinterrogationKey).
	PlatformReinterrogationAllowed bool `json:"platform_reinterrogation_allowed"`
	// InterrogatedByAgent is true when this device's most recent completed job
	// was run by an agent. Identity enrichment then re-asks THAT agent, and the
	// consent above does not apply — the form hides the control for such a
	// device. Read-only; the same rule the enrichment planner uses.
	InterrogatedByAgent bool       `json:"interrogated_by_agent"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt           *time.Time `json:"deleted_at" db:"deleted_at"`
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
	// PlatformReinterrogationAllowed: see Device. Nil leaves it as it is.
	PlatformReinterrogationAllowed *bool `json:"platform_reinterrogation_allowed,omitempty"`

	// ProbeEvidence is set ONLY by Add device, after the platform itself
	// authenticated to the device and read its identity. It is never bound from
	// a request body (json:"-"): an operator typing a serial into the form is a
	// declaration, not evidence, and must not be able to claim otherwise.
	ProbeEvidence *identity.AdmissionEvidence `json:"-"`

	// ProbeMACAddress is the MAC Add device's probe read from the device. Set
	// ONLY by Add device, never bound from a request body (json:"-"), for the
	// same reason as ProbeEvidence: it is evidence, and becomes an identifier.
	// (metadata.mac_address is client-settable and stays display-only.)
	ProbeMACAddress string `json:"-"`
	// ProbeSSHHostKeyFingerprint and ProbeSSHHostKeyType are the host key the
	// probe authenticated through, set ONLY by Add device. Evidence, like the
	// MAC: it becomes an ssh_host_key_fingerprint identifier with its key
	// algorithm ( D4: the drift classifier compares keys by algorithm).
	ProbeSSHHostKeyFingerprint string `json:"-"`
	ProbeSSHHostKeyType        string `json:"-"`
	// ProbeRead records which of IPAddress, Hostname and SerialNumber the
	// probe filled in from what it READ off the device, so the identity
	// sighting can store those as measured and only what the operator typed
	// as declared. Set only by Add device.
	ProbeRead ProbeReadValues `json:"-"`
}

// ProbeReadValues are the form values Add device's probe read off the device.
type ProbeReadValues struct {
	IPAddress    string
	Hostname     string
	SerialNumber string
}

// Value is the read value of one form field: ip, host or serial.
func (p ProbeReadValues) Value(field string) string {
	switch field {
	case "ip":
		return p.IPAddress
	case "host":
		return p.Hostname
	case "serial":
		return p.SerialNumber
	}
	return ""
}

// Has reports whether the probe read v (case-insensitive).
func (p ProbeReadValues) Has(v string) bool {
	for _, read := range []string{p.IPAddress, p.Hostname, p.SerialNumber} {
		if read != "" && strings.EqualFold(strings.TrimSpace(read), v) {
			return true
		}
	}
	return false
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
	// PlatformReinterrogationAllowed: see Device. Nil leaves it as it is;
	// false withdraws the consent, true grants it.
	PlatformReinterrogationAllowed *bool `json:"platform_reinterrogation_allowed,omitempty"`
}

// InterrogateDeviceRequest represents a request to interrogate a device
type InterrogateDeviceRequest struct {
	DeviceID uuid.UUID `json:"device_id" binding:"required"`
}
