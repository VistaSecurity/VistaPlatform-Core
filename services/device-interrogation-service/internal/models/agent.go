package models

import (
	"time"

	"github.com/google/uuid"
)

// Agent represents a registered device agent. Field order and nullability mirror
// AdminAgent (minus the tenant join) so the tenant GET /agents and the admin
// Fleet view stay in lock-step. `name` and `profile` are nullable (DB NULLs
// surface as JSON null); they are carried from the pending registration at
// bootstrap time.
type Agent struct {
	ID       uuid.UUID `json:"id" db:"id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`
	// RegistrationKey is the bootstrap secret. It is scanned internally during
	// enrollment but never serialized to tenant clients (json:"-") — they already
	// hold the key from registration, and the admin Fleet view omits it too.
	RegistrationKey string     `json:"-" db:"registration_key"`
	Name            *string    `json:"name" db:"name"`
	Platform        string     `json:"platform" db:"platform"`
	Profile         *string    `json:"profile" db:"profile"`
	Version         string     `json:"version" db:"version"`
	Status          string     `json:"status" db:"status"` // "active", "inactive", "error"
	LastHeartbeat   *time.Time `json:"last_heartbeat" db:"last_heartbeat"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// AdminAgent represents a registered device interrogation agent enriched with
// tenant identity, for the platform-admin cross-tenant Fleet view. It deliberately
// omits registration_key (a secret) and includes only telemetry fields that exist
// on the device_agents table plus the tenant name/slug from a cheap join.
type AdminAgent struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	TenantID      uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	TenantName    string     `json:"tenant_name" db:"tenant_name"`
	TenantSlug    string     `json:"tenant_slug" db:"tenant_slug"`
	Name          *string    `json:"name" db:"name"`
	Platform      string     `json:"platform" db:"platform"`
	Profile       *string    `json:"profile" db:"profile"`
	Version       string     `json:"version" db:"version"`
	Status        string     `json:"status" db:"status"` // "active", "inactive", "error"
	LastHeartbeat *time.Time `json:"last_heartbeat" db:"last_heartbeat"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
}

// RegisterAgentRequest represents an agent registration request
type RegisterAgentRequest struct {
	RegistrationKey string `json:"registration_key" binding:"required"`
	Platform        string `json:"platform" binding:"required"`
	Version         string `json:"version" binding:"required"`
	// CSR-based registration fields (optional for backward compatibility)
	CSR     string `json:"csr,omitempty"`      // Certificate Signing Request (PEM format)
	AgentID string `json:"agent_id,omitempty"` // Proposed agent ID (UUID string) for CSR CN
}

// RegisterAgentResponse represents an agent registration response
type RegisterAgentResponse struct {
	AgentID              uuid.UUID `json:"agent_id"`
	ClientCert           string    `json:"client_cert,omitempty"`            // Signed certificate (CSR-based) or cert+key (legacy)
	ClientKey            string    `json:"client_key,omitempty"`             // Only in legacy flow, omitted in CSR flow
	ServerCACert         string    `json:"server_ca_cert,omitempty"`         // CA certificate for trust
	CertificateExpiresAt string    `json:"certificate_expires_at,omitempty"` // Certificate expiration timestamp
	// ControlPlaneURL is the mTLS passthrough URL the agent must switch to for
	// all post-registration traffic. Only set when fail-closed agent
	// mTLS is enforced; empty means "keep the URL you registered against".
	ControlPlaneURL string `json:"control_plane_url,omitempty"`
}

// Job represents a job for an agent to execute
type Job struct {
	ID          uuid.UUID              `json:"id"`
	Type        string                 `json:"type"`
	DeviceID    *uuid.UUID             `json:"device_id,omitempty"`
	DeviceType  string                 `json:"device_type"`
	Credentials map[string]interface{} `json:"credentials"` // Encrypted credentials
	Parameters  map[string]interface{} `json:"parameters"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
}

// JobResult represents the result of a job execution
type JobResult struct {
	JobID       uuid.UUID              `json:"job_id"`
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	Assets      []DiscoveredAsset      `json:"assets,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CompletedAt time.Time              `json:"completed_at"`
}

// DiscoveredAsset represents an infrastructure asset discovered during interrogation.
// This model mirrors the device-agent's DiscoveredAsset struct so that the full
// enriched payload from the agent is preserved through JSON deserialization.
type DiscoveredAsset struct {
	Hostname        string `json:"hostname,omitempty"`
	IPAddress       string `json:"ip_address,omitempty"`
	Port            int    `json:"port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	AssetType       string `json:"asset_type,omitempty"`

	// Cipher and crypto details
	CipherSuite          string   `json:"cipher_suite,omitempty"`
	SupportedCiphers     []string `json:"supported_ciphers,omitempty"`
	KeySize              int      `json:"key_size,omitempty"`
	KeyExchangeAlgorithm string   `json:"key_exchange_algorithm,omitempty"`
	HashAlgorithm        string   `json:"hash_algorithm,omitempty"`

	// TLS details
	TLSVersions []string `json:"tls_versions,omitempty"`

	// Certificate chain
	Certificate  *CertificateInfo  `json:"certificate,omitempty"`
	Certificates []CertificateInfo `json:"certificates,omitempty"`

	// Certificate validation
	CertValidationStatus string `json:"cert_validation_status,omitempty"`
	CertValidationError  string `json:"cert_validation_error,omitempty"`

	// SSH details
	SSHInfo *SSHInfo `json:"ssh_info,omitempty"`

	// Device identity
	DeviceInfo *DeviceIdentity `json:"device_info,omitempty"`

	// Service identification
	ServiceHints *ServiceHints `json:"service_hints,omitempty"`

	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// CertificateInfo represents certificate information with full chain support.
type CertificateInfo struct {
	SubjectDN               string    `json:"subject_dn"`
	IssuerDN                string    `json:"issuer_dn"`
	SerialNumber            string    `json:"serial_number,omitempty"`
	NotBefore               time.Time `json:"not_before,omitempty"`
	NotAfter                time.Time `json:"not_after,omitempty"`
	Fingerprint             string    `json:"fingerprint,omitempty"`
	FingerprintSHA256       string    `json:"fingerprint_sha256,omitempty"`
	FingerprintSHA1         string    `json:"fingerprint_sha1,omitempty"`
	KeyAlgorithm            string    `json:"key_algorithm,omitempty"`
	KeySize                 int       `json:"key_size,omitempty"`
	SignatureAlgorithm      string    `json:"signature_alg,omitempty"`
	IsCA                    bool      `json:"is_ca,omitempty"`
	CertificatePEM          string    `json:"certificate_pem,omitempty"`
	SubjectAlternativeNames []string  `json:"subject_alternative_names,omitempty"`
	KeyUsage                []string  `json:"key_usage,omitempty"`
	ExtendedKeyUsage        []string  `json:"extended_key_usage,omitempty"`
	ChainOrder              int       `json:"chain_order,omitempty"`
}

// SSHInfo contains SSH protocol negotiation details.
type SSHInfo struct {
	Banner               string   `json:"banner,omitempty"`
	KeyTypes             []string `json:"key_types,omitempty"`
	HostKeyType          string   `json:"host_key_type,omitempty"`
	HostKeyFingerprint   string   `json:"host_key_fingerprint,omitempty"`
	KexAlgorithm         string   `json:"kex_algorithm,omitempty"`
	EncryptionAlgC2S     string   `json:"encryption_alg_c2s,omitempty"`
	EncryptionAlgS2C     string   `json:"encryption_alg_s2c,omitempty"`
	MACAlgC2S            string   `json:"mac_alg_c2s,omitempty"`
	MACAlgS2C            string   `json:"mac_alg_s2c,omitempty"`
	CompressionAlgorithm string   `json:"compression_alg,omitempty"`
}

// DeviceIdentity captures hardware and software identity of the interrogated device.
type DeviceIdentity struct {
	Vendor          string `json:"vendor,omitempty"`
	Model           string `json:"model,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	SerialNumber    string `json:"serial_number,omitempty"`
	OSVersion       string `json:"os_version,omitempty"`
}

// ServiceHints holds identified service name/version for inventory enrichment.
type ServiceHints struct {
	ServiceName          string `json:"service_name,omitempty"`
	ServiceVersion       string `json:"service_version,omitempty"`
	Confidence           string `json:"confidence,omitempty"`
	IdentificationMethod string `json:"identification_method,omitempty"`
}

// HeartbeatRequest represents an agent heartbeat
type HeartbeatRequest struct {
	Status    string                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Metrics   map[string]interface{} `json:"metrics,omitempty"`
}
