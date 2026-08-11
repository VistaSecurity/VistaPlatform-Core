package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Job represents a device interrogation job from the platform
type Job struct {
	ID          uuid.UUID              `json:"id"`
	Type        string                 `json:"type"` // "device_interrogation", "cloud_discovery"
	DeviceID    *uuid.UUID             `json:"device_id,omitempty"`
	DeviceType  string                 `json:"device_type"` // "f5", "cisco_router", "aws_alb", etc.
	Credentials map[string]interface{} `json:"credentials"` // Encrypted credentials (decrypted by agent)
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
// This model is aligned with the sensor's DiscoveryFinding to provide consistent
// data quality across both discovery paths (sensor probing and device interrogation).
type DiscoveredAsset struct {
	Hostname        string `json:"hostname,omitempty"`
	IPAddress       string `json:"ip_address,omitempty"`
	Port            int    `json:"port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	AssetType       string `json:"asset_type,omitempty"` // server, appliance, firewall, switch, load_balancer, vpn_gateway

	// Cipher and crypto details
	CipherSuite          string   `json:"cipher_suite,omitempty"`
	SupportedCiphers     []string `json:"supported_ciphers,omitempty"`
	KeySize              int      `json:"key_size,omitempty"`
	KeyExchangeAlgorithm string   `json:"key_exchange_algorithm,omitempty"`
	HashAlgorithm        string   `json:"hash_algorithm,omitempty"`

	// TLS details
	TLSVersions []string `json:"tls_versions,omitempty"` // All supported TLS versions

	// Certificate chain (full, not just leaf)
	Certificate  *CertificateInfo  `json:"certificate,omitempty"`  // Leaf cert (backward compat)
	Certificates []CertificateInfo `json:"certificates,omitempty"` // Full chain: leaf + intermediates

	// Certificate validation
	CertValidationStatus string `json:"cert_validation_status,omitempty"` // valid, self_signed, expired, hostname_mismatch, untrusted_ca
	CertValidationError  string `json:"cert_validation_error,omitempty"`

	// SSH details (for SSH-capable devices)
	SSHInfo *SSHInfo `json:"ssh_info,omitempty"`

	// Device hardware/software identity
	DeviceInfo *DeviceIdentity `json:"device_info,omitempty"`

	// Service identification
	ServiceHints *ServiceHints `json:"service_hints,omitempty"`

	// Freeform metadata (backward compat)
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// CertificateInfo represents certificate information with full chain support.
// Aligned with sensor's models.CertificateInfo for consistent processing.
type CertificateInfo struct {
	SubjectDN               string    `json:"subject_dn"`
	IssuerDN                string    `json:"issuer_dn"`
	SerialNumber            string    `json:"serial_number,omitempty"`
	NotBefore               time.Time `json:"not_before,omitempty"`
	NotAfter                time.Time `json:"not_after,omitempty"`
	Fingerprint             string    `json:"fingerprint,omitempty"`        // SHA256 (backward compat alias)
	FingerprintSHA256       string    `json:"fingerprint_sha256,omitempty"` // SHA256 hex
	FingerprintSHA1         string    `json:"fingerprint_sha1,omitempty"`   // SHA1 hex
	KeyAlgorithm            string    `json:"key_algorithm,omitempty"`      // RSA, ECDSA, Ed25519
	KeySize                 int       `json:"key_size,omitempty"`           // Bit length
	SignatureAlgorithm      string    `json:"signature_alg,omitempty"`      // SHA256WithRSA, etc.
	IsCA                    bool      `json:"is_ca,omitempty"`              // Basic constraint
	CertificatePEM          string    `json:"certificate_pem,omitempty"`    // Full PEM
	SubjectAlternativeNames []string  `json:"subject_alternative_names,omitempty"`
	KeyUsage                []string  `json:"key_usage,omitempty"`
	ExtendedKeyUsage        []string  `json:"extended_key_usage,omitempty"`
	ChainOrder              int       `json:"chain_order,omitempty"` // 0 = leaf, 1+ = intermediates
}

// SSHInfo contains SSH protocol negotiation details collected during interrogation.
type SSHInfo struct {
	Banner               string   `json:"banner,omitempty"`
	KeyTypes             []string `json:"key_types,omitempty"`
	HostKeyType          string   `json:"host_key_type,omitempty"`
	HostKeyFingerprint   string   `json:"host_key_fingerprint,omitempty"` // SHA256
	KexAlgorithm         string   `json:"kex_algorithm,omitempty"`
	EncryptionAlgC2S     string   `json:"encryption_alg_c2s,omitempty"`
	EncryptionAlgS2C     string   `json:"encryption_alg_s2c,omitempty"`
	MACAlgC2S            string   `json:"mac_alg_c2s,omitempty"`
	MACAlgS2C            string   `json:"mac_alg_s2c,omitempty"`
	CompressionAlgorithm string   `json:"compression_alg,omitempty"`
}

// DeviceIdentity captures hardware and software identity of the interrogated device.
type DeviceIdentity struct {
	Vendor          string `json:"vendor,omitempty"`           // F5 Networks, Cisco, Fortinet, etc.
	Model           string `json:"model,omitempty"`            // BIG-IP i5800, ASA 5525-X, etc.
	FirmwareVersion string `json:"firmware_version,omitempty"` // 15.1.0, 9.16(3), etc.
	SerialNumber    string `json:"serial_number,omitempty"`
	OSVersion       string `json:"os_version,omitempty"` // TMOS 15.1, IOS-XE 17.3, etc.
}

// ServiceHints holds identified service name/version for inventory enrichment.
type ServiceHints struct {
	ServiceName          string `json:"service_name,omitempty"`
	ServiceVersion       string `json:"service_version,omitempty"`
	Confidence           string `json:"confidence,omitempty"`            // high, medium, low
	IdentificationMethod string `json:"identification_method,omitempty"` // banner, api, port_heuristic, device_config
}

// UnmarshalJSON custom unmarshaling for Job to handle credentials decryption
func (j *Job) UnmarshalJSON(data []byte) error {
	type Alias Job
	aux := &struct {
		*Alias
		Credentials json.RawMessage `json:"credentials"`
	}{
		Alias: (*Alias)(j),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Credentials will be decrypted by the API client before unmarshaling
	if len(aux.Credentials) > 0 {
		if err := json.Unmarshal(aux.Credentials, &j.Credentials); err != nil {
			return err
		}
	}

	return nil
}
