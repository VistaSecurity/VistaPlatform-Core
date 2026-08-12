package models

import (
	"time"

	"github.com/google/uuid"
)

// ServiceHints holds identified service name/version and confidence for inventory enrichment.
type ServiceHints struct {
	ServiceName          string `json:"service_name,omitempty"`
	ServiceVersion       string `json:"service_version,omitempty"`
	Confidence           string `json:"confidence,omitempty"`            // high, medium, low
	IdentificationMethod string `json:"identification_method,omitempty"` // banner, ja3s, port_heuristic, http_header, manual
	RawBanner            string `json:"raw_banner,omitempty"`
	JA3SFingerprint      string `json:"ja3s_fingerprint,omitempty"`
	JA3Fingerprint       string `json:"ja3_fingerprint,omitempty"`
	JA4Fingerprint       string `json:"ja4_fingerprint,omitempty"`
}

// CryptoDiscovery represents a discovered cryptographic implementation
type CryptoDiscovery struct {
	ID              string                 `json:"id"`
	SensorID        string                 `json:"sensor_id"`
	Timestamp       time.Time              `json:"timestamp"`
	SourceIP        string                 `json:"source_ip"`
	DestIP          string                 `json:"dest_ip"`
	Port            int                    `json:"port"`
	Protocol        string                 `json:"protocol"`
	Version         string                 `json:"version"`
	CipherSuite     string                 `json:"cipher_suite"`
	KeySize         int                    `json:"key_size"`
	DiscoveryMethod string                 `json:"discovery_method"`
	Confidence      float64                `json:"confidence"`
	RawMetadata     map[string]interface{} `json:"raw_metadata"`
	ServiceHints    *ServiceHints          `json:"service_hints,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	// SessionID is a UUID assigned per TCP flow by the TLS assembler and is always
	// non-empty for passive ("passive") discoveries.
	SessionID string `json:"session_id,omitempty"`
}

// CertificateInfo represents certificate information
type CertificateInfo struct {
	SubjectDN               string    `json:"subject_dn"`
	IssuerDN                string    `json:"issuer_dn"`
	Subject                 string    `json:"subject"`
	Issuer                  string    `json:"issuer"`
	ValidFrom               time.Time `json:"valid_from"`
	ValidTo                 time.Time `json:"valid_to"`
	KeySize                 int       `json:"key_size"`
	Signature               string    `json:"signature"`
	Serial                  string    `json:"serial"`
	SerialNumber            string    `json:"serial_number"`
	NotBefore               time.Time `json:"not_before"`
	NotAfter                time.Time `json:"not_after"`
	KeyAlgorithm            string    `json:"key_algorithm"`
	SignatureAlg            string    `json:"signature_alg"`
	IsCA                    bool      `json:"is_ca"`
	CertificatePEM          string    `json:"certificate_pem"`
	FingerprintSHA256       string    `json:"fingerprint_sha256"`
	FingerprintSHA1         string    `json:"fingerprint_sha1"`
	SubjectAlternativeNames []string  `json:"subject_alternative_names"`
	KeyUsage                []string  `json:"key_usage"`
	ExtendedKeyUsage        []string  `json:"extended_key_usage"`
	ChainOrder              int       `json:"chain_order"`
}

// DiscoveryBatch represents a batch of discovery results
type DiscoveryBatch struct {
	SensorID    string            `json:"sensor_id"`
	Discoveries []CryptoDiscovery `json:"discoveries"`
	BatchID     string            `json:"batch_id"`
	Timestamp   time.Time         `json:"timestamp"`
	Count       int               `json:"count"`
}

// SensorHealth represents sensor health status
type SensorHealth struct {
	SensorID string `json:"sensor_id"`
	Status   string `json:"status"`
	// Version is the sensor binary's stamped release version, reported on every
	// heartbeat so the platform's recorded version tracks in-place upgrades —
	// registration-only recording left a swapped binary reporting its old
	// version forever. Empty is allowed (older sensors) and leaves the stored
	// value untouched.
	Version         string                 `json:"version,omitempty"`
	LastHeartbeat   time.Time              `json:"last_heartbeat"`
	Uptime          int64                  `json:"uptime"`
	MemoryUsage     int64                  `json:"memory_usage"`
	CPUUsage        float64                `json:"cpu_usage"`
	PacketsCaptured int64                  `json:"packets_captured"`
	DiscoveriesMade int64                  `json:"discoveries_made"`
	Errors          int64                  `json:"errors"`
	Metrics         map[string]interface{} `json:"metrics"`
	InterfaceStats  []InterfaceStatEntry   `json:"interface_stats,omitempty"`
	// AvailableInterfaces is the full host NIC inventory, reported so the
	// platform/UI can offer a real interface picker.
	AvailableInterfaces []string `json:"available_interfaces,omitempty"`
	// ReportingInterval (seconds) is the sensor's current data-send cadence,
	// reported every heartbeat so the platform's stored value tracks reality
	// (including after an operator-initiated change is applied).
	ReportingInterval int       `json:"reporting_interval,omitempty"`
	Timestamp         time.Time `json:"timestamp"`
}

// InterfaceStatEntry holds per-interface packet capture statistics
type InterfaceStatEntry struct {
	InterfaceName string  `json:"interface_name"`
	PacketCount   int64   `json:"packet_count"`
	DropCount     int64   `json:"drop_count"`
	DropRatePct   float64 `json:"drop_rate_pct"`
}

// SensorConfig represents sensor configuration
type SensorConfig struct {
	ReportingInterval int             `json:"reporting_interval"`
	StorageConfig     StorageConfig   `json:"storage_config"`
	CaptureConfig     CaptureConfig   `json:"capture_config"`
	Features          map[string]bool `json:"features"`
}

// StorageConfig represents storage configuration
type StorageConfig struct {
	MaxStorageSize int64 `json:"max_storage_size"`
	RotationSize   int64 `json:"rotation_size"`
	RetentionDays  int   `json:"retention_days"`
}

// CaptureConfig represents capture configuration
type CaptureConfig struct {
	ActiveProbing    bool `json:"active_probing"`
	NetworkDiscovery bool `json:"network_discovery"`
	MaxConnections   int  `json:"max_connections"`
	TimeoutSeconds   int  `json:"timeout_seconds"`
	DedupTTLMinutes  int  `json:"dedup_ttl_minutes"`
}

// SensorCommands represents a collection of commands for a sensor
type SensorCommands struct {
	Commands []Command `json:"commands"`
}

// Command represents a command sent to a sensor
type Command struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Priority    int                    `json:"priority"`
	Payload     map[string]interface{} `json:"payload"`
	RequiresAck bool                   `json:"requires_ack"`
	ExpiresAt   *time.Time             `json:"expires_at"`
	CreatedAt   time.Time              `json:"created_at"`
}

// CommandResponse represents a response to a command execution
type CommandResponse struct {
	ID           uuid.UUID              `json:"id"`
	CommandID    string                 `json:"command_id"`
	SensorID     string                 `json:"sensor_id"`
	Status       string                 `json:"status"`
	Message      string                 `json:"message"`
	ResponseData map[string]interface{} `json:"response_data"`
	Timestamp    time.Time              `json:"timestamp"`
}

// SensorRegistration represents a sensor registration request
type SensorRegistration struct {
	RegistrationKey   string   `json:"registration_key"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Platform          string   `json:"platform"`
	Version           string   `json:"version"`
	Profile           string   `json:"profile"`
	NetworkInterfaces []string `json:"network_interfaces"`
	// AvailableInterfaces is the full host NIC inventory reported at
	// registration so the platform's interface picker is populated immediately,
	// without waiting for the first heartbeat (matters for air-gapped sensors).
	AvailableInterfaces []string `json:"available_interfaces,omitempty"`
	IPAddress           string   `json:"ip_address"`
	// ReportingInterval (seconds) is the sensor's configured data-send cadence,
	// reported at registration so the platform records the real value from the
	// start (set at install; changed later via update_config commands).
	ReportingInterval int `json:"reporting_interval,omitempty"`
	// CSR-based registration fields
	CSR      string `json:"csr,omitempty"`       // Certificate Signing Request (PEM format)
	SensorID string `json:"sensor_id,omitempty"` // Proposed sensor ID (UUID string) for CSR CN
}

// DiscoveryOptions represents options for discovery operations
type DiscoveryOptions struct {
	Targets        []string `json:"targets"`
	Protocols      []string `json:"protocols"`
	Timeout        int      `json:"timeout"`
	MaxRetries     int      `json:"max_retries"`
	Concurrency    int      `json:"concurrency"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	RetryCount     int      `json:"retry_count"`
	RespectRobots  bool     `json:"respect_robots"`
	BannerGrabbing bool     `json:"banner_grabbing"`
	FollowDNS      bool     `json:"follow_dns"`
	// DeepScan enables TLS version enumeration and deprecated-cipher detection
	// by making additional handshakes per target port.  Off by default.
	DeepScan bool `json:"deep_scan"`
	// ActiveScanning controls whether the sensor performs active probing.
	// When false, the sensor skips all active probing for this job.
	// Defaults to true (active probing enabled).
	ActiveScanning *bool `json:"active_scanning,omitempty"`
}

// DiscoveryJobRequest represents a discovery job request
type DiscoveryJobRequest struct {
	JobID             string           `json:"job_id"`
	Targets           []string         `json:"targets"`
	Protocols         []string         `json:"protocols"`
	Ports             []int            `json:"ports"`
	Options           DiscoveryOptions `json:"options"`
	CreatedAt         time.Time        `json:"created_at"`
	TenantID          string           `json:"tenant_id"`
	RetentionCapMB    int              `json:"retention_cap_mb"`
	RetentionTTLHours int              `json:"retention_ttl_hours"`
}

// DiscoveryJobResult represents the result of a discovery job
type DiscoveryJobResult struct {
	JobID             string             `json:"job_id"`
	Target            string             `json:"target"`
	Status            string             `json:"status"`
	ExecutedVia       string             `json:"executed_via"`
	CreatedAt         time.Time          `json:"created_at"`
	SuccessfulTargets int                `json:"successful_targets"`
	FailedTargets     int                `json:"failed_targets"`
	Findings          []DiscoveryFinding `json:"findings"`
	Errors            []string           `json:"errors"`
	ErrorCode         string             `json:"error_code"`
	ErrorMessage      string             `json:"error_message"`
	ResolvedIP        string             `json:"resolved_ip"`  // first resolved IP (backward compat)
	ResolvedIPs       []string           `json:"resolved_ips"` // all resolved IPs
	ExecutionTime     int64              `json:"execution_time"`
	CompletedAt       time.Time          `json:"completed_at"`
}

// DiscoveryFinding represents a single discovery finding
type DiscoveryFinding struct {
	Target           string                 `json:"target"`
	Protocol         string                 `json:"protocol"`
	Port             int                    `json:"port"`
	Confidence       float64                `json:"confidence"`
	Details          map[string]interface{} `json:"details"`
	DiscoveredAt     time.Time              `json:"discovered_at"`
	TLSVersions      []string               `json:"tls_versions"`
	SelectedCipher   string                 `json:"selected_cipher"`
	SupportedCiphers []string               `json:"supported_ciphers"`
	ALPN             []string               `json:"alpn"`
	Certificates     []CertificateInfo      `json:"certificates"`
	RawMetadata      map[string]interface{} `json:"raw_metadata"`
	ServiceHints     *ServiceHints          `json:"service_hints,omitempty"`

	// TLS certificate validation (active probe only)
	CertValidationStatus string `json:"cert_validation_status,omitempty"` // "valid", "self_signed", "expired", "hostname_mismatch", "untrusted_ca"
	CertValidationError  string `json:"cert_validation_error,omitempty"`  // raw error message when not "valid"

	// SSH banner (available from passive capture and active probe)
	SSHBanner   string   `json:"ssh_banner"`
	SSHKeyTypes []string `json:"ssh_key_types"`

	// SSH algorithm negotiation (active probe only — requires completing key exchange)
	SSHHostKeyType        string `json:"ssh_host_key_type,omitempty"`        // e.g. "ssh-ed25519", "rsa-sha2-256"
	SSHHostKeyFingerprint string `json:"ssh_host_key_fingerprint,omitempty"` // SHA256 fingerprint of host key
	SSHKexAlgorithm       string `json:"ssh_kex_algorithm,omitempty"`        // e.g. "curve25519-sha256"
	SSHEncryptionAlgC2S   string `json:"ssh_encryption_alg_c2s,omitempty"`   // client-to-server cipher
	SSHEncryptionAlgS2C   string `json:"ssh_encryption_alg_s2c,omitempty"`   // server-to-client cipher
	SSHMACAlgC2S          string `json:"ssh_mac_alg_c2s,omitempty"`          // client-to-server MAC
	SSHMACAlgS2C          string `json:"ssh_mac_alg_s2c,omitempty"`          // server-to-client MAC
	SSHCompressionAlg     string `json:"ssh_compression_alg,omitempty"`      // compression algorithm

	// Key exchange algorithm parsed from selected cipher suite
	KeyExchangeAlgorithm string `json:"key_exchange_algorithm,omitempty"`
}

// DiscoveryJobResponse represents a response to a discovery job
type DiscoveryJobResponse struct {
	SensorID          string               `json:"sensor_id"`
	JobID             string               `json:"job_id"`
	Status            string               `json:"status"`
	TotalTargets      int                  `json:"total_targets"`
	CreatedAt         time.Time            `json:"created_at"`
	SuccessfulTargets int                  `json:"successful_targets"`
	FailedTargets     int                  `json:"failed_targets"`
	Findings          []DiscoveryFinding   `json:"findings"`
	Results           []DiscoveryJobResult `json:"results"`
	Errors            []string             `json:"errors"`
	ExecutionTime     int64                `json:"execution_time"`
	CompletedAt       time.Time            `json:"completed_at"`
}
