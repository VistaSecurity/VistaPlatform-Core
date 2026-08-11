package models

import (
	"time"

	"github.com/google/uuid"
)

// Sensor represents a sensor in the system
type Sensor struct {
	ID          uuid.UUID `json:"id" db:"id"`
	TenantID    uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Name        string    `json:"name" db:"name"`
	SensorType  string    `json:"sensor_type" db:"sensor_type"` // 'network', 'endpoint', 'cloud', 'api'
	Description *string   `json:"description" db:"description"`
	Platform    string    `json:"platform" db:"platform"`
	Version     string    `json:"version" db:"version"`
	Profile     string    `json:"profile" db:"profile"`
	Status      string    `json:"status" db:"status"` // 'pending', 'active', 'inactive', 'error', 'offline'
	// AirGapped marks a sensor that does not check in / heartbeat / stream
	// discoveries; the platform still shows it registered and imports findings
	// out-of-band. Replaces the deprecated profile selector.
	AirGapped         bool     `json:"air_gapped" db:"air_gapped"`
	NetworkInterfaces []string `json:"network_interfaces" db:"network_interfaces"`
	// AvailableInterfaces is the full host NIC inventory the sensor reports in
	// its heartbeat, so the UI can offer a real interface picker. Distinct from
	// NetworkInterfaces (the subset actually being monitored).
	AvailableInterfaces []string   `json:"available_interfaces" db:"available_interfaces"`
	Tags                []string   `json:"tags" db:"tags"`
	IPAddress           *string    `json:"ip_address" db:"ip_address"`
	LastHeartbeat       *time.Time `json:"last_heartbeat" db:"last_heartbeat"`
	// ReportingInterval is the sensor's actual data-send cadence in seconds,
	// reported by the sensor at registration and on every heartbeat. Nil until
	// the sensor reports it (older sensors, or before first check-in). Operators
	// change it via an update_config command (see IsAllowedReportingInterval).
	ReportingInterval *int       `json:"reporting_interval" db:"reporting_interval"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt         *time.Time `json:"deleted_at" db:"deleted_at"`
	// Legacy fields for backward compatibility
	Type         string                 `json:"type,omitempty" db:"type"`
	LastSeen     *time.Time             `json:"last_seen,omitempty" db:"last_seen"`
	Config       SensorConfig           `json:"config,omitempty" db:"config"`
	Capabilities []string               `json:"capabilities,omitempty" db:"capabilities"`
	Location     *string                `json:"location,omitempty" db:"location"`
	LegacyTags   map[string]interface{} `json:"legacy_tags,omitempty" db:"legacy_tags"`
	Metadata     map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
}

// AllowedReportingIntervals is the fixed menu of reporting-interval values
// (seconds) an operator may choose: 30s, 1m, 5m, 15m, 30m, 1h, 2h, 4h, 8h, 12h,
// 24h. A fixed set (rather than free-form) keeps fleet-wide cadence predictable
// for operational planning. The frontend dropdown renders this same list, and
// the API rejects anything not in it.
var AllowedReportingIntervals = []int{30, 60, 300, 900, 1800, 3600, 7200, 14400, 28800, 43200, 86400}

// IsAllowedReportingInterval reports whether sec is one of the allowed presets.
func IsAllowedReportingInterval(sec int) bool {
	for _, v := range AllowedReportingIntervals {
		if v == sec {
			return true
		}
	}
	return false
}

// SensorConfig represents sensor configuration
type SensorConfig struct {
	ID                 uuid.UUID        `json:"id" db:"id"`
	SensorID           uuid.UUID        `json:"sensor_id" db:"sensor_id"`
	ScanInterval       int              `json:"scan_interval" db:"scan_interval"` // seconds
	MaxConcurrentScans int              `json:"max_concurrent_scans" db:"max_concurrent_scans"`
	RetentionDays      int              `json:"retention_days" db:"retention_days"`
	DataCompression    bool             `json:"data_compression" db:"data_compression"`
	EncryptionEnabled  bool             `json:"encryption_enabled" db:"encryption_enabled"`
	ReportingInterval  int              `json:"reporting_interval" db:"reporting_interval"` // seconds
	ControlPlaneURL    string           `json:"control_plane_url" db:"control_plane_url"`
	Features           []string         `json:"features" db:"features"`
	WebhookConfig      *WebhookConfig   `json:"webhook_config" db:"webhook_config"`
	NetworkConfig      *NetworkConfig   `json:"network_config" db:"network_config"`
	DiscoveryConfig    *DiscoveryConfig `json:"discovery_config" db:"discovery_config"`
	SecurityConfig     *SecurityConfig  `json:"security_config" db:"security_config"`
	StorageConfig      *StorageConfig   `json:"storage_config" db:"storage_config"`
	CaptureConfig      *CaptureConfig   `json:"capture_config" db:"capture_config"`
	CreatedAt          time.Time        `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time        `json:"updated_at" db:"updated_at"`
}

// WebhookConfig represents webhook configuration
type WebhookConfig struct {
	URL            string            `json:"url" db:"url"`
	WebhookURL     string            `json:"webhook_url" db:"webhook_url"`
	Secret         string            `json:"secret" db:"secret"`
	Headers        map[string]string `json:"headers" db:"headers"`
	RetryAttempts  int               `json:"retry_attempts" db:"retry_attempts"`
	RetryCount     int               `json:"retry_count" db:"retry_count"`
	TimeoutSeconds int               `json:"timeout_seconds" db:"timeout_seconds"`
	Timeout        int               `json:"timeout" db:"timeout"`
	Enabled        bool              `json:"enabled" db:"enabled"`
	Events         []string          `json:"events" db:"events"`
	SensorID       string            `json:"sensor_id" db:"sensor_id"`
}

// NetworkConfig represents network configuration
type NetworkConfig struct {
	AllowedNetworks    []string `json:"allowed_networks" db:"allowed_networks"`
	BlockedNetworks    []string `json:"blocked_networks" db:"blocked_networks"`
	PortRange          string   `json:"port_range" db:"port_range"`
	Protocols          []string `json:"protocols" db:"protocols"`
	MaxHostsPerScan    int      `json:"max_hosts_per_scan" db:"max_hosts_per_scan"`
	ScanTimeoutSeconds int      `json:"scan_timeout_seconds" db:"scan_timeout_seconds"`
}

// DiscoveryConfig represents discovery configuration
type DiscoveryConfig struct {
	EnabledProtocols    []string `json:"enabled_protocols" db:"enabled_protocols"`
	DeepScanEnabled     bool     `json:"deep_scan_enabled" db:"deep_scan_enabled"`
	VulnerabilityScan   bool     `json:"vulnerability_scan" db:"vulnerability_scan"`
	ComplianceCheck     bool     `json:"compliance_check" db:"compliance_check"`
	AssetClassification bool     `json:"asset_classification" db:"asset_classification"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	EncryptionKey         string   `json:"encryption_key" db:"encryption_key"`
	AllowedIPs            []string `json:"allowed_ips" db:"allowed_ips"`
	RequireAuthentication bool     `json:"require_authentication" db:"require_authentication"`
	CertificatePath       string   `json:"certificate_path" db:"certificate_path"`
	PrivateKeyPath        string   `json:"private_key_path" db:"private_key_path"`
}

// StorageConfig represents storage configuration
type StorageConfig struct {
	Type               string `json:"type" db:"type"` // "local", "s3", "azure", "gcp"
	Path               string `json:"path" db:"path"`
	MaxSize            int64  `json:"max_size" db:"max_size"`                 // bytes
	MaxStorageSize     int64  `json:"max_storage_size" db:"max_storage_size"` // bytes
	RetentionDays      int    `json:"retention_days" db:"retention_days"`
	RotationSize       int64  `json:"rotation_size" db:"rotation_size"` // bytes
	CompressionEnabled bool   `json:"compression_enabled" db:"compression_enabled"`
	EncryptionEnabled  bool   `json:"encryption_enabled" db:"encryption_enabled"`
	EncryptionKey      string `json:"encryption_key" db:"encryption_key"`
}

// CaptureConfig represents data capture configuration
type CaptureConfig struct {
	Enabled          bool     `json:"enabled" db:"enabled"`
	CaptureTypes     []string `json:"capture_types" db:"capture_types"`
	Interfaces       []string `json:"interfaces" db:"interfaces"`
	MaxPacketSize    int      `json:"max_packet_size" db:"max_packet_size"`
	BufferSize       int      `json:"buffer_size" db:"buffer_size"`
	FlushInterval    int      `json:"flush_interval" db:"flush_interval"` // seconds
	FilterRules      []string `json:"filter_rules" db:"filter_rules"`
	SamplingRate     float64  `json:"sampling_rate" db:"sampling_rate"`
	ActiveProbing    bool     `json:"active_probing" db:"active_probing"`
	NetworkDiscovery bool     `json:"network_discovery" db:"network_discovery"`
	MaxConnections   int      `json:"max_connections" db:"max_connections"`
	TimeoutSeconds   int      `json:"timeout_seconds" db:"timeout_seconds"`
	// DedupTTLMinutes is the minimum number of minutes between re-reporting
	// the same observation.  0 means use the sensor default (60 minutes).
	DedupTTLMinutes int `json:"dedup_ttl_minutes" db:"dedup_ttl_minutes"`
}

// Command represents a command sent to a sensor
type Command struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	SensorID    uuid.UUID              `json:"sensor_id" db:"sensor_id"`
	Type        string                 `json:"type" db:"type"` // "scan", "stop", "restart", "update", "status"
	CommandType string                 `json:"command_type" db:"command_type"`
	Payload     map[string]interface{} `json:"payload" db:"payload"`
	Priority    int                    `json:"priority" db:"priority"`
	Status      string                 `json:"status" db:"status"` // "pending", "sent", "acknowledged", "completed", "failed"
	ExpiresAt   *time.Time             `json:"expires_at" db:"expires_at"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	CompletedAt *time.Time             `json:"completed_at" db:"completed_at"`
}

// CommandResponse represents a response from a sensor
type CommandResponse struct {
	ID           uuid.UUID              `json:"id" db:"id"`
	CommandID    uuid.UUID              `json:"command_id" db:"command_id"`
	SensorID     uuid.UUID              `json:"sensor_id" db:"sensor_id"`
	Status       string                 `json:"status" db:"status"` // "success", "error", "partial"
	Message      string                 `json:"message" db:"message"`
	Data         map[string]interface{} `json:"data" db:"data"`
	ResponseData map[string]interface{} `json:"response_data" db:"response_data"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
}

// DiscoveryBatch represents a batch of discoveries submitted by a sensor
type DiscoveryBatch struct {
	SensorID    uuid.UUID              `json:"sensor_id"`
	BatchID     uuid.UUID              `json:"batch_id"`
	Discoveries []SensorDiscoveryInput `json:"discoveries"`
	Timestamp   time.Time              `json:"timestamp"`
	Count       int                    `json:"count"`
}

// ServiceHints holds identified service name/version and confidence (from sensor) for inventory enrichment.
type ServiceHints struct {
	ServiceName          string `json:"service_name,omitempty"`
	ServiceVersion       string `json:"service_version,omitempty"`
	Confidence           string `json:"confidence,omitempty"`
	IdentificationMethod string `json:"identification_method,omitempty"`
	RawBanner            string `json:"raw_banner,omitempty"`
	JA3SFingerprint      string `json:"ja3s_fingerprint,omitempty"`
}

// SensorDiscoveryInput represents a single discovery submitted by a sensor
type SensorDiscoveryInput struct {
	Protocol        string                 `json:"protocol"`
	SourceIP        string                 `json:"source_ip"`
	DestIP          string                 `json:"dest_ip"`
	Port            int                    `json:"port"`
	Hostname        string                 `json:"hostname,omitempty"`
	Version         string                 `json:"version"`
	CipherSuite     string                 `json:"cipher_suite"`
	KeySize         int                    `json:"key_size"`
	DiscoveryMethod string                 `json:"discovery_method"`
	Confidence      float64                `json:"confidence"`
	RawMetadata     map[string]interface{} `json:"raw_metadata"`
	ServiceHints    *ServiceHints          `json:"service_hints,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
}

// AirGappedExport represents an air-gapped export
type AirGappedExport struct {
	ID           uuid.UUID              `json:"id" db:"id"`
	ExportID     uuid.UUID              `json:"export_id" db:"export_id"`
	SensorID     uuid.UUID              `json:"sensor_id" db:"sensor_id"`
	TenantID     uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	ExportType   string                 `json:"export_type" db:"export_type"` // "full", "incremental", "compliance"
	Status       string                 `json:"status" db:"status"`           // "pending", "generating", "ready", "downloaded", "expired"
	Data         map[string]interface{} `json:"data" db:"data"`
	FilePath     *string                `json:"file_path" db:"file_path"`
	FileSize     *int64                 `json:"file_size" db:"file_size"`
	Checksum     *string                `json:"checksum" db:"checksum"`
	Signature    *string                `json:"signature" db:"signature"`
	ExpiresAt    *time.Time             `json:"expires_at" db:"expires_at"`
	DownloadedAt *time.Time             `json:"downloaded_at" db:"downloaded_at"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at" db:"updated_at"`
}

// PendingSensorRegistration represents a pending sensor registration
type PendingSensorRegistration struct {
	ID                uuid.UUID              `json:"id" db:"id"`
	TenantID          uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	RegistrationKey   string                 `json:"registration_key" db:"registration_key"`
	Name              string                 `json:"name" db:"name"`
	IPAddress         string                 `json:"ip_address" db:"ip_address"`
	Profile           string                 `json:"profile" db:"profile"`                       // 'datacenter_host', 'cloud_instance', etc.
	NetworkInterfaces []string               `json:"network_interfaces" db:"network_interfaces"` // TEXT[] in DB
	Tags              []string               `json:"tags" db:"tags"`                             // TEXT[] in DB
	Description       *string                `json:"description" db:"description"`
	Metadata          map[string]interface{} `json:"metadata" db:"metadata"`
	Status            string                 `json:"status" db:"status"` // "pending", "used", "expired", "cancelled"
	ExpiresAt         time.Time              `json:"expires_at" db:"expires_at"`
	UsedAt            *time.Time             `json:"used_at" db:"used_at"`
	CreatedAt         time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at" db:"updated_at"`
}

// SensorHeartbeat represents a sensor heartbeat
type SensorHeartbeat struct {
	ID        uuid.UUID              `json:"id" db:"id"`
	SensorID  uuid.UUID              `json:"sensor_id" db:"sensor_id"`
	Status    string                 `json:"status" db:"status"`
	Message   string                 `json:"message" db:"message"`
	Metrics   map[string]interface{} `json:"metrics" db:"metrics"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
}

// SensorMetrics represents sensor performance metrics
type SensorMetrics struct {
	ID               uuid.UUID `json:"id" db:"id"`
	SensorID         uuid.UUID `json:"sensor_id" db:"sensor_id"`
	CPUUsage         float64   `json:"cpu_usage" db:"cpu_usage"`
	MemoryUsage      float64   `json:"memory_usage" db:"memory_usage"`
	DiskUsage        float64   `json:"disk_usage" db:"disk_usage"`
	NetworkIO        int64     `json:"network_io" db:"network_io"`
	ScansCompleted   int       `json:"scans_completed" db:"scans_completed"`
	AssetsDiscovered int       `json:"assets_discovered" db:"assets_discovered"`
	ErrorsCount      int       `json:"errors_count" db:"errors_count"`
	Uptime           int64     `json:"uptime" db:"uptime"`                         // seconds
	LastScanDuration int64     `json:"last_scan_duration" db:"last_scan_duration"` // milliseconds
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
}

// SensorRegistration represents a sensor registration request
type SensorRegistration struct {
	ID                  uuid.UUID              `json:"id" db:"id"`
	TenantID            uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	RegistrationKey     string                 `json:"registration_key" db:"registration_key"`
	SensorName          string                 `json:"sensor_name" db:"sensor_name"`
	SensorType          string                 `json:"sensor_type" db:"sensor_type"`
	Profile             string                 `json:"profile" db:"profile"`
	Platform            string                 `json:"platform" db:"platform"`
	IPAddress           string                 `json:"ip_address" db:"ip_address"`
	Version             string                 `json:"version" db:"version"`
	Description         string                 `json:"description" db:"description"`
	Tags                []string               `json:"tags" db:"tags"`
	NetworkInterfaces   []string               `json:"network_interfaces" db:"network_interfaces"`
	AvailableInterfaces []string               `json:"available_interfaces" db:"available_interfaces"`
	Capabilities        []string               `json:"capabilities" db:"capabilities"`
	Metadata            map[string]interface{} `json:"metadata" db:"metadata"`
	Status              string                 `json:"status" db:"status"` // "pending", "approved", "rejected"
	CreatedAt           time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at" db:"updated_at"`
	// Optional: Pre-generated sensor ID (for CSR-based registration)
	SensorID *uuid.UUID `json:"sensor_id,omitempty"`
	// ReportingInterval (seconds) the sensor reports at registration, so the
	// platform stores its real cadence immediately (nil if not reported).
	ReportingInterval *int `json:"reporting_interval,omitempty"`
}

// SensorHealth represents sensor health status
type SensorHealth struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	SensorID    uuid.UUID              `json:"sensor_id" db:"sensor_id"`
	TenantID    uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Status      string                 `json:"status" db:"status"` // "healthy", "degraded", "unhealthy"
	Message     string                 `json:"message" db:"message"`
	LastSeen    time.Time              `json:"last_seen" db:"last_seen"`
	Uptime      int64                  `json:"uptime" db:"uptime"` // seconds
	CPUUsage    float64                `json:"cpu_usage" db:"cpu_usage"`
	MemoryUsage float64                `json:"memory_usage" db:"memory_usage"`
	DiskUsage   float64                `json:"disk_usage" db:"disk_usage"`
	NetworkIO   int64                  `json:"network_io" db:"network_io"`
	HealthData  map[string]interface{} `json:"health_data" db:"health_data"`
	Metrics     map[string]interface{} `json:"metrics" db:"metrics"`
	// AvailableInterfaces is the host's NIC inventory, reported with the
	// heartbeat so the platform can keep the sensor's available-interface list
	// current for the UI picker.
	AvailableInterfaces []string `json:"available_interfaces"`
	// ReportingInterval (seconds) is the sensor's current data-send cadence,
	// reported on every heartbeat so the platform's stored value tracks what the
	// sensor is actually doing (including after an operator change is applied).
	ReportingInterval *int      `json:"reporting_interval,omitempty"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
}

// SensorCommands represents a collection of commands for a sensor
type SensorCommands struct {
	SensorID string                 `json:"sensor_id"`
	Commands []Command              `json:"commands"`
	Metadata map[string]interface{} `json:"metadata"`
}

// SensorCommand model matching our database schema
type SensorCommand struct {
	ID             uuid.UUID              `json:"id" db:"id"`
	SensorID       uuid.UUID              `json:"sensor_id" db:"sensor_id"`
	CommandType    string                 `json:"command_type" db:"command_type"`
	Payload        map[string]interface{} `json:"payload" db:"payload"`
	Status         string                 `json:"status" db:"status"` // 'pending', 'delivered', 'acknowledged', 'completed', 'failed'
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
	DeliveredAt    *time.Time             `json:"delivered_at" db:"delivered_at"`
	AcknowledgedAt *time.Time             `json:"acknowledged_at" db:"acknowledged_at"`
	CompletedAt    *time.Time             `json:"completed_at" db:"completed_at"`
	UpdatedAt      *time.Time             `json:"updated_at" db:"updated_at"`
	ErrorMessage   *string                `json:"error_message" db:"error_message"`
	// ResponseData is the sensor's execution result/output, surfaced in the
	// command console so operators can see what each command actually did.
	ResponseData map[string]interface{} `json:"response_data" db:"response_data"`
}

// SensorHealthMetrics model matching our database schema
type SensorHealthMetrics struct {
	ID               uuid.UUID `json:"id" db:"id"`
	SensorID         uuid.UUID `json:"sensor_id" db:"sensor_id"`
	UptimeSeconds    int64     `json:"uptime_seconds" db:"uptime_seconds"`
	MemoryUsageBytes int64     `json:"memory_usage_bytes" db:"memory_usage_bytes"`
	CPUUsagePercent  float64   `json:"cpu_usage_percent" db:"cpu_usage_percent"`
	PacketsCaptured  int64     `json:"packets_captured" db:"packets_captured"`
	DiscoveriesMade  int64     `json:"discoveries_made" db:"discoveries_made"`
	ErrorsCount      int       `json:"errors_count" db:"errors_count"`
	RecordedAt       time.Time `json:"recorded_at" db:"recorded_at"`
}

// SensorDiscovery model for storing discovery batches from sensors
type SensorDiscovery struct {
	ID         uuid.UUID              `json:"id" db:"id"`
	SensorID   uuid.UUID              `json:"sensor_id" db:"sensor_id"`
	TenantID   uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	BatchID    string                 `json:"batch_id" db:"batch_id"`
	Protocol   string                 `json:"protocol" db:"protocol"`
	DestIP     string                 `json:"dest_ip" db:"dest_ip"`
	Port       int                    `json:"port" db:"port"`
	Confidence float64                `json:"confidence" db:"confidence"`
	Metadata   map[string]interface{} `json:"metadata" db:"metadata"`
	Timestamp  time.Time              `json:"timestamp" db:"timestamp"`
	CreatedAt  time.Time              `json:"created_at" db:"created_at"`
}

// New simplified models for sensor operations
type CreatePendingSensorRequest struct {
	Name              string   `json:"name" binding:"required"`
	IPAddress         string   `json:"ip_address" binding:"required"`
	Profile           string   `json:"profile" binding:"required"`
	NetworkInterfaces []string `json:"network_interfaces"`
	Tags              []string `json:"tags"`
	Description       string   `json:"description"`
}

type RegisterSensorRequest struct {
	RegistrationKey   string   `json:"registration_key" binding:"required"`
	Name              string   `json:"name" binding:"required"`
	Description       string   `json:"description"`
	Platform          string   `json:"platform" binding:"required"`
	Version           string   `json:"version" binding:"required"`
	Profile           string   `json:"profile" binding:"required"`
	NetworkInterfaces []string `json:"network_interfaces" binding:"required"`
	IPAddress         string   `json:"ip_address" binding:"required"`
	Tags              []string `json:"tags"`
}

type HeartbeatRequest struct {
	Status string
}

// DiscoveryJob represents a discovery job
type DiscoveryJob struct {
	ID                 uuid.UUID  `json:"id" db:"id"`
	TenantID           uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	CreatedBy          uuid.UUID  `json:"created_by" db:"created_by"`
	ExecutionMode      string     `json:"execution_mode" db:"execution_mode"` // 'cloud', 'sensors', 'auto'
	Status             string     `json:"status" db:"status"`                 // 'queued', 'running', 'completed', 'failed', 'cancelled'
	RequestedSensorIDs []string   `json:"requested_sensor_ids" db:"requested_sensor_ids"`
	Fanout             bool       `json:"fanout" db:"fanout"`
	RetentionCapMB     int        `json:"retention_cap_mb" db:"retention_cap_mb"`
	RetentionTTLHours  int        `json:"retention_ttl_hours" db:"retention_ttl_hours"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`
	StartedAt          *time.Time `json:"started_at" db:"started_at"`
	CompletedAt        *time.Time `json:"completed_at" db:"completed_at"`
	ErrorMessage       *string    `json:"error_message" db:"error_message"`
}

// DiscoveryJobInput represents input for creating a discovery job
type DiscoveryJobInput struct {
	ExecutionMode      string   `json:"execution_mode" binding:"required,oneof=cloud sensors auto"`
	RequestedSensorIDs []string `json:"requested_sensor_ids"`
	Fanout             *bool    `json:"fanout"`
	RetentionCapMB     *int     `json:"retention_cap_mb"`
	RetentionTTLHours  *int     `json:"retention_ttl_hours"`
}

// DiscoveryJobResult represents results submitted for a discovery job
type DiscoveryJobResult struct {
	Findings []DiscoveryFinding `json:"findings"`
}

// DiscoveryFinding represents a single discovery finding
type DiscoveryFinding struct {
	TargetID        uuid.UUID              `json:"target_id"`
	ExecutedVia     string                 `json:"executed_via"` // 'cloud', 'sensor', 'manual'
	Protocol        string                 `json:"protocol"`
	Port            int                    `json:"port"`
	ResolvedIP      *string                `json:"resolved_ip"`
	ResolvedIPs     []string               `json:"resolved_ips"`
	Hostname        *string                `json:"hostname"`
	Details         *string                `json:"details"`
	RawBlobRef      *string                `json:"raw_blob_ref"`
	RawBlobSize     *int                   `json:"raw_blob_size"`
	ErrorCode       *string                `json:"error_code"`
	ConfidenceScore *float64               `json:"confidence_score"`
	Metadata        map[string]interface{} `json:"metadata"`

	// TLS probe results (from sensor active probe or cluster-sensor TLS prober)
	TLSVersions      []string                 `json:"tls_versions,omitempty"`
	TLSVersion       string                   `json:"tls_version,omitempty"`
	SelectedCipher   string                   `json:"selected_cipher,omitempty"`
	CipherSuite      string                   `json:"cipher_suite,omitempty"`
	SupportedCiphers []string                 `json:"supported_ciphers,omitempty"`
	ALPN             []string                 `json:"alpn,omitempty"`
	Certificates     []map[string]interface{} `json:"certificates,omitempty"`

	// TLS certificate validation fields
	CertValidationStatus string `json:"cert_validation_status,omitempty"` // "valid", "self_signed", "expired", "hostname_mismatch", "untrusted_ca"
	CertValidationError  string `json:"cert_validation_error,omitempty"`

	// Key exchange algorithm parsed from cipher suite
	KeyExchangeAlgorithm string `json:"key_exchange_algorithm,omitempty"`

	// SSH algorithm negotiation fields (active probe only)
	SSHHostKeyType        string `json:"ssh_host_key_type,omitempty"`
	SSHHostKeyFingerprint string `json:"ssh_host_key_fingerprint,omitempty"`
	SSHKexAlgorithm       string `json:"ssh_kex_algorithm,omitempty"`
	SSHEncryptionAlgC2S   string `json:"ssh_encryption_alg_c2s,omitempty"`
	SSHEncryptionAlgS2C   string `json:"ssh_encryption_alg_s2c,omitempty"`
	SSHMACAlgC2S          string `json:"ssh_mac_alg_c2s,omitempty"`
	SSHMACAlgS2C          string `json:"ssh_mac_alg_s2c,omitempty"`
	SSHCompressionAlg     string `json:"ssh_compression_alg,omitempty"`
}
