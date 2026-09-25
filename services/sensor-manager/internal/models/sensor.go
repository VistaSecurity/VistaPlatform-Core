package models

import (
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"time"

	"github.com/google/uuid"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
)

// Sensor represents a sensor in the system
type Sensor struct {
	ReportedDNSInterfaces []string  `json:"reported_dns_interfaces,omitempty" db:"reported_dns_interfaces"`
	ReportedCapabilities  []string  `json:"reported_capabilities,omitempty" db:"reported_capabilities"`
	ID                    uuid.UUID `json:"id" db:"id"`
	TenantID              uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Name                  string    `json:"name" db:"name"`
	SensorType            string    `json:"sensor_type" db:"sensor_type"` // 'network', 'endpoint', 'cloud', 'api'
	Description           *string   `json:"description" db:"description"`
	Platform              string    `json:"platform" db:"platform"`
	Version               string    `json:"version" db:"version"`
	Profile               string    `json:"profile" db:"profile"`
	Status                string    `json:"status" db:"status"` // 'pending', 'active', 'inactive', 'error', 'offline'
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
	ReportingInterval *int `json:"reporting_interval" db:"reporting_interval"`
	// AssetID is the asset the HOST THIS SENSOR RUNS ON resolved to, from the
	// sensor's own self-reported host_observation ingest (asset-inventory
	// decision 9). nil until the first successful self-observation, and
	// forever nil for a sensor build old enough to send none.
	AssetID   *uuid.UUID `json:"asset_id" db:"asset_id"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at" db:"deleted_at"`
	// Legacy fields for backward compatibility
	Type         string                 `json:"type,omitempty" db:"type"`
	LastSeen     *time.Time             `json:"last_seen,omitempty" db:"last_seen"`
	Config       SensorConfig           `json:"config,omitempty" db:"config"`
	Capabilities []string               `json:"capabilities,omitempty" db:"capabilities"`
	Location     *string                `json:"location,omitempty" db:"location"`
	LegacyTags   map[string]interface{} `json:"legacy_tags,omitempty" db:"legacy_tags"`
	Metadata     map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	// Addresses is the host's full recorded address inventory, populated on the
	// single-sensor read only (the fleet list does not need it). IPAddress
	// remains the primary; this is every address the host reported.
	Addresses []AgentAddress `json:"addresses,omitempty" db:"-"`
}

// IsPlatformManaged reports whether this row is a platform-managed sensor — the
// tenant's per-workspace identity handle to an in-cluster service shared by
// every tenant, not a customer deployment.
//
// Two markers, ORed rather than ANDed, because either alone already identifies
// the row and requiring both would let a partially-stamped row slip through:
//
//   - platform = "platform" — the sentinel `create_system_sensors_for_tenant`
//     and cluster-sensor-service's auto-registration both stamp. Already the
//     codebase's definition of a platform sensor: the admin Fleet view derives
//     is_platform_sensor from it, and billing excludes it from purchased
//     capacity by it.
//   - the "system" tag — what result_processor's lookupSystemSensor selects on.
//     Including it makes this guard a superset of that selector, so no row the
//     interrogation pipeline can depend on is deletable.
//
// The `profile` values ("discovery", "device_interrogation") are deliberately
// NOT part of the test: they are legitimate values for a customer-deployed
// sensor, and keying on them would block deletions a tenant is entitled to make
// — the same bug pointed the other way.
func (s *Sensor) IsPlatformManaged() bool {
	if s == nil {
		return false
	}
	if s.Platform == "platform" {
		return true
	}
	for _, t := range s.Tags {
		if t == "system" {
			return true
		}
	}
	return false
}

// AgentAddress is one IP recorded against an agent, as returned to the UI.
type AgentAddress struct {
	InterfaceName string `json:"interface_name"`
	Address       string `json:"address"`
	PrefixLength  *int   `json:"prefix_length,omitempty"`
	IsPrimary     bool   `json:"is_primary"`
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
	// HostObservation is the passive host-observation switch (asset-inventory
	// ADR-0004 D2). A POINTER so that "the platform has no opinion" is
	// distinguishable from "the platform says off": a plain bool would be
	// serialised as false by a control plane that has never been told about
	// the feature, and the sensor would read that as an instruction to disable
	// something its own config had enabled.
	HostObservation *bool `json:"host_observation,omitempty" db:"host_observation"`
	MaxConnections  int   `json:"max_connections" db:"max_connections"`
	TimeoutSeconds  int   `json:"timeout_seconds" db:"timeout_seconds"`
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
	Protocol        string `json:"protocol"`
	SourceIP        string `json:"source_ip"`
	DestIP          string `json:"dest_ip"`
	Port            int    `json:"port"`
	Hostname        string `json:"hostname,omitempty"`
	Version         string `json:"version"`
	CipherSuite     string `json:"cipher_suite"`
	KeySize         int    `json:"key_size"`
	DiscoveryMethod string `json:"discovery_method"`
	// DiscoveryType names the KIND of observation, distinct from the method
	// used to make it. Empty on a crypto discovery — the legacy shape, and
	// what every sensor before this field sends; "host_observation" on a
	// passive host-presence row (asset-inventory ADR-0004 D2), whose payload
	// is under RawMetadata["host_observation"].
	DiscoveryType string                 `json:"discovery_type,omitempty"`
	Confidence    float64                `json:"confidence"`
	RawMetadata   map[string]interface{} `json:"raw_metadata"`
	ServiceHints  *ServiceHints          `json:"service_hints,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
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
	// Host is the sensor's own host identity, always sent at registration
	// (registration happens once, so the sensor applies no throttle there).
	// See [HostIdentity].
	Host *HostIdentity `json:"host,omitempty"`
}

// HostIdentity mirrors the sensor's own sensor/internal/models.HostIdentity
// wire shape exactly (asset-inventory decision 9, morning notes).
// It is what the sensor knows about the machine it runs ON, reported on
// registration and (throttled) on heartbeat so the Heartbeat/RegisterSensor
// handlers can turn it into a host observation through the SAME ingest path
// every other passive observation already uses (see outbound.go).
type HostIdentity struct {
	Hostname   string                           `json:"hostname,omitempty"`
	FQDN       string                           `json:"fqdn,omitempty"`
	OS         string                           `json:"os,omitempty"`
	Arch       string                           `json:"arch,omitempty"`
	Interfaces []sharednetwork.InterfaceAddress `json:"interfaces,omitempty"`
}

// SensorHealth represents sensor health status
type SensorHealth struct {
	DNSInterfaces []string               `json:"dns_interfaces"`
	Capabilities  []string               `json:"capabilities" db:"-"`
	ID            uuid.UUID              `json:"id" db:"id"`
	SensorID      uuid.UUID              `json:"sensor_id" db:"sensor_id"`
	TenantID      uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Status        string                 `json:"status" db:"status"` // "healthy", "degraded", "unhealthy"
	Message       string                 `json:"message" db:"message"`
	LastSeen      time.Time              `json:"last_seen" db:"last_seen"`
	Uptime        int64                  `json:"uptime" db:"uptime"` // seconds
	CPUUsage      float64                `json:"cpu_usage" db:"cpu_usage"`
	MemoryUsage   float64                `json:"memory_usage" db:"memory_usage"`
	DiskUsage     float64                `json:"disk_usage" db:"disk_usage"`
	NetworkIO     int64                  `json:"network_io" db:"network_io"`
	HealthData    map[string]interface{} `json:"health_data" db:"health_data"`
	Metrics       map[string]interface{} `json:"metrics" db:"metrics"`
	// AvailableInterfaces is the host's NIC inventory, reported with the
	// heartbeat so the platform can keep the sensor's available-interface list
	// current for the UI picker.
	AvailableInterfaces []string `json:"available_interfaces"`
	// ConfigRevision, ConfigFailures and ConfigPendingRestart are the sensor's
	// desired-state report: the revision it has applied, anything it
	// could not apply and why, and anything it will adopt on restart. All
	// optional — an older sensor sends none of them, and an empty revision
	// reads as "this build does not speak desired state", which is true.
	ConfigRevision       string            `json:"config_revision"`
	ConfigFailures       map[string]string `json:"config_failures"`
	ConfigPendingRestart []string          `json:"config_pending_restart"`
	// ConfigRunning is what the sensor says its managed settings are set to
	// right now, including whatever came from its own configuration file. It is
	// how a sensor that enrolled before the control plane existed establishes
	// its starting position on its first report, instead of being handed
	// built-in defaults that undo its local configuration. Absent from an older
	// sensor, which is distinct from "running nothing" — see
	// agentconfig.ExchangeReport.Running.
	ConfigRunning agentconfig.Values `json:"config_running"`
	// ReportingInterval (seconds) is the sensor's current data-send cadence,
	// reported on every heartbeat so the platform's stored value tracks what the
	// sensor is actually doing (including after an operator change is applied).
	ReportingInterval *int `json:"reporting_interval,omitempty"`
	// Version is the sensor binary's self-reported release version, sent on
	// every heartbeat (json only — persisted onto sensors.version, not a
	// sensor_health column). Empty means "not reported" and leaves the stored
	// version untouched, so pre-stamping sensors cannot blank it.
	Version string `json:"version,omitempty" db:"-"`
	// IPAddress is the sensor host's own address, as the sensor determines it —
	// the source address its kernel uses to reach the control plane. It MUST be
	// self-reported: the platform cannot observe it. Behind an ingress, NAT, or
	// kube-proxy (which SNATs to the receiving node under
	// externalTrafficPolicy: Cluster) the connection's source address is a
	// proxy/node IP, and X-Forwarded-For carries that same wrong value. Reading
	// it from the connection is what made every sensor report a Kubernetes node
	// IP. Empty means "not reported" and leaves the stored address untouched,
	// so an older sensor cannot blank the value captured at registration.
	IPAddress string `json:"ip_address,omitempty" db:"-"`
	// Interfaces is the host's full address inventory (every bound IP with its
	// prefix), reconciled into agent_addresses on each heartbeat. A multi-homed
	// capture host watches several segments at once, which IPAddress alone
	// cannot express. Empty leaves the recorded set untouched.
	Interfaces []sharednetwork.InterfaceAddress `json:"interfaces,omitempty" db:"-"`
	// Host is the sensor's own host identity, sent only when the sensor's own
	// throttle decided to (new, changed, or an hour since the last send) — see
	// [HostIdentity] and outbound.go's Heartbeat handler. nil is the common
	// case and does not mean "no host was ever reported."
	Host      *HostIdentity `json:"host,omitempty" db:"-"`
	CreatedAt time.Time     `json:"created_at" db:"created_at"`
}

// SensorCommands represents a collection of commands for a sensor
type SensorCommands struct {
	SensorID string                 `json:"sensor_id"`
	Commands []Command              `json:"commands"`
	Metadata map[string]interface{} `json:"metadata"`
	// Config is the sensor's desired state: what it SHOULD be running,
	// answered on every heartbeat. Omitted when the exchange could not be
	// served, which an older sensor and a sensor whose lookup failed both read
	// as "no change" rather than as an instruction to revert.
	//
	// Typed rather than interface{}: the wire shape is the contract between two
	// independently-built binaries, and a field that documents itself is worth
	// more here than one that accepts anything.
	Config *agentconfig.ExchangePayload `json:"config,omitempty"`
	// OwnedNetworks is the public space the tenant declared as its own, the
	// endpoints it elevated, and what it asked never to be probed (
	// W5.13). The sensor's TLS enricher reads it to decide which passively
	// seen destinations it may actively handshake with. Omitted when it could
	// not be built: the sensor keeps what it last had, and one that never had
	// any treats only private space as the tenant's.
	OwnedNetworks *probeconsent.OwnedNetworks `json:"owned_networks,omitempty"`
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

	// ExtraCounters carries every heartbeat counter that has no column of its
	// own — today, the eight `host_observations_*` metrics the passive
	// host-observation pipeline reports.
	//
	// It is a pointer so "the sensor reported none" (nil, an older build or the
	// feature switched off) stays distinguishable from "it reported all zeroes"
	// (an empty or zeroed map, running and seeing nothing). The contract doc
	// insists on that distinction for these metrics specifically: they are
	// absent entirely when the feature is off, because "not running" and
	// "running and seeing nothing" must not look the same.
	ExtraCounters *map[string]int64 `json:"extra_counters,omitempty" db:"extra_counters"`

	RecordedAt time.Time `json:"recorded_at" db:"recorded_at"`
}

// HostObservationCounterPrefix marks the heartbeat counters the passive
// host-observation pipeline reports. Everything under it is carried into
// ExtraCounters verbatim; the set grows whenever shared/hostobs gains a decoder,
// which is why this is a prefix rather than a list.
const HostObservationCounterPrefix = "host_observations_"

// MaxHeartbeatCounters and MaxHeartbeatCounterKeyLen bound what one heartbeat
// may put in ExtraCounters.
//
// A prefix accepts an OPEN set, and the heartbeat body is written by the sensor
// — which is customer-operated software holding a registered credential, on an
// endpoint with no request-size limit. Without a bound, a sensor with a runaway
// counter loop (or a compromised one) can push an arbitrarily large jsonb value
// into a row every thirty seconds, into a table nothing prunes. The fixed
// column set this replaced could not be grown that way; the whole point of jsonb
// is that it can, so the ceiling has to be stated rather than assumed.
//
// 64 against the 8 counters that exist leaves room for several more decoders
// without anyone having to think about this again, and is still three orders of
// magnitude short of a problem. 64 bytes is comfortably longer than the longest
// real name (`host_observations_coalesce_dropped`, 34).
const (
	MaxHeartbeatCounters      = 64
	MaxHeartbeatCounterKeyLen = 64
)

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
