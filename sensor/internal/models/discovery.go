package models

import (
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"time"

	"github.com/google/uuid"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// HostIdentity is what the sensor knows about the machine it runs ON, as
// distinct from anything it discovers about OTHER hosts on the network
// (asset-inventory decision 9, morning notes).
//
// Before this existed, the sensor never called os.Hostname() anywhere, so the
// host it ran on was seen only PASSIVELY — an ARP or mDNS frame someone else's
// sensor happened to capture — and landed in inventory as `unknown_host`
// holding nothing but a MAC and an IP. Reporting this block lets
// sensor-manager turn that into a named, classed asset via the SAME
// host-observation ingest path every other passive observation already uses,
// using KindAgentID (the strongest identifier kind there is) so it can never
// mis-merge with an unrelated host that happens to share an address.
//
// Sent on registration and (throttled — see the sensor's heartbeat builder)
// on heartbeat. Omitted entirely (nil) is how an older sensor binary looks;
// the consumer must treat that as "unchanged", never as "cleared".
type HostIdentity struct {
	// Hostname is the short name os.Hostname() returned. Empty when the call
	// failed, which happens on some minimal containers.
	Hostname string `json:"hostname,omitempty"`
	// FQDN is a fully-qualified name for Hostname, resolved best-effort and
	// CACHED — never looked up fresh on the heartbeat path, which must not
	// block on DNS every 30 seconds. Empty when no qualified name could be
	// resolved cheaply.
	FQDN string `json:"fqdn,omitempty"`
	// OS is runtime.GOOS ("linux", "windows", "darwin").
	OS string `json:"os,omitempty"`
	// Arch is runtime.GOARCH.
	Arch string `json:"arch,omitempty"`
	// Interfaces is the host's own bound addresses, each now carrying its
	// interface's MAC (shared/network.InterfaceAddress.MAC) alongside the
	// address — the same slice the heartbeat already reports as
	// SensorHealth.Interfaces, duplicated here so a self-report is a complete,
	// self-contained statement about the host that does not depend on the
	// reader cross-referencing a sibling field.
	Interfaces []sharednetwork.InterfaceAddress `json:"interfaces,omitempty"`
}

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
	ID              string    `json:"id"`
	SensorID        string    `json:"sensor_id"`
	Timestamp       time.Time `json:"timestamp"`
	SourceIP        string    `json:"source_ip"`
	DestIP          string    `json:"dest_ip"`
	Port            int       `json:"port"`
	Protocol        string    `json:"protocol"`
	Version         string    `json:"version"`
	CipherSuite     string    `json:"cipher_suite"`
	KeySize         int       `json:"key_size"`
	DiscoveryMethod string    `json:"discovery_method"`
	// DiscoveryType names the KIND of thing observed, distinct from the method
	// used to observe it. Empty on every crypto discovery, which is the legacy
	// shape and means "a cryptographic observation"; "host_observation" marks a
	// passive host-presence row whose payload is a hostobs.HostObservation
	// under RawMetadata["host_observation"] (asset-inventory ADR-0004 D2).
	//
	// sensor-manager promotes this into the metadata envelope ONLY when it is
	// non-empty: written unconditionally, the empty string would travel as an
	// outer envelope key and erase a nested discovery_type on the way through
	// discovery-processor's outer-wins promotion.
	DiscoveryType string                 `json:"discovery_type,omitempty"`
	Confidence    float64                `json:"confidence"`
	RawMetadata   map[string]interface{} `json:"raw_metadata"`
	ServiceHints  *ServiceHints          `json:"service_hints,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
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
	DNSInterfaces []string `json:"dns_interfaces"`
	Capabilities  []string `json:"capabilities"`
	SensorID      string   `json:"sensor_id"`
	Status        string   `json:"status"`
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
	// ConfigRevision, ConfigFailures and ConfigPendingRestart are the sensor's
	// desired-state report: the revision it has applied, anything it
	// could not apply and why, and anything recorded but not in force until it
	// restarts. Omitted when empty, so a sensor with nothing to say sends the
	// body it always sent.
	ConfigRevision       string            `json:"config_revision,omitempty"`
	ConfigFailures       map[string]string `json:"config_failures,omitempty"`
	ConfigPendingRestart []string          `json:"config_pending_restart,omitempty"`
	// ConfigRunning is what the sensor says its managed settings are set to
	// right now, including whatever came from its own configuration file. It is
	// how a sensor that enrolled before the control plane existed establishes
	// its starting position on its first report, instead of being handed
	// built-in defaults that would silently undo locally customised settings
	// (active_probing, host_observation_dns, dedup_ttl_minutes, ...). Omitted
	// when empty, which is a build too old to report what it is running — not
	// the same as "running nothing" ('s agentconfig.ExchangeReport.Running).
	ConfigRunning agentconfig.Values `json:"config_running,omitempty"`
	// ReportingInterval (seconds) is the sensor's current data-send cadence,
	// reported every heartbeat so the platform's stored value tracks reality
	// (including after an operator-initiated change is applied).
	ReportingInterval int `json:"reporting_interval,omitempty"`
	// IPAddress is this host's own address — the source address the kernel uses
	// to reach the control plane. Only the sensor can know it: by the time a
	// request reaches the platform, NAT/ingress/kube-proxy have rewritten the
	// connection source to a proxy or node address. Empty is allowed and leaves
	// the platform's stored value untouched.
	IPAddress string `json:"ip_address,omitempty"`
	// Interfaces is every IP bound on this host, with prefixes. A capture host is
	// often multi-homed and watching several segments at once, which a single
	// scalar address cannot express. Empty leaves the platform's recorded set
	// untouched.
	Interfaces []sharednetwork.InterfaceAddress `json:"interfaces,omitempty"`
	// Host is this sensor's own host identity — hostname, FQDN, OS/arch and
	// per-interface MACs. Sent on every heartbeat only when it is new or has
	// changed since the last send (the sensor's own throttle; see
	// cmd/main.go's sendHeartbeat), never on every 30s beat, so nil here is
	// the common case and does not mean "no host block was ever reported."
	Host      *HostIdentity `json:"host,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
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
	CaptureConfig     CaptureConfig   `json:"capture_config"`
	Features          map[string]bool `json:"features"`
}

// NOTE: there is no StorageConfig here. The control plane may still send a
// "storage_config" object in update_config payloads (sensor-manager populates
// one); the sensor ignores it, because it does not persist discoveries. Unknown
// JSON keys unmarshal away harmlessly, so older control planes stay compatible.

// CaptureConfig represents capture configuration
type CaptureConfig struct {
	ActiveProbing    bool `json:"active_probing"`
	NetworkDiscovery bool `json:"network_discovery"`
	// HostObservation is the platform-pushed switch for passive host
	// observation, alongside network_discovery.
	//
	// A POINTER, unlike its neighbours, because it is new: a control plane
	// older than this field sends no value at all, and a plain bool would
	// unmarshal that silence as false and switch the feature off on every
	// sensor talking to it. nil means "the platform said nothing", and the
	// sensor keeps its own configured value.
	HostObservation *bool `json:"host_observation,omitempty"`
	MaxConnections  int   `json:"max_connections"`
	TimeoutSeconds  int   `json:"timeout_seconds"`
	DedupTTLMinutes int   `json:"dedup_ttl_minutes"`
}

// SensorCommands represents a collection of commands for a sensor
type SensorCommands struct {
	Commands []Command `json:"commands"`
	// Config is the sensor's desired state, answered on every
	// heartbeat. Absent from an older platform's reply, which the sensor treats
	// as "no change" rather than as an instruction to revert — silence is not
	// an instruction.
	Config *agentconfig.ExchangePayload `json:"config,omitempty"`
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
	// Host is this sensor's own host identity, always sent at registration
	// (registration happens once, so there is no throttle to apply). See
	// [HostIdentity].
	Host *HostIdentity `json:"host,omitempty"`
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
	SSHProtocolVersion    string `json:"ssh_protocol_version,omitempty"`     // catalogue code, e.g. "SSH-2.0"
	SSHSoftwareVersion    string `json:"ssh_software_version,omitempty"`     // e.g. "OpenSSH_9.6p1"
	SSHKexAlgorithm       string `json:"ssh_kex_algorithm,omitempty"`        // e.g. "curve25519-sha256"
	SSHHostKeyAlgorithm   string `json:"ssh_host_key_algorithm,omitempty"`   // negotiated host key algorithm
	SSHEncryptionAlgC2S   string `json:"ssh_encryption_alg_c2s,omitempty"`   // client-to-server cipher
	SSHEncryptionAlgS2C   string `json:"ssh_encryption_alg_s2c,omitempty"`   // server-to-client cipher
	SSHMACAlgC2S          string `json:"ssh_mac_alg_c2s,omitempty"`          // client-to-server MAC
	SSHMACAlgS2C          string `json:"ssh_mac_alg_s2c,omitempty"`          // server-to-client MAC
	SSHCompressionAlg     string `json:"ssh_compression_alg,omitempty"`      // compression algorithm

	// SSH algorithms the server OFFERED in its SSH_MSG_KEXINIT (active probe
	// only). These are not in use — they are what the server will agree to if
	// a client asks — and the inventory ingest links them as is_inferred=true.
	// The json tags are the same key names the passive sensor's SSH assembler
	// and the in-cluster Platform Sensor emit, so all three producers land in
	// one vocabulary.
	SSHServerKexAlgorithms     []string `json:"ssh_kex_algorithms_server,omitempty"`
	SSHServerHostKeyAlgorithms []string `json:"ssh_host_key_algs_server,omitempty"`
	SSHServerEncryptionC2S     []string `json:"ssh_encryption_algs_c2s_server,omitempty"`
	SSHServerEncryptionS2C     []string `json:"ssh_encryption_algs_s2c_server,omitempty"`
	SSHServerMACsC2S           []string `json:"ssh_mac_algs_c2s_server,omitempty"`
	SSHServerMACsS2C           []string `json:"ssh_mac_algs_s2c_server,omitempty"`
	SSHServerCompressionC2S    []string `json:"ssh_compression_algs_c2s_server,omitempty"`
	SSHServerCompressionS2C    []string `json:"ssh_compression_algs_s2c_server,omitempty"`

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
