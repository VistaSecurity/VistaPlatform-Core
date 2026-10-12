package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
	"github.com/vistasecurity/vistaplatform/shared/atomicfile"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
	"gopkg.in/yaml.v3"
)

// Config represents sensor configuration
type Config struct {
	// Sensor identity
	SensorID    string `json:"sensor_id"`
	TenantID    string `json:"tenant_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Platform    string `json:"platform"`
	Version     string `json:"version"`
	Profile     string `json:"profile"`

	// Control plane connection
	ControlPlaneURL string `json:"control_plane_url"`
	RegistrationKey string `json:"registration_key"`
	// RegistrationKeySHA256 is the SHA-256 (hex) of the registration key this
	// sensor enrolled with, written in its place once the key is no longer kept
	//. The key is single-use and spent at enrolment; the installer needs
	// only to recognise "this host already enrolled with this key", which a hash
	// answers without keeping the key on disk.
	RegistrationKeySHA256 string `json:"registration_key_sha256"`

	// Reporting configuration
	ReportingInterval time.Duration `json:"reporting_interval"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
	BatchSize         int           `json:"batch_size"`

	// Storage configuration
	Storage StorageConfig `json:"storage"`

	// Capture configuration
	Capture CaptureConfig `json:"capture"`

	// Network configuration
	Network NetworkConfig `json:"network"`

	// Security configuration
	Security SecurityConfig `json:"security"`

	// Features
	Features map[string]bool `json:"features"`

	// Test mode configuration
	TestMode bool `json:"test_mode"`

	// Verbose is the config-file override for log verbosity. Verbose logging is
	// the command-line default, so this is a three-state value: nil means "the
	// config says nothing, leave the default alone", and only an explicit
	// `verbose:` key in the YAML (or the VERBOSE env var) turns it off or
	// pins it on.
	Verbose *bool `json:"verbose"`

	// live mirrors the capture switches that concurrent probe workers read
	// while the main loop changes them. See EnableLiveSwitches.
	live *liveSwitches

	// agentSecrets is the per-sensor secret the platform issued at enrolment
	// (and the one it replaced, for a rotation window). It lives in
	// Security.AgentSecretPath, not in the YAML, and is reached only through the
	// methods below, which hold agentSecretsMu.
	agentSecrets agentcreds.SecretState
}

// agentSecretsMu guards every Config's agentSecrets. Package-level rather than a
// field so a Config stays a plain copyable value.
var agentSecretsMu sync.RWMutex

// AgentSecretState returns a snapshot of the sensor's secrets.
func (c *Config) AgentSecretState() agentcreds.SecretState {
	agentSecretsMu.RLock()
	defer agentSecretsMu.RUnlock()
	return c.agentSecrets
}

// SetAgentSecretState replaces the sensor's secrets (loading them from disk).
func (c *Config) SetAgentSecretState(s agentcreds.SecretState) {
	agentSecretsMu.Lock()
	c.agentSecrets = s
	agentSecretsMu.Unlock()
}

// SetEnrolledAgentSecret records the secret issued at enrolment.
func (c *Config) SetEnrolledAgentSecret(secret string, version int) {
	c.SetAgentSecretState(agentcreds.SecretState{Secret: secret, Version: version})
}

// RotateAgentSecret records the secret issued at a certificate rotation. The
// one it replaces — or, for a sensor that held none, its registration key —
// stays valid for agentcreds.PreviousSecretWindow.
func (c *Config) RotateAgentSecret(secret string, version int, now time.Time) {
	agentSecretsMu.Lock()
	c.agentSecrets = c.agentSecrets.Rotate(secret, version, c.RegistrationKey, now)
	agentSecretsMu.Unlock()
}

// PruneAgentSecrets drops an expired previous secret and reports whether it did.
func (c *Config) PruneAgentSecrets(now time.Time) bool {
	agentSecretsMu.Lock()
	defer agentSecretsMu.Unlock()
	next, changed := c.agentSecrets.Prune(now)
	c.agentSecrets = next
	return changed
}

// RegistrationKeyRetained reports whether the registration key still has to be
// kept in the config file: only while no agent secret is safely on disk.
func (c *Config) RegistrationKeyRetained() bool {
	return c.Security.AgentSecretPath == "" || c.AgentSecretState().IsZero()
}

// RegistrationKeyFingerprint is the value written in place of the key: the
// stored hash, or the hash of the key held in memory.
func (c *Config) RegistrationKeyFingerprint() string {
	if c.RegistrationKeySHA256 != "" {
		return c.RegistrationKeySHA256
	}
	if c.RegistrationKey == "" {
		return ""
	}
	return HashRegistrationKey(c.RegistrationKey)
}

// HashRegistrationKey is the fingerprint the installer compares against.
func HashRegistrationKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// liveSwitches holds the capture switches the TLS enricher's workers read on
// every observation while the heartbeat and command handlers change them. A
// plain bool read on one goroutine and written on another is a data race
// ( review); these are atomics, and the plain CaptureConfig fields stay
// the value everything single-threaded reads and reports.
type liveSwitches struct {
	activeProbing           atomic.Bool
	thirdPartyTLSEnrichment atomic.Bool
}

// EnableLiveSwitches starts mirroring ActiveProbing and ThirdPartyTLSEnrichment
// into atomics, seeded from the current field values. Call it once, before
// any concurrent reader starts — the enricher constructor does — and from then
// on change the two switches only through SetActiveProbing and
// SetThirdPartyTLSEnrichment.
func (c *Config) EnableLiveSwitches() {
	if c == nil || c.live != nil {
		return
	}
	l := &liveSwitches{}
	l.activeProbing.Store(c.Capture.ActiveProbing)
	l.thirdPartyTLSEnrichment.Store(c.Capture.ThirdPartyTLSEnrichment)
	c.live = l
}

// ActiveProbingEnabled is safe to call from any goroutine once live switches
// are enabled.
func (c *Config) ActiveProbingEnabled() bool {
	if c.live != nil {
		return c.live.activeProbing.Load()
	}
	return c.Capture.ActiveProbing
}

// ThirdPartyTLSEnrichmentEnabled is safe to call from any goroutine once live
// switches are enabled.
func (c *Config) ThirdPartyTLSEnrichmentEnabled() bool {
	if c.live != nil {
		return c.live.thirdPartyTLSEnrichment.Load()
	}
	return c.Capture.ThirdPartyTLSEnrichment
}

// SetActiveProbing changes the switch for every reader.
func (c *Config) SetActiveProbing(on bool) {
	c.Capture.ActiveProbing = on
	if c.live != nil {
		c.live.activeProbing.Store(on)
	}
}

// SetThirdPartyTLSEnrichment changes the switch for every reader.
func (c *Config) SetThirdPartyTLSEnrichment(on bool) {
	c.Capture.ThirdPartyTLSEnrichment = on
	if c.live != nil {
		c.live.thirdPartyTLSEnrichment.Store(on)
	}
}

// StorageConfig represents on-disk paths the sensor uses.
//
// The sensor does not persist discoveries. Captured findings live in an
// in-memory buffer until they are submitted to the control plane, and are
// re-queued in memory on submission failure. DataPath holds supporting files
// only — the enrollment certificates under certs/ and, in test mode, the
// test logger's output.
type StorageConfig struct {
	DataPath string `json:"data_path"`
}

// CaptureConfig represents packet capture configuration
type CaptureConfig struct {
	Interfaces    []string `json:"interfaces"`
	ActiveProbing bool     `json:"active_probing"`
	// ThirdPartyTLSEnrichment lets the TLS enricher actively handshake with
	// passively seen destinations that are NOT the tenant's own (see
	// shared/probeconsent). Off by default ( W5.13, owner decision Q10).
	//
	// The control plane's third_party_tls_enrichment setting governs it. The
	// file key `thirdPartyTLSEnrichment` / env THIRD_PARTY_TLS_ENRICHMENT is a
	// LOCAL value for a sensor the platform has never told — an air-gapped
	// one, or one talking to a platform older than the setting. Once the
	// platform delivers a value it wins, and keeps winning across restarts
	// (see sensor/cmd/probe_consent_state.go).
	ThirdPartyTLSEnrichment bool `json:"third_party_tls_enrichment"`
	// OwnedNetworks is the LOCAL list of public prefixes this sensor may treat
	// as the tenant's own, from the file key `ownedNetworks` / env
	// OWNED_NETWORKS (comma-separated). The air-gapped equivalent of declared
	// network segments, under the same precedence as ThirdPartyTLSEnrichment:
	// the platform's owned networks replace it the moment they arrive.
	OwnedNetworks    []string `json:"owned_networks,omitempty"`
	NetworkDiscovery bool     `json:"network_discovery"`
	MaxConnections   int      `json:"max_connections"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	BufferSize       int      `json:"buffer_size"`
	// ExtraPortsToMonitor lists additional TCP ports that are captured and
	// decoded as TLS (e.g. 9443). A port with a built-in meaning (SSH, SMB,
	// a STARTTLS port, ...) keeps it; values outside 1-65535 are ignored.
	ExtraPortsToMonitor []int `json:"extra_ports_to_monitor"`
	// DeepScan enables additional probes in the active prober:
	// TLS version enumeration and deprecated-cipher detection.
	// Increases network connections per target; default false.
	DeepScan bool `json:"deep_scan"`
	// DedupTTLMinutes is the minimum number of minutes between re-reporting
	// the same observation (same endpoint/protocol).  Applies to both the
	// passive connection cache and the TLS enricher debounce.  Default: 60.
	DedupTTLMinutes int `json:"dedup_ttl_minutes"`
	// STARTTLSPorts are TCP ports to monitor for STARTTLS upgrades.
	// Defaults: [25, 143, 110, 5432, 3306, 21, 5222, 389]
	STARTTLSPorts []int `json:"starttls_ports"`
	// EnableJA3 enables JA3/JA4 client fingerprinting on passive capture. Default: true.
	EnableJA3 bool `json:"enable_ja3"`
	// EnableSTARTTLS enables STARTTLS detection on plaintext ports. Default: true.
	EnableSTARTTLS bool `json:"enable_starttls"`
	// EnableQUICDecrypt enables QUIC Initial packet decryption. Default: true.
	EnableQUICDecrypt bool `json:"enable_quic_decrypt"`
	// EnableWireGuard enables WireGuard VPN detection on UDP port 51820. Default: true.
	EnableWireGuard bool `json:"enable_wireguard"`
	// EnableSMB enables SMB signing/encryption detection on TCP port 445. Default: true.
	EnableSMB bool `json:"enable_smb"`
	// EnableOpenVPN enables OpenVPN detection on UDP port 1194. Default: true.
	EnableOpenVPN bool `json:"enable_openvpn"`
	// EnableKerberos enables Kerberos etype detection on port 88. Default: true.
	EnableKerberos bool `json:"enable_kerberos"`
	// EnableModbus enables Modbus/TCP detection on port 502 (and Modbus/TLS
	// on 802 via the TLS assembler). Default: true — Modbus is so universal
	// in OT environments that it should be on by default.
	EnableModbus bool `json:"enable_modbus"`
	// EnableMMS enables IEC 61850 MMS and ICCP/TASE.2 detection on TCP port
	// 102. The same port handles both plaintext (TPKT/COTP framing) and
	// TLS-wrapped sessions; ICCP is differentiated from MMS at parse time
	// by the TASE.2 application-context OID. Default: true.
	EnableMMS bool `json:"enable_mms"`
	// EnableDNP3 enables DNP3 (IEEE 1815) detection on TCP port 20000,
	// including SAv2 / SAv5 Secure Authentication classification. Default:
	// true — North American electric T&D ubiquity makes this useful by
	// default everywhere a sensor runs.
	EnableDNP3 bool `json:"enable_dnp3"`
	// EnableOPCUA enables OPC UA Binary detection on TCP port 4840 with
	// SecurityPolicy URI extraction from the OpenSecureChannel message.
	// Default: true.
	EnableOPCUA bool `json:"enable_opcua"`
	// EnableENIP enables EtherNet/IP CIP passive detection on TCP port
	// 44818. Symmetric to the active List-Identity prober — when active
	// probing is disabled, this passive path still captures the
	// Allen-Bradley / Rockwell ecosystem's plaintext sessions. Default:
	// true.
	EnableENIP bool `json:"enable_enip"`
	// EnableHARTIP enables HART-IP (HCF Spec 85) passive detection on
	// TCP and UDP port 5094. Used in process industries (oil & gas,
	// refineries, water treatment, chemical plants) for instrument
	// diagnostics. Default: true.
	EnableHARTIP bool `json:"enable_hartip"`
	// HostObservation enables passive host observation: ARP, DHCP, mDNS,
	// NetBIOS, DNS answers, LLDP and CDP decoded into host identity
	// (asset-inventory ADR-0004 D2). Default: true, and pushed from the
	// platform like network_discovery.
	//
	// Turning it on widens the BPF filter — the crypto filter is a list of
	// ports, and ARP and LLDP are not even IP — so the sensor sees more
	// packets. The decoders run on their own goroutine behind a bounded
	// queue, so that extra traffic cannot delay the TLS/SSH paths; on a
	// segment busy enough to saturate the queue the sensor sheds host
	// observations and says so on the heartbeat.
	HostObservation bool `json:"host_observation"`
	// HostObservationWindowSeconds is how long observations about one host
	// are merged before being emitted. Default: 60. Longer means fewer,
	// richer rows and a longer wait before a new device appears.
	HostObservationWindowSeconds int `json:"host_observation_window_seconds"`
	// HostObservationDNS enables the unicast-DNS decoder on UDP 53.
	// Default: FALSE — the one part of host observation that is opt-in.
	//
	// Volume: UDP 53 on a busy segment is more packets than every other
	// protocol host observation decodes put together, and the BPF filter is
	// the only place that cost can be avoided outright.
	//
	// Privacy: the decoder reads answers only and never the question section,
	// but an answer names what was asked. A stream of A-record answers is a
	// record of which names this network resolved — a materially different
	// collection from "these devices are on this segment", and one somebody
	// should choose rather than inherit.
	//
	// Deliberately configured ON THE SENSOR HOST (file or environment) and not
	// pushed from the platform: whoever owns the segment being captured is who
	// should be turning this on. mDNS is unaffected — a multicast
	// announcement is a device advertising itself, not a lookup.
	HostObservationDNS bool `json:"host_observation_dns"`
}

// NetworkConfig represents network configuration
type NetworkConfig struct {
	Interfaces []string `json:"interfaces"`
	VLANs      []string `json:"vlans"`
	Gateways   []string `json:"gateways"`
	IPAddress  string   `json:"ip_address"`

	// ipAddressPinned records that IPAddress came from an operator (config file
	// or SENSOR_IP_ADDRESS) rather than from detection. A pinned address is
	// reported verbatim and never re-derived; an unpinned one is re-detected on
	// each heartbeat so a host that changes network (DHCP lease, VPN, failover)
	// corrects itself instead of reporting the address it had at startup.
	ipAddressPinned bool
}

// CurrentIPAddress returns the host address to report to the platform right now.
//
// An operator-pinned address is returned verbatim — if someone configured it,
// they mean it. Otherwise the address is re-derived on each call so a host that
// changed network since startup (DHCP lease, VPN, NIC failover) reports where it
// actually is rather than where it was. Returns "" when nothing can be
// determined; callers must send that as "unreported" rather than substituting a
// placeholder.
func (c *Config) CurrentIPAddress() string {
	if c.Network.ipAddressPinned {
		return c.Network.IPAddress
	}
	if ip := DetectPrimaryIPv4(c.ControlPlaneURL); ip != "" {
		return ip
	}
	return c.Network.IPAddress
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	ClientCert       string `json:"client_cert"`         // PEM-encoded certificate (or file content)
	ClientKey        string `json:"client_key"`          // PEM-encoded private key (or file content)
	ServerCACert     string `json:"server_ca_cert"`      // PEM-encoded CA certificate (or file content)
	ClientCertPath   string `json:"client_cert_path"`    // Path to certificate file on disk
	ClientKeyPath    string `json:"client_key_path"`     // Path to private key file on disk
	ServerCACertPath string `json:"server_ca_cert_path"` // Path to CA certificate file on disk
	// AgentSecretPath is the 0600 file holding the per-sensor secret.
	AgentSecretPath string `json:"agent_secret_path"`
	UseTLS          bool   `json:"use_tls"`
}

// ConfigFile represents the YAML config file structure
type ConfigFile struct {
	SensorID              string `yaml:"sensorId"`
	ControlPlaneURL       string `yaml:"controlPlaneUrl"`
	RegistrationKey       string `yaml:"registrationKey"`
	RegistrationKeySHA256 string `yaml:"registrationKeySha256"`
	ReportingIntervalSecs int    `yaml:"reportingIntervalSeconds"`
	HeartbeatIntervalSecs int    `yaml:"heartbeatIntervalSeconds"`
	Storage               struct {
		DataPath string `yaml:"dataPath"`
	} `yaml:"storage"`
	Capture struct {
		Interfaces                   []string `yaml:"interfaces"`
		ActiveProbing                bool     `yaml:"activeProbing"`
		ThirdPartyTLSEnrichment      bool     `yaml:"thirdPartyTLSEnrichment"`
		OwnedNetworks                []string `yaml:"ownedNetworks"`
		NetworkDiscovery             bool     `yaml:"networkDiscovery"`
		MaxConnections               int      `yaml:"maxConnections"`
		TimeoutSeconds               int      `yaml:"timeoutSeconds"`
		BufferSize                   int      `yaml:"bufferSize"`
		ExtraPortsToMonitor          []int    `yaml:"extraPortsToMonitor"`
		DeepScan                     bool     `yaml:"deepScan"`
		DedupTTLMinutes              int      `yaml:"dedupTTLMinutes"`
		STARTTLSPorts                []int    `yaml:"starttlsPorts"`
		EnableJA3                    *bool    `yaml:"enableJA3"`
		EnableSTARTTLS               *bool    `yaml:"enableSTARTTLS"`
		EnableQUICDecrypt            *bool    `yaml:"enableQUICDecrypt"`
		EnableWireGuard              *bool    `yaml:"enableWireGuard"`
		EnableSMB                    *bool    `yaml:"enableSMB"`
		EnableOpenVPN                *bool    `yaml:"enableOpenVPN"`
		EnableKerberos               *bool    `yaml:"enableKerberos"`
		EnableModbus                 *bool    `yaml:"enableModbus"`
		EnableMMS                    *bool    `yaml:"enableMMS"`
		EnableDNP3                   *bool    `yaml:"enableDNP3"`
		EnableOPCUA                  *bool    `yaml:"enableOPCUA"`
		EnableENIP                   *bool    `yaml:"enableENIP"`
		EnableHARTIP                 *bool    `yaml:"enableHARTIP"`
		HostObservation              *bool    `yaml:"hostObservation"`
		HostObservationWindowSeconds int      `yaml:"hostObservationWindowSeconds"`
		HostObservationDNS           *bool    `yaml:"hostObservationDNS"`
	} `yaml:"capture"`
	// Security holds the mTLS material written after a successful registration
	// (see Sensor.saveConfigFile). It MUST be parsed back here so that the
	// certificate the control plane issued is reloaded on restart — otherwise
	// the sensor loses its identity and tries to re-register with an already
	// consumed registration key.
	Security struct {
		ClientCert       string `yaml:"clientCert"`
		ClientKey        string `yaml:"clientKey"`
		ServerCACert     string `yaml:"serverCACert"`
		ClientCertPath   string `yaml:"clientCertPath"`
		ClientKeyPath    string `yaml:"clientKeyPath"`
		ServerCACertPath string `yaml:"serverCACertPath"`
		AgentSecretPath  string `yaml:"agentSecretPath"`
		UseTLS           bool   `yaml:"useTLS"`
	} `yaml:"security"`
	TestMode bool `yaml:"testMode"`
	// Verbose is a pointer so an absent `verbose:` key is distinguishable from
	// an explicit `verbose: false` — see Config.Verbose.
	Verbose *bool `yaml:"verbose"`
}

// LoadFromFile loads configuration from a YAML file and merges with environment variables
// Environment variables override config file values
func LoadFromFile(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// The raw file is deliberately never echoed: it contains the registration
	// key (and, after registration, the mTLS private key).

	var cfgFile ConfigFile
	if err := yaml.Unmarshal(data, &cfgFile); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Secret-safe summary of what was parsed; the registration key is reported
	// by length only. Verbose is not resolved yet at this point (env overrides
	// are applied later), so the summary stays unconditional.
	keyState := "(empty)"
	if cfgFile.RegistrationKey != "" {
		keyState = fmt.Sprintf("(set, %d chars)", len(cfgFile.RegistrationKey))
	}
	log.Printf("🔍 Parsed from config file: controlPlaneUrl=%q sensorId=%q registrationKey=%s interfaces=%v dataPath=%q",
		cfgFile.ControlPlaneURL, cfgFile.SensorID, keyState, cfgFile.Capture.Interfaces, cfgFile.Storage.DataPath)

	// Convert ConfigFile to Config, using config file values as base
	cfg := &Config{
		SensorID:              cfgFile.SensorID,
		ControlPlaneURL:       cfgFile.ControlPlaneURL,
		RegistrationKey:       cfgFile.RegistrationKey,
		RegistrationKeySHA256: cfgFile.RegistrationKeySHA256,
		ReportingInterval:     time.Duration(cfgFile.ReportingIntervalSecs) * time.Second,
		HeartbeatInterval:     time.Duration(cfgFile.HeartbeatIntervalSecs) * time.Second,
		Storage: StorageConfig{
			DataPath: cfgFile.Storage.DataPath,
		},
		Capture: CaptureConfig{
			Interfaces:                   cfgFile.Capture.Interfaces,
			ActiveProbing:                cfgFile.Capture.ActiveProbing,
			ThirdPartyTLSEnrichment:      cfgFile.Capture.ThirdPartyTLSEnrichment,
			OwnedNetworks:                cfgFile.Capture.OwnedNetworks,
			NetworkDiscovery:             cfgFile.Capture.NetworkDiscovery,
			MaxConnections:               cfgFile.Capture.MaxConnections,
			TimeoutSeconds:               cfgFile.Capture.TimeoutSeconds,
			BufferSize:                   cfgFile.Capture.BufferSize,
			ExtraPortsToMonitor:          cfgFile.Capture.ExtraPortsToMonitor,
			DeepScan:                     cfgFile.Capture.DeepScan,
			DedupTTLMinutes:              cfgFile.Capture.DedupTTLMinutes,
			STARTTLSPorts:                cfgFile.Capture.STARTTLSPorts,
			EnableJA3:                    cfgFile.Capture.EnableJA3 == nil || *cfgFile.Capture.EnableJA3,
			EnableSTARTTLS:               cfgFile.Capture.EnableSTARTTLS == nil || *cfgFile.Capture.EnableSTARTTLS,
			EnableQUICDecrypt:            cfgFile.Capture.EnableQUICDecrypt == nil || *cfgFile.Capture.EnableQUICDecrypt,
			EnableWireGuard:              cfgFile.Capture.EnableWireGuard == nil || *cfgFile.Capture.EnableWireGuard,
			EnableSMB:                    cfgFile.Capture.EnableSMB == nil || *cfgFile.Capture.EnableSMB,
			EnableOpenVPN:                cfgFile.Capture.EnableOpenVPN == nil || *cfgFile.Capture.EnableOpenVPN,
			EnableKerberos:               cfgFile.Capture.EnableKerberos == nil || *cfgFile.Capture.EnableKerberos,
			EnableModbus:                 cfgFile.Capture.EnableModbus == nil || *cfgFile.Capture.EnableModbus,
			EnableMMS:                    cfgFile.Capture.EnableMMS == nil || *cfgFile.Capture.EnableMMS,
			EnableDNP3:                   cfgFile.Capture.EnableDNP3 == nil || *cfgFile.Capture.EnableDNP3,
			EnableOPCUA:                  cfgFile.Capture.EnableOPCUA == nil || *cfgFile.Capture.EnableOPCUA,
			EnableENIP:                   cfgFile.Capture.EnableENIP == nil || *cfgFile.Capture.EnableENIP,
			EnableHARTIP:                 cfgFile.Capture.EnableHARTIP == nil || *cfgFile.Capture.EnableHARTIP,
			HostObservation:              cfgFile.Capture.HostObservation == nil || *cfgFile.Capture.HostObservation,
			HostObservationWindowSeconds: cfgFile.Capture.HostObservationWindowSeconds,
			// Absent means OFF, the opposite of its neighbours above: this one
			// defaults off, so silence in the file is the default rather than
			// an override of it.
			HostObservationDNS: cfgFile.Capture.HostObservationDNS != nil && *cfgFile.Capture.HostObservationDNS,
		},
		Security: SecurityConfig{
			ClientCert:       cfgFile.Security.ClientCert,
			ClientKey:        cfgFile.Security.ClientKey,
			ServerCACert:     cfgFile.Security.ServerCACert,
			ClientCertPath:   cfgFile.Security.ClientCertPath,
			ClientKeyPath:    cfgFile.Security.ClientKeyPath,
			ServerCACertPath: cfgFile.Security.ServerCACertPath,
			AgentSecretPath:  cfgFile.Security.AgentSecretPath,
			UseTLS:           cfgFile.Security.UseTLS,
		},
		TestMode: cfgFile.TestMode,
		Verbose:  cfgFile.Verbose,
	}

	// Apply defaults for missing values
	if cfg.Storage.DataPath == "" {
		cfg.Storage.DataPath = getDefaultDataPath()
	}
	if cfg.ReportingInterval <= 0 {
		cfg.ReportingInterval = 30 * time.Second
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 60 * time.Second
	}
	if cfg.Capture.DedupTTLMinutes == 0 {
		cfg.Capture.DedupTTLMinutes = 60
	}
	if len(cfg.Capture.STARTTLSPorts) == 0 {
		cfg.Capture.STARTTLSPorts = []int{25, 143, 110, 5432, 3306, 21, 5222, 389}
	}
	// Note: Don't apply default interfaces here - let it be empty if not specified
	// The default "eth0" is Linux-specific and wrong for Windows

	// Apply default ControlPlaneURL if empty (but only if not set in file)
	if cfg.ControlPlaneURL == "" {
		cfg.ControlPlaneURL = "http://localhost:8085"
		fmt.Printf("⚠️  ControlPlaneURL not found in config file, using default: %s\n", cfg.ControlPlaneURL)
	}

	// Apply defaults for registration fields (required for registration)
	if cfg.Name == "" {
		if cfg.SensorID != "" {
			cfg.Name = cfg.SensorID
		} else {
			cfg.Name = "crypto-sensor"
		}
	}
	if cfg.Platform == "" {
		cfg.Platform = runtime.GOOS
	}
	if cfg.Version == "" {
		// Placeholder only — cmd/main.go overwrites this with the
		// build-stamped main.Version after loading.
		cfg.Version = "dev"
	}
	if cfg.Profile == "" {
		cfg.Profile = "datacenter_host"
	}
	if cfg.Description == "" {
		cfg.Description = "Vista Platform Network Sensor"
	}

	// Merge with environment variables (env vars override config file)
	mergeEnvVars(cfg)

	// Load certificates from files if paths are set
	if err := loadCertificatesFromFiles(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// mergeEnvVars merges environment variables into config, overriding existing values
// Logs when environment variables override config file values
func mergeEnvVars(cfg *Config) {
	if sensorID := sharedconfig.GetEnv("SENSOR_ID", ""); sensorID != "" {
		if cfg.SensorID != sensorID {
			fmt.Printf("⚠️  Environment variable SENSOR_ID=%s overriding config file value\n", sensorID)
		}
		cfg.SensorID = sensorID
	}
	if controlPlaneURL := sharedconfig.GetEnv("CONTROL_PLANE_URL", ""); controlPlaneURL != "" {
		// Explicit escape hatch, mirroring the device-agent's
		// PLATFORM_URL_OVERRIDE. CONTROL_PLANE_URL is documented, so an operator
		// deliberately repointing an enrolled sensor needs a supported way to do
		// it rather than having to hand-edit the saved config.
		if sharedconfig.GetEnv("CONTROL_PLANE_URL_OVERRIDE", "") == "1" {
			fmt.Printf("⚠️  CONTROL_PLANE_URL_OVERRIDE=1 — repointing an enrolled sensor to %s; its mTLS client cert is bound to the previous endpoint and will likely fail until re-enrolled\n", controlPlaneURL)
			cfg.ControlPlaneURL = controlPlaneURL
		} else if shouldPreserveEnrolledControlPlaneURL(cfg) {
			if cfg.ControlPlaneURL != controlPlaneURL {
				fmt.Printf("ℹ️  Ignoring CONTROL_PLANE_URL=%s because enrolled mTLS config already pins controlPlaneUrl=%s (set CONTROL_PLANE_URL_OVERRIDE=1 to force)\n", controlPlaneURL, cfg.ControlPlaneURL)
			}
		} else {
			if cfg.ControlPlaneURL != controlPlaneURL {
				fmt.Printf("⚠️  Environment variable CONTROL_PLANE_URL=%s overriding config file value\n", controlPlaneURL)
			}
			cfg.ControlPlaneURL = controlPlaneURL
		}
	}
	if registrationKey := sharedconfig.GetEnv("REGISTRATION_KEY", ""); registrationKey != "" {
		if cfg.RegistrationKey != registrationKey {
			fmt.Printf("⚠️  Environment variable REGISTRATION_KEY overriding config file value\n")
		}
		cfg.RegistrationKey = registrationKey
	}
	if reportingInterval := getDurationEnv("REPORTING_INTERVAL", 0); reportingInterval > 0 {
		if cfg.ReportingInterval != reportingInterval {
			fmt.Printf("⚠️  Environment variable REPORTING_INTERVAL=%v overriding config file value\n", reportingInterval)
		}
		cfg.ReportingInterval = reportingInterval
	}
	if heartbeatInterval := getDurationEnv("HEARTBEAT_INTERVAL", 0); heartbeatInterval > 0 {
		cfg.HeartbeatInterval = heartbeatInterval
	}
	if dedupTTL := getIntEnv("DEDUP_TTL_MINUTES", 0); dedupTTL > 0 {
		cfg.Capture.DedupTTLMinutes = dedupTTL
	}
	if starttlsPorts := getIntSliceEnv("STARTTLS_PORTS", nil); len(starttlsPorts) > 0 {
		cfg.Capture.STARTTLSPorts = starttlsPorts
	}
	if v := os.Getenv("ENABLE_JA3"); v != "" {
		cfg.Capture.EnableJA3 = getBoolEnv("ENABLE_JA3", true)
	}
	if v := os.Getenv("ENABLE_STARTTLS"); v != "" {
		cfg.Capture.EnableSTARTTLS = getBoolEnv("ENABLE_STARTTLS", true)
	}
	if v := os.Getenv("ENABLE_QUIC_DECRYPT"); v != "" {
		cfg.Capture.EnableQUICDecrypt = getBoolEnv("ENABLE_QUIC_DECRYPT", true)
	}
	if v := os.Getenv("ENABLE_WIREGUARD"); v != "" {
		cfg.Capture.EnableWireGuard = getBoolEnv("ENABLE_WIREGUARD", true)
	}
	if v := os.Getenv("ENABLE_SMB"); v != "" {
		cfg.Capture.EnableSMB = getBoolEnv("ENABLE_SMB", true)
	}
	if v := os.Getenv("ENABLE_OPENVPN"); v != "" {
		cfg.Capture.EnableOpenVPN = getBoolEnv("ENABLE_OPENVPN", true)
	}
	if v := os.Getenv("ENABLE_KERBEROS"); v != "" {
		cfg.Capture.EnableKerberos = getBoolEnv("ENABLE_KERBEROS", true)
	}
	if v := os.Getenv("ENABLE_MODBUS"); v != "" {
		cfg.Capture.EnableModbus = getBoolEnv("ENABLE_MODBUS", true)
	}
	if v := os.Getenv("ENABLE_MMS"); v != "" {
		cfg.Capture.EnableMMS = getBoolEnv("ENABLE_MMS", true)
	}
	if v := os.Getenv("ENABLE_DNP3"); v != "" {
		cfg.Capture.EnableDNP3 = getBoolEnv("ENABLE_DNP3", true)
	}
	if v := os.Getenv("ENABLE_OPCUA"); v != "" {
		cfg.Capture.EnableOPCUA = getBoolEnv("ENABLE_OPCUA", true)
	}
	if v := os.Getenv("ENABLE_ENIP"); v != "" {
		cfg.Capture.EnableENIP = getBoolEnv("ENABLE_ENIP", true)
	}
	if v := os.Getenv("ENABLE_HARTIP"); v != "" {
		cfg.Capture.EnableHARTIP = getBoolEnv("ENABLE_HARTIP", true)
	}
	if v := os.Getenv("HOST_OBSERVATION"); v != "" {
		cfg.Capture.HostObservation = getBoolEnv("HOST_OBSERVATION", true)
	}
	if v := os.Getenv("HOST_OBSERVATION_WINDOW_SECONDS"); v != "" {
		cfg.Capture.HostObservationWindowSeconds = getIntEnv("HOST_OBSERVATION_WINDOW_SECONDS", 60)
	}
	if v := os.Getenv("HOST_OBSERVATION_DNS"); v != "" {
		cfg.Capture.HostObservationDNS = getBoolEnv("HOST_OBSERVATION_DNS", false)
	}
	// Local probe-consent values: in force only until the platform delivers
	// its own (see CaptureConfig.ThirdPartyTLSEnrichment).
	if v := os.Getenv("THIRD_PARTY_TLS_ENRICHMENT"); v != "" {
		cfg.Capture.ThirdPartyTLSEnrichment = getBoolEnv("THIRD_PARTY_TLS_ENRICHMENT", false)
	}
	if owned := getStringSliceEnv("OWNED_NETWORKS", nil); len(owned) > 0 {
		cfg.Capture.OwnedNetworks = owned
	}
	if dataPath := sharedconfig.GetEnv("DATA_PATH", ""); dataPath != "" {
		if cfg.Storage.DataPath != dataPath {
			fmt.Printf("⚠️  Environment variable DATA_PATH=%s overriding config file value\n", dataPath)
		}
		cfg.Storage.DataPath = dataPath
	}
	if interfaces := getStringSliceEnv("INTERFACES", nil); len(interfaces) > 0 {
		// Check if interfaces differ from config file
		interfacesMatch := len(cfg.Capture.Interfaces) == len(interfaces)
		if interfacesMatch {
			for i, iface := range interfaces {
				if i >= len(cfg.Capture.Interfaces) || cfg.Capture.Interfaces[i] != iface {
					interfacesMatch = false
					break
				}
			}
		}
		if !interfacesMatch {
			fmt.Printf("⚠️  Environment variable INTERFACES=%s overriding config file value %v\n",
				strings.Join(interfaces, ","), cfg.Capture.Interfaces)
		}
		cfg.Capture.Interfaces = interfaces
	}
	if interfaces := getStringSliceEnv("NETWORK_INTERFACES", nil); len(interfaces) > 0 {
		cfg.Network.Interfaces = interfaces
	}
	if ipAddr := sharedconfig.GetEnv("SENSOR_IP_ADDRESS", ""); ipAddr != "" {
		cfg.Network.IPAddress = ipAddr
		cfg.Network.ipAddressPinned = true
	}
	if testMode := getBoolEnv("TEST_MODE", false); testMode {
		if !cfg.TestMode {
			fmt.Printf("⚠️  Environment variable TEST_MODE=true overriding config file value\n")
		}
		cfg.TestMode = testMode
	}
	if v := boolEnvPtr("VERBOSE"); v != nil {
		cfg.Verbose = v
	}

	if cfg.Network.IPAddress == "" {
		cfg.Network.IPAddress = DetectPrimaryIPv4(cfg.ControlPlaneURL)
	} else {
		// Set from the config file (the env case is flagged above).
		cfg.Network.ipAddressPinned = true
	}
}

func shouldPreserveEnrolledControlPlaneURL(cfg *Config) bool {
	return cfg.ControlPlaneURL != "" &&
		cfg.Security.UseTLS &&
		(cfg.Security.ClientCert != "" || cfg.Security.ClientCertPath != "") &&
		(cfg.Security.ClientKey != "" || cfg.Security.ClientKeyPath != "")
}

// Load loads configuration from environment variables and defaults
// Environment variables override defaults
func Load() *Config {
	cfg := &Config{
		SensorID:          sharedconfig.GetEnv("SENSOR_ID", ""),
		TenantID:          sharedconfig.GetEnv("TENANT_ID", "default-tenant"),
		Name:              sharedconfig.GetEnv("SENSOR_NAME", "crypto-sensor"),
		Description:       sharedconfig.GetEnv("SENSOR_DESCRIPTION", "Vista Platform Network Sensor"),
		Platform:          sharedconfig.GetEnv("SENSOR_PLATFORM", "linux"),
		Version:           sharedconfig.GetEnv("SENSOR_VERSION", "dev"),
		Profile:           sharedconfig.GetEnv("SENSOR_PROFILE", "datacenter_host"),
		ControlPlaneURL:   sharedconfig.GetEnv("CONTROL_PLANE_URL", "http://localhost:8085"),
		RegistrationKey:   sharedconfig.GetEnv("REGISTRATION_KEY", ""),
		ReportingInterval: getDurationEnv("REPORTING_INTERVAL", 30*time.Second),
		HeartbeatInterval: getDurationEnv("HEARTBEAT_INTERVAL", 60*time.Second),
		BatchSize:         getIntEnv("BATCH_SIZE", 100),
		Storage: StorageConfig{
			DataPath: sharedconfig.GetEnv("DATA_PATH", getDefaultDataPath()),
		},
		Capture: CaptureConfig{
			Interfaces:                   getStringSliceEnv("INTERFACES", []string{"eth0"}),
			ActiveProbing:                getBoolEnv("ACTIVE_PROBING", true),
			ThirdPartyTLSEnrichment:      getBoolEnv("THIRD_PARTY_TLS_ENRICHMENT", false),
			OwnedNetworks:                getStringSliceEnv("OWNED_NETWORKS", nil),
			NetworkDiscovery:             getBoolEnv("NETWORK_DISCOVERY", true),
			MaxConnections:               getIntEnv("MAX_CONNECTIONS", 1000),
			TimeoutSeconds:               getIntEnv("TIMEOUT_SECONDS", 30),
			BufferSize:                   getIntEnv("BUFFER_SIZE", 1024*1024), // 1MB
			ExtraPortsToMonitor:          []int{},
			DeepScan:                     getBoolEnv("DEEP_SCAN", false),
			STARTTLSPorts:                getIntSliceEnv("STARTTLS_PORTS", []int{25, 143, 110, 5432, 3306, 21, 5222, 389}),
			EnableJA3:                    getBoolEnv("ENABLE_JA3", true),
			EnableSTARTTLS:               getBoolEnv("ENABLE_STARTTLS", true),
			EnableQUICDecrypt:            getBoolEnv("ENABLE_QUIC_DECRYPT", true),
			EnableWireGuard:              getBoolEnv("ENABLE_WIREGUARD", true),
			EnableSMB:                    getBoolEnv("ENABLE_SMB", true),
			EnableOpenVPN:                getBoolEnv("ENABLE_OPENVPN", true),
			EnableKerberos:               getBoolEnv("ENABLE_KERBEROS", true),
			EnableModbus:                 getBoolEnv("ENABLE_MODBUS", true),
			EnableMMS:                    getBoolEnv("ENABLE_MMS", true),
			EnableDNP3:                   getBoolEnv("ENABLE_DNP3", true),
			EnableOPCUA:                  getBoolEnv("ENABLE_OPCUA", true),
			EnableENIP:                   getBoolEnv("ENABLE_ENIP", true),
			EnableHARTIP:                 getBoolEnv("ENABLE_HARTIP", true),
			HostObservation:              getBoolEnv("HOST_OBSERVATION", true),
			HostObservationWindowSeconds: getIntEnv("HOST_OBSERVATION_WINDOW_SECONDS", 60),
			HostObservationDNS:           getBoolEnv("HOST_OBSERVATION_DNS", false),
		},
		Network: NetworkConfig{
			Interfaces: getStringSliceEnv("NETWORK_INTERFACES", []string{"eth0"}),
			VLANs:      getStringSliceEnv("VLANS", []string{}),
			Gateways:   getStringSliceEnv("GATEWAYS", []string{}),
			IPAddress:  sharedconfig.GetEnv("SENSOR_IP_ADDRESS", ""),
		},
		Security: SecurityConfig{
			ClientCert:   sharedconfig.GetEnv("CLIENT_CERT", ""),
			ClientKey:    sharedconfig.GetEnv("CLIENT_KEY", ""),
			ServerCACert: sharedconfig.GetEnv("SERVER_CA_CERT", ""),
			UseTLS:       getBoolEnv("USE_TLS", false),
		},
		Features: map[string]bool{
			"tls_analysis":         getBoolEnv("FEATURE_TLS_ANALYSIS", true),
			"ssh_analysis":         getBoolEnv("FEATURE_SSH_ANALYSIS", true),
			"certificate_analysis": getBoolEnv("FEATURE_CERTIFICATE_ANALYSIS", true),
			"active_probing":       getBoolEnv("FEATURE_ACTIVE_PROBING", true),
			"network_discovery":    getBoolEnv("FEATURE_NETWORK_DISCOVERY", true),
			"host_observation":     getBoolEnv("FEATURE_HOST_OBSERVATION", true),
			"air_gapped_export":    getBoolEnv("FEATURE_AIR_GAPPED_EXPORT", false),
		},
		TestMode: getBoolEnv("TEST_MODE", false),
		Verbose:  boolEnvPtr("VERBOSE"),
	}

	return cfg
}

// boolEnvPtr returns a pointer to the parsed boolean env var, or nil when the
// variable is unset — preserving the "said nothing" state that lets the
// command-line default stand.
func boolEnvPtr(key string) *bool {
	raw := sharedconfig.GetEnv(key, "")
	if raw == "" {
		return nil
	}
	v := strings.ToLower(raw) == "true" || raw == "1"
	return &v
}

// Helper functions for environment variable parsing

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// DetectPrimaryIPv4 returns this host's own IPv4 address as the platform should
// record it: the source address the kernel would use to reach controlPlaneURL.
// Delegates to shared/network so the sensor and the device agent cannot drift
// apart on what "this host's address" means.
func DetectPrimaryIPv4(controlPlaneURL string) string {
	return sharednetwork.PrimarySourceIPv4(controlPlaneURL)
}

func getStringSliceEnv(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		// Parse comma-separated values
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				result = append(result, part)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultValue
}

func getIntSliceEnv(key string, defaultValue []int) []int {
	if value := os.Getenv(key); value != "" {
		parts := strings.Split(value, ",")
		result := make([]int, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				if n, err := strconv.Atoi(part); err == nil {
					result = append(result, n)
				}
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultValue
}

// getDefaultDataPath returns the appropriate default data path for the current OS
func getDefaultDataPath() string {
	switch runtime.GOOS {
	case "windows":
		// Use user's AppData\Local directory on Windows
		if appData := os.Getenv("LOCALAPPDATA"); appData != "" {
			return filepath.Join(appData, "CryptoSensor")
		}
		// Fallback to current directory if LOCALAPPDATA is not set
		return "CryptoSensor"
	case "darwin":
		// Use user's Library/Application Support on macOS
		if home := os.Getenv("HOME"); home != "" {
			return filepath.Join(home, "Library", "Application Support", "CryptoSensor")
		}
		return "/tmp/crypto-sensor"
	default:
		// Linux and other Unix-like systems
		return "/var/lib/crypto-sensor"
	}
}

// getCertsPath returns the path to the certificates directory
func getCertsPath(dataPath string) string {
	return filepath.Join(dataPath, "certs")
}

// CertificateReadError is returned when a certificate, key or CA file named by
// the configuration exists but cannot be read (typically a permissions
// problem). Callers must not fall back to running without mTLS.
type CertificateReadError struct {
	Label string
	Path  string
	Err   error
}

func (e *CertificateReadError) Error() string {
	return fmt.Sprintf("cannot read %s %s: %v (is it readable by the user this process runs as?)", e.Label, e.Path, e.Err)
}

func (e *CertificateReadError) Unwrap() error { return e.Err }

// loadCertificatesFromFiles loads certificates from disk if file paths are set.
//
// A file that is missing is logged and skipped (the host is simply not
// enrolled yet, or its data directory was wiped). Any OTHER read error — a
// root-owned key read by the service user, an I/O error — is returned: the
// config says the material exists, and running on without it would silently
// drop mTLS and then try to re-register with a registration key that is
// already spent.
func loadCertificatesFromFiles(cfg *Config) error {
	read := func(label, path string, dst *string) error {
		if path == "" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				log.Printf("⚠️  %s %s does not exist; continuing without it", label, path)
				return nil
			}
			return &CertificateReadError{Label: label, Path: path, Err: err}
		}
		*dst = string(data)
		return nil
	}
	if err := read("client certificate", cfg.Security.ClientCertPath, &cfg.Security.ClientCert); err != nil {
		return err
	}
	if err := read("client private key", cfg.Security.ClientKeyPath, &cfg.Security.ClientKey); err != nil {
		return err
	}
	if err := read("server CA certificate", cfg.Security.ServerCACertPath, &cfg.Security.ServerCACert); err != nil {
		return err
	}

	if err := loadAgentSecret(cfg); err != nil {
		return err
	}

	// Enable TLS if we have certificates
	if cfg.Security.ClientCert != "" && cfg.Security.ClientKey != "" {
		cfg.Security.UseTLS = true
	}
	return nil
}

// loadAgentSecret reads the agent secret file the config names. A missing file
// is logged and skipped like the certificates; one that exists but cannot be
// read or parsed is an error. A previous secret past its window is dropped from
// the file here, so a replaced secret does not stay on disk after it stopped
// being honoured.
func loadAgentSecret(cfg *Config) error {
	path := cfg.Security.AgentSecretPath
	if path == "" {
		return nil
	}
	state, err := agentcreds.LoadSecretStateFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("⚠️  agent secret %s does not exist; continuing without it", path)
			return nil
		}
		return &CertificateReadError{Label: "agent secret", Path: path, Err: err}
	}
	if pruned, changed := state.Prune(time.Now()); changed {
		state = pruned
		if f, ferr := agentcreds.SecretStateFile(path, state); ferr == nil {
			if werr := atomicfile.WriteAll([]atomicfile.File{f}); werr != nil {
				log.Printf("⚠️  could not drop the expired previous agent secret from %s: %v", path, werr)
			}
		}
	}
	cfg.SetAgentSecretState(state)
	return nil
}

// SaveCertificatesToFiles saves certificates to disk and updates config with file paths
func SaveCertificatesToFiles(cfg *Config, clientCert, clientKey, serverCACert string) error {
	certsDir := getCertsPath(cfg.Storage.DataPath)

	// Create certs directory with secure permissions
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		return fmt.Errorf("failed to create certs directory: %w", err)
	}

	// Define file paths
	clientCertPath := filepath.Join(certsDir, "client.crt")
	clientKeyPath := filepath.Join(certsDir, "client.key")
	serverCACertPath := filepath.Join(certsDir, "ca.crt")

	// Write every file as one unit (temp files, then renames) so a crash or a
	// failure part-way never leaves a certificate that does not match its key.
	var files []atomicfile.File
	if clientCert != "" {
		files = append(files, atomicfile.File{Path: clientCertPath, Data: []byte(clientCert), Perm: 0o644})
	}
	// The private key is owner read/write only.
	if clientKey != "" {
		files = append(files, atomicfile.File{Path: clientKeyPath, Data: []byte(clientKey), Perm: 0o600})
	}
	if serverCACert != "" {
		files = append(files, atomicfile.File{Path: serverCACertPath, Data: []byte(serverCACert), Perm: 0o644})
	}
	// The agent secret goes in the SAME unit as the certificate: a
	// rotation replaces both or neither.
	agentSecretPath := filepath.Join(certsDir, agentcreds.SecretFileName)
	haveSecret := false
	if state := cfg.AgentSecretState(); !state.IsZero() {
		state, _ = state.Prune(time.Now()) // never write a replaced secret back to disk after its window
		f, err := agentcreds.SecretStateFile(agentSecretPath, state)
		if err != nil {
			return fmt.Errorf("failed to encode agent secret: %w", err)
		}
		files = append(files, f)
		haveSecret = true
	}
	if err := atomicfile.WriteAll(files); err != nil {
		return fmt.Errorf("failed to write certificates: %w", err)
	}
	if clientCert != "" {
		cfg.Security.ClientCert = clientCert
		cfg.Security.ClientCertPath = clientCertPath
	}
	if clientKey != "" {
		cfg.Security.ClientKey = clientKey
		cfg.Security.ClientKeyPath = clientKeyPath
	}
	if serverCACert != "" {
		cfg.Security.ServerCACert = serverCACert
		cfg.Security.ServerCACertPath = serverCACertPath
	}

	if haveSecret {
		cfg.Security.AgentSecretPath = agentSecretPath
	}

	// Enable TLS now that we have certificates
	cfg.Security.UseTLS = true

	return nil
}
