package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
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
}

// StorageConfig represents storage configuration
type StorageConfig struct {
	MaxStorageSize int64  `json:"max_storage_size"` // bytes
	RotationSize   int64  `json:"rotation_size"`    // bytes
	RetentionDays  int    `json:"retention_days"`
	DataPath       string `json:"data_path"`
	EncryptionKey  string `json:"encryption_key"`
	// KeyPath is where the AES encryption key file is stored.
	// Deliberately separate from DataPath so an attacker who
	// exfiltrates the discovery data directory does not automatically
	// obtain the key.  Defaults to an OS-appropriate state directory.
	KeyPath           string `json:"key_path"`
	MinFreeSpaceMB    int64  `json:"min_free_space_mb"`  // Minimum free disk space in MB before refusing writes
	EnableCompression bool   `json:"enable_compression"` // Gzip compress before encrypting
}

// CaptureConfig represents packet capture configuration
type CaptureConfig struct {
	Interfaces       []string `json:"interfaces"`
	ActiveProbing    bool     `json:"active_probing"`
	NetworkDiscovery bool     `json:"network_discovery"`
	MaxConnections   int      `json:"max_connections"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	BufferSize       int      `json:"buffer_size"`
	// ExtraPortsToMonitor extends the default BPF port list.
	// Useful for non-standard TLS ports (e.g. 8443, 9443).
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
}

// NetworkConfig represents network configuration
type NetworkConfig struct {
	Interfaces []string `json:"interfaces"`
	VLANs      []string `json:"vlans"`
	Gateways   []string `json:"gateways"`
	IPAddress  string   `json:"ip_address"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	ClientCert       string `json:"client_cert"`         // PEM-encoded certificate (or file content)
	ClientKey        string `json:"client_key"`          // PEM-encoded private key (or file content)
	ServerCACert     string `json:"server_ca_cert"`      // PEM-encoded CA certificate (or file content)
	ClientCertPath   string `json:"client_cert_path"`    // Path to certificate file on disk
	ClientKeyPath    string `json:"client_key_path"`     // Path to private key file on disk
	ServerCACertPath string `json:"server_ca_cert_path"` // Path to CA certificate file on disk
	UseTLS           bool   `json:"use_tls"`
}

// ConfigFile represents the YAML config file structure
type ConfigFile struct {
	SensorID              string `yaml:"sensorId"`
	ControlPlaneURL       string `yaml:"controlPlaneUrl"`
	RegistrationKey       string `yaml:"registrationKey"`
	ReportingIntervalSecs int    `yaml:"reportingIntervalSeconds"`
	HeartbeatIntervalSecs int    `yaml:"heartbeatIntervalSeconds"`
	Storage               struct {
		MaxStorageSize    int64  `yaml:"maxStorageSize"`
		RotationSize      int64  `yaml:"rotationSize"`
		RetentionDays     int    `yaml:"retentionDays"`
		DataPath          string `yaml:"dataPath"`
		EncryptionKey     string `yaml:"encryptionKey"`
		KeyPath           string `yaml:"keyPath"`
		MinFreeSpaceMB    int64  `yaml:"minFreeSpaceMB"`
		EnableCompression bool   `yaml:"enableCompression"`
	} `yaml:"storage"`
	Capture struct {
		Interfaces          []string `yaml:"interfaces"`
		ActiveProbing       bool     `yaml:"activeProbing"`
		NetworkDiscovery    bool     `yaml:"networkDiscovery"`
		MaxConnections      int      `yaml:"maxConnections"`
		TimeoutSeconds      int      `yaml:"timeoutSeconds"`
		BufferSize          int      `yaml:"bufferSize"`
		ExtraPortsToMonitor []int    `yaml:"extraPortsToMonitor"`
		DeepScan            bool     `yaml:"deepScan"`
		DedupTTLMinutes     int      `yaml:"dedupTTLMinutes"`
		STARTTLSPorts       []int    `yaml:"starttlsPorts"`
		EnableJA3           *bool    `yaml:"enableJA3"`
		EnableSTARTTLS      *bool    `yaml:"enableSTARTTLS"`
		EnableQUICDecrypt   *bool    `yaml:"enableQUICDecrypt"`
		EnableWireGuard     *bool    `yaml:"enableWireGuard"`
		EnableSMB           *bool    `yaml:"enableSMB"`
		EnableOpenVPN       *bool    `yaml:"enableOpenVPN"`
		EnableKerberos      *bool    `yaml:"enableKerberos"`
		EnableModbus        *bool    `yaml:"enableModbus"`
		EnableMMS           *bool    `yaml:"enableMMS"`
		EnableDNP3          *bool    `yaml:"enableDNP3"`
		EnableOPCUA         *bool    `yaml:"enableOPCUA"`
		EnableENIP          *bool    `yaml:"enableENIP"`
		EnableHARTIP        *bool    `yaml:"enableHARTIP"`
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
		UseTLS           bool   `yaml:"useTLS"`
	} `yaml:"security"`
	TestMode bool `yaml:"testMode"`
}

// LoadFromFile loads configuration from a YAML file and merges with environment variables
// Environment variables override config file values
func LoadFromFile(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Debug: Show first 500 chars of YAML file
	preview := string(data)
	if len(preview) > 500 {
		preview = preview[:500] + "..."
	}
	fmt.Printf("🔍 Reading config file (first 500 chars):\n%s\n", preview)

	var cfgFile ConfigFile
	if err := yaml.Unmarshal(data, &cfgFile); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Debug: Log what was parsed from the file (using fmt.Printf for immediate output)
	fmt.Printf("🔍 Parsed from config file:\n")
	fmt.Printf("  controlPlaneUrl: %q\n", cfgFile.ControlPlaneURL)
	fmt.Printf("  sensorId: %q\n", cfgFile.SensorID)
	if cfgFile.RegistrationKey != "" {
		fmt.Printf("  registrationKey: (set, %d chars)\n", len(cfgFile.RegistrationKey))
	} else {
		fmt.Printf("  registrationKey: (empty)\n")
	}
	fmt.Printf("  interfaces: %v\n", cfgFile.Capture.Interfaces)
	fmt.Printf("  dataPath: %q\n", cfgFile.Storage.DataPath)

	// Convert ConfigFile to Config, using config file values as base
	cfg := &Config{
		SensorID:          cfgFile.SensorID,
		ControlPlaneURL:   cfgFile.ControlPlaneURL,
		RegistrationKey:   cfgFile.RegistrationKey,
		ReportingInterval: time.Duration(cfgFile.ReportingIntervalSecs) * time.Second,
		HeartbeatInterval: time.Duration(cfgFile.HeartbeatIntervalSecs) * time.Second,
		Storage: StorageConfig{
			MaxStorageSize:    cfgFile.Storage.MaxStorageSize,
			RotationSize:      cfgFile.Storage.RotationSize,
			RetentionDays:     cfgFile.Storage.RetentionDays,
			DataPath:          cfgFile.Storage.DataPath,
			EncryptionKey:     cfgFile.Storage.EncryptionKey,
			KeyPath:           cfgFile.Storage.KeyPath,
			MinFreeSpaceMB:    cfgFile.Storage.MinFreeSpaceMB,
			EnableCompression: cfgFile.Storage.EnableCompression,
		},
		Capture: CaptureConfig{
			Interfaces:          cfgFile.Capture.Interfaces,
			ActiveProbing:       cfgFile.Capture.ActiveProbing,
			NetworkDiscovery:    cfgFile.Capture.NetworkDiscovery,
			MaxConnections:      cfgFile.Capture.MaxConnections,
			TimeoutSeconds:      cfgFile.Capture.TimeoutSeconds,
			BufferSize:          cfgFile.Capture.BufferSize,
			ExtraPortsToMonitor: cfgFile.Capture.ExtraPortsToMonitor,
			DeepScan:            cfgFile.Capture.DeepScan,
			DedupTTLMinutes:     cfgFile.Capture.DedupTTLMinutes,
			STARTTLSPorts:       cfgFile.Capture.STARTTLSPorts,
			EnableJA3:           cfgFile.Capture.EnableJA3 == nil || *cfgFile.Capture.EnableJA3,
			EnableSTARTTLS:      cfgFile.Capture.EnableSTARTTLS == nil || *cfgFile.Capture.EnableSTARTTLS,
			EnableQUICDecrypt:   cfgFile.Capture.EnableQUICDecrypt == nil || *cfgFile.Capture.EnableQUICDecrypt,
			EnableWireGuard:     cfgFile.Capture.EnableWireGuard == nil || *cfgFile.Capture.EnableWireGuard,
			EnableSMB:           cfgFile.Capture.EnableSMB == nil || *cfgFile.Capture.EnableSMB,
			EnableOpenVPN:       cfgFile.Capture.EnableOpenVPN == nil || *cfgFile.Capture.EnableOpenVPN,
			EnableKerberos:      cfgFile.Capture.EnableKerberos == nil || *cfgFile.Capture.EnableKerberos,
			EnableModbus:        cfgFile.Capture.EnableModbus == nil || *cfgFile.Capture.EnableModbus,
			EnableMMS:           cfgFile.Capture.EnableMMS == nil || *cfgFile.Capture.EnableMMS,
			EnableDNP3:          cfgFile.Capture.EnableDNP3 == nil || *cfgFile.Capture.EnableDNP3,
			EnableOPCUA:         cfgFile.Capture.EnableOPCUA == nil || *cfgFile.Capture.EnableOPCUA,
			EnableENIP:          cfgFile.Capture.EnableENIP == nil || *cfgFile.Capture.EnableENIP,
			EnableHARTIP:        cfgFile.Capture.EnableHARTIP == nil || *cfgFile.Capture.EnableHARTIP,
		},
		Security: SecurityConfig{
			ClientCert:       cfgFile.Security.ClientCert,
			ClientKey:        cfgFile.Security.ClientKey,
			ServerCACert:     cfgFile.Security.ServerCACert,
			ClientCertPath:   cfgFile.Security.ClientCertPath,
			ClientKeyPath:    cfgFile.Security.ClientKeyPath,
			ServerCACertPath: cfgFile.Security.ServerCACertPath,
			UseTLS:           cfgFile.Security.UseTLS,
		},
		TestMode: cfgFile.TestMode,
	}

	// Apply defaults for missing values
	if cfg.Storage.DataPath == "" {
		cfg.Storage.DataPath = getDefaultDataPath()
	}
	if cfg.Storage.KeyPath == "" {
		cfg.Storage.KeyPath = getDefaultKeyPath()
	}
	if cfg.Storage.MinFreeSpaceMB == 0 {
		cfg.Storage.MinFreeSpaceMB = 100
	}
	if cfg.ReportingInterval == 0 {
		cfg.ReportingInterval = 30 * time.Second
	}
	if cfg.HeartbeatInterval == 0 {
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
		cfg.Description = "VistaPlatform Network Sensor"
	}

	// Merge with environment variables (env vars override config file)
	mergeEnvVars(cfg)

	// Load certificates from files if paths are set
	loadCertificatesFromFiles(cfg)

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
	if dataPath := sharedconfig.GetEnv("DATA_PATH", ""); dataPath != "" {
		if cfg.Storage.DataPath != dataPath {
			fmt.Printf("⚠️  Environment variable DATA_PATH=%s overriding config file value\n", dataPath)
		}
		cfg.Storage.DataPath = dataPath
	}
	if interfaces := getStringSliceEnv("INTERFACES", nil); interfaces != nil && len(interfaces) > 0 {
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
	if interfaces := getStringSliceEnv("NETWORK_INTERFACES", nil); interfaces != nil && len(interfaces) > 0 {
		cfg.Network.Interfaces = interfaces
	}
	if ipAddr := sharedconfig.GetEnv("SENSOR_IP_ADDRESS", ""); ipAddr != "" {
		cfg.Network.IPAddress = ipAddr
	}
	if testMode := getBoolEnv("TEST_MODE", false); testMode {
		if !cfg.TestMode {
			fmt.Printf("⚠️  Environment variable TEST_MODE=true overriding config file value\n")
		}
		cfg.TestMode = testMode
	}

	if cfg.Network.IPAddress == "" {
		cfg.Network.IPAddress = detectPrimaryIPv4()
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
		Description:       sharedconfig.GetEnv("SENSOR_DESCRIPTION", "VistaPlatform Network Sensor"),
		Platform:          sharedconfig.GetEnv("SENSOR_PLATFORM", "linux"),
		Version:           sharedconfig.GetEnv("SENSOR_VERSION", "dev"),
		Profile:           sharedconfig.GetEnv("SENSOR_PROFILE", "datacenter_host"),
		ControlPlaneURL:   sharedconfig.GetEnv("CONTROL_PLANE_URL", "http://localhost:8085"),
		RegistrationKey:   sharedconfig.GetEnv("REGISTRATION_KEY", ""),
		ReportingInterval: getDurationEnv("REPORTING_INTERVAL", 30*time.Second),
		HeartbeatInterval: getDurationEnv("HEARTBEAT_INTERVAL", 60*time.Second),
		BatchSize:         getIntEnv("BATCH_SIZE", 100),
		Storage: StorageConfig{
			MaxStorageSize:    getInt64Env("MAX_STORAGE_SIZE", 100*1024*1024), // 100MB
			RotationSize:      getInt64Env("ROTATION_SIZE", 10*1024*1024),     // 10MB
			RetentionDays:     getIntEnv("RETENTION_DAYS", 7),
			DataPath:          sharedconfig.GetEnv("DATA_PATH", getDefaultDataPath()),
			EncryptionKey:     sharedconfig.GetEnv("ENCRYPTION_KEY", ""),
			KeyPath:           sharedconfig.GetEnv("KEY_PATH", getDefaultKeyPath()),
			MinFreeSpaceMB:    getInt64Env("MIN_FREE_SPACE_MB", 100), // 100 MB
			EnableCompression: getBoolEnv("ENABLE_COMPRESSION", true),
		},
		Capture: CaptureConfig{
			Interfaces:          getStringSliceEnv("INTERFACES", []string{"eth0"}),
			ActiveProbing:       getBoolEnv("ACTIVE_PROBING", true),
			NetworkDiscovery:    getBoolEnv("NETWORK_DISCOVERY", true),
			MaxConnections:      getIntEnv("MAX_CONNECTIONS", 1000),
			TimeoutSeconds:      getIntEnv("TIMEOUT_SECONDS", 30),
			BufferSize:          getIntEnv("BUFFER_SIZE", 1024*1024), // 1MB
			ExtraPortsToMonitor: []int{},
			DeepScan:            getBoolEnv("DEEP_SCAN", false),
			STARTTLSPorts:       getIntSliceEnv("STARTTLS_PORTS", []int{25, 143, 110, 5432, 3306, 21, 5222, 389}),
			EnableJA3:           getBoolEnv("ENABLE_JA3", true),
			EnableSTARTTLS:      getBoolEnv("ENABLE_STARTTLS", true),
			EnableQUICDecrypt:   getBoolEnv("ENABLE_QUIC_DECRYPT", true),
			EnableWireGuard:     getBoolEnv("ENABLE_WIREGUARD", true),
			EnableSMB:           getBoolEnv("ENABLE_SMB", true),
			EnableOpenVPN:       getBoolEnv("ENABLE_OPENVPN", true),
			EnableKerberos:      getBoolEnv("ENABLE_KERBEROS", true),
			EnableModbus:        getBoolEnv("ENABLE_MODBUS", true),
			EnableMMS:           getBoolEnv("ENABLE_MMS", true),
			EnableDNP3:          getBoolEnv("ENABLE_DNP3", true),
			EnableOPCUA:         getBoolEnv("ENABLE_OPCUA", true),
			EnableENIP:          getBoolEnv("ENABLE_ENIP", true),
			EnableHARTIP:        getBoolEnv("ENABLE_HARTIP", true),
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
			"air_gapped_export":    getBoolEnv("FEATURE_AIR_GAPPED_EXPORT", false),
		},
		TestMode: getBoolEnv("TEST_MODE", false),
	}

	return cfg
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

func getInt64Env(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
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

func detectPrimaryIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipv4 := ipNet.IP.To4(); ipv4 != nil {
				return ipv4.String()
			}
		}
	}

	return ""
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

// getDefaultKeyPath returns the OS-appropriate directory for the encryption key file.
// Deliberately separate from the data directory so discovery ciphertext and key
// are not co-located.
func getDefaultKeyPath() string {
	switch runtime.GOOS {
	case "windows":
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "CryptoSensor")
		}
		return "CryptoSensorKeys"
	case "darwin":
		if home := os.Getenv("HOME"); home != "" {
			return filepath.Join(home, "Library", "Application Support", "CryptoSensorKeys")
		}
		return "/tmp/crypto-sensor-keys"
	default:
		// XDG_STATE_HOME preferred; fall back to ~/.local/state
		if stateHome := os.Getenv("XDG_STATE_HOME"); stateHome != "" {
			return filepath.Join(stateHome, "crypto-sensor")
		}
		if home := os.Getenv("HOME"); home != "" {
			return filepath.Join(home, ".local", "state", "crypto-sensor")
		}
		return "/var/lib/crypto-sensor-keys"
	}
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

// loadCertificatesFromFiles loads certificates from disk if file paths are set
func loadCertificatesFromFiles(cfg *Config) {
	// If certificate paths are set, load from files
	if cfg.Security.ClientCertPath != "" {
		if certData, err := os.ReadFile(cfg.Security.ClientCertPath); err == nil {
			cfg.Security.ClientCert = string(certData)
		}
	}
	if cfg.Security.ClientKeyPath != "" {
		if keyData, err := os.ReadFile(cfg.Security.ClientKeyPath); err == nil {
			cfg.Security.ClientKey = string(keyData)
		}
	}
	if cfg.Security.ServerCACertPath != "" {
		if caData, err := os.ReadFile(cfg.Security.ServerCACertPath); err == nil {
			cfg.Security.ServerCACert = string(caData)
		}
	}

	// Enable TLS if we have certificates
	if cfg.Security.ClientCert != "" && cfg.Security.ClientKey != "" {
		cfg.Security.UseTLS = true
	}
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

	// Save client certificate
	if clientCert != "" {
		if err := os.WriteFile(clientCertPath, []byte(clientCert), 0644); err != nil {
			return fmt.Errorf("failed to write client certificate: %w", err)
		}
		cfg.Security.ClientCert = clientCert
		cfg.Security.ClientCertPath = clientCertPath
	}

	// Save private key with restricted permissions (0600 - owner read/write only)
	if clientKey != "" {
		if err := os.WriteFile(clientKeyPath, []byte(clientKey), 0600); err != nil {
			return fmt.Errorf("failed to write client key: %w", err)
		}
		cfg.Security.ClientKey = clientKey
		cfg.Security.ClientKeyPath = clientKeyPath
	}

	// Save CA certificate
	if serverCACert != "" {
		if err := os.WriteFile(serverCACertPath, []byte(serverCACert), 0644); err != nil {
			return fmt.Errorf("failed to write server CA certificate: %w", err)
		}
		cfg.Security.ServerCACert = serverCACert
		cfg.Security.ServerCACertPath = serverCACertPath
	}

	// Enable TLS now that we have certificates
	cfg.Security.UseTLS = true

	return nil
}
