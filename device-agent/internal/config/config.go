package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"gopkg.in/yaml.v3"
)

// DefaultHeartbeatInterval is the agent's liveness cadence. It must stay well
// inside the 15-minute dwell window the platform's discovery_agent_offline
// detector uses, with room for several consecutive failures.
const DefaultHeartbeatInterval = 60 * time.Second

// Config holds all configuration for the device agent
type Config struct {
	PlatformURL       string        `yaml:"platform_url" env:"PLATFORM_URL"`
	AgentID           string        `yaml:"agent_id" env:"AGENT_ID"`
	RegistrationKey   string        `yaml:"registration_key" env:"REGISTRATION_KEY"`
	PollInterval      time.Duration `yaml:"poll_interval" env:"POLL_INTERVAL"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval" env:"HEARTBEAT_INTERVAL"`
	DataPath          string        `yaml:"data_path" env:"DATA_PATH"` // Path for storing data and certificates
	// Verbose is the config-file override for log verbosity. Verbose logging is
	// the command-line default, so this is three-state: nil means "the config
	// says nothing, leave the default alone", and only an explicit `verbose:`
	// key (or the VERBOSE env var) turns it off or pins it on.
	Verbose  *bool          `yaml:"verbose" env:"VERBOSE"`
	Security SecurityConfig `yaml:"security"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	ClientCert       string `yaml:"client_cert" env:"CLIENT_CERT"`                 // PEM-encoded certificate (or file content)
	ClientKey        string `yaml:"client_key" env:"CLIENT_KEY"`                   // PEM-encoded private key (or file content)
	ServerCACert     string `yaml:"server_ca_cert" env:"SERVER_CA_CERT"`           // PEM-encoded CA certificate (or file content)
	ClientCertPath   string `yaml:"client_cert_path" env:"CLIENT_CERT_PATH"`       // Path to certificate file on disk
	ClientKeyPath    string `yaml:"client_key_path" env:"CLIENT_KEY_PATH"`         // Path to private key file on disk
	ServerCACertPath string `yaml:"server_ca_cert_path" env:"SERVER_CA_CERT_PATH"` // Path to CA certificate file on disk
	UseTLS           bool   `yaml:"use_tls" env:"USE_TLS"`
}

// Load loads configuration from environment variables
func Load() *Config {
	cfg := &Config{
		PlatformURL:     sharedconfig.GetEnv("PLATFORM_URL", "http://localhost:8080"),
		AgentID:         sharedconfig.GetEnv("AGENT_ID", ""),
		RegistrationKey: sharedconfig.GetEnv("REGISTRATION_KEY", ""),
		DataPath:        sharedconfig.GetEnv("DATA_PATH", getDefaultDataPath()),
		Verbose:         boolEnvPtr("VERBOSE"),
		Security: SecurityConfig{
			ClientCert:   sharedconfig.GetEnv("CLIENT_CERT", ""),
			ClientKey:    sharedconfig.GetEnv("CLIENT_KEY", ""),
			ServerCACert: sharedconfig.GetEnv("SERVER_CA_CERT", ""),
			UseTLS:       sharedconfig.GetEnvAsBool("USE_TLS", false),
		},
	}

	// Parse poll interval
	pollIntervalStr := sharedconfig.GetEnv("POLL_INTERVAL", "30s")
	if interval, err := time.ParseDuration(pollIntervalStr); err == nil {
		cfg.PollInterval = interval
	} else {
		cfg.PollInterval = 30 * time.Second
	}

	cfg.HeartbeatInterval = parseHeartbeatInterval(sharedconfig.GetEnv("HEARTBEAT_INTERVAL", ""))

	return cfg
}

// boolEnvPtr returns a pointer to the parsed boolean env var, or nil when the
// variable is unset — preserving the "said nothing" state that lets the
// command-line default stand.
func boolEnvPtr(key string) *bool {
	if sharedconfig.GetEnv(key, "") == "" {
		return nil
	}
	v := sharedconfig.GetEnvAsBool(key, false)
	return &v
}

// parseHeartbeatInterval turns a duration string into a usable interval,
// falling back to the default for empty, unparseable or non-positive input. A
// zero interval would panic time.NewTicker, and a negative one is meaningless.
func parseHeartbeatInterval(s string) time.Duration {
	if s == "" {
		return DefaultHeartbeatInterval
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		log.Printf("⚠️  Invalid HEARTBEAT_INTERVAL %q — using %s", s, DefaultHeartbeatInterval)
		return DefaultHeartbeatInterval
	}
	return d
}

// LoadFromFile loads configuration from a YAML file
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Apply defaults for missing values
	if cfg.DataPath == "" {
		cfg.DataPath = getDefaultDataPath()
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = DefaultHeartbeatInterval
	}

	// Override with environment variables if set. Once the agent has enrolled,
	// the saved mTLS endpoint is identity state; a stale bootstrap env URL must
	// not send post-registration traffic back through the edge proxy.
	if platformURL := os.Getenv("PLATFORM_URL"); platformURL != "" {
		switch {
		case os.Getenv("PLATFORM_URL_OVERRIDE") == "1":
			// Explicit escape hatch. PLATFORM_URL is a documented knob
			// (docsv4/core/operate/deployment/device-agent-deployment.md), so an
			// operator deliberately repointing an enrolled agent must have a
			// supported way to do it rather than having to delete config.
			log.Printf("PLATFORM_URL_OVERRIDE=1 — repointing an enrolled agent to %s; its mTLS client cert is bound to the previous endpoint and will likely fail until re-enrolled", platformURL)
			cfg.PlatformURL = platformURL
		case shouldPreserveEnrolledPlatformURL(&cfg):
			// Never silently: an operator who set PLATFORM_URL and sees it
			// ignored has no way to tell what happened. The sensor logs the
			// equivalent; this is the matching breadcrumb.
			log.Printf("ignoring PLATFORM_URL=%s because this agent is enrolled with mTLS and its saved endpoint %s is bound to its client certificate; set PLATFORM_URL_OVERRIDE=1 to force", platformURL, cfg.PlatformURL)
		default:
			cfg.PlatformURL = platformURL
		}
	}
	if agentID := os.Getenv("AGENT_ID"); agentID != "" {
		cfg.AgentID = agentID
	}
	if regKey := os.Getenv("REGISTRATION_KEY"); regKey != "" {
		cfg.RegistrationKey = regKey
	}
	if hb := os.Getenv("HEARTBEAT_INTERVAL"); hb != "" {
		cfg.HeartbeatInterval = parseHeartbeatInterval(hb)
	}
	if dataPath := os.Getenv("DATA_PATH"); dataPath != "" {
		cfg.DataPath = dataPath
	}
	if v := boolEnvPtr("VERBOSE"); v != nil {
		cfg.Verbose = v
	}

	// Load certificates from files if paths are set
	loadCertificatesFromFiles(&cfg)

	return &cfg, nil
}

func shouldPreserveEnrolledPlatformURL(cfg *Config) bool {
	return cfg.PlatformURL != "" &&
		cfg.Security.UseTLS &&
		(cfg.Security.ClientCert != "" || cfg.Security.ClientCertPath != "") &&
		(cfg.Security.ClientKey != "" || cfg.Security.ClientKeyPath != "")
}

// getDefaultDataPath returns the appropriate default data path for the current OS
func getDefaultDataPath() string {
	switch runtime.GOOS {
	case "windows":
		// Use user's AppData\Local directory on Windows
		if appData := os.Getenv("LOCALAPPDATA"); appData != "" {
			return filepath.Join(appData, "CryptoDeviceAgent")
		}
		// Fallback to current directory if LOCALAPPDATA is not set
		return "CryptoDeviceAgent"
	case "darwin":
		// Use user's Library/Application Support on macOS
		if home := os.Getenv("HOME"); home != "" {
			return filepath.Join(home, "Library", "Application Support", "CryptoDeviceAgent")
		}
		return "/tmp/crypto-device-agent"
	default:
		// Linux and other Unix-like systems
		return "/var/lib/crypto-device-agent"
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
func SaveCertificatesToFiles(cfg *Config, clientCert, clientKey, serverCACert string, dataPath string) error {
	certsDir := getCertsPath(dataPath)

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
