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
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
	"github.com/vistasecurity/vistaplatform/shared/atomicfile"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"gopkg.in/yaml.v3"
)

// DefaultHeartbeatInterval is the agent's liveness cadence. It must stay well
// inside the 15-minute dwell window the platform's discovery_agent_offline
// detector uses, with room for several consecutive failures.
const DefaultHeartbeatInterval = 60 * time.Second

// Local host-inventory cadence (asset-inventory ADR-0004 D3).
const (
	// DefaultHostInventoryInterval is how often an agent re-describes the host
	// it runs on. A day, because the things it collects — the OS release, the
	// package list, the hardware serial — change on the scale of a patch
	// window, and because the collection walks the whole package database.
	DefaultHostInventoryInterval = 24 * time.Hour
	// MinHostInventoryInterval is the floor. An operator who asks for a
	// one-minute interval gets an hour, with a log line saying so: a package
	// enumeration every minute is a self-inflicted denial of service on the
	// customer's own host, and silently honouring it would be worse than
	// silently ignoring it.
	MinHostInventoryInterval = 1 * time.Hour
)

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
	Verbose *bool `yaml:"verbose" env:"VERBOSE"`
	// HostInventoryEnabled turns on the LOCAL host-inventory schedule — the
	// agent describing the machine it is installed on. Off by default: an
	// agent installed to interrogate network devices should not start
	// enumerating its own host's software because it was upgraded.
	HostInventoryEnabled bool `yaml:"host_inventory_enabled" env:"HOST_INVENTORY_ENABLED"`
	// HostInventoryConnectionsEnabled opts this agent into collecting bounded
	// remote peer data. It is separate because connection history is more
	// privacy-sensitive than OS/package/listener posture.
	HostInventoryConnectionsEnabled bool `yaml:"host_inventory_connections_enabled" env:"HOST_INVENTORY_CONNECTIONS_ENABLED"`
	// HostInventoryInterval is the local collection cadence. Below
	// MinHostInventoryInterval it is raised to the floor, with a log line.
	HostInventoryInterval time.Duration  `yaml:"host_inventory_interval" env:"HOST_INVENTORY_INTERVAL"`
	Security              SecurityConfig `yaml:"security"`

	// RegistrationKeySHA256 is the SHA-256 (hex) of the registration key this
	// agent enrolled with, written in its place once the key is no longer kept
	//. The key is single-use and spent at enrolment; the installer needs
	// only to recognise "this host already enrolled with this key", which a hash
	// answers without keeping the key on disk.
	RegistrationKeySHA256 string `yaml:"registration_key_sha256,omitempty"`

	// agentSecrets is the per-agent secret (and, for a rotation window, the one
	// it replaced) the platform seals job credentials under. It lives in
	// Security.AgentSecretPath, not in the YAML. Reached only through the
	// methods below, which hold agentSecretsMu: the rotation goroutine writes it
	// while job goroutines read it.
	agentSecrets agentcreds.SecretState
}

// agentSecretsMu guards every Config's agentSecrets. Package-level rather than a
// field so a Config stays a plain copyable value, as the rest of the code and
// its tests treat it.
var agentSecretsMu sync.RWMutex

// AgentSecretState returns a snapshot of the agent's secrets.
func (c *Config) AgentSecretState() agentcreds.SecretState {
	agentSecretsMu.RLock()
	defer agentSecretsMu.RUnlock()
	return c.agentSecrets
}

// SetAgentSecretState replaces the agent's secrets (loading them from disk).
func (c *Config) SetAgentSecretState(s agentcreds.SecretState) {
	agentSecretsMu.Lock()
	c.agentSecrets = s
	agentSecretsMu.Unlock()
}

// SetEnrolledAgentSecret records the secret issued at enrolment. Nothing was
// ever sealed under the registration key for an agent that enrols with a secret,
// so there is no previous secret to honour.
func (c *Config) SetEnrolledAgentSecret(secret string, version int) {
	c.SetAgentSecretState(agentcreds.SecretState{Secret: secret, Version: version})
}

// RotateAgentSecret records the secret issued at a certificate rotation. The
// one it replaces — or, for an agent that held none, its registration key —
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

// CredentialSecrets lists the secrets a job's credential envelope may be sealed
// under, in the order to try them: the agent secret (and the one it replaced,
// for agentcreds.PreviousSecretWindow after a rotation), or — for an agent that
// has not rotated since before agent secrets existed — its registration key.
func (c *Config) CredentialSecrets() []string {
	return c.AgentSecretState().Candidates(c.RegistrationKey, time.Now())
}

// RegistrationKeyRetained reports whether the registration key still has to be
// written to the config file: only while no agent secret is safely on disk.
func (c *Config) RegistrationKeyRetained() bool {
	return c.Security.AgentSecretPath == "" || c.AgentSecretState().IsZero()
}

// RegistrationKeyFingerprint is the value written to registration_key_sha256:
// the stored hash, or the hash of the key held in memory.
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

// SecurityConfig represents security configuration
type SecurityConfig struct {
	ClientCert       string `yaml:"client_cert" env:"CLIENT_CERT"`                 // PEM-encoded certificate (or file content)
	ClientKey        string `yaml:"client_key" env:"CLIENT_KEY"`                   // PEM-encoded private key (or file content)
	ServerCACert     string `yaml:"server_ca_cert" env:"SERVER_CA_CERT"`           // PEM-encoded CA certificate (or file content)
	ClientCertPath   string `yaml:"client_cert_path" env:"CLIENT_CERT_PATH"`       // Path to certificate file on disk
	ClientKeyPath    string `yaml:"client_key_path" env:"CLIENT_KEY_PATH"`         // Path to private key file on disk
	ServerCACertPath string `yaml:"server_ca_cert_path" env:"SERVER_CA_CERT_PATH"` // Path to CA certificate file on disk
	// AgentSecretPath is the 0600 file holding the per-agent secret.
	AgentSecretPath string `yaml:"agent_secret_path" env:"AGENT_SECRET_PATH"`
	UseTLS          bool   `yaml:"use_tls" env:"USE_TLS"`
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
	cfg.HostInventoryEnabled = sharedconfig.GetEnvAsBool("HOST_INVENTORY_ENABLED", false)
	cfg.HostInventoryConnectionsEnabled = sharedconfig.GetEnvAsBool("HOST_INVENTORY_CONNECTIONS_ENABLED", false)
	cfg.HostInventoryInterval = ParseHostInventoryInterval(sharedconfig.GetEnv("HOST_INVENTORY_INTERVAL", ""))

	return cfg
}

// ParseHostInventoryInterval turns a duration string into a usable local
// host-inventory cadence.
//
// Empty, unparseable or non-positive gives the default. A value below the floor
// is RAISED to the floor and logged, rather than honoured or rejected: an
// operator who typed "5m" wants frequent collection, and the right answer is
// the most frequent one that is safe for their host plus a line telling them
// what happened. Silently honouring it would have the agent walk the whole
// package database twelve times an hour.
func ParseHostInventoryInterval(s string) time.Duration {
	if s == "" {
		return DefaultHostInventoryInterval
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		log.Printf("⚠️  Invalid HOST_INVENTORY_INTERVAL %q — using %s", s, DefaultHostInventoryInterval)
		return DefaultHostInventoryInterval
	}
	if d < MinHostInventoryInterval {
		log.Printf("⚠️  HOST_INVENTORY_INTERVAL %s is below the %s floor — using %s", d, MinHostInventoryInterval, MinHostInventoryInterval)
		return MinHostInventoryInterval
	}
	return d
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
	if cfg.HostInventoryInterval <= 0 {
		cfg.HostInventoryInterval = DefaultHostInventoryInterval
	} else if cfg.HostInventoryInterval < MinHostInventoryInterval {
		log.Printf("⚠️  host_inventory_interval %s is below the %s floor — using %s",
			cfg.HostInventoryInterval, MinHostInventoryInterval, MinHostInventoryInterval)
		cfg.HostInventoryInterval = MinHostInventoryInterval
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
	if hi := os.Getenv("HOST_INVENTORY_ENABLED"); hi != "" {
		cfg.HostInventoryEnabled = sharedconfig.GetEnvAsBool("HOST_INVENTORY_ENABLED", false)
	}
	if connections := os.Getenv("HOST_INVENTORY_CONNECTIONS_ENABLED"); connections != "" {
		cfg.HostInventoryConnectionsEnabled = sharedconfig.GetEnvAsBool("HOST_INVENTORY_CONNECTIONS_ENABLED", false)
	}
	if hi := os.Getenv("HOST_INVENTORY_INTERVAL"); hi != "" {
		cfg.HostInventoryInterval = ParseHostInventoryInterval(hi)
	}
	if dataPath := os.Getenv("DATA_PATH"); dataPath != "" {
		cfg.DataPath = dataPath
	}
	if v := boolEnvPtr("VERBOSE"); v != nil {
		cfg.Verbose = v
	}

	// Load certificates from files if paths are set
	if err := loadCertificatesFromFiles(&cfg); err != nil {
		return nil, err
	}

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
// read or parsed is an error — running on would open every job with the wrong
// key and report each as a decryption failure.
//
// A previous secret past its window is dropped from the file here, so a replaced
// secret does not stay on disk after it stopped being honoured.
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
	// rotation replaces both or neither, so the key that opens the platform's
	// envelopes never disagrees with the identity the platform knows.
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
