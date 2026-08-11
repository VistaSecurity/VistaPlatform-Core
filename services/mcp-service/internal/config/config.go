package config

import (
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// Config for mcp-service. Deliberately small: the service holds no state and
// owns no datastore — it authenticates API tokens via auth-service and fans
// out to platform read APIs as the token's user.
type Config struct {
	Server      ServerConfig
	Environment string
	LogLevel    string

	// Internal service authentication (HMAC signing for the PAT→JWT
	// exchange call to auth-service).
	InternalAuthSecret string

	// Peer service base URLs. Empty values are derived from USE_MTLS via
	// shared/config.PeerServiceURLAuto at call sites.
	AuthServiceURL      string
	InventoryServiceURL string
	ComplianceEngineURL string
	CBOMServiceURL      string

	// mTLS Configuration
	UseMTLS            bool
	TLSPort            string
	ServiceCertPath    string
	ServiceKeyPath     string
	ClientCertPath     string
	ClientKeyPath      string
	PlatformCACertPath string
}

type ServerConfig struct {
	Host string
	Port string
}

func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Host: sharedconfig.GetEnv("SERVER_HOST", "0.0.0.0"),
			Port: sharedconfig.GetEnv("PORT", "8080"),
		},
		Environment:        sharedconfig.GetEnv("ENV", "development"),
		LogLevel:           sharedconfig.GetEnv("LOG_LEVEL", "info"),
		InternalAuthSecret: sharedconfig.GetEnv("INTERNAL_AUTH_SECRET", ""),

		AuthServiceURL:      sharedconfig.PeerServiceURLAuto("AUTH_SERVICE_URL", "auth-service"),
		InventoryServiceURL: sharedconfig.PeerServiceURLAuto("INVENTORY_SERVICE_URL", "inventory-service"),
		ComplianceEngineURL: sharedconfig.PeerServiceURLAuto("COMPLIANCE_ENGINE_URL", "compliance-engine"),
		CBOMServiceURL:      sharedconfig.PeerServiceURLAuto("CBOM_SERVICE_URL", "cbom-service"),

		UseMTLS:            sharedconfig.GetEnvAsBool("USE_MTLS", true),
		TLSPort:            sharedconfig.GetEnv("TLS_PORT", "8443"),
		ServiceCertPath:    sharedconfig.GetEnv("SERVICE_CERT_PATH", "/app/certs/server-cert.pem"),
		ServiceKeyPath:     sharedconfig.GetEnv("SERVICE_KEY_PATH", "/app/certs/server-key.pem"),
		ClientCertPath:     sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem"),
		ClientKeyPath:      sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem"),
		PlatformCACertPath: sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem"),
	}
}
