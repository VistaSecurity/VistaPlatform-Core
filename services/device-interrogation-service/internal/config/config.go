package config

import (
	"fmt"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// Config holds all configuration for the device interrogation service
type Config struct {
	Port                string
	Environment         string
	DatabaseURL         string
	RedisURL            string
	NATSURL             string
	LogLevel            string
	JWTSecret           string
	EncryptionMasterKey string
	// mTLS Configuration
	UseMTLS            bool
	TLSPort            string
	ServiceCertPath    string
	ServiceKeyPath     string
	ClientCertPath     string
	ClientKeyPath      string
	PlatformCACertPath string

	// Agent mTLS (outbound device-agent auth). When AgentMTLSRequired is true,
	// the /agents/:id/{jobs,results,heartbeat} routes fail closed: a verified
	// per-tenant client cert is mandatory (see middleware.AgentAuth). A
	// dedicated TLS listener on AgentTLSPort terminates the agent's mTLS so the
	// real client cert reaches the service (edge does TLS passthrough). Off by
	// default; enabled via the chart's agentMtls toggle (requires UseMTLS for
	// the service cert).
	AgentMTLSRequired bool
	// AgentMTLSAdvertisedURL is the passthrough URL advertised to agents in the
	// registration response when AgentMTLSRequired. Chart-derived from
	// agentMtls.backends.device-interrogation-service.dnsName + agentMtls.port.
	AgentMTLSAdvertisedURL string
	AgentTLSPort           string
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	config := &Config{
		Port:                sharedconfig.GetEnv("PORT", "8080"),
		Environment:         sharedconfig.GetEnv("ENV", "development"),
		DatabaseURL:         sharedconfig.GetEnv("DATABASE_URL", "postgres://crypto_user:crypto_pass_dev@postgres:5432/crypto_inventory?sslmode=prefer"),
		RedisURL:            sharedconfig.GetEnv("REDIS_URL", "redis://:redis_pass_dev@redis:6379/0"),
		NATSURL:             sharedconfig.GetEnv("NATS_URL", ""),
		LogLevel:            sharedconfig.GetEnv("LOG_LEVEL", "info"),
		JWTSecret:           sharedconfig.JWTSecret(),
		EncryptionMasterKey: sharedconfig.GetEnv("ENCRYPTION_MASTER_KEY", ""),
		// mTLS Configuration
		UseMTLS:            sharedconfig.GetEnvAsBool("USE_MTLS", true),
		TLSPort:            sharedconfig.GetEnv("TLS_PORT", "8443"),
		ServiceCertPath:    sharedconfig.GetEnv("SERVICE_CERT_PATH", "/app/certs/server-cert.pem"),
		ServiceKeyPath:     sharedconfig.GetEnv("SERVICE_KEY_PATH", "/app/certs/server-key.pem"),
		ClientCertPath:     sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem"),
		ClientKeyPath:      sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem"),
		PlatformCACertPath: sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem"),

		// Defaults to TRUE — see the sensor-manager equivalent: an unconfigured
		// deployment must authenticate agents rather than trust a bare agent
		// UUID. Opting out is now an explicit AGENT_MTLS_REQUIRED=false.
		AgentMTLSRequired:      sharedconfig.GetEnvAsBool("AGENT_MTLS_REQUIRED", true),
		AgentMTLSAdvertisedURL: sharedconfig.GetEnv("AGENT_MTLS_ADVERTISED_URL", ""),
		AgentTLSPort:           sharedconfig.GetEnv("AGENT_TLS_PORT", "8444"),
	}

	// ENCRYPTION_MASTER_KEY encrypts tenant device credentials at rest — there is
	// no safe fallback, so require it explicitly rather than shipping a default.
	if config.EncryptionMasterKey == "" {
		return nil, fmt.Errorf("FATAL: ENCRYPTION_MASTER_KEY is required (encrypts tenant device credentials) — set a strong secret")
	}

	// Reject well-known dev defaults in production (shared guard across services).
	sharedconfig.RejectInsecureDefaults(config.Environment, map[string]string{
		"JWT_SECRET":            config.JWTSecret,
		"ENCRYPTION_MASTER_KEY": config.EncryptionMasterKey,
	})

	return config, nil
}
