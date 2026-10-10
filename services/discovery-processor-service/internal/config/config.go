package config

import (
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

type Config struct {
	// Polling Configuration
	PollIntervalSeconds int

	// Service URLs
	InventoryServiceURL string

	// Batch Processing
	BatchSize int

	// Retry Configuration
	MaxRetries       int
	RetryBackoffBase int

	// Database Configuration
	DatabaseURL      string
	MaxDBConnections int

	// Server Configuration
	Port     string
	LogLevel string

	// mTLS Configuration
	UseMTLS            bool
	TLSPort            string
	ServiceCertPath    string
	ServiceKeyPath     string
	ClientCertPath     string
	ClientKeyPath      string
	PlatformCACertPath string
}

func Load() *Config {
	// Production refuses to start with a missing or weak platform secret and
	// rejects the well-known dev literals (shared guard across services).
	sharedconfig.EnforceProductionSecrets(sharedconfig.GetEnv("ENV", "development"), sharedconfig.SecretSpec{
		Required: []string{"INTERNAL_AUTH_SECRET"},
	})

	return &Config{
		// Polling Configuration
		// Fallback poll only ( D6): every sensor_discoveries writer
		// publishes discovery.queue.ready, which drains the queue at once.
		PollIntervalSeconds: sharedconfig.GetEnvAsInt("DISCOVERY_POLL_INTERVAL", 60),

		// Service URLs
		InventoryServiceURL: sharedconfig.PeerServiceURLAuto("INVENTORY_SERVICE_URL", "inventory-service"),

		// Batch Processing
		BatchSize: sharedconfig.GetEnvAsInt("DISCOVERY_BATCH_SIZE", 100), // Max discoveries per API call

		// Retry Configuration
		MaxRetries:       sharedconfig.GetEnvAsInt("DISCOVERY_MAX_RETRIES", 7),         // Failed attempts per row before it is rejected
		RetryBackoffBase: sharedconfig.GetEnvAsInt("DISCOVERY_RETRY_BACKOFF_BASE", 30), // Seconds after the first failure; doubles per attempt, capped at 10 min

		// Database Configuration
		DatabaseURL:      sharedconfig.GetEnv("DATABASE_URL", "postgres://crypto_user:crypto_pass_dev@postgres:5432/crypto_inventory?sslmode=prefer"),
		MaxDBConnections: sharedconfig.GetEnvAsInt("DB_MAX_CONNECTIONS", 10),

		// Server Configuration
		Port:     sharedconfig.GetEnv("PORT", "8080"),
		LogLevel: sharedconfig.GetEnv("LOG_LEVEL", "info"),
		// mTLS Configuration
		UseMTLS:            sharedconfig.GetEnvAsBool("USE_MTLS", true),
		TLSPort:            sharedconfig.GetEnv("TLS_PORT", "8443"),
		ServiceCertPath:    sharedconfig.GetEnv("SERVICE_CERT_PATH", "/app/certs/server-cert.pem"),
		ServiceKeyPath:     sharedconfig.GetEnv("SERVICE_KEY_PATH", "/app/certs/server-key.pem"),
		ClientCertPath:     sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem"),
		ClientKeyPath:      sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem"),
		PlatformCACertPath: sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem"),
	}
}
