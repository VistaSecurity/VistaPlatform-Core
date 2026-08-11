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
	BatchSize         int
	ConcurrentBatches int

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
	return &Config{
		// Polling Configuration
		PollIntervalSeconds: sharedconfig.GetEnvAsInt("DISCOVERY_POLL_INTERVAL", 5), // Production: 10

		// Service URLs
		InventoryServiceURL: sharedconfig.PeerServiceURLAuto("INVENTORY_SERVICE_URL", "inventory-service"),

		// Batch Processing
		BatchSize:         sharedconfig.GetEnvAsInt("DISCOVERY_BATCH_SIZE", 100),       // Max discoveries per API call
		ConcurrentBatches: sharedconfig.GetEnvAsInt("DISCOVERY_CONCURRENT_BATCHES", 3), // Max batches processed in parallel

		// Retry Configuration
		MaxRetries:       sharedconfig.GetEnvAsInt("DISCOVERY_MAX_RETRIES", 3),        // Retry attempts
		RetryBackoffBase: sharedconfig.GetEnvAsInt("DISCOVERY_RETRY_BACKOFF_BASE", 1), // Base seconds for exponential backoff

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
