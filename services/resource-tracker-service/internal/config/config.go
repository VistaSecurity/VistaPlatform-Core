package config

import (
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

type Config struct {
	// Server configuration
	Port        string
	Environment string
	LogLevel    string

	// Authentication
	JWTSecret          string
	InternalAuthSecret string

	// Database configuration
	DatabaseURL   string
	EncryptionKey string

	// AWS Cost Explorer configuration
	AWSRegion           string
	AWSAccountID        string
	CostExplorerEnabled bool
	CostSyncInterval    string // e.g., "1h", "24h"

	// Tenant mapping configuration
	TenantTagKey string // AWS tag key used to identify tenants (e.g., "TenantID")

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
	// Reject well-known dev defaults in production (shared guard across services).
	sharedconfig.RejectInsecureDefaults(sharedconfig.GetEnv("ENV", "development"), map[string]string{
		"JWT_SECRET":            sharedconfig.GetEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
		"INTERNAL_AUTH_SECRET":  sharedconfig.GetEnv("INTERNAL_AUTH_SECRET", ""),
		"ENCRYPTION_MASTER_KEY": sharedconfig.GetEnv("ENCRYPTION_MASTER_KEY", ""),
	})

	return &Config{
		Port:               sharedconfig.GetEnv("PORT", "8080"),
		Environment:        sharedconfig.GetEnv("ENV", "development"),
		LogLevel:           sharedconfig.GetEnv("LOG_LEVEL", "info"),
		JWTSecret:          sharedconfig.GetEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
		InternalAuthSecret: sharedconfig.GetEnv("INTERNAL_AUTH_SECRET", ""),
		DatabaseURL:        sharedconfig.GetEnv("DATABASE_URL", "postgres://crypto_user:crypto_pass_dev@localhost:5432/crypto_inventory?sslmode=prefer"),
		EncryptionKey:      sharedconfig.GetEnv("ENCRYPTION_MASTER_KEY", ""),

		// AWS Cost Explorer configuration
		AWSRegion:           sharedconfig.GetEnv("AWS_REGION", "us-east-1"),
		AWSAccountID:        sharedconfig.GetEnv("AWS_ACCOUNT_ID", ""),
		CostExplorerEnabled: sharedconfig.GetEnv("AWS_COST_EXPLORER_ENABLED", "false") == "true",
		CostSyncInterval:    sharedconfig.GetEnv("AWS_COST_SYNC_INTERVAL", "1h"),

		// Tenant mapping
		TenantTagKey: sharedconfig.GetEnv("AWS_TENANT_TAG_KEY", "TenantID"),
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
