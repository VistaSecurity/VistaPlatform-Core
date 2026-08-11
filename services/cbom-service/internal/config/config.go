package config

import (
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// Config holds the application configuration
type Config struct {
	JWTSecret   string
	Environment string
	Port        string
	Database    DatabaseConfig
	DatabaseURL string

	// mTLS Configuration
	UseMTLS            bool
	TLSPort            string
	ServiceCertPath    string
	ServiceKeyPath     string
	ClientCertPath     string
	ClientKeyPath      string
	PlatformCACertPath string
}

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	Host     string
	Port     string
	Name     string
	User     string
	Password string
	SSLMode  string
}

// Load loads configuration from environment variables
func Load() *Config {
	// Reject well-known dev defaults in production (shared guard across services).
	sharedconfig.RejectInsecureDefaults(sharedconfig.GetEnv("ENV", "development"), map[string]string{
		"JWT_SECRET": sharedconfig.GetEnv("JWT_SECRET", "your-secret-key-change-in-production"),
	})

	// Primary configuration uses DATABASE_URL for consistency
	databaseURL := sharedconfig.GetEnv("DATABASE_URL", "")

	// Fallback to individual environment variables if DATABASE_URL not provided
	var dbConfig DatabaseConfig
	if databaseURL == "" {
		dbConfig = DatabaseConfig{
			Host:     sharedconfig.GetEnv("DB_HOST", "postgres"),
			Port:     sharedconfig.GetEnv("DB_PORT", "5432"),
			Name:     sharedconfig.GetEnv("DB_NAME", "crypto_inventory"),
			User:     sharedconfig.GetEnv("DB_USER", "crypto_user"),
			Password: sharedconfig.GetEnv("DB_PASSWORD", "crypto_pass_dev"),
			SSLMode:  sharedconfig.GetEnv("DB_SSLMODE", "disable"),
		}
	}

	return &Config{
		JWTSecret:   sharedconfig.GetEnv("JWT_SECRET", "your-secret-key-change-in-production"),
		Environment: sharedconfig.GetEnv("ENV", "development"),
		Port:        sharedconfig.GetEnv("PORT", "8080"),
		Database:    dbConfig,
		DatabaseURL: databaseURL,
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
