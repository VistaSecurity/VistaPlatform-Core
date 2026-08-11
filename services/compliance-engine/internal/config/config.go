package config

import (
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// Config holds all configuration for the compliance engine
type Config struct {
	Port        string
	Environment string
	DatabaseURL string
	NATSURL     string
	LogLevel    string
	JWTSecret   string
	JWTExpiry   time.Duration

	// mTLS Configuration
	UseMTLS            bool
	TLSPort            string
	ServiceCertPath    string
	ServiceKeyPath     string
	ClientCertPath     string
	ClientKeyPath      string
	PlatformCACertPath string
}

// Load loads configuration from environment variables
func Load() *Config {
	// Reject well-known dev defaults in production (shared guard across services).
	sharedconfig.RejectInsecureDefaults(sharedconfig.GetEnv("ENV", "development"), map[string]string{
		"JWT_SECRET": sharedconfig.GetEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
	})

	return &Config{
		Port:        sharedconfig.GetEnv("PORT", "8080"),
		Environment: sharedconfig.GetEnv("ENV", "development"),
		DatabaseURL: sharedconfig.GetEnv("DATABASE_URL", "postgres://crypto_user:crypto_pass_dev@postgres:5432/crypto_inventory?sslmode=prefer"),
		NATSURL:     sharedconfig.GetEnv("NATS_URL", ""),
		LogLevel:    sharedconfig.GetEnv("LOG_LEVEL", "info"),
		JWTSecret:   sharedconfig.GetEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
		JWTExpiry:   sharedconfig.GetEnvAsDuration("JWT_EXPIRY", 24*time.Hour),
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
