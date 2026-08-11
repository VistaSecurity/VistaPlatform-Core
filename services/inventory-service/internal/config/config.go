package config

import (
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

type Config struct {
	Server      ServerConfig
	Database    DatabaseConfig
	JWT         JWTConfig
	DatabaseURL string
	RedisURL    string // Redis URL for caching

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

type DatabaseConfig struct {
	Host     string
	Port     string
	Name     string
	User     string
	Password string
	SSLMode  string
}

type JWTConfig struct {
	Secret string
}

func Load() *Config {
	// Reject well-known dev defaults in production (shared guard across services).
	sharedconfig.RejectInsecureDefaults(sharedconfig.GetEnv("ENV", "development"), map[string]string{
		"JWT_SECRET":            sharedconfig.GetEnv("JWT_SECRET", "your-secret-key"),
		"ENCRYPTION_MASTER_KEY": sharedconfig.GetEnv("ENCRYPTION_MASTER_KEY", ""),
	})

	// Primary configuration uses DATABASE_URL for consistency
	databaseURL := sharedconfig.GetEnv("DATABASE_URL", "")

	// Fallback to individual environment variables if DATABASE_URL not provided
	var dbConfig DatabaseConfig
	if databaseURL == "" {
		dbConfig = DatabaseConfig{
			Host:     sharedconfig.GetEnv("DB_HOST", "localhost"),
			Port:     sharedconfig.GetEnv("DB_PORT", "5432"),
			Name:     sharedconfig.GetEnv("DB_NAME", "crypto_inventory"),
			User:     sharedconfig.GetEnv("DB_USER", "crypto_user"),
			Password: sharedconfig.GetEnv("DB_PASSWORD", "crypto_password"),
			SSLMode:  sharedconfig.GetEnv("DB_SSLMODE", "disable"),
		}
	} else {
		// When DATABASE_URL is provided, we don't need individual components
		// The database connection will use the URL directly
		dbConfig = DatabaseConfig{}
	}

	return &Config{
		Server: ServerConfig{
			Host: sharedconfig.GetEnv("SERVER_HOST", "0.0.0.0"),
			Port: sharedconfig.GetEnv("PORT", "8080"),
		},
		Database:    dbConfig,
		DatabaseURL: databaseURL,
		RedisURL:    sharedconfig.GetEnv("REDIS_URL", "redis://:redis_pass_dev@redis:6379/0"),
		JWT: JWTConfig{
			Secret: sharedconfig.GetEnv("JWT_SECRET", "your-secret-key"),
		},
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
