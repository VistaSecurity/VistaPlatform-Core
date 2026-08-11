package config

import (
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

type Config struct {
	Server      ServerConfig
	Database    DatabaseConfig
	JWT         JWTConfig
	S3          S3Config
	Telemetry   TelemetryConfig
	DatabaseURL string
	Environment string
	LogLevel    string

	// Internal service authentication
	InternalAuthSecret string

	// Posture-snapshot job (ADR-0007): nightly per-tenant risk-summary snapshot.
	InventoryServiceURL    string
	PostureSnapshotEnabled bool

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

type S3Config struct {
	Enabled         bool
	Bucket          string
	Region          string
	Endpoint        string // For S3-compatible storage (MinIO, etc.)
	AccessKeyID     string
	SecretAccessKey string
	KMSKeyID        string // For server-side encryption
	PathPrefix      string // Prefix for all archived files
}

type TelemetryConfig struct {
	Enabled      bool
	CollectorURL string
	ServiceName  string
	SampleRate   float64
}

func Load() *Config {
	// Reject well-known dev defaults in production (shared guard across services).
	sharedconfig.RejectInsecureDefaults(sharedconfig.GetEnv("ENV", "development"), map[string]string{
		"JWT_SECRET":            sharedconfig.GetEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
		"INTERNAL_AUTH_SECRET":  sharedconfig.GetEnv("INTERNAL_AUTH_SECRET", ""),
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

	// S3 archival configuration
	s3Enabled := sharedconfig.GetEnv("S3_ARCHIVAL_ENABLED", "false") == "true"
	s3Config := S3Config{
		Enabled:         s3Enabled,
		Bucket:          sharedconfig.GetEnv("S3_LOG_BUCKET", ""),
		Region:          sharedconfig.GetEnv("S3_REGION", "us-east-1"),
		Endpoint:        sharedconfig.GetEnv("S3_ENDPOINT", ""), // Empty for AWS, set for MinIO
		AccessKeyID:     sharedconfig.GetEnv("AWS_ACCESS_KEY_ID", ""),
		SecretAccessKey: sharedconfig.GetEnv("AWS_SECRET_ACCESS_KEY", ""),
		KMSKeyID:        sharedconfig.GetEnv("S3_KMS_KEY_ID", ""),
		PathPrefix:      sharedconfig.GetEnv("S3_PATH_PREFIX", "audit-logs"),
	}

	// Telemetry configuration
	telemetryConfig := TelemetryConfig{
		Enabled:      sharedconfig.GetEnv("OTEL_ENABLED", "false") == "true",
		CollectorURL: sharedconfig.GetEnv("OTEL_COLLECTOR_URL", "otel-collector:4317"),
		ServiceName:  sharedconfig.GetEnv("OTEL_SERVICE_NAME", "audit-service"),
		SampleRate:   float64(sharedconfig.GetEnvAsInt("OTEL_SAMPLE_RATE", 100)) / 100.0,
	}

	return &Config{
		Server: ServerConfig{
			Host: sharedconfig.GetEnv("SERVER_HOST", "0.0.0.0"),
			Port: sharedconfig.GetEnv("PORT", "8080"),
		},
		Database:    dbConfig,
		DatabaseURL: databaseURL,
		JWT: JWTConfig{
			Secret: sharedconfig.GetEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
		},
		S3:                 s3Config,
		Telemetry:          telemetryConfig,
		InternalAuthSecret: sharedconfig.GetEnv("INTERNAL_AUTH_SECRET", ""),
		// Peer URL flips http:8080 ↔ https:8443 with USE_MTLS unless overridden.
		InventoryServiceURL:    sharedconfig.PeerServiceURLAuto("INVENTORY_SERVICE_URL", "inventory-service"),
		PostureSnapshotEnabled: sharedconfig.GetEnvAsBool("POSTURE_SNAPSHOT_JOB_ENABLED", true),
		Environment:            sharedconfig.GetEnv("ENV", "development"),
		LogLevel:               sharedconfig.GetEnv("LOG_LEVEL", "info"),
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
