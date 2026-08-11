package config

import (
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// Config holds all configuration for the sensor manager
type Config struct {
	Port         string
	Environment  string
	DatabaseURL  string
	InfluxURL    string
	InfluxToken  string
	InfluxOrg    string
	InfluxBucket string
	NATSURL      string
	LogLevel     string
	JWTSecret    string
	// S3 Configuration for sensor binary storage
	S3ArtifactsBucket  string
	S3ArtifactsRegion  string
	S3ArtifactsVersion string // Version to use for S3 downloads (default: "latest")
	// Encryption master key for CA certificate private key encryption
	EncryptionMasterKey string

	// mTLS Configuration
	UseMTLS            bool
	TLSPort            string
	ServiceCertPath    string
	ServiceKeyPath     string
	ClientCertPath     string
	ClientKeyPath      string
	PlatformCACertPath string

	// Sensor mTLS (outbound sensor auth). When SensorMTLSRequired is true, the
	// /sensors/:sensor_id/{heartbeat,commands/poll,discoveries,...} routes fail
	// closed: a verified per-tenant client cert is mandatory (see
	// middleware.SensorAuth). A dedicated TLS listener on AgentTLSPort
	// terminates the sensor's mTLS so the real client cert reaches the service
	// (edge does TLS passthrough). Off by default; enabled via the chart's
	// agentMtls toggle (requires UseMTLS for the service cert).
	SensorMTLSRequired bool
	AgentTLSPort       string
}

// Load loads configuration from environment variables
func Load() *Config {
	// Reject well-known dev defaults in production (shared guard across services).
	sharedconfig.RejectInsecureDefaults(sharedconfig.GetEnv("ENV", "development"), map[string]string{
		"JWT_SECRET":            sharedconfig.GetEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
		"ENCRYPTION_MASTER_KEY": sharedconfig.GetEnv("ENCRYPTION_MASTER_KEY", ""),
	})

	return &Config{
		Port:         sharedconfig.GetEnv("PORT", "8080"),
		Environment:  sharedconfig.GetEnv("ENV", "development"),
		DatabaseURL:  sharedconfig.GetEnv("DATABASE_URL", "postgres://crypto_user:crypto_pass_dev@postgres:5432/crypto_inventory?sslmode=prefer"),
		InfluxURL:    sharedconfig.GetEnv("INFLUXDB_URL", "http://influxdb:8086"),
		InfluxToken:  sharedconfig.GetEnv("INFLUXDB_TOKEN", "dev-token-1234567890"),
		InfluxOrg:    sharedconfig.GetEnv("INFLUXDB_ORG", "crypto-inventory"),
		InfluxBucket: sharedconfig.GetEnv("INFLUXDB_BUCKET", "metrics"),
		NATSURL:      sharedconfig.GetEnv("NATS_URL", ""),
		LogLevel:     sharedconfig.GetEnv("LOG_LEVEL", "info"),
		JWTSecret:    sharedconfig.GetEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
		// S3 Configuration
		S3ArtifactsBucket:  sharedconfig.GetEnv("S3_ARTIFACTS_BUCKET", ""),
		S3ArtifactsRegion:  sharedconfig.GetEnv("S3_ARTIFACTS_REGION", sharedconfig.GetEnv("AWS_REGION", "us-east-1")),
		S3ArtifactsVersion: sharedconfig.GetEnv("S3_ARTIFACTS_VERSION", "latest"),
		// Encryption master key
		EncryptionMasterKey: sharedconfig.GetEnv("ENCRYPTION_MASTER_KEY", ""),
		// mTLS Configuration
		UseMTLS:            sharedconfig.GetEnvAsBool("USE_MTLS", true),
		TLSPort:            sharedconfig.GetEnv("TLS_PORT", "8443"),
		ServiceCertPath:    sharedconfig.GetEnv("SERVICE_CERT_PATH", "/app/certs/server-cert.pem"),
		ServiceKeyPath:     sharedconfig.GetEnv("SERVICE_KEY_PATH", "/app/certs/server-key.pem"),
		ClientCertPath:     sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem"),
		ClientKeyPath:      sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem"),
		PlatformCACertPath: sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem"),

		SensorMTLSRequired: sharedconfig.GetEnvAsBool("AGENT_MTLS_REQUIRED", false),
		AgentTLSPort:       sharedconfig.GetEnv("AGENT_TLS_PORT", "8444"),
	}
}
