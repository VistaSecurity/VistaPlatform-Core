package config

import (
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

type Config struct {
	Port                      string
	Environment               string
	DatabaseURL               string
	NATSURL                   string
	RedisURL                  string
	LogLevel                  string
	JWTSecret                 string
	BootstrapCertPath         string // Path to bootstrap client certificate
	BootstrapKeyPath          string // Path to bootstrap client private key
	BootstrapCACertPath       string // Path to bootstrap CA certificate
	SensorManagerURL          string // URL for sensor-manager service
	PlatformDiscoverySensorID string // Fixed sensor ID for platform discovery sensor

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
		"ENCRYPTION_MASTER_KEY": sharedconfig.GetEnv("ENCRYPTION_MASTER_KEY", ""),
	})

	return &Config{
		Port:                      sharedconfig.GetEnv("PORT", "8088"),
		Environment:               sharedconfig.GetEnv("ENV", "development"),
		DatabaseURL:               sharedconfig.GetEnv("DATABASE_URL", "postgres://crypto_user:crypto_pass_dev@postgres:5432/crypto_inventory?sslmode=prefer"),
		NATSURL:                   sharedconfig.GetEnv("NATS_URL", ""),
		RedisURL:                  sharedconfig.GetEnv("REDIS_URL", "redis://:redis_pass_dev@redis:6379/0"),
		LogLevel:                  sharedconfig.GetEnv("LOG_LEVEL", "info"),
		JWTSecret:                 sharedconfig.GetEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
		BootstrapCertPath:         sharedconfig.GetEnv("BOOTSTRAP_CERT_PATH", "/app/bootstrap-certs/cluster-sensor-service-cert.pem"),
		BootstrapKeyPath:          sharedconfig.GetEnv("BOOTSTRAP_KEY_PATH", "/app/bootstrap-certs/cluster-sensor-service-key.pem"),
		BootstrapCACertPath:       sharedconfig.GetEnv("BOOTSTRAP_CA_CERT_PATH", "/app/bootstrap-certs/bootstrap-ca-cert.pem"),
		SensorManagerURL:          sharedconfig.PeerServiceURLAuto("SENSOR_MANAGER_URL", "sensor-manager"),
		PlatformDiscoverySensorID: sharedconfig.GetEnv("PLATFORM_DISCOVERY_SENSOR_ID", "550e8400-e29b-41d4-a716-446655440001"), // Fixed UUID for platform-discovery-sensor
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
