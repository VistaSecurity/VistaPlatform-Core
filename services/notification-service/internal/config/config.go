package config

import (
	"strconv"
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

type Config struct {
	Port                string
	Environment         string
	LogLevel            string
	DatabaseURL         string
	JWTSecret           string
	EncryptionMasterKey string
	ServiceTimeout      time.Duration
	RetryMaxAttempts    int
	RetryInitialDelay   time.Duration
	RetryMaxDelay       time.Duration
	DeliveryQueueSize   int
	DeliveryWorkers     int

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

	timeout, _ := strconv.Atoi(sharedconfig.GetEnv("SERVICE_TIMEOUT", "5"))
	retryMax, _ := strconv.Atoi(sharedconfig.GetEnv("RETRY_MAX_ATTEMPTS", "3"))
	retryInitial, _ := strconv.Atoi(sharedconfig.GetEnv("RETRY_INITIAL_DELAY_SECONDS", "1"))
	retryMaxDelay, _ := strconv.Atoi(sharedconfig.GetEnv("RETRY_MAX_DELAY_SECONDS", "60"))
	queueSize, _ := strconv.Atoi(sharedconfig.GetEnv("DELIVERY_QUEUE_SIZE", "1000"))
	workers, _ := strconv.Atoi(sharedconfig.GetEnv("DELIVERY_WORKERS", "10"))

	return &Config{
		Port:                sharedconfig.GetEnv("PORT", "8080"),
		Environment:         sharedconfig.GetEnv("ENV", "development"),
		LogLevel:            sharedconfig.GetEnv("LOG_LEVEL", "info"),
		DatabaseURL:         sharedconfig.GetEnv("DATABASE_URL", "postgres://crypto_user:crypto_pass_dev@postgres:5432/crypto_inventory?sslmode=prefer"),
		JWTSecret:           sharedconfig.GetEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
		EncryptionMasterKey: sharedconfig.GetEnv("ENCRYPTION_MASTER_KEY", ""),
		ServiceTimeout:      time.Duration(timeout) * time.Second,
		RetryMaxAttempts:    retryMax,
		RetryInitialDelay:   time.Duration(retryInitial) * time.Second,
		RetryMaxDelay:       time.Duration(retryMaxDelay) * time.Second,
		DeliveryQueueSize:   queueSize,
		DeliveryWorkers:     workers,
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
