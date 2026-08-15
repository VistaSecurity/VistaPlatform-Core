package config

import (
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// Config holds configuration for the pcap-processor service.
type Config struct {
	DatabaseURL        string
	NATSUrl            string
	TempDir            string
	ProcessingTimeout  time.Duration
	MaxConcurrentJobs  int
	InternalAuthSecret string
	SensorManagerURL   string
	Port               string

	// mTLS Configuration (M-14: pcap-processor previously never read these
	// and never started the :8443 listener, so under serviceMtls.enabled it
	// only ever answered on plaintext :8080 — monitoring-service's version
	// aggregator probes https://pcap-processor:8443/health and reported the
	// pod "unreachable" even when healthy, and any S2S caller using
	// PeerURL()/mTLS could not reach it either.)
	UseMTLS            bool
	TLSPort            string
	ServiceCertPath    string
	ServiceKeyPath     string
	ClientCertPath     string
	ClientKeyPath      string
	PlatformCACertPath string
}

// Load reads configuration from environment variables.
func Load() *Config {
	// Reject well-known dev defaults in production (shared guard across services).
	sharedconfig.RejectInsecureDefaults(sharedconfig.GetEnv("ENV", "development"), map[string]string{
		"INTERNAL_AUTH_SECRET": sharedconfig.GetEnv("INTERNAL_AUTH_SECRET", ""),
	})

	return &Config{
		DatabaseURL:        sharedconfig.GetEnv("DATABASE_URL", ""),
		NATSUrl:            sharedconfig.GetEnv("NATS_URL", ""),
		TempDir:            sharedconfig.GetEnv("PCAP_TEMP_DIR", "/tmp/pcap-uploads"),
		ProcessingTimeout:  sharedconfig.GetEnvAsDuration("PCAP_PROCESSING_TIMEOUT", 5*time.Minute),
		MaxConcurrentJobs:  sharedconfig.GetEnvAsInt("PCAP_MAX_CONCURRENT_JOBS", 4),
		InternalAuthSecret: sharedconfig.GetEnv("INTERNAL_AUTH_SECRET", ""),
		SensorManagerURL:   sharedconfig.PeerServiceURLAuto("SENSOR_MANAGER_URL", "sensor-manager"),
		Port:               sharedconfig.GetEnv("PORT", "8080"),

		UseMTLS:         sharedconfig.GetEnvAsBool("USE_MTLS", true),
		TLSPort:         sharedconfig.GetEnv("TLS_PORT", "8443"),
		ServiceCertPath: sharedconfig.GetEnv("SERVICE_CERT_PATH", "/app/certs/server-cert.pem"),
		ServiceKeyPath:  sharedconfig.GetEnv("SERVICE_KEY_PATH", "/app/certs/server-key.pem"),
		// Client material for outbound S2S calls (audit-service on :8443 under
		// the mesh). Same env names and defaults every other backend uses; the
		// chart's app ConfigMap sets them when serviceMtls is enabled.
		ClientCertPath:     sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem"),
		ClientKeyPath:      sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem"),
		PlatformCACertPath: sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem"),
	}
}
