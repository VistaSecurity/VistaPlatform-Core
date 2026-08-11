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
	}
}
