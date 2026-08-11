package resourcetracking

import (
	"os"
	"strings"
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// Config holds configuration for the resource tracking middleware
type Config struct {
	// ServiceName identifies the service using this middleware
	ServiceName string

	// TrackerURL is the base URL of the resource-tracker-service
	TrackerURL string

	// BatchSize is the number of metrics to batch before sending
	BatchSize int

	// FlushInterval is how often to flush metrics even if batch isn't full
	FlushInterval time.Duration

	// Enabled controls whether tracking is active
	Enabled bool

	// Timeout for HTTP requests to tracker service
	Timeout time.Duration

	// RetryAttempts for failed requests
	RetryAttempts int

	// CircuitBreakerThreshold for failing requests
	CircuitBreakerThreshold int

	// DisableCircuitBreaker skips open-circuit behavior when sending metric batches (local dev).
	DisableCircuitBreaker bool

	// mTLS Configuration
	UseMTLS            bool
	ClientCertPath     string
	ClientKeyPath      string
	PlatformCACertPath string
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	disableCB := strings.EqualFold(strings.TrimSpace(os.Getenv("ENV")), "development")
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RESOURCE_TRACKING_DISABLE_CIRCUIT_BREAKER"))) {
	case "true", "1", "yes":
		disableCB = true
	case "false", "0", "no":
		disableCB = false
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("RESOURCE_TRACKING_ENABLE_CIRCUIT_BREAKER")), "true") {
		disableCB = false
	}
	return &Config{
		ServiceName:             "unknown-service",
		TrackerURL:              sharedconfig.PeerURL("resource-tracker-service", sharedconfig.MTLSEnabled()),
		BatchSize:               5,                // Reduced for testing
		FlushInterval:           30 * time.Second, // Reduced for testing
		Enabled:                 true,
		Timeout:                 10 * time.Second,
		RetryAttempts:           3,
		CircuitBreakerThreshold: 5,
		DisableCircuitBreaker:   disableCB,
		UseMTLS:                 false,
		ClientCertPath:          "",
		ClientKeyPath:           "",
		PlatformCACertPath:      "",
	}
}
