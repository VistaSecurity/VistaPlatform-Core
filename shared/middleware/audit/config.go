package audit

import (
	"os"
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// Config holds configuration for the audit logging middleware
type Config struct {
	// ServiceName identifies the service using this middleware
	ServiceName string

	// AuditServiceURL is the base URL of the audit-service
	AuditServiceURL string

	// Enabled controls whether audit logging is active
	Enabled bool

	// BatchSize is the number of audit logs to batch before sending
	BatchSize int

	// FlushInterval is how often to flush audit logs even if batch isn't full
	FlushInterval time.Duration

	// Timeout for HTTP requests to audit service
	Timeout time.Duration

	// RetryAttempts for failed requests
	RetryAttempts int

	// SkipPaths are paths that should not be audited (e.g., health checks)
	SkipPaths []string

	// EventTypeMap maps HTTP method + path to event type
	EventTypeMap map[string]string

	// mTLS Configuration (optional - if not set, uses standard HTTP client)
	UseMTLS            bool
	ClientCertPath     string
	ClientKeyPath      string
	PlatformCACertPath string

	// UseNATS enables publishing audit logs via NATS JetStream instead of HTTP.
	// When enabled, the HTTP client is only used as a fallback if NATS is unavailable.
	UseNATS bool
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		ServiceName:     "unknown-service",
		AuditServiceURL: sharedconfig.PeerURL("audit-service", sharedconfig.MTLSEnabled()),
		Enabled:         true,
		BatchSize:       10,
		FlushInterval:   5 * time.Second,
		Timeout:         5 * time.Second,
		RetryAttempts:   3,
		SkipPaths: []string{
			"/health",
			"/ready",
			"/api/v1/health",
		},
		EventTypeMap: make(map[string]string),
	}
}

// ServiceConfig returns DefaultConfig with the per-service knobs every backend
// sets identically: the service name, the AUDIT_SERVICE_URL override, the
// AUDIT_LOGGING_ENABLED kill-switch, and the mTLS client material used to
// reach audit-service on :8443 when the mesh is on.
//
// Nine services open-code this same block. New wiring should call this instead
// of copying it a tenth time — the copies are where an unset AUDIT_SERVICE_URL
// or a forgotten cert path quietly turns audit logging into a no-op.
func ServiceConfig(serviceName string, useMTLS bool, clientCertPath, clientKeyPath, platformCACertPath string) *Config {
	cfg := DefaultConfig()
	cfg.ServiceName = serviceName
	if url := os.Getenv("AUDIT_SERVICE_URL"); url != "" {
		cfg.AuditServiceURL = url
	} else {
		cfg.AuditServiceURL = sharedconfig.PeerURL("audit-service", useMTLS)
	}
	cfg.Enabled = os.Getenv("AUDIT_LOGGING_ENABLED") != "false"
	cfg.UseMTLS = useMTLS
	cfg.ClientCertPath = clientCertPath
	cfg.ClientKeyPath = clientKeyPath
	cfg.PlatformCACertPath = platformCACertPath
	return cfg
}
