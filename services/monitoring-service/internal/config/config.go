package config

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

type Config struct {
	Port                string
	Environment         string
	LogLevel            string
	DatabaseURL         string
	RedisURL            string
	InfluxDBURL         string
	JWTSecret           string
	ServiceTimeout      time.Duration
	HealthCheckInterval time.Duration
	Services            map[string]ServiceConfig
	// S3 Configuration for compliance logging
	S3Bucket             string
	S3Region             string
	S3KMSKeyID           string
	IncidentHooksEnabled bool
	RetentionJobInterval time.Duration

	// mTLS Configuration
	UseMTLS            bool
	TLSPort            string
	ServiceCertPath    string
	ServiceKeyPath     string
	ClientCertPath     string
	ClientKeyPath      string
	PlatformCACertPath string

	// Traefik dashboard API URL (separate from the routing entrypoint)
	TraefikAPIURL string

	// External synthetic checks. Each entry exercises the customer-facing
	// edge end-to-end (DNS → LB → ingress controller → middleware chain →
	// backend Service → backend handler), so a "down" result means
	// something in the chart-owned routing layer is broken even when every
	// backend Service reports healthy. Populated from SYNTHETIC_CHECKS_JSON
	// at startup.
	SyntheticChecks []SyntheticCheck

	// ExtraTrustedCACertPath optionally points at a PEM file (mounted from an
	// operator-supplied Secret) added to the system trust pool used to
	// verify synthetic-check TLS connections. Self-hosted deployments whose
	// edge certificate chains to a private CA — one their host OS trusts but
	// their containers don't, since container images ship their own CA
	// bundle independent of the node's — need this to make a synthetic check
	// verify for real rather than reaching for InsecureSkipVerify. Empty
	// leaves the system pool untouched (the common case: public ACME/CA
	// certs verify with no extra trust needed).
	ExtraTrustedCACertPath string
}

type ServiceConfig struct {
	URL     string
	Timeout time.Duration
	Enabled bool
}

// SyntheticCheck is one external-path health probe.
//
// The probe issues a GET against URL and asserts the response status equals
// ExpectedStatus (default 200). Reported as service name "synthetic-<Name>"
// in the dashboard so synthetic results are distinguishable from per-service
// probes.
type SyntheticCheck struct {
	// Name is the human-readable label for this check. Required.
	// Conventionally "edge-tenant" / "edge-admin" / etc.
	Name string `json:"name"`
	// URL the probe issues a GET against. Required. Should be the external
	// hostname (e.g. https://vistaplatform.example.com/api/v1/auth-service/health)
	// so the probe exercises the same path as a real client.
	URL string `json:"url"`
	// ExpectedStatus is the HTTP status code that counts as healthy.
	// Defaults to 200.
	ExpectedStatus int `json:"expectedStatus,omitempty"`
	// TimeoutSeconds caps the probe at this many seconds. Defaults to 5.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
	// InsecureSkipVerify disables TLS verification for this probe entirely.
	// Prefer ExtraTrustedCACertPath (above) when the edge cert chains to a
	// private CA — that verifies for real instead of turning verification
	// off, so a genuine break (wrong hostname, expired cert) still surfaces
	// as a finding instead of being silently skipped. Only reach for this
	// when there's no CA to hand the process at all (e.g. a throwaway
	// self-signed cert with no private root).
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
	// HostHeader overrides the HTTP Host header sent with the probe. Use when
	// the probe must reach the edge by IP or an internal address while still
	// presenting the customer-facing hostname, so Traefik Host() routing rules
	// match the same way they do for a real client. Empty leaves the Host
	// derived from URL.
	HostHeader string `json:"hostHeader,omitempty"`
}

func Load() *Config {
	// Reject well-known dev defaults in production (shared guard across services).
	sharedconfig.RejectInsecureDefaults(sharedconfig.GetEnv("ENV", "development"), map[string]string{
		"JWT_SECRET":            sharedconfig.GetEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
		"ENCRYPTION_MASTER_KEY": sharedconfig.GetEnv("ENCRYPTION_MASTER_KEY", ""),
	})

	timeout, _ := strconv.Atoi(sharedconfig.GetEnv("SERVICE_TIMEOUT", "5"))
	interval, _ := strconv.Atoi(sharedconfig.GetEnv("HEALTH_CHECK_INTERVAL", "30"))
	retentionHours, _ := strconv.Atoi(sharedconfig.GetEnv("LOG_RETENTION_INTERVAL_HOURS", "24"))
	if retentionHours <= 0 {
		retentionHours = 24
	}
	incidentHooksEnabled := strings.EqualFold(sharedconfig.GetEnv("ENABLE_INCIDENT_HOOKS", "true"), "true")

	// POSTGRES_URL is the canonical var for health-check DSN. When absent (e.g. ec2-smoke compose
	// only sets DATABASE_URL), fall back to DATABASE_URL so the health check uses real credentials.
	databaseURL := sharedconfig.GetEnv("DATABASE_URL", "postgres://crypto_user:crypto_pass_dev@postgres:5432/crypto_inventory?sslmode=prefer")
	postgresURL := sharedconfig.GetEnv("POSTGRES_URL", databaseURL)

	syntheticChecks := loadSyntheticChecks()

	return &Config{
		Port:                 sharedconfig.GetEnv("PORT", "8080"),
		Environment:          sharedconfig.GetEnv("ENV", "development"),
		LogLevel:             sharedconfig.GetEnv("LOG_LEVEL", "info"),
		DatabaseURL:          databaseURL,
		RedisURL:             sharedconfig.GetEnv("REDIS_URL", "redis://:redis_pass_dev@redis:6379/0"),
		InfluxDBURL:          sharedconfig.GetEnv("INFLUXDB_URL", "http://influxdb:8086"),
		JWTSecret:            sharedconfig.GetEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
		ServiceTimeout:       time.Duration(timeout) * time.Second,
		HealthCheckInterval:  time.Duration(interval) * time.Second,
		S3Bucket:             sharedconfig.GetEnv("S3_LOG_BUCKET", "crypto-inventory-logs-dev"),
		S3Region:             sharedconfig.GetEnv("S3_REGION", "us-east-1"),
		S3KMSKeyID:           sharedconfig.GetEnv("S3_KMS_KEY_ID", ""),
		IncidentHooksEnabled: incidentHooksEnabled,
		RetentionJobInterval: time.Duration(retentionHours) * time.Hour,
		// mTLS Configuration
		UseMTLS:                sharedconfig.GetEnvAsBool("USE_MTLS", true),
		TLSPort:                sharedconfig.GetEnv("TLS_PORT", "8443"),
		ServiceCertPath:        sharedconfig.GetEnv("SERVICE_CERT_PATH", "/app/certs/server-cert.pem"),
		ServiceKeyPath:         sharedconfig.GetEnv("SERVICE_KEY_PATH", "/app/certs/server-key.pem"),
		ClientCertPath:         sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem"),
		ClientKeyPath:          sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem"),
		PlatformCACertPath:     sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem"),
		TraefikAPIURL:          sharedconfig.GetEnv("TRAEFIK_API_URL", "http://api-gateway:8080"),
		SyntheticChecks:        syntheticChecks,
		ExtraTrustedCACertPath: sharedconfig.GetEnv("EXTRA_TRUSTED_CA_PATH", ""),
		Services: map[string]ServiceConfig{
			"api-gateway": {
				// GetEnvIfPresent (not GetEnv) so an explicitly-empty
				// API_GATEWAY_URL opts the probe out — the K8s/Helm deployment
				// has no in-namespace api-gateway pod (routing is cluster-level
				// Traefik), so it blanks this to disable the probe. checkHTTPHealth
				// reports "disabled" for an empty URL.
				URL:     sharedconfig.GetEnvIfPresent("API_GATEWAY_URL", "http://api-gateway:80"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"auth-service": {
				URL:     sharedconfig.PeerServiceURLAuto("AUTH_SERVICE_URL", "auth-service"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"inventory-service": {
				URL:     sharedconfig.PeerServiceURLAuto("INVENTORY_SERVICE_URL", "inventory-service"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"compliance-engine": {
				URL:     sharedconfig.PeerServiceURLAuto("COMPLIANCE_ENGINE_URL", "compliance-engine"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"cbom-service": {
				URL:     sharedconfig.PeerServiceURLAuto("CBOM_SERVICE_URL", "cbom-service"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"sensor-manager": {
				URL:     sharedconfig.PeerServiceURLAuto("SENSOR_MANAGER_URL", "sensor-manager"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"cluster-sensor-service": {
				URL:     sharedconfig.PeerServiceURLAuto("CLUSTER_SENSOR_SERVICE_URL", "cluster-sensor-service"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"admin-service": {
				URL:     sharedconfig.PeerServiceURLAuto("ADMIN_SERVICE_URL", "admin-service"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"tenant-health-service": {
				URL:     sharedconfig.PeerServiceURLAuto("TENANT_HEALTH_SERVICE_URL", "tenant-health-service"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"resource-tracker-service": {
				URL:     sharedconfig.PeerServiceURLAuto("RESOURCE_TRACKER_SERVICE_URL", "resource-tracker-service"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"device-interrogation-service": {
				URL:     sharedconfig.PeerServiceURLAuto("DEVICE_INTERROGATION_SERVICE_URL", "device-interrogation-service"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"audit-service": {
				URL:     sharedconfig.PeerServiceURLAuto("AUDIT_SERVICE_URL", "audit-service"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"notification-service": {
				URL:     sharedconfig.PeerServiceURLAuto("NOTIFICATION_SERVICE_URL", "notification-service"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"discovery-processor-service": {
				URL:     sharedconfig.PeerServiceURLAuto("DISCOVERY_PROCESSOR_SERVICE_URL", "discovery-processor-service"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"pcap-processor": {
				URL:     sharedconfig.PeerServiceURLAuto("PCAP_PROCESSOR_URL", "pcap-processor"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"mcp-service": {
				URL:     sharedconfig.PeerServiceURLAuto("MCP_SERVICE_URL", "mcp-service"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"postgres": {
				URL:     postgresURL,
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"redis": {
				URL:     sharedconfig.GetEnv("REDIS_URL", "redis://:redis_pass_dev@redis:6379/0"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"influxdb": {
				URL:     sharedconfig.GetEnv("INFLUXDB_URL", "http://influxdb:8086"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"grafana": {
				URL:     sharedconfig.GetEnv("GRAFANA_URL", ""),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
			"nats": {
				// NATS_MONITOR_URL is the HTTP monitor endpoint (port 8222), distinct
				// from NATS_URL which is the client-connection string
				// (nats://TOKEN@host:4222) used by backends to publish/subscribe.
				// In K8s the chart sets this to `http://nats-headless:8222` because
				// the regular `nats` Service publishes only port 4222.
				URL:     sharedconfig.GetEnv("NATS_MONITOR_URL", "http://nats:8222"),
				Timeout: time.Duration(timeout) * time.Second,
				Enabled: true,
			},
		},
	}
}

// loadSyntheticChecks parses SYNTHETIC_CHECKS_JSON, a JSON array of
// SyntheticCheck objects. The Helm chart renders this from
// .Values.monitoring.syntheticChecks so the operator can declare any number
// of external-path probes in values.yaml. Malformed JSON is logged and
// ignored — synthetic checks are operator-facing, never request-path, so a
// config typo should not crash the service.
func loadSyntheticChecks() []SyntheticCheck {
	raw := strings.TrimSpace(sharedconfig.GetEnv("SYNTHETIC_CHECKS_JSON", ""))
	if raw == "" {
		return nil
	}
	var checks []SyntheticCheck
	if err := json.Unmarshal([]byte(raw), &checks); err != nil {
		fmt.Printf("⚠️  SYNTHETIC_CHECKS_JSON parse error: %v (synthetic checks disabled)\n", err)
		return nil
	}
	// Drop entries that don't have both a name and URL — they're definitionally
	// unusable, and silently skipping is friendlier than crashing.
	out := make([]SyntheticCheck, 0, len(checks))
	for _, c := range checks {
		if c.Name == "" || c.URL == "" {
			fmt.Printf("⚠️  synthetic check skipped: name+url required (got name=%q url=%q)\n", c.Name, c.URL)
			continue
		}
		out = append(out, c)
	}
	return out
}
