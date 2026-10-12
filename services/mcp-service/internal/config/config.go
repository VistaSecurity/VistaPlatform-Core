package config

import (
	"strings"
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// Config for mcp-service. Deliberately small: the service holds no state and
// owns no datastore — it authenticates API tokens via auth-service and fans
// out to platform read APIs as the token's user.
type Config struct {
	Server      ServerConfig
	Environment string
	LogLevel    string

	// Internal service authentication (HMAC signing for the PAT→JWT
	// exchange call to auth-service).
	InternalAuthSecret string

	// Peer service base URLs. Empty values are derived from USE_MTLS via
	// shared/config.PeerServiceURLAuto at call sites.
	AuthServiceURL      string
	InventoryServiceURL string
	ComplianceEngineURL string
	CBOMServiceURL      string

	// PublicBaseURL is the external origin clients address this service by
	// (scheme://host[:port]), used to build the RFC 9728 protected-resource
	// metadata and the resource_metadata pointer in the 401 challenge. Both
	// sources come from the chart's shared app ConfigMap and carry the same
	// public host; OAUTH_CALLBACK_BASE_URL is preferred because auth-service
	// derives its OAuth issuer from it, and the two must agree.
	PublicBaseURL string

	// AllowHostFallback (MCP_ALLOW_HOST_FALLBACK) lets production derive the
	// OAuth discovery origin from the request Host when PublicBaseURL is unset.
	AllowHostFallback bool

	// TrustedProxyCIDRs (TRUSTED_PROXY_CIDRS, comma separated) are the peers
	// whose X-Forwarded-For is believed when deriving the client address for
	// audit rows and the auth rate limits. Empty trusts nobody.
	TrustedProxyCIDRs []string

	// Token-exchange hardening (see platform.Options).
	GrantCacheTTL         time.Duration // MCP_GRANT_CACHE_TTL, default 60s
	NegativeCacheTTL      time.Duration // MCP_NEGATIVE_CACHE_TTL, default 30s
	AuthAttemptsPerMinute int           // MCP_AUTH_ATTEMPTS_PER_MINUTE per client address, default 60; <0 disables

	// AuditFailOpen (MCP_AUDIT_FAIL_OPEN=true) lets a tool read succeed when
	// its audit record cannot be written. Default false: no audit, no data.
	AuditFailOpen bool

	// MaxResultBytes (MCP_MAX_RESULT_BYTES) caps one tool result; default 256 KiB.
	MaxResultBytes int

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

func Load() *Config {
	// Production refuses to start with a missing or weak platform secret and
	// rejects the well-known dev literals (shared guard across services).
	sharedconfig.EnforceProductionSecrets(sharedconfig.GetEnv("ENV", "development"), sharedconfig.SecretSpec{
		Required: []string{"INTERNAL_AUTH_SECRET"},
	})

	return &Config{
		Server: ServerConfig{
			Host: sharedconfig.GetEnv("SERVER_HOST", "0.0.0.0"),
			Port: sharedconfig.GetEnv("PORT", "8080"),
		},
		Environment:        sharedconfig.GetEnv("ENV", "development"),
		LogLevel:           sharedconfig.GetEnv("LOG_LEVEL", "info"),
		InternalAuthSecret: sharedconfig.GetEnv("INTERNAL_AUTH_SECRET", ""),

		AuthServiceURL:      sharedconfig.PeerServiceURLAuto("AUTH_SERVICE_URL", "auth-service"),
		InventoryServiceURL: sharedconfig.PeerServiceURLAuto("INVENTORY_SERVICE_URL", "inventory-service"),
		ComplianceEngineURL: sharedconfig.PeerServiceURLAuto("COMPLIANCE_ENGINE_URL", "compliance-engine"),
		CBOMServiceURL:      sharedconfig.PeerServiceURLAuto("CBOM_SERVICE_URL", "cbom-service"),

		PublicBaseURL: firstNonEmpty(
			sharedconfig.GetEnv("OAUTH_CALLBACK_BASE_URL", ""),
			sharedconfig.GetEnv("WEB_UI_BASE_URL", ""),
		),

		AllowHostFallback: sharedconfig.GetEnvAsBool("MCP_ALLOW_HOST_FALLBACK", false),
		TrustedProxyCIDRs: splitList(sharedconfig.GetEnv("TRUSTED_PROXY_CIDRS", "")),

		GrantCacheTTL:         sharedconfig.GetEnvAsDuration("MCP_GRANT_CACHE_TTL", 60*time.Second),
		NegativeCacheTTL:      sharedconfig.GetEnvAsDuration("MCP_NEGATIVE_CACHE_TTL", 30*time.Second),
		AuthAttemptsPerMinute: sharedconfig.GetEnvAsInt("MCP_AUTH_ATTEMPTS_PER_MINUTE", 60),
		AuditFailOpen:         sharedconfig.GetEnvAsBool("MCP_AUDIT_FAIL_OPEN", false),
		MaxResultBytes:        sharedconfig.GetEnvAsInt("MCP_MAX_RESULT_BYTES", 256<<10),

		UseMTLS:            sharedconfig.GetEnvAsBool("USE_MTLS", true),
		TLSPort:            sharedconfig.GetEnv("TLS_PORT", "8443"),
		ServiceCertPath:    sharedconfig.GetEnv("SERVICE_CERT_PATH", "/app/certs/server-cert.pem"),
		ServiceKeyPath:     sharedconfig.GetEnv("SERVICE_KEY_PATH", "/app/certs/server-key.pem"),
		ClientCertPath:     sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem"),
		ClientKeyPath:      sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem"),
		PlatformCACertPath: sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem"),
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
