package config

import (
	"strings"
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// Config holds all configuration for the auth service
type Config struct {
	Port             string
	Environment      string
	DatabaseURL      string
	RedisURL         string
	JWTSecret        string
	JWTExpiry        time.Duration
	LogLevel         string
	CORSOrigins      []string
	RateLimitDefault int
	RateLimitWindow  time.Duration
	RateLimitLogin   int

	// Cookie/CSRF Configuration
	CookieDomain string
	CookieSecure bool

	// OAuthCallbackBaseURL is the public base URL (scheme://host[:port]) the
	// service uses to build the OAuth/OIDC redirect_uri for SSO. It is pinned
	// explicitly rather than derived from CORSOrigins[0]: CORS origins
	// are an allow-list that can legitimately include several entries, and the
	// first one is not guaranteed to be the externally-reachable callback host.
	// When empty, getBaseURL falls back to the legacy CORSOrigins[0] behavior.
	OAuthCallbackBaseURL string

	// mTLS Configuration
	UseMTLS            bool
	TLSPort            string
	ServiceCertPath    string
	ServiceKeyPath     string
	ClientCertPath     string
	ClientKeyPath      string
	PlatformCACertPath string
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	config := &Config{
		Port:        sharedconfig.GetEnv("PORT", "8080"),
		Environment: sharedconfig.GetEnv("ENV", "development"),
		DatabaseURL: sharedconfig.GetEnv("DATABASE_URL", "postgres://crypto_user:crypto_pass_dev@localhost:5432/crypto_inventory?sslmode=prefer"),
		RedisURL:    sharedconfig.GetEnv("REDIS_URL", "redis://:redis_pass_dev@localhost:6379/0"),
		JWTSecret:   sharedconfig.GetEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
		LogLevel:    sharedconfig.GetEnv("LOG_LEVEL", "info"),
	}

	// Parse JWT expiry (default 1h; 24h was excessive — stolen tokens valid all day)
	jwtExpiryStr := sharedconfig.GetEnv("JWT_EXPIRY", "1h")
	jwtExpiry, err := time.ParseDuration(jwtExpiryStr)
	if err != nil {
		return nil, err
	}
	config.JWTExpiry = jwtExpiry

	// Parse CORS origins - supports multiple origins for development and production
	// Default includes both standard port 3000 and Vite dev server port 5174
	// In production, this should be set to specific allowed domains
	corsOrigins := sharedconfig.GetEnv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5174,http://localhost:3006")
	config.CORSOrigins = strings.Split(corsOrigins, ",")

	// Rate limiting configuration
	config.RateLimitDefault = sharedconfig.GetEnvAsInt("RATE_LIMIT_DEFAULT", 100)
	config.RateLimitLogin = sharedconfig.GetEnvAsInt("RATE_LIMIT_LOGIN", 5)

	// Parse rate limit window
	rateLimitWindowStr := sharedconfig.GetEnv("RATE_LIMIT_WINDOW", "1m")
	rateLimitWindow, err := time.ParseDuration(rateLimitWindowStr)
	if err != nil {
		rateLimitWindow = 1 * time.Minute
	}
	config.RateLimitWindow = rateLimitWindow

	// Cookie/CSRF Configuration
	config.CookieDomain = sharedconfig.GetEnv("COOKIE_DOMAIN", "")
	config.CookieSecure = sharedconfig.GetEnvAsBool("COOKIE_SECURE", config.Environment == "production")

	// Explicit public base URL for OAuth/OIDC SSO callbacks.
	config.OAuthCallbackBaseURL = sharedconfig.GetEnv("OAUTH_CALLBACK_BASE_URL", "")

	// mTLS Configuration
	config.UseMTLS = sharedconfig.GetEnvAsBool("USE_MTLS", true)
	config.TLSPort = sharedconfig.GetEnv("TLS_PORT", "8443")
	config.ServiceCertPath = sharedconfig.GetEnv("SERVICE_CERT_PATH", "/app/certs/server-cert.pem")
	config.ServiceKeyPath = sharedconfig.GetEnv("SERVICE_KEY_PATH", "/app/certs/server-key.pem")
	config.ClientCertPath = sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem")
	config.ClientKeyPath = sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem")
	config.PlatformCACertPath = sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem")

	// Reject well-known dev defaults in production (shared guard across services).
	sharedconfig.RejectInsecureDefaults(config.Environment, map[string]string{
		"JWT_SECRET":           config.JWTSecret,
		"INTERNAL_AUTH_SECRET": sharedconfig.GetEnv("INTERNAL_AUTH_SECRET", "dev-internal-auth-secret-change-in-production"),
	})

	return config, nil
}
