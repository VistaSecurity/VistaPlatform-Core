package config

import (
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

type Config struct {
	Port                      string
	DatabaseURL               string
	RedisURL                  string // Redis URL for caching
	JWTSecret                 string
	Environment               string
	StripeWebhookSecret       string
	StripeSecretKey           string
	StripePublishableKey      string
	MonitoringServiceURL      string
	ResourceTrackerServiceURL string

	// FrontendBaseURL is the public URL of the web-UI, used as the default
	// return_url when opening a Stripe billing portal session. Customers can
	// override per-request, but this fallback keeps the call working without
	// a body.
	FrontendBaseURL     string
	EncryptionMasterKey string // Master key for encrypting integration credentials
	InternalAuthSecret  string // HMAC secret for service-to-service auth

	// CookieDomain sets the Domain attribute on auth cookies. Must match the
	// auth-service COOKIE_DOMAIN value (e.g. ".vista.example.com") so that
	// both services write to the same cookie slot. Without this, the admin-service
	// issues cookies for the exact gateway hostname while the auth-service issues
	// them for the wildcard domain, causing the browser to hold two access_token
	// cookies simultaneously and sending the tenant one first.
	CookieDomain string

	// EnforceSecureCookies forces the Secure flag on auth cookies regardless of
	// the X-Forwarded-Proto header. Set to true in production where TLS is
	// always terminated upstream so a misconfigured proxy cannot drop the flag.
	EnforceSecureCookies bool

	// Billing Background Workers
	BillingWebhookWorkerEnabled bool
	BillingDunningWorkerEnabled bool
	BillingDunningCronSchedule  string
	BillingGracePeriodDays      int

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
	// Environment is keyed off ENV — the var the Helm chart sets (configmap-app.yaml)
	// and the one the other backend services read. admin-service previously read
	// ENVIRONMENT, which the chart never emits, so every chart deployment silently
	// ran as "development" and these production guards never fired.
	sharedconfig.RejectInsecureDefaults(sharedconfig.GetEnv("ENV", "development"), map[string]string{
		"JWT_SECRET":            sharedconfig.GetEnv("JWT_SECRET", "your-super-secret-jwt-key-change-in-production"),
		"INTERNAL_AUTH_SECRET":  sharedconfig.GetEnv("INTERNAL_AUTH_SECRET", "dev-internal-auth-secret-change-in-production"),
		"ENCRYPTION_MASTER_KEY": sharedconfig.GetEnv("ENCRYPTION_MASTER_KEY", "change-this-master-key-in-production"),
	})

	return &Config{
		Port:                 sharedconfig.GetEnv("PORT", "8084"),
		DatabaseURL:          sharedconfig.GetEnv("DATABASE_URL", "postgres://crypto_user:crypto_pass_dev@localhost:5432/crypto_inventory?sslmode=prefer"),
		RedisURL:             sharedconfig.GetEnv("REDIS_URL", "redis://:redis_pass_dev@redis:6379/0"),
		JWTSecret:            sharedconfig.GetEnv("JWT_SECRET", "your-super-secret-jwt-key-change-in-production"),
		Environment:          sharedconfig.GetEnv("ENV", "development"),
		StripeWebhookSecret:  sharedconfig.GetEnv("STRIPE_WEBHOOK_SECRET", "change-me"),
		StripeSecretKey:      sharedconfig.GetEnv("STRIPE_SECRET_KEY", ""),
		StripePublishableKey: sharedconfig.GetEnv("STRIPE_PUBLISHABLE_KEY", ""),
		// admin-service's dashboard aggregates data by calling backends directly
		// over their in-cluster Service DNS — there is NO api-gateway pod in the
		// Helm/K8s deployment (cluster Traefik routes external traffic only).
		// These default to the Compose/K8s Service names and are HMAC-signed.
		MonitoringServiceURL:        sharedconfig.PeerServiceURLAuto("MONITORING_SERVICE_URL", "monitoring-service"),
		ResourceTrackerServiceURL:   sharedconfig.PeerServiceURLAuto("RESOURCE_TRACKER_SERVICE_URL", "resource-tracker-service"),
		FrontendBaseURL:             sharedconfig.GetEnv("FRONTEND_BASE_URL", "http://localhost:3000"),
		EncryptionMasterKey:         sharedconfig.GetEnv("ENCRYPTION_MASTER_KEY", "change-this-master-key-in-production"), // Should use AWS KMS or similar in production
		InternalAuthSecret:          sharedconfig.GetEnv("INTERNAL_AUTH_SECRET", "dev-internal-auth-secret-change-in-production"),
		CookieDomain:                sharedconfig.GetEnv("COOKIE_DOMAIN", ""),
		EnforceSecureCookies:        sharedconfig.GetEnvAsBool("ENFORCE_SECURE_COOKIES", false),
		BillingWebhookWorkerEnabled: sharedconfig.GetEnvAsBool("BILLING_WEBHOOK_WORKER_ENABLED", true),
		BillingDunningWorkerEnabled: sharedconfig.GetEnvAsBool("BILLING_DUNNING_WORKER_ENABLED", true),
		BillingDunningCronSchedule:  sharedconfig.GetEnv("BILLING_DUNNING_CRON_SCHEDULE", "0 */6 * * *"),
		BillingGracePeriodDays:      sharedconfig.GetEnvAsInt("BILLING_GRACE_PERIOD_DAYS", 7),
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
