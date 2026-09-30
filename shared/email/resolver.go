package email

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
)

// ErrNotConfigured means no SMTP host has been configured anywhere the platform
// looks: no tenant override, no platform_settings.email_config, and no SMTP_HOST
// in the environment. It is a property of the deployment, not a transient
// fault — retrying cannot make it succeed.
//
// ResolveEmailConfig / GetPlatformEmailConfig deliberately do NOT return it:
// they fall back to localhost:587 (and other callers, e.g. auth-service, rely
// on getting *a* config back). Callers that need to tell "unconfigured" from
// "configured but unreachable" use ResolveDeliverableConfig.
var ErrNotConfigured = errors.New("email delivery is not configured")

// EmailConfigResolver resolves email configuration for tenants
// Supports platform default with optional tenant overrides
type EmailConfigResolver struct {
	db            *sql.DB
	encryptionKey string
}

// NewEmailConfigResolver creates a new email config resolver
func NewEmailConfigResolver(db *sql.DB, encryptionKey string) *EmailConfigResolver {
	return &EmailConfigResolver{
		db:            db,
		encryptionKey: encryptionKey,
	}
}

// ResolveEmailConfig resolves email configuration for a tenant
// Returns platform default if tenant has no override, or tenant config if configured
func (r *EmailConfigResolver) ResolveEmailConfig(tenantID uuid.UUID) (*EmailConfig, error) {
	// Use database function to get email config
	query := `SELECT get_tenant_email_config($1)`
	var configJSON []byte
	err := r.db.QueryRow(query, tenantID).Scan(&configJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant email config: %w", err)
	}

	var configMap map[string]interface{}
	if err := json.Unmarshal(configJSON, &configMap); err != nil {
		return nil, fmt.Errorf("failed to parse email config: %w", err)
	}

	// Build EmailConfig from map
	config := &EmailConfig{
		SMTPHost:     getStringFromMap(configMap, "smtp_host", "localhost"),
		SMTPPort:     getStringFromMap(configMap, "smtp_port", "587"),
		SMTPUsername: getStringFromMap(configMap, "smtp_username", ""),
		SMTPPassword: getStringFromMap(configMap, "smtp_password", ""),
		FromEmail:    getStringFromMap(configMap, "from_email", "noreply@vista.local"),
		FromName:     getStringFromMap(configMap, "from_name", "Vista"),
		BrandName:    r.PlatformBrandName(),
	}

	// Decrypt password if encrypted
	if config.SMTPPassword != "" && r.encryptionKey != "" {
		// Check if password is encrypted (starts with base64 pattern or is in encrypted format)
		// For now, assume if it's not empty and encryption key exists, it needs decryption
		// In practice, you might want to add a flag or detect encryption format
		decrypted, err := r.decryptPassword(config.SMTPPassword)
		if err == nil {
			config.SMTPPassword = decrypted
		}
		// If decryption fails, use as-is (might be plaintext for backward compatibility)
	}

	return config, nil
}

// ResolveDeliverableConfig returns the email configuration to send with, or
// ErrNotConfigured when there is no SMTP host to send through.
//
// Order: the tenant's own override (tenantID != nil), then the platform's
// admin-UI-managed email_config, then an explicit SMTP_HOST in the environment
// (the dev/compose path). A blank smtp_host anywhere counts as "not set" — the
// silent localhost:587 default that the older resolvers apply is exactly what
// made an unconfigured deployment retry every alert email against a port
// nothing listens on.
//
// Any other error is a lookup failure and is returned wrapped: the caller may
// treat it as transient.
func (r *EmailConfigResolver) ResolveDeliverableConfig(tenantID *uuid.UUID) (*EmailConfig, error) {
	if tenantID != nil {
		var configJSON []byte
		// A NULL result (no platform config, no tenant override) scans to nil;
		// a lookup error is not fatal here — the platform config is the fallback.
		if err := r.db.QueryRow(`SELECT get_tenant_email_config($1)`, *tenantID).Scan(&configJSON); err == nil {
			if cfg := r.configFromJSON(configJSON); cfg != nil {
				return cfg, nil
			}
		}
	}

	var configJSON []byte
	err := r.db.QueryRow(`SELECT setting_value FROM platform_settings WHERE setting_key = 'email_config'`).Scan(&configJSON)
	switch {
	case err == nil:
		if cfg := r.configFromJSON(configJSON); cfg != nil {
			return cfg, nil
		}
	case errors.Is(err, sql.ErrNoRows):
		// fall through to the environment
	default:
		return nil, fmt.Errorf("failed to get platform email config: %w", err)
	}

	// Read through os.Getenv, not GetEmailConfigFromEnv's defaulting helper: that
	// one turns an unset SMTP_HOST into "localhost", which would make every
	// deployment look configured.
	if strings.TrimSpace(os.Getenv("SMTP_HOST")) != "" {
		envConfig := GetEmailConfigFromEnv()
		envConfig.BrandName = r.PlatformBrandName()
		return &envConfig, nil
	}
	return nil, ErrNotConfigured
}

// configFromJSON builds an EmailConfig from a stored email_config document, or
// returns nil when the document is absent, unparseable, or names no smtp_host.
func (r *EmailConfigResolver) configFromJSON(raw []byte) *EmailConfig {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	host := strings.TrimSpace(getStringFromMap(m, "smtp_host", ""))
	if host == "" {
		return nil
	}
	cfg := &EmailConfig{
		SMTPHost:     host,
		SMTPPort:     getStringFromMap(m, "smtp_port", "587"),
		SMTPUsername: getStringFromMap(m, "smtp_username", ""),
		SMTPPassword: getStringFromMap(m, "smtp_password", ""),
		FromEmail:    getStringFromMap(m, "from_email", "noreply@vista.local"),
		FromName:     getStringFromMap(m, "from_name", "Vista"),
		BrandName:    r.PlatformBrandName(),
	}
	if cfg.SMTPPassword != "" && r.encryptionKey != "" {
		if decrypted, err := r.decryptPassword(cfg.SMTPPassword); err == nil {
			cfg.SMTPPassword = decrypted
		}
	}
	return cfg
}

// PlatformBrandName reads the white-label platform display name
// (platform_settings.platform_name, managed in admin-ui Settings → Branding).
// Returns "" when unset or on any error — email templates fall back to the
// product default ("Vista").
func (r *EmailConfigResolver) PlatformBrandName() string {
	var raw []byte
	if err := r.db.QueryRow(`SELECT setting_value FROM platform_settings WHERE setting_key = 'platform_name'`).Scan(&raw); err != nil {
		return ""
	}
	var name string
	if err := json.Unmarshal(raw, &name); err != nil {
		return ""
	}
	return name
}

// GetPlatformEmailConfig gets the platform default email configuration
func (r *EmailConfigResolver) GetPlatformEmailConfig() (*EmailConfig, error) {
	query := `SELECT setting_value FROM platform_settings WHERE setting_key = 'email_config'`
	var configJSON []byte
	err := r.db.QueryRow(query).Scan(&configJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			// Return default config if not set
			envConfig := GetEmailConfigFromEnv()
			envConfig.BrandName = r.PlatformBrandName()
			return &envConfig, nil
		}
		return nil, fmt.Errorf("failed to get platform email config: %w", err)
	}

	var configMap map[string]interface{}
	if err := json.Unmarshal(configJSON, &configMap); err != nil {
		return nil, fmt.Errorf("failed to parse platform email config: %w", err)
	}

	config := &EmailConfig{
		SMTPHost:     getStringFromMap(configMap, "smtp_host", "localhost"),
		SMTPPort:     getStringFromMap(configMap, "smtp_port", "587"),
		SMTPUsername: getStringFromMap(configMap, "smtp_username", ""),
		SMTPPassword: getStringFromMap(configMap, "smtp_password", ""),
		FromEmail:    getStringFromMap(configMap, "from_email", "noreply@vista.local"),
		FromName:     getStringFromMap(configMap, "from_name", "Vista"),
		BrandName:    r.PlatformBrandName(),
	}

	// Decrypt password if encrypted
	if config.SMTPPassword != "" && r.encryptionKey != "" {
		decrypted, err := r.decryptPassword(config.SMTPPassword)
		if err == nil {
			config.SMTPPassword = decrypted
		}
	}

	return config, nil
}

// decryptPassword decrypts an encrypted password using the encryption service
func (r *EmailConfigResolver) decryptPassword(encrypted string) (string, error) {
	if r.encryptionKey == "" {
		return encrypted, nil // No encryption key, assume plaintext
	}

	// Import encryption service dynamically to avoid circular dependencies
	// We'll use the encryption package
	encryptionService, err := newEncryptionService(r.encryptionKey)
	if err != nil {
		return encrypted, fmt.Errorf("failed to create encryption service: %w", err)
	}

	decrypted, err := encryptionService.Decrypt(encrypted)
	if err != nil {
		return encrypted, fmt.Errorf("failed to decrypt password: %w", err)
	}

	return decrypted, nil
}

// getStringFromMap safely extracts a string value from a map
func getStringFromMap(m map[string]interface{}, key, defaultValue string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultValue
}

// encryptionService interface to avoid direct import (prevent circular deps)
type encryptionService interface {
	Decrypt(ciphertext string) (string, error)
}

// newEncryptionService creates an encryption service instance
// This is a helper to avoid circular dependencies
func newEncryptionService(masterKey string) (encryptionService, error) {
	// We need to import the encryption package
	// For now, we'll create a wrapper that imports it
	return newEncryptionServiceImpl(masterKey)
}
