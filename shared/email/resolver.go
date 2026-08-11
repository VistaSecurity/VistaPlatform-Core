package email

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

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
