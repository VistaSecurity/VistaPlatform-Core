package email

import (
	"database/sql"

	"github.com/vistasecurity/vistaplatform/shared/config"
)

// PlatformEmailService builds an EmailService from the platform email
// configuration managed in the admin-UI (the platform_settings.email_config
// row), decrypting the stored SMTP password with ENCRYPTION_MASTER_KEY. It
// resolves on every call so live changes in the admin-UI take effect without a
// restart, and falls back to env-var config when no row exists yet. Prefer this
// over GetEmailConfigFromEnv for any platform-level send.
func PlatformEmailService(db *sql.DB) (*EmailService, error) {
	resolver := NewEmailConfigResolver(db, config.GetEnv("ENCRYPTION_MASTER_KEY", ""))
	cfg, err := resolver.GetPlatformEmailConfig()
	if err != nil {
		return nil, err
	}
	return NewEmailService(*cfg), nil
}

// GetEmailConfigFromEnv creates email configuration from environment variables
func GetEmailConfigFromEnv() EmailConfig {
	return EmailConfig{
		SMTPHost:     config.GetEnv("SMTP_HOST", "localhost"),
		SMTPPort:     config.GetEnv("SMTP_PORT", "587"),
		SMTPUsername: config.GetEnv("SMTP_USERNAME", ""),
		SMTPPassword: config.GetEnv("SMTP_PASSWORD", ""),
		FromEmail:    config.GetEnv("FROM_EMAIL", "noreply@vista.local"),
		FromName:     config.GetEnv("FROM_NAME", "Vista"),
		BrandName:    config.GetEnv("PLATFORM_NAME", ""),
	}
}
