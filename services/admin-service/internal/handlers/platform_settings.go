package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// platformSettingKV is one persisted setting row (setting_key, setting_value JSON).
type platformSettingKV struct {
	Key   string
	Value []byte
}

// platformSettingsStore is the narrow DB surface the platform-settings handlers
// use. Extracting it (the concrete repo holds the SQL verbatim) lets the handlers
// run over an in-memory stub in the contract test (ADR-0001). Public
// Get/UpdatePlatformSettings(db) wrap the *WithStore variants, so server wiring is
// unchanged.
type platformSettingsStore interface {
	ListSettings(ctx context.Context) ([]platformSettingKV, error)
	UpsertSetting(ctx context.Context, key string, value []byte, updatedBy uuid.UUID) error
}

type platformSettingsRepository struct{ db *sql.DB }

func newPlatformSettingsStore(db *sql.DB) platformSettingsStore {
	return &platformSettingsRepository{db: db}
}

func (r *platformSettingsRepository) ListSettings(ctx context.Context) ([]platformSettingKV, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT setting_key, setting_value
		FROM platform_settings
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []platformSettingKV
	for rows.Next() {
		var kv platformSettingKV
		if err := rows.Scan(&kv.Key, &kv.Value); err != nil {
			return nil, err
		}
		out = append(out, kv)
	}
	return out, rows.Err()
}

func (r *platformSettingsRepository) UpsertSetting(ctx context.Context, key string, value []byte, updatedBy uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO platform_settings (setting_key, setting_value, updated_by, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (setting_key)
		DO UPDATE SET
			setting_value = EXCLUDED.setting_value,
			updated_by = EXCLUDED.updated_by,
			updated_at = NOW()
	`, key, value, updatedBy)
	return err
}

// EmailConfig holds SMTP delivery settings for outbound platform email.
// On read, SMTPPassword is always empty; use SMTPPasswordSet to check if one is stored.
type EmailConfig struct {
	SMTPHost        string `json:"smtp_host"`
	SMTPPort        string `json:"smtp_port"`
	SMTPUsername    string `json:"smtp_username"`
	SMTPPassword    string `json:"smtp_password"`     // write-only; always "" on read
	SMTPPasswordSet bool   `json:"smtp_password_set"` // true when a password is stored
	FromEmail       string `json:"from_email"`
	FromName        string `json:"from_name"`
}

// UIConfig represents UI configuration settings
type UIConfig struct {
	Palette      string          `json:"palette,omitempty"`
	Enhancements map[string]bool `json:"enhancements,omitempty"`
}

// LogStorageConfig holds S3 archival settings for platform operations logs.
type LogStorageConfig struct {
	IntegrationID *string `json:"integration_id"`
	Bucket        string  `json:"bucket"`
	Region        string  `json:"region"`
	Enabled       bool    `json:"enabled"`
}

// PlatformSettings represents platform-wide configuration settings
type PlatformSettings struct {
	// Branding & identity
	PlatformName         string  `json:"platform_name"`
	PlatformLogoURL      *string `json:"platform_logo_url,omitempty"`
	PlatformLoginLogoURL *string `json:"platform_login_logo_url,omitempty"`
	PlatformFaviconURL   *string `json:"platform_favicon_url,omitempty"`
	PlatformDomain       string  `json:"platform_domain"`
	// AdminUIBaseURL is the public base URL of the admin console (e.g. "https://admin.yourplatform.com").
	// Used to build password-reset and invitation links so emails work with white-label domains.
	AdminUIBaseURL string `json:"admin_ui_base_url"`
	SupportEmail   string `json:"support_email"`

	// Tenant management
	MaxTenants       *int `json:"max_tenants"`
	DefaultTrialDays *int `json:"default_trial_days"`

	// Access control
	MaintenanceMode     *bool `json:"maintenance_mode"`
	RegistrationEnabled *bool `json:"registration_enabled"`
	// BlockPersonalEmailDomains opts into rejecting consumer domains (gmail,
	// outlook, …) at signup. Default false — required for self-hosted Core,
	// where signup is the only way in and the operator may use a personal
	// address. auth-service EnforceWorkEmailPolicy reads the same key.
	BlockPersonalEmailDomains *bool `json:"block_personal_email_domains"`

	// Password & session policy (applies to both tenant and platform users)
	EmailVerificationRequired      *bool `json:"email_verification_required"`
	AdminEmailVerificationRequired *bool `json:"admin_email_verification_required"`
	PasswordMinLength              *int  `json:"password_min_length"`
	SessionTimeoutMinutes          *int  `json:"session_timeout_minutes"`
	MaxLoginAttempts               *int  `json:"max_login_attempts"`
	LockoutDurationMinutes         *int  `json:"lockout_duration_minutes"`

	// Operations
	BackupRetentionDays *int  `json:"backup_retention_days"`
	LogRetentionDays    *int  `json:"log_retention_days"`
	MonitoringEnabled   *bool `json:"monitoring_enabled"`
	AlertingEnabled     *bool `json:"alerting_enabled"`

	// SSO / integrations
	SSOEnabled *bool `json:"sso_enabled"`

	// Limits
	APIRateLimit        *int `json:"api_rate_limit"`
	FileUploadLimitMB   *int `json:"file_upload_limit_mb"`
	PcapMaxUploadSizeMB *int `json:"pcap_max_upload_size_mb"`

	// Misc
	NotificationChannels []string          `json:"notification_channels"`
	UIConfig             *UIConfig         `json:"ui_config,omitempty"`
	LogStorageConfig     *LogStorageConfig `json:"log_storage_config,omitempty"`
	EmailConfig          *EmailConfig      `json:"email_config,omitempty"`
}

// GetPlatformSettings returns platform-wide settings.
// Retrieves settings from platform_settings table, with defaults if not set.
func GetPlatformSettings(db *sql.DB) gin.HandlerFunc {
	return getPlatformSettingsWithStore(newPlatformSettingsStore(db))
}

func getPlatformSettingsWithStore(store platformSettingsStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Default settings (used as fallback)
		defaultSettings := PlatformSettings{
			PlatformName:                   "Vista",
			PlatformDomain:                 "example.com",
			AdminUIBaseURL:                 "http://localhost:3006",
			SupportEmail:                   "support@example.com",
			MaxTenants:                     nil,
			DefaultTrialDays:               nil,
			MaintenanceMode:                boolPtr(false),
			RegistrationEnabled:            boolPtr(true),
			BlockPersonalEmailDomains:      boolPtr(false),
			EmailVerificationRequired:      boolPtr(true),
			AdminEmailVerificationRequired: boolPtr(false),
			PasswordMinLength:              intPtr(8),
			SessionTimeoutMinutes:          intPtr(1440),
			MaxLoginAttempts:               intPtr(5),
			LockoutDurationMinutes:         intPtr(30),
			BackupRetentionDays:            intPtr(30),
			LogRetentionDays:               intPtr(90),
			MonitoringEnabled:              boolPtr(true),
			AlertingEnabled:                boolPtr(true),
			SSOEnabled:                     boolPtr(false),
			APIRateLimit:                   intPtr(1000),
			FileUploadLimitMB:              intPtr(100),
			PcapMaxUploadSizeMB:            intPtr(500),
			NotificationChannels:           []string{"email"},
		}

		// Try to get settings from database
		settings := defaultSettings

		// Load persisted key-value overrides from the store.
		kvs, err := store.ListSettings(c.Request.Context())
		if err == nil {
			for _, kv := range kvs {
				key := kv.Key
				valueJSON := kv.Value
				{
					var value interface{}
					if err := json.Unmarshal(valueJSON, &value); err == nil {
						switch key {
						case "platform_name":
							if s, ok := value.(string); ok {
								settings.PlatformName = s
							}
						case "platform_logo_url":
							if s, ok := value.(string); ok && s != "" {
								settings.PlatformLogoURL = &s
							}
						case "platform_login_logo_url":
							if s, ok := value.(string); ok && s != "" {
								settings.PlatformLoginLogoURL = &s
							}
						case "platform_favicon_url":
							if s, ok := value.(string); ok && s != "" {
								settings.PlatformFaviconURL = &s
							}
						case "platform_domain":
							if s, ok := value.(string); ok {
								settings.PlatformDomain = s
							}
						case "admin_ui_base_url":
							if s, ok := value.(string); ok && s != "" {
								settings.AdminUIBaseURL = s
							}
						case "support_email":
							if s, ok := value.(string); ok {
								settings.SupportEmail = s
							}
						case "email_verification_required":
							if b, ok := value.(bool); ok {
								settings.EmailVerificationRequired = boolPtr(b)
							}
						case "admin_email_verification_required":
							if b, ok := value.(bool); ok {
								settings.AdminEmailVerificationRequired = boolPtr(b)
							}
						case "registration_enabled":
							if b, ok := value.(bool); ok {
								settings.RegistrationEnabled = boolPtr(b)
							}
						case "block_personal_email_domains":
							if b, ok := value.(bool); ok {
								settings.BlockPersonalEmailDomains = boolPtr(b)
							}
						case "password_min_length":
							if f, ok := value.(float64); ok {
								settings.PasswordMinLength = intPtr(int(f))
							}
						case "session_timeout_minutes":
							if f, ok := value.(float64); ok {
								settings.SessionTimeoutMinutes = intPtr(int(f))
							}
						case "max_login_attempts":
							if f, ok := value.(float64); ok {
								settings.MaxLoginAttempts = intPtr(int(f))
							}
						case "lockout_duration_minutes":
							if f, ok := value.(float64); ok {
								settings.LockoutDurationMinutes = intPtr(int(f))
							}
						case "ui_config":
							var uiConfig UIConfig
							if err := json.Unmarshal(valueJSON, &uiConfig); err == nil {
								settings.UIConfig = &uiConfig
							}
						case "pcap_max_upload_size_mb":
							if f, ok := value.(float64); ok {
								settings.PcapMaxUploadSizeMB = intPtr(int(f))
							}
						case "log_storage_config":
							var logCfg LogStorageConfig
							if err := json.Unmarshal(valueJSON, &logCfg); err == nil {
								settings.LogStorageConfig = &logCfg
							}
						case "email_config":
							// Unmarshal into the internal type so we can mask the password.
							var raw platformEmailConfig
							if err := json.Unmarshal(valueJSON, &raw); err == nil {
								settings.EmailConfig = &EmailConfig{
									SMTPHost:        raw.SMTPHost,
									SMTPPort:        raw.SMTPPort,
									SMTPUsername:    raw.SMTPUsername,
									SMTPPassword:    "", // never expose the stored password
									SMTPPasswordSet: raw.SMTPPassword != "",
									FromEmail:       raw.FromEmail,
									FromName:        raw.FromName,
								}
							}
						}
					}
				}
			}
		}

		c.JSON(http.StatusOK, settings)
	}
}

// UpdatePlatformSettings updates platform-wide settings.
// Persists settings to platform_settings table.
func UpdatePlatformSettings(db *sql.DB) gin.HandlerFunc {
	return updatePlatformSettingsWithStore(newPlatformSettingsStore(db))
}

func updatePlatformSettingsWithStore(store platformSettingsStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context (set by auth middleware)
		userIDStr, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}

		userID, err := uuid.Parse(userIDStr.(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			return
		}

		var settings PlatformSettings
		if err := c.ShouldBindJSON(&settings); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}

		// Validate settings (basic validation)
		if settings.PasswordMinLength != nil && *settings.PasswordMinLength < 4 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password minimum length must be at least 4"})
			return
		}

		if settings.SessionTimeoutMinutes != nil && *settings.SessionTimeoutMinutes < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Session timeout must be at least 1 minute"})
			return
		}

		if settings.PcapMaxUploadSizeMB != nil {
			if *settings.PcapMaxUploadSizeMB < 1 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "PCAP upload size limit must be at least 1 MB"})
				return
			}
			if *settings.PcapMaxUploadSizeMB > 5000 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "PCAP upload size limit cannot exceed 5000 MB"})
				return
			}
		}

		// Persist settings to database
		// Use upsert pattern for each setting
		upsertSetting := func(key string, value interface{}) error {
			valueJSON, err := json.Marshal(value)
			if err != nil {
				return err
			}
			return store.UpsertSetting(c.Request.Context(), key, valueJSON, userID)
		}

		// Update each setting that is provided
		if settings.PlatformName != "" {
			if err := upsertSetting("platform_name", settings.PlatformName); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update platform_name"})
				return
			}
		}
		if settings.PlatformDomain != "" {
			if err := upsertSetting("platform_domain", settings.PlatformDomain); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update platform_domain"})
				return
			}
		}
		if settings.AdminUIBaseURL != "" {
			if err := upsertSetting("admin_ui_base_url", settings.AdminUIBaseURL); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update admin_ui_base_url"})
				return
			}
		}
		if settings.PlatformLoginLogoURL != nil {
			if err := upsertSetting("platform_login_logo_url", *settings.PlatformLoginLogoURL); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update platform_login_logo_url"})
				return
			}
		}
		if settings.SupportEmail != "" {
			if err := upsertSetting("support_email", settings.SupportEmail); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update support_email"})
				return
			}
		}
		if settings.EmailVerificationRequired != nil {
			if err := upsertSetting("email_verification_required", *settings.EmailVerificationRequired); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update email_verification_required"})
				return
			}
		}
		if settings.AdminEmailVerificationRequired != nil {
			if err := upsertSetting("admin_email_verification_required", *settings.AdminEmailVerificationRequired); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update admin_email_verification_required"})
				return
			}
		}
		if settings.RegistrationEnabled != nil {
			if err := upsertSetting("registration_enabled", *settings.RegistrationEnabled); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update registration_enabled"})
				return
			}
		}
		if settings.BlockPersonalEmailDomains != nil {
			if err := upsertSetting("block_personal_email_domains", *settings.BlockPersonalEmailDomains); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update block_personal_email_domains"})
				return
			}
		}
		if settings.PasswordMinLength != nil {
			if err := upsertSetting("password_min_length", *settings.PasswordMinLength); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password_min_length"})
				return
			}
		}
		if settings.SessionTimeoutMinutes != nil {
			if err := upsertSetting("session_timeout_minutes", *settings.SessionTimeoutMinutes); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update session_timeout_minutes"})
				return
			}
		}
		if settings.MaxLoginAttempts != nil {
			if err := upsertSetting("max_login_attempts", *settings.MaxLoginAttempts); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update max_login_attempts"})
				return
			}
		}
		if settings.LockoutDurationMinutes != nil {
			if err := upsertSetting("lockout_duration_minutes", *settings.LockoutDurationMinutes); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update lockout_duration_minutes"})
				return
			}
		}
		if settings.PcapMaxUploadSizeMB != nil {
			if err := upsertSetting("pcap_max_upload_size_mb", *settings.PcapMaxUploadSizeMB); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update pcap_max_upload_size_mb"})
				return
			}
		}

		// Update UI config if provided
		if settings.UIConfig != nil {
			if err := upsertSetting("ui_config", settings.UIConfig); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update ui_config"})
				return
			}
		}

		if settings.LogStorageConfig != nil {
			if err := upsertSetting("log_storage_config", settings.LogStorageConfig); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update log_storage_config"})
				return
			}
		}

		if settings.EmailConfig != nil {
			ec := settings.EmailConfig
			// Determine the password to persist. A new password is normalized
			// (callers commonly paste Gmail app passwords in the spaced
			// "xxxx xxxx xxxx xxxx" display form, which SMTP AUTH rejects) and
			// then encrypted at rest. An empty string means "keep the current
			// one" — preserve the already-stored value verbatim so we don't
			// double-encrypt it.
			var storedPassword string
			if ec.SMTPPassword != "" {
				clean := strings.ReplaceAll(ec.SMTPPassword, " ", "")
				storedPassword = smtpEncrypt(clean)
			} else {
				if existing, err := store.ListSettings(c.Request.Context()); err == nil {
					for _, kv := range existing {
						if kv.Key == "email_config" {
							var prev platformEmailConfig
							if json.Unmarshal(kv.Value, &prev) == nil {
								storedPassword = prev.SMTPPassword
							}
						}
					}
				}
			}
			toStore := platformEmailConfig{
				SMTPHost:     ec.SMTPHost,
				SMTPPort:     ec.SMTPPort,
				SMTPUsername: ec.SMTPUsername,
				SMTPPassword: storedPassword,
				FromEmail:    ec.FromEmail,
				FromName:     ec.FromName,
			}
			if err := upsertSetting("email_config", toStore); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update email_config"})
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"message":  "Settings updated successfully",
			"settings": settings,
		})
	}
}

// Helper functions for pointer creation
func boolPtr(b bool) *bool {
	return &b
}

func intPtr(i int) *int {
	return &i
}
