package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	sharedemail "github.com/vistasecurity/vistaplatform/shared/email"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// smtpEncrypt encrypts an SMTP password for storage at rest using
// ENCRYPTION_MASTER_KEY. On any failure (no key configured, encryption error) it
// returns the plaintext unchanged so configuration still saves — the read path
// (smtpDecrypt) tolerates plaintext.
func smtpEncrypt(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	key := os.Getenv("ENCRYPTION_MASTER_KEY")
	if key == "" {
		return plaintext
	}
	svc, err := encryption.NewService(key)
	if err != nil {
		return plaintext
	}
	enc, err := svc.Encrypt(plaintext)
	if err != nil {
		return plaintext
	}
	return enc
}

// smtpDecrypt reverses smtpEncrypt. Values stored before encryption-at-rest
// landed (legacy plaintext) fail GCM authentication on Decrypt and are returned
// as-is, so existing configs keep working until the next save re-encrypts them.
func smtpDecrypt(stored string) string {
	if stored == "" {
		return ""
	}
	key := os.Getenv("ENCRYPTION_MASTER_KEY")
	if key == "" {
		return stored
	}
	svc, err := encryption.NewService(key)
	if err != nil {
		return stored
	}
	dec, err := svc.Decrypt(stored)
	if err != nil {
		return stored // legacy plaintext / not our ciphertext
	}
	return dec
}

// platformEmailConfig holds SMTP settings read from platform_settings.
type platformEmailConfig struct {
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     string `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	SMTPPassword string `json:"smtp_password"`
	FromEmail    string `json:"from_email"`
	FromName     string `json:"from_name"`
}

// platformBrandConfig holds branding/URL settings used when building email content.
type platformBrandConfig struct {
	PlatformName string
	AdminUIBase  string // e.g. "https://admin.yourplatform.com"
}

// getEmailService reads SMTP configuration from platform_settings and returns a
// configured EmailService.  Returns an error if SMTP is not configured.
func getEmailService(db *sql.DB) (*sharedemail.EmailService, error) {
	var raw []byte
	err := db.QueryRow(`
		SELECT setting_value FROM platform_settings WHERE setting_key = 'email_config'
	`).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("email is not configured: add SMTP settings in Platform Settings → Integrations")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read email config: %w", err)
	}

	var cfg platformEmailConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("invalid email config format: %w", err)
	}
	if cfg.SMTPHost == "" || cfg.FromEmail == "" {
		return nil, fmt.Errorf("email is not fully configured: smtp_host and from_email are required")
	}

	return sharedemail.NewEmailService(sharedemail.EmailConfig{
		SMTPHost:     cfg.SMTPHost,
		SMTPPort:     cfg.SMTPPort,
		SMTPUsername: cfg.SMTPUsername,
		SMTPPassword: smtpDecrypt(cfg.SMTPPassword),
		FromEmail:    cfg.FromEmail,
		FromName:     cfg.FromName,
	}), nil
}

// getPlatformBrandConfig reads platform_name and admin_ui_base_url from
// platform_settings so that emails and reset links are correctly branded.
// Resolution order for AdminUIBase:
//  1. platform_settings.admin_ui_base_url  (operator-configured via admin UI)
//  2. ADMIN_UI_BASE_URL env var            (injected by the Helm chart from tls.adminDnsName)
//  3. http://localhost:3006                (last-resort local fallback)
func getPlatformBrandConfig(db *sql.DB) platformBrandConfig {
	fallback := "http://localhost:3006"
	if v := os.Getenv("ADMIN_UI_BASE_URL"); v != "" {
		fallback = v
	}
	cfg := platformBrandConfig{
		PlatformName: "Vista",
		AdminUIBase:  fallback,
	}

	rows, err := db.Query(`
		SELECT setting_key, setting_value
		FROM platform_settings
		WHERE setting_key IN ('platform_name', 'admin_ui_base_url')
	`)
	if err != nil {
		return cfg
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var key string
		var val []byte
		if err := rows.Scan(&key, &val); err != nil {
			continue
		}
		var s string
		if err := json.Unmarshal(val, &s); err != nil || s == "" {
			continue
		}
		switch key {
		case "platform_name":
			cfg.PlatformName = s
		case "admin_ui_base_url":
			cfg.AdminUIBase = s
		}
	}
	return cfg
}

// generateSecureToken generates a 32-byte (64 hex char) cryptographically secure token.
func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// hashPasswordResetToken returns the hex-encoded SHA-256 digest of the plaintext token for DB storage.
func hashPasswordResetToken(plainToken string) string {
	sum := sha256.Sum256([]byte(plainToken))
	return hex.EncodeToString(sum[:])
}
