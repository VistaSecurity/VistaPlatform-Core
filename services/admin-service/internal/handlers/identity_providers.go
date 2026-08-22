package handlers

// Platform Identity Providers — CRUD over `platform_sso_providers`, the
// global config for VISTA'S OWN OAuth app used by social signup ("Sign up with
// Google/Microsoft"). This is NOT a tenant's IdP (that's auth-service's
// /tenant/sso/providers) — it's one row per provider type for the whole platform.
// Gated by platform.settings; the client secret is encrypted at rest with
// ENCRYPTION_MASTER_KEY and never returned to the UI.

import (
	"database/sql"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

var validPlatformProviderTypes = map[string]bool{"google": true, "microsoft": true}

// titleProviderType capitalises a provider type for display. It is only ever
// called after req.ProviderType has been validated against
// validPlatformProviderTypes, so the input is a single lower-case ASCII word
// ("google" / "microsoft") and this is exactly equivalent to the deprecated
// strings.Title for those inputs.
func titleProviderType(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// purpose: 'signup' = Vista's app for tenant founders; 'admin_login' =
// staff sign-in to admin-ui. One row per (provider_type, purpose).
var validPlatformProviderPurposes = map[string]bool{"signup": true, "admin_login": true}

type platformIdPRequest struct {
	ProviderType string `json:"provider_type"`
	ProviderName string `json:"provider_name"`
	Purpose      string `json:"purpose"` // signup (default) | admin_login; immutable on update
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` // write-only; blank on update = keep existing
	AuthURL      string `json:"auth_url"`
	TokenURL     string `json:"token_url"`
	UserinfoURL  string `json:"userinfo_url"`
	Scopes       string `json:"scopes"`
	IsEnabled    *bool  `json:"is_enabled"`
}

type platformIdPResponse struct {
	ID           string `json:"id"`
	ProviderType string `json:"provider_type"`
	ProviderName string `json:"provider_name"`
	Purpose      string `json:"purpose"`
	ClientID     string `json:"client_id"`
	HasSecret    bool   `json:"has_secret"` // the secret is never returned; this flags whether one is set
	AuthURL      string `json:"auth_url"`
	TokenURL     string `json:"token_url"`
	UserinfoURL  string `json:"userinfo_url"`
	Scopes       string `json:"scopes"`
	IsEnabled    bool   `json:"is_enabled"`
}

// platformSecretEncrypt encrypts a client secret for storage. Mirrors smtpEncrypt:
// a missing master key (dev) falls back to plaintext rather than failing the save.
func platformSecretEncrypt(plaintext string) string {
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

// ListPlatformIdentityProviders handles GET /admin/identity-providers.
func ListPlatformIdentityProviders(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := db.Query(`
			SELECT id, provider_type, provider_name, purpose, client_id, client_secret_encrypted,
			       auth_url, token_url, userinfo_url, scopes, is_enabled
			FROM platform_sso_providers
			ORDER BY purpose, provider_type`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list identity providers"})
			return
		}
		defer func() { _ = rows.Close() }()
		providers := []platformIdPResponse{}
		for rows.Next() {
			var p platformIdPResponse
			var secret string
			if err := rows.Scan(&p.ID, &p.ProviderType, &p.ProviderName, &p.Purpose, &p.ClientID, &secret,
				&p.AuthURL, &p.TokenURL, &p.UserinfoURL, &p.Scopes, &p.IsEnabled); err == nil {
				p.HasSecret = secret != ""
				providers = append(providers, p)
			}
		}
		c.JSON(http.StatusOK, gin.H{"providers": providers})
	}
}

// CreatePlatformIdentityProvider handles POST /admin/identity-providers. One row
// per provider type (unique constraint) — a duplicate type returns 409.
func CreatePlatformIdentityProvider(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req platformIdPRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		req.ProviderType = strings.ToLower(strings.TrimSpace(req.ProviderType))
		if !validPlatformProviderTypes[req.ProviderType] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider type", "valid_types": []string{"google", "microsoft"}})
			return
		}
		purpose := strings.TrimSpace(req.Purpose)
		if purpose == "" {
			purpose = "signup"
		}
		if !validPlatformProviderPurposes[purpose] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid purpose", "valid_purposes": []string{"signup", "admin_login"}})
			return
		}
		if req.ClientID == "" || req.ClientSecret == "" || req.AuthURL == "" || req.TokenURL == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "client_id, client_secret, auth_url, and token_url are required"})
			return
		}
		name := req.ProviderName
		if name == "" {
			name = titleProviderType(req.ProviderType)
		}
		scopes := req.Scopes
		if scopes == "" {
			scopes = "openid email profile"
		}
		enabled := true
		if req.IsEnabled != nil {
			enabled = *req.IsEnabled
		}

		var id string
		err := db.QueryRow(`
			INSERT INTO platform_sso_providers
			    (provider_type, provider_name, purpose, client_id, client_secret_encrypted, auth_url, token_url, userinfo_url, scopes, is_enabled)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			RETURNING id`,
			req.ProviderType, name, purpose, req.ClientID, platformSecretEncrypt(req.ClientSecret),
			req.AuthURL, req.TokenURL, req.UserinfoURL, scopes, enabled).Scan(&id)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
				c.JSON(http.StatusConflict, gin.H{"error": "An identity provider of this type and purpose already exists. Edit it instead."})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create identity provider"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Identity provider created"})
	}
}

// UpdatePlatformIdentityProvider handles PUT /admin/identity-providers/:id.
// A blank client_secret keeps the stored one. provider_type is immutable.
func UpdatePlatformIdentityProvider(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
			return
		}
		var req platformIdPRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		enabled := true
		if req.IsEnabled != nil {
			enabled = *req.IsEnabled
		}
		// COALESCE keeps the stored secret when the caller sends a blank one.
		var newSecret interface{}
		if strings.TrimSpace(req.ClientSecret) != "" {
			newSecret = platformSecretEncrypt(req.ClientSecret)
		} else {
			newSecret = nil
		}
		res, err := db.Exec(`
			UPDATE platform_sso_providers SET
			    provider_name = COALESCE(NULLIF($2,''), provider_name),
			    client_id     = COALESCE(NULLIF($3,''), client_id),
			    client_secret_encrypted = COALESCE($4, client_secret_encrypted),
			    auth_url      = COALESCE(NULLIF($5,''), auth_url),
			    token_url     = COALESCE(NULLIF($6,''), token_url),
			    userinfo_url  = $7,
			    scopes        = COALESCE(NULLIF($8,''), scopes),
			    is_enabled    = $9,
			    updated_at    = now()
			WHERE id = $1`,
			id, req.ProviderName, req.ClientID, newSecret,
			req.AuthURL, req.TokenURL, req.UserinfoURL, req.Scopes, enabled)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update identity provider"})
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Identity provider not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Identity provider updated"})
	}
}

// DeletePlatformIdentityProvider handles DELETE /admin/identity-providers/:id.
func DeletePlatformIdentityProvider(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
			return
		}
		res, err := db.Exec(`DELETE FROM platform_sso_providers WHERE id = $1`, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete identity provider"})
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Identity provider not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Identity provider deleted"})
	}
}
