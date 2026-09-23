package handlers

// Platform Identity Providers — CRUD over `platform_sso_providers`, the
// global config for VISTA'S OWN OAuth app used by social signup ("Sign up with
// Google/Microsoft") and by staff sign-in to the admin console. This is
// NOT a tenant's IdP (that's auth-service's /tenant/sso/providers) — it's one
// row per (provider type, purpose) for the whole platform.
//
// Authorization: reads are gated by platform.settings; EVERY write (create,
// update — which is also how a provider is enabled or disabled — and delete) is
// gated by platform.security.manage in server.go. An admin_login row decides
// who can sign in as staff: its token/userinfo endpoints are trusted to name
// the platform user, so whoever can write one can sign in as any staff member.
// A signup row decides who can found a tenant. Neither is a "setting".
//
// The client secret is encrypted at rest with ENCRYPTION_MASTER_KEY and never
// returned (has_secret flags whether one is stored). Every write records
// updated_by — the staff SSO callback trusts an admin_login provider to sign in
// a super administrator only when a super administrator made the last change
// (see staffSSOProviderTrustedForSuperAdmin) — and emits a platform audit event
// naming the changed fields, never the secret.

import (
	"database/sql"
	"errors"
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

// platformIdPFields is the non-secret, mutable part of a provider row — what an
// update can change and what its audit event may carry.
type platformIdPFields struct {
	ProviderName string
	ClientID     string
	AuthURL      string
	TokenURL     string
	UserinfoURL  string
	Scopes       string
	IsEnabled    bool
}

// platformIdPFieldOrder fixes the order changed fields are reported in.
var platformIdPFieldOrder = []string{"provider_name", "client_id", "auth_url", "token_url", "userinfo_url", "scopes", "is_enabled"}

func (f platformIdPFields) values() map[string]interface{} {
	return map[string]interface{}{
		"provider_name": f.ProviderName,
		"client_id":     f.ClientID,
		"auth_url":      f.AuthURL,
		"token_url":     f.TokenURL,
		"userinfo_url":  f.UserinfoURL,
		"scopes":        f.Scopes,
		"is_enabled":    f.IsEnabled,
	}
}

// diff names the fields whose value differs between f and next.
func (f platformIdPFields) diff(next platformIdPFields) []string {
	a, b := f.values(), next.values()
	changed := []string{}
	for _, k := range platformIdPFieldOrder {
		if a[k] != b[k] {
			changed = append(changed, k)
		}
	}
	return changed
}

// auditValues is the secret-free record of the named fields' new values. The
// client secret is represented only by whether this write set it.
func (f platformIdPFields) auditValues(fields []string, secretWritten bool) map[string]interface{} {
	all := f.values()
	out := map[string]interface{}{"client_secret_rotated": secretWritten}
	for _, k := range fields {
		if v, ok := all[k]; ok {
			out[k] = v
		}
	}
	return out
}

// platformIdPCaller returns the authenticated platform user making a write, or
// writes a 401 and reports false. Every write records its author (updated_by),
// so an unattributed write is refused rather than stored.
func platformIdPCaller(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.GetString("userID"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return uuid.Nil, false
	}
	return id, true
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
// per (provider type, purpose) — a duplicate returns 409.
func CreatePlatformIdentityProvider(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		callerID, ok := platformIdPCaller(c)
		if !ok {
			return
		}
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
			    (provider_type, provider_name, purpose, client_id, client_secret_encrypted, auth_url, token_url, userinfo_url, scopes, is_enabled, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			RETURNING id`,
			req.ProviderType, name, purpose, req.ClientID, platformSecretEncrypt(req.ClientSecret),
			req.AuthURL, req.TokenURL, req.UserinfoURL, scopes, enabled, callerID).Scan(&id)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
				c.JSON(http.StatusConflict, gin.H{"error": "An identity provider of this type and purpose already exists. Edit it instead."})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create identity provider"})
			return
		}

		created := platformIdPFields{
			ProviderName: name, ClientID: req.ClientID, AuthURL: req.AuthURL, TokenURL: req.TokenURL,
			UserinfoURL: req.UserinfoURL, Scopes: scopes, IsEnabled: enabled,
		}
		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "platform_identity_provider.created",
			Action:        "create",
			EventCategory: "config",
			ResourceType:  "platform_identity_provider",
			ResourceID:    id,
			ChangedFields: append(append([]string(nil), platformIdPFieldOrder...), "client_secret"),
			NewValues:     created.auditValues(platformIdPFieldOrder, true),
			Metadata:      map[string]interface{}{"provider_type": req.ProviderType, "purpose": purpose},
		})
		c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Identity provider created"})
	}
}

// UpdatePlatformIdentityProvider handles PUT /admin/identity-providers/:id.
// A blank client_secret keeps the stored one; a blank provider_name, client_id,
// auth_url, token_url or scopes keeps the stored value. userinfo_url and
// is_enabled are always taken from the request (is_enabled defaults to true).
// provider_type and purpose are immutable.
//
// The stored row is read under FOR UPDATE so the audit event names the fields
// that actually changed. Any update — even one that changes nothing — records
// the caller as updated_by: re-saving a provider is how a super administrator
// vouches for it again.
func UpdatePlatformIdentityProvider(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		callerID, ok := platformIdPCaller(c)
		if !ok {
			return
		}
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

		ctx := c.Request.Context()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update identity provider"})
			return
		}
		defer func() { _ = tx.Rollback() }()

		var before platformIdPFields
		var providerType, purpose string
		err = tx.QueryRowContext(ctx, `
			SELECT provider_type, purpose, provider_name, client_id, auth_url, token_url, userinfo_url, scopes, is_enabled
			FROM platform_sso_providers WHERE id = $1 FOR UPDATE`, id).
			Scan(&providerType, &purpose, &before.ProviderName, &before.ClientID, &before.AuthURL,
				&before.TokenURL, &before.UserinfoURL, &before.Scopes, &before.IsEnabled)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Identity provider not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update identity provider"})
			return
		}

		after := before
		for dst, v := range map[*string]string{
			&after.ProviderName: req.ProviderName,
			&after.ClientID:     req.ClientID,
			&after.AuthURL:      req.AuthURL,
			&after.TokenURL:     req.TokenURL,
			&after.Scopes:       req.Scopes,
		} {
			if v != "" {
				*dst = v
			}
		}
		after.UserinfoURL = req.UserinfoURL
		after.IsEnabled = true
		if req.IsEnabled != nil {
			after.IsEnabled = *req.IsEnabled
		}
		// COALESCE keeps the stored secret when the caller sends a blank one.
		var newSecret interface{}
		secretRotated := strings.TrimSpace(req.ClientSecret) != ""
		if secretRotated {
			newSecret = platformSecretEncrypt(req.ClientSecret)
		}

		if _, err := tx.ExecContext(ctx, `
			UPDATE platform_sso_providers SET
			    provider_name = $2,
			    client_id     = $3,
			    client_secret_encrypted = COALESCE($4, client_secret_encrypted),
			    auth_url      = $5,
			    token_url     = $6,
			    userinfo_url  = $7,
			    scopes        = $8,
			    is_enabled    = $9,
			    updated_by    = $10,
			    updated_at    = now()
			WHERE id = $1`,
			id, after.ProviderName, after.ClientID, newSecret,
			after.AuthURL, after.TokenURL, after.UserinfoURL, after.Scopes, after.IsEnabled, callerID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update identity provider"})
			return
		}
		if err := tx.Commit(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update identity provider"})
			return
		}

		changed := before.diff(after)
		values := after.auditValues(changed, secretRotated)
		if secretRotated {
			changed = append(changed, "client_secret")
		}
		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "platform_identity_provider.updated",
			Action:        "update",
			EventCategory: "config",
			ResourceType:  "platform_identity_provider",
			ResourceID:    id.String(),
			ChangedFields: changed,
			NewValues:     values,
			Metadata:      map[string]interface{}{"provider_type": providerType, "purpose": purpose},
		})
		c.JSON(http.StatusOK, gin.H{"message": "Identity provider updated"})
	}
}

// DeletePlatformIdentityProvider handles DELETE /admin/identity-providers/:id.
func DeletePlatformIdentityProvider(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := platformIdPCaller(c); !ok {
			return
		}
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
			return
		}
		var providerType, purpose string
		err = db.QueryRow(`DELETE FROM platform_sso_providers WHERE id = $1 RETURNING provider_type, purpose`, id).
			Scan(&providerType, &purpose)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Identity provider not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete identity provider"})
			return
		}
		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "platform_identity_provider.deleted",
			Action:        "delete",
			EventCategory: "config",
			ResourceType:  "platform_identity_provider",
			ResourceID:    id.String(),
			Metadata:      map[string]interface{}{"provider_type": providerType, "purpose": purpose},
		})
		c.JSON(http.StatusOK, gin.H{"message": "Identity provider deleted"})
	}
}
