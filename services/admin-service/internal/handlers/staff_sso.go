package handlers

// Staff admin SSO: platform admins sign into admin-ui-v2 via the COMPANY
// identity provider. Uses platform_sso_providers rows with purpose='admin_login'.
// It NEVER provisions — it only authenticates an existing active platform_user
// matched by the IdP-asserted email (that match is the security gate: an outside
// Google/MS account can't match a Vista admin's email). On success it issues the
// normal platform session (platform_access_token) and lands the admin in the UI.
//
// OIDC is done manually (no oauth2 dep in admin-service): code→token POST, then a
// userinfo GET. State is carried in a short-lived Lax cookie so it survives the
// IdP's top-level redirect back to the callback.

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/shared/security/authpolicy"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

func staffStateToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func requestIsHTTPS(c *gin.Context) bool {
	return enforceSecureCookies || c.GetHeader("X-Forwarded-Proto") == "https"
}

// adminCallbackRedirectURI is the redirect_uri registered in the IdP — on the
// admin host the request arrived on.
func adminCallbackRedirectURI(c *gin.Context, provider string) string {
	scheme := "http"
	if requestIsHTTPS(c) {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/api/v1/admin-service/admin/sso/%s/callback", scheme, c.Request.Host, provider)
}

func decryptProviderSecret(enc string) string {
	key := os.Getenv("ENCRYPTION_MASTER_KEY")
	if key == "" {
		return enc
	}
	svc, err := encryption.NewService(key)
	if err != nil {
		return enc
	}
	if dec, derr := svc.Decrypt(enc); derr == nil {
		return dec
	}
	return enc
}

// ListStaffSsoProviders handles GET /admin/sso/providers (public): the enabled
// admin-login providers, so the login page can render "Continue with …".
func ListStaffSsoProviders(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := db.Query(`
			SELECT provider_type, provider_name FROM platform_sso_providers
			WHERE purpose = 'admin_login' AND is_enabled = true ORDER BY provider_type`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list providers"})
			return
		}
		defer func() { _ = rows.Close() }()
		providers := []gin.H{}
		for rows.Next() {
			var pt, pn string
			if rows.Scan(&pt, &pn) == nil {
				providers = append(providers, gin.H{"provider_type": pt, "provider_name": pn})
			}
		}
		c.JSON(http.StatusOK, gin.H{"providers": providers})
	}
}

// StaffSsoAuthorize handles GET /admin/sso/:provider/authorize (public).
func StaffSsoAuthorize(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		providerType := c.Param("provider")
		var clientID, authURL, scopes string
		err := db.QueryRow(`
			SELECT client_id, auth_url, scopes FROM platform_sso_providers
			WHERE provider_type = $1 AND purpose = 'admin_login' AND is_enabled = true
		`, providerType).Scan(&clientID, &authURL, &scopes)
		if err != nil {
			c.Redirect(http.StatusFound, "/login?error=sso_unavailable")
			return
		}
		state := staffStateToken()
		http.SetCookie(c.Writer, &http.Cookie{
			Name: "admin_sso_state", Value: state, Path: "/", MaxAge: 600,
			HttpOnly: true, Secure: requestIsHTTPS(c), SameSite: http.SameSiteLaxMode,
		})
		q := url.Values{}
		q.Set("client_id", clientID)
		q.Set("redirect_uri", adminCallbackRedirectURI(c, providerType))
		q.Set("response_type", "code")
		q.Set("scope", scopes)
		q.Set("state", state)
		c.Redirect(http.StatusFound, authURL+"?"+q.Encode())
	}
}

// StaffSsoCallback handles GET /admin/sso/:provider/callback (public).
func StaffSsoCallback(db *sql.DB, jwtSecret string, refreshTokenService *auth.PlatformRefreshTokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		providerType := c.Param("provider")

		// CSRF: the state query param must match the cookie set at authorize.
		stateCookie, _ := c.Cookie("admin_sso_state")
		if stateCookie == "" || c.Query("state") != stateCookie {
			c.Redirect(http.StatusFound, "/login?error=sso_state")
			return
		}
		http.SetCookie(c.Writer, &http.Cookie{Name: "admin_sso_state", Value: "", Path: "/", MaxAge: -1})
		code := c.Query("code")
		if code == "" {
			c.Redirect(http.StatusFound, "/login?error=sso_no_code")
			return
		}

		var clientID, secretEnc, tokenURL, userinfoURL string
		if err := db.QueryRow(`
			SELECT client_id, client_secret_encrypted, token_url, userinfo_url FROM platform_sso_providers
			WHERE provider_type = $1 AND purpose = 'admin_login' AND is_enabled = true
		`, providerType).Scan(&clientID, &secretEnc, &tokenURL, &userinfoURL); err != nil {
			c.Redirect(http.StatusFound, "/login?error=sso_unavailable")
			return
		}

		// Exchange the code for an access token (manual OIDC).
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", adminCallbackRedirectURI(c, providerType))
		form.Set("client_id", clientID)
		form.Set("client_secret", decryptProviderSecret(secretEnc))
		tokResp, err := http.PostForm(tokenURL, form)
		if err != nil {
			c.Redirect(http.StatusFound, "/login?error=sso_exchange")
			return
		}
		defer func() { _ = tokResp.Body.Close() }()
		var tok struct {
			AccessToken string `json:"access_token"`
		}
		if json.NewDecoder(tokResp.Body).Decode(&tok) != nil || tok.AccessToken == "" {
			c.Redirect(http.StatusFound, "/login?error=sso_exchange")
			return
		}

		// Fetch the verified identity.
		req, _ := http.NewRequest(http.MethodGet, userinfoURL, nil)
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		uiResp, err := http.DefaultClient.Do(req)
		if err != nil {
			c.Redirect(http.StatusFound, "/login?error=sso_userinfo")
			return
		}
		defer func() { _ = uiResp.Body.Close() }()
		bodyBytes, _ := io.ReadAll(uiResp.Body)
		var ui map[string]interface{}
		_ = json.Unmarshal(bodyBytes, &ui)
		email, _ := ui["email"].(string)
		email = strings.ToLower(strings.TrimSpace(email))
		if email == "" {
			c.Redirect(http.StatusFound, "/login?error=sso_no_email")
			return
		}

		// Match an EXISTING active platform admin — never provision from the IdP.
		var userID uuid.UUID
		var roleName string
		var forcePasswordChange bool
		err = db.QueryRow(`
			SELECT pu.id, pr.name, pu.force_password_change FROM platform_users pu
			JOIN platform_roles pr ON pu.role_id = pr.id
			WHERE pu.email = $1 AND pu.is_active = true AND pu.deleted_at IS NULL
		`, email).Scan(&userID, &roleName, &forcePasswordChange)
		if err != nil {
			c.Redirect(http.StatusFound, "/login?error=no_admin_account")
			return
		}

		// Issue the platform session — same path as the password login, including
		// the limited change-password-only session when force_password_change is
		// set: the break-glass password still needs rotating even though
		// this sign-in came through the IdP.
		sessionTTL := authpolicy.SessionLifetime(db, defaultPlatformSessionTTL)
		accessToken, refreshToken, err := generateTokens(userID.String(), email, roleName, jwtSecret, forcePasswordChange, sessionTTL)
		if err != nil {
			c.Redirect(http.StatusFound, "/login?error=sso_session")
			return
		}
		expiresAt := time.Now().Add(sessionTTL)
		_, _ = refreshTokenService.StoreRefreshToken(userID, refreshToken, nil, expiresAt, c.ClientIP(), c.Request.UserAgent())
		_, _ = db.Exec(`UPDATE platform_users SET last_login_at = now() WHERE id = $1`, userID)
		setPlatformAuthCookies(c, accessToken, 3600, refreshToken, jwtSecret)
		c.Redirect(http.StatusFound, "/")
	}
}
