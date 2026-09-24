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
//
// Two further gates sit between the userinfo response and the session:
//
//  1. The email must be VERIFIED — the shared ssoclaims policy every SSO path
// uses. Either the IdP asserts email_verified, or (Microsoft Entra,
//     which never sends the claim) the provider carries a non-empty
//     allowed_email_domains list, the email's domain exactly matches an entry
//     (ASCII, case-insensitive, no subdomains), AND the provider's authorize
//     and token URLs name a single Entra directory. The last condition is what
//     keeps the domain rule from being the "nOAuth" hole: Entra does not verify
//     the email claim, so through a multi-tenant endpoint (common,
//     organizations, consumers) any directory's administrator could assert an
//     allow-listed address. An empty list keeps the claim mandatory. Refusals
//     are audited with the specific reason; a success records which rule
//     verified the address.
//  2. A provider signs in only staff its last writer (updated_by) outranks.
//     Provider writes need platform.security.manage, which the seed grants to
//     super_admin alone — but an owner can grant it to a custom role, and the
//     provider's token/userinfo endpoints name the account that signs in. So:
//       - a SUPER ADMINISTRATOR signs in only through a provider whose last
//         writer is, now, an active super administrator;
//       - anyone else signs in only if the last writer currently holds every
//         permission of that person's role (the same "does this role outrank
//         the caller?" test platform-user management uses). A provider with no
//         recorded writer (saved before updated_by existed) still signs in
//         non-super staff, so an upgrade does not lock them out.
//     Holding platform.security.manage is therefore never, by itself, a path
//     into an account with permissions the holder lacks. Every outcome is
//     audited; password sign-in (break-glass) is unaffected.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/shared/security/authpolicy"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
	"github.com/vistasecurity/vistaplatform/shared/security/ssoclaims"
)

// staffSSOSuperAdminRole is the seeded platform role that holds every platform
// permission.
const staffSSOSuperAdminRole = "super_admin"

// staffSSOProviderTrustedForSuperAdmin reports whether the provider's last
// writer (platform_sso_providers.updated_by) is, NOW, an active super
// administrator. It fails closed: a row no one is recorded against (created
// before updated_by existed, or its author deleted), an author since demoted
// or deactivated — all untrusted until a super administrator saves the
// provider again.
func staffSSOProviderTrustedForSuperAdmin(db *sql.DB, updatedBy uuid.NullUUID) (bool, error) {
	if !updatedBy.Valid {
		return false, nil
	}
	var trusted bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM platform_users pu
			JOIN platform_roles pr ON pr.id = pu.role_id
			WHERE pu.id = $1 AND pr.name = $2 AND pu.is_active = true AND pu.deleted_at IS NULL)`,
		updatedBy.UUID, staffSSOSuperAdminRole).Scan(&trusted)
	return trusted, err
}

// staffSSOProviderTrustedFor reports whether a provider last written by
// updatedBy may sign in a platform user holding targetRoleID (targetRoleName).
// Super administrators keep the stricter named-role rule above. For everyone
// else the writer must currently hold every permission the target's role
// grants — evaluated through platform_user_has_permission, so a writer since
// deactivated, deleted or demoted below the target is untrusted until someone
// who does outrank the target saves the provider again. A NULL writer (a row
// saved before updated_by existed) is trusted for non-super staff only.
func staffSSOProviderTrustedFor(ctx context.Context, db *sql.DB, updatedBy uuid.NullUUID, targetRoleID uuid.UUID, targetRoleName string) (bool, error) {
	if targetRoleName == staffSSOSuperAdminRole {
		return staffSSOProviderTrustedForSuperAdmin(db, updatedBy)
	}
	if !updatedBy.Valid {
		return true, nil
	}
	missing, err := rolePermissionsNotHeldBy(ctx, db, updatedBy.UUID.String(), targetRoleID.String())
	if err != nil {
		return false, err
	}
	return len(missing) == 0, nil
}

// recordStaffSSORefusal audits a staff SSO sign-in the callback refused after
// the IdP answered. The request has no session, so the actor is the identity
// the provider asserted (and the matched platform user, when there is one).
func recordStaffSSORefusal(c *gin.Context, reason, userID, email, providerType, providerID string) {
	recordStaffSSOLogin(c, true, reason, userID, email, providerType, providerID)
}

// recordStaffSSOLogin audits a staff SSO sign-in outcome. failed=false records
// a session issued through the provider (reason empty). extra is key/value
// pairs added to the event metadata.
func recordStaffSSOLogin(c *gin.Context, failed bool, reason, userID, email, providerType, providerID string, extra ...string) {
	meta := map[string]interface{}{"provider_type": providerType, "purpose": "admin_login"}
	if reason != "" {
		meta["reason"] = reason
	}
	for i := 0; i+1 < len(extra); i += 2 {
		meta[extra[i]] = extra[i+1]
	}
	recordPlatformAudit(c, PlatformAuditEntry{
		EventType:     "auth.sso_login",
		Action:        "sso_login",
		EventCategory: "authentication",
		ResourceType:  "platform_identity_provider",
		ResourceID:    providerID,
		Failed:        failed,
		ErrorCode:     reason,
		ActorID:       userID,
		ActorEmail:    email,
		Metadata:      meta,
	})
}

// Staff SSO email-verification outcomes. The refusal codes are the audit
// event's error_code; the success values are its email_verified_by metadata.
const (
	staffEmailVerifiedByClaim  = "idp_claim"
	staffEmailVerifiedByDomain = "allowed_domain"

	staffRefusalEmailNotVerified   = "email_not_verified"
	staffRefusalDomainNotAllowed   = "email_domain_not_allowed"
	staffRefusalDomainsMultiTenant = "allowed_domains_multi_tenant_authority"
)

// staffSSOEmailVerification decides gate 1. It returns how the address was
// verified, or a refusal code. The domain rule is the shared ssoclaims one
// (Microsoft only, exact ASCII match, never for an empty list) and applies
// only while BOTH the authorize and token URLs name a single Entra directory —
// admin-service refuses to save a list otherwise, and this re-check keeps a
// row changed behind its back (or saved before the rule) from relaxing the
// gate. An IdP that SENDS email_verified and says anything but true is
// believed: the domain rule stands in for a claim Entra omits, never for one
// that contradicts it.
func staffSSOEmailVerification(claim interface{}, providerType, email, authURL, tokenURL string, allowedDomains []string) (string, string) {
	if ssoclaims.EmailVerifiedClaim(claim) {
		return staffEmailVerifiedByClaim, ""
	}
	if claim != nil || len(allowedDomains) == 0 || providerType != "microsoft" {
		return "", staffRefusalEmailNotVerified
	}
	if !ssoclaims.EntraAuthorityIsSingleTenant(authURL) || !ssoclaims.EntraAuthorityIsSingleTenant(tokenURL) {
		return "", staffRefusalDomainsMultiTenant
	}
	if !ssoclaims.EmailEffectivelyVerified(false, providerType, email, allowedDomains) {
		return "", staffRefusalDomainNotAllowed
	}
	return staffEmailVerifiedByDomain, ""
}

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

		var providerID, clientID, secretEnc, authURL, tokenURL, userinfoURL string
		var providerUpdatedBy uuid.NullUUID
		var allowedDomains []string
		if err := db.QueryRow(`
			SELECT id, client_id, client_secret_encrypted, auth_url, token_url, userinfo_url, updated_by, allowed_email_domains FROM platform_sso_providers
			WHERE provider_type = $1 AND purpose = 'admin_login' AND is_enabled = true
		`, providerType).Scan(&providerID, &clientID, &secretEnc, &authURL, &tokenURL, &userinfoURL, &providerUpdatedBy, pq.Array(&allowedDomains)); err != nil {
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
		// ASCII-only folding: strings.ToLower would map a non-ASCII lookalike
		// (U+212A KELVIN SIGN -> "k") onto an existing staff address.
		email = ssoclaims.CanonicalEmail(email)
		if email == "" {
			c.Redirect(http.StatusFound, "/login?error=sso_no_email")
			return
		}

		// Gate 1: the address must be verified — by the IdP's own claim, or by
		// the provider's allowed-domain list under the conditions above.
		verifiedBy, refusal := staffSSOEmailVerification(ui["email_verified"], providerType, email, authURL, tokenURL, allowedDomains)
		if refusal != "" {
			recordStaffSSORefusal(c, refusal, "", email, providerType, providerID)
			c.Redirect(http.StatusFound, "/login?error=sso_email_unverified")
			return
		}

		// Match an EXISTING active platform admin — never provision from the IdP.
		var userID, roleID uuid.UUID
		var roleName string
		var forcePasswordChange bool
		err = db.QueryRow(`
			SELECT pu.id, pr.id, pr.name, pu.force_password_change FROM platform_users pu
			JOIN platform_roles pr ON pu.role_id = pr.id
			WHERE pu.email = $1 AND pu.is_active = true AND pu.deleted_at IS NULL
		`, email).Scan(&userID, &roleID, &roleName, &forcePasswordChange)
		if err != nil {
			c.Redirect(http.StatusFound, "/login?error=no_admin_account")
			return
		}

		// Gate 2: only staff the provider's last writer outranks (a super
		// administrator: only a provider a super administrator last configured).
		trusted, terr := staffSSOProviderTrustedFor(c.Request.Context(), db, providerUpdatedBy, roleID, roleName)
		if terr != nil {
			recordStaffSSORefusal(c, "provider_trust_check_error", userID.String(), email, providerType, providerID)
			c.Redirect(http.StatusFound, "/login?error=sso_session")
			return
		}
		if !trusted {
			if roleName == staffSSOSuperAdminRole {
				recordStaffSSORefusal(c, "super_admin_provider_untrusted", userID.String(), email, providerType, providerID)
				c.Redirect(http.StatusFound, "/login?error=sso_super_admin_untrusted_provider")
				return
			}
			recordStaffSSORefusal(c, "provider_author_outranked", userID.String(), email, providerType, providerID)
			c.Redirect(http.StatusFound, "/login?error=sso_untrusted_provider")
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
		setPlatformAuthCookies(c, accessToken, 3600, int(sessionTTL.Seconds()), refreshToken, jwtSecret)
		recordStaffSSOLogin(c, false, "", userID.String(), email, providerType, providerID, "email_verified_by", verifiedBy)
		c.Redirect(http.StatusFound, "/")
	}
}
