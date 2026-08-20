package api

// Auth-method-agnostic tenant member invitations. An invitation is a
// tokenized, role-scoped intent to grant access, independent of how the invitee
// authenticates. No users row is created until accept — which is what lets a
// single flow serve local-password, Google, and Microsoft/MS365 members without
// the password-account-vs-SSO collision. The raw token lives only in the emailed
// accept link; the DB stores its SHA-256. The SSO accept path is the linchpin:
// the accept page sends the token through /auth/sso/<provider>/authorize, and the
// callback consumes it (consumeInvitationForSSO) to AUTHORIZE binding the IdP
// identity to the invited account — bypassing the email-link-required 409 and the
// email_verified gate (the admin has vouched), for Google and Microsoft alike.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/email"
	"github.com/vistasecurity/vistaplatform/shared/security/authpolicy"
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"
)

const invitationTTL = 7 * 24 * time.Hour

// newInvitationToken returns a URL-safe raw token and its SHA-256 hex hash.
func newInvitationToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, hashInvitationToken(raw), nil
}

func hashInvitationToken(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

// getWebUIBaseURL is the public origin of the tenant app, where /accept-invite
// lives. Prefer WEB_UI_BASE_URL (set by the chart from tls.dnsName), then fall
// back to the OAuth callback base — both resolve to the customer's web origin.
func getWebUIBaseURL(cfg *config.Config) string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("WEB_UI_BASE_URL")), "/"); v != "" {
		return v
	}
	return getBaseURL(cfg)
}

// createInvitation issues a fresh pending invitation, superseding any prior
// pending invite for the same (tenant, email). Returns the row id and raw token.
func createInvitation(db *sql.DB, tenantID uuid.UUID, emailNorm, roleName string, invitedBy uuid.UUID) (uuid.UUID, string, error) {
	raw, hash, err := newInvitationToken()
	if err != nil {
		return uuid.Nil, "", err
	}
	var invitedByArg interface{}
	if invitedBy != uuid.Nil {
		invitedByArg = invitedBy
	}
	// RLS-scoped: invitations carries a tenant_isolation policy; tenant is known
	// from the caller's JWT. Supersede + INSERT run under one tenant-scoped tx so
	// the supersede UPDATE actually sees the prior pending row (fail-closed
	// otherwise) and the INSERT satisfies the WITH CHECK on tenant_id.
	var id uuid.UUID
	err = shareddatabase.WithTenantTx(context.Background(), db, tenantID, func(tx *sql.Tx) error {
		// Supersede any existing pending invite so the partial unique index
		// (one pending per tenant+email) never conflicts.
		if _, err := tx.ExecContext(context.Background(), `
			UPDATE public.invitations SET status = 'revoked'
			WHERE tenant_id = $1 AND lower(email) = lower($2) AND status = 'pending'
		`, tenantID, emailNorm); err != nil {
			return err
		}
		return tx.QueryRowContext(context.Background(), `
			INSERT INTO public.invitations (tenant_id, email, role, invited_by, token_hash, status, expires_at)
			VALUES ($1, $2, $3, $4, $5, 'pending', $6)
			RETURNING id
		`, tenantID, emailNorm, roleName, invitedByArg, hash, time.Now().Add(invitationTTL)).Scan(&id)
	})
	if err != nil {
		return uuid.Nil, "", err
	}
	return id, raw, nil
}

// sendInvitationEmail emails the accept link. Best-effort: a missing/broken SMTP
// config logs and returns — the admin still gets the accept_url in the API
// response to share directly.
func sendInvitationEmail(db *sql.DB, cfg *config.Config, toEmail, rawToken, tenantName string) {
	link := fmt.Sprintf("%s/accept-invite?token=%s", getWebUIBaseURL(cfg), rawToken)
	es, err := email.PlatformEmailService(db)
	if err != nil {
		logrus.WithError(err).Warn("invitation email: no email service configured; share accept_url manually")
		return
	}
	if err := es.SendTenantInviteEmail(toEmail, tenantName, link); err != nil {
		logrus.WithError(err).Warn("invitation email: send failed; share accept_url manually")
	}
}

// invitationAcceptURL builds the public accept link for a raw token.
func invitationAcceptURL(cfg *config.Config, rawToken string) string {
	return fmt.Sprintf("%s/accept-invite?token=%s", getWebUIBaseURL(cfg), rawToken)
}

// --- public: accept page support -----------------------------------------

// LookupInvitation handles GET /auth/invitations/lookup?token=... (public). It
// returns the invited email plus the sign-in methods the tenant offers, so the
// accept page can render "Set a password" and/or "Continue with <provider>".
func LookupInvitation(db *sql.DB, bypassDB *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := strings.TrimSpace(c.Query("token"))
		if raw == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing token"})
			return
		}
		// RLS bypass (pure-output): the invitation's tenant is the RESULT of this
		// lookup, so it cannot be known yet — read it on the BYPASSRLS handle.
		var tenantID uuid.UUID
		var emailAddr, status string
		var expiresAt time.Time
		err := bypassDB.QueryRow(`
			SELECT tenant_id, email, status, expires_at FROM public.invitations WHERE token_hash = $1
		`, hashInvitationToken(raw)).Scan(&tenantID, &emailAddr, &status, &expiresAt)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "This invitation is not valid."})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to look up invitation"})
			return
		}
		if status != "pending" {
			c.JSON(http.StatusGone, gin.H{"error": "This invitation has already been used or was revoked."})
			return
		}
		if time.Now().After(expiresAt) {
			c.JSON(http.StatusGone, gin.H{"error": "This invitation has expired. Ask an administrator to resend it."})
			return
		}

		// Methods the tenant offers: password (unless policy is SSO-only) plus
		// each enabled SSO provider. tenants is not RLS-scoped — read plain.
		var authPolicy string
		_ = db.QueryRow(`SELECT COALESCE(authentication_policy, 'password_only') FROM tenants WHERE id = $1`, tenantID).Scan(&authPolicy)
		allowPassword := authPolicy != "sso_only"

		type ssoMethod struct {
			Provider     string `json:"provider"`
			ProviderName string `json:"provider_name"`
		}
		var providers []ssoMethod
		// RLS-scoped: sso_providers carries a tenant_isolation policy; the tenant
		// was just resolved from the token above, so scope the read to it.
		_ = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			rows, qErr := tx.QueryContext(c.Request.Context(), `
				SELECT provider_type, provider_name FROM public.sso_providers
				WHERE tenant_id = $1 AND is_enabled = true ORDER BY is_default DESC, provider_name
			`, tenantID)
			if qErr != nil {
				return qErr
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var m ssoMethod
				if rows.Scan(&m.Provider, &m.ProviderName) == nil {
					providers = append(providers, m)
				}
			}
			return nil
		})

		var tenantName string
		_ = db.QueryRow(`SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&tenantName)

		c.JSON(http.StatusOK, gin.H{
			"email":          emailAddr,
			"tenant_name":    tenantName,
			"allow_password": allowPassword,
			"sso_providers":  providers,
		})
	}
}

// AcceptInvitation handles POST /auth/invitations/accept (public) for the
// PASSWORD path: { token, password }. SSO acceptance goes through the SSO
// authorize/callback with the token instead. On success the new user is created,
// assigned the invited role, and logged in (cookies set).
func AcceptInvitation(cfg *config.Config, db *sql.DB, bypassDB *sql.DB, jwtService *auth.JWTService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Token    string `json:"token" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		// The split: resolve the invitation by token on the BYPASSRLS handle (its
		// tenant is the output), THEN do every downstream user/invitation write
		// under WithTenantTx(db, inv.tenantID, …) so RLS still enforces on them.
		inv, err := lockPendingInvitation(bypassDB, req.Token)
		if err != nil {
			respondInvitationError(c, err)
			return
		}

		if policyForbidsPassword(db, inv.tenantID) {
			c.JSON(http.StatusForbidden, gin.H{"error": "This organization requires single sign-on. Use one of the SSO options instead."})
			return
		}
		if err := passwordsvc.ValidatePasswordStrengthWithPolicy(db, req.Password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		userID, role, err := materializeInvitedUser(c.Request.Context(), db, inv, func(tx *sql.Tx, uid uuid.UUID) error {
			hashed, hErr := passwordService.HashPassword(req.Password)
			if hErr != nil {
				return hErr
			}
			// RLS-scoped: users carries a tenant_isolation policy. This runs on the
			// same tenant-scoped tx as the INSERT in materializeInvitedUser.
			_, uErr := tx.ExecContext(c.Request.Context(), `UPDATE users SET password_hash = $1 WHERE id = $2`, hashed, uid)
			return uErr
		})
		if err != nil {
			respondInvitationError(c, err)
			return
		}

		// Log the new member in.
		accessToken, refreshToken, tErr := jwtService.GenerateTokens(userID, inv.tenantID, inv.email, role)
		if tErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Account created but sign-in failed; please sign in."})
			return
		}
		rts := auth.NewRefreshTokenService(db)
		_, _ = rts.StoreRefreshToken(userID, refreshToken, nil, time.Now().Add(authpolicy.SessionLifetime(db, jwtService.GetRefreshExpiry())), c.ClientIP(), c.Request.UserAgent())
		setAuthCookiesResponseWriter(c.Writer, cfg, int(jwtService.GetAccessExpiry().Seconds()), accessToken, refreshToken)

		c.JSON(http.StatusOK, gin.H{"message": "Invitation accepted", "redirect": "/dashboard"})
	}
}

// --- admin: list / revoke / resend ----------------------------------------

// ListTenantInvitations handles GET /tenant/{tenantId}/invitations (admin):
// pending invitations for the People & Access view.
func ListTenantInvitations(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := requireCallerTenant(c)
		if !ok {
			return
		}
		type invite struct {
			ID        string    `json:"id"`
			Email     string    `json:"email"`
			Role      string    `json:"role"`
			Status    string    `json:"status"`
			CreatedAt time.Time `json:"created_at"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		invites := []invite{}
		// RLS-scoped: invitations carries a tenant_isolation policy; tenant is
		// known from the caller's JWT.
		err := shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			rows, qErr := tx.QueryContext(c.Request.Context(), `
				SELECT id, email, role, status, created_at, expires_at
				FROM public.invitations
				WHERE tenant_id = $1 AND status = 'pending'
				ORDER BY created_at DESC
			`, tenantID)
			if qErr != nil {
				return qErr
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var i invite
				if rows.Scan(&i.ID, &i.Email, &i.Role, &i.Status, &i.CreatedAt, &i.ExpiresAt) == nil {
					invites = append(invites, i)
				}
			}
			return nil
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list invitations"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"invitations": invites})
	}
}

// RevokeTenantInvitation handles DELETE /tenant/{tenantId}/invitations/{id}.
func RevokeTenantInvitation(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := requireCallerTenant(c)
		if !ok {
			return
		}
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid invitation ID"})
			return
		}
		var affected int64
		// RLS-scoped: invitations carries a tenant_isolation policy; tenant is
		// known from the caller's JWT.
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			res, eErr := tx.ExecContext(c.Request.Context(), `
				UPDATE public.invitations SET status = 'revoked'
				WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
			`, id, tenantID)
			if eErr != nil {
				return eErr
			}
			affected, _ = res.RowsAffected()
			return nil
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke invitation"})
			return
		}
		if affected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "No pending invitation found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Invitation revoked"})
	}
}

// ResendTenantInvitation handles POST /tenant/{tenantId}/invitations/{id}/resend:
// mints a fresh token + expiry and re-sends the email.
func ResendTenantInvitation(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := requireCallerTenant(c)
		if !ok {
			return
		}
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid invitation ID"})
			return
		}
		raw, hash, tErr := newInvitationToken()
		if tErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mint token"})
			return
		}
		// RLS-scoped: invitations carries a tenant_isolation policy; tenant is
		// known from the caller's JWT. The lookup + token UPDATE share one
		// tenant-scoped tx (the tenant-name read below is on tenants — not scoped).
		var emailAddr string
		found := false
		err = shareddatabase.WithTenantTx(c.Request.Context(), db, tenantID, func(tx *sql.Tx) error {
			lErr := tx.QueryRowContext(c.Request.Context(), `SELECT email FROM public.invitations WHERE id = $1 AND tenant_id = $2 AND status = 'pending'`, id, tenantID).Scan(&emailAddr)
			if lErr == sql.ErrNoRows {
				return nil
			}
			if lErr != nil {
				return lErr
			}
			found = true
			_, uErr := tx.ExecContext(c.Request.Context(), `UPDATE public.invitations SET token_hash = $1, expires_at = $2 WHERE id = $3`, hash, time.Now().Add(invitationTTL), id)
			return uErr
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh invitation"})
			return
		}
		if !found {
			c.JSON(http.StatusNotFound, gin.H{"error": "No pending invitation found"})
			return
		}
		var tenantName string
		_ = db.QueryRow(`SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&tenantName)
		sendInvitationEmail(db, cfg, emailAddr, raw, tenantName)
		c.JSON(http.StatusOK, gin.H{"message": "Invitation resent", "accept_url": invitationAcceptURL(cfg, raw)})
	}
}

// --- shared internals ------------------------------------------------------

type pendingInvitation struct {
	id        uuid.UUID
	tenantID  uuid.UUID
	email     string
	role      string
	invitedBy uuid.UUID
}

// lockPendingInvitation loads a still-valid pending invitation by raw token.
// This is THE linchpin token→tenant lookup: the invitation's tenant is the
// OUTPUT, so it cannot be known yet — callers MUST pass the BYPASSRLS handle
// (bypassDB). Under crypto_app with no tenant context set this would fail closed
// (zero rows) and every valid invite would read as "invalid".
func lockPendingInvitation(bypassDB *sql.DB, rawToken string) (*pendingInvitation, error) {
	var inv pendingInvitation
	var invitedBy uuid.NullUUID
	var status string
	var expiresAt time.Time
	err := bypassDB.QueryRow(`
		SELECT id, tenant_id, email, role, invited_by, status, expires_at
		FROM public.invitations WHERE token_hash = $1
	`, hashInvitationToken(rawToken)).Scan(&inv.id, &inv.tenantID, &inv.email, &inv.role, &invitedBy, &status, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, errInvitationInvalid
	}
	if err != nil {
		return nil, err
	}
	if status != "pending" {
		return nil, errInvitationUsed
	}
	if time.Now().After(expiresAt) {
		return nil, errInvitationExpired
	}
	if invitedBy.Valid {
		inv.invitedBy = invitedBy.UUID
	}
	return &inv, nil
}

// materializeInvitedUser creates (or returns) the user for an accepted
// invitation, assigns the invited role, marks the invitation accepted, and runs
// an optional extra step (e.g. set a password) inside the same flow. Returns the
// user id and the assigned role name. Rejects if the email is already an active
// user in the tenant (the invite should be revoked/used instead).
func materializeInvitedUser(ctx context.Context, db *sql.DB, inv *pendingInvitation, extra func(*sql.Tx, uuid.UUID) error) (uuid.UUID, string, error) {
	// inv.role is already an internal role name (mapped at invite-create time).
	roleName := inv.role
	userID := uuid.New()
	if err := ensureRoleGrantableByName(ctx, db, inv.tenantID, inv.invitedBy, roleName); err != nil {
		return uuid.Nil, "", err
	}

	// The existing-user check, the user INSERT, and the optional extra step (set a
	// password) are all RLS-scoped (users carries a tenant_isolation policy). They
	// share ONE tenant-scoped tx: the INSERT's WITH CHECK on tenant_id is
	// satisfied, and the existence check fails closed unless the tenant is set.
	emailTaken := false
	localPart := strings.ToLower(inv.email)
	if i := strings.IndexByte(localPart, '@'); i > 0 {
		localPart = localPart[:i]
	}
	err := shareddatabase.WithTenantTx(ctx, db, inv.tenantID, func(tx *sql.Tx) error {
		var existing uuid.UUID
		emailErr := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE tenant_id = $1 AND lower(email) = lower($2) AND deleted_at IS NULL`, inv.tenantID, inv.email).Scan(&existing)
		if emailErr == nil {
			emailTaken = true
			return nil
		}
		if emailErr != sql.ErrNoRows {
			return emailErr
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO users (id, tenant_id, email, first_name, last_name, is_active, email_verified, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, true, true, NOW(), NOW())
		`, userID, inv.tenantID, strings.ToLower(inv.email), localPart, ""); err != nil {
			return err
		}
		if extra != nil {
			if err := extra(tx, userID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, "", err
	}
	if emailTaken {
		return uuid.Nil, "", errInvitationEmailTaken
	}

	// assignUserRole owns its own WithTenantTx (tenant_roles + user_tenant_roles
	// are RLS-scoped). TODO(rls): if user_roles ever gains a tenant_isolation
	// policy, this still threads the tenant via assignUserRole's own context.
	if err := assignUserRole(db, userID, inv.tenantID, inv.invitedBy, roleName); err != nil {
		return uuid.Nil, "", err
	}

	// RLS-scoped: invitations carries a tenant_isolation policy; tenant is known.
	if err := shareddatabase.WithTenantTx(ctx, db, inv.tenantID, func(tx *sql.Tx) error {
		_, uErr := tx.ExecContext(ctx, `
			UPDATE public.invitations SET status = 'accepted', accepted_at = NOW(), accepted_user_id = $1 WHERE id = $2
		`, userID, inv.id)
		return uErr
	}); err != nil {
		return uuid.Nil, "", err
	}
	return userID, roleName, nil
}

// consumeInvitationForSSO is the linchpin: called from the SSO callback when an
// invitation token rode through the OAuth state. It validates the token against
// the IdP-asserted email + tenant and, if valid, materializes/links the invited
// user with the invited role — authorizing the bind without email_verified or
// the email-link-required 409. Returns (userID, role, true) on success.
func consumeInvitationForSSO(db *sql.DB, bypassDB *sql.DB, rawToken, idpEmail string, tenantID uuid.UUID) (uuid.UUID, string, bool) {
	// Token lookup on the BYPASSRLS handle (tenant is the output); the downstream
	// user/invitation writes inside materializeInvitedUser are tenant-scoped.
	inv, err := lockPendingInvitation(bypassDB, rawToken)
	if err != nil {
		return uuid.Nil, "", false
	}
	if inv.tenantID != tenantID || !strings.EqualFold(inv.email, idpEmail) {
		return uuid.Nil, "", false
	}
	userID, role, mErr := materializeInvitedUser(context.Background(), db, inv, nil)
	if mErr != nil {
		logrus.WithError(mErr).WithField("invitation_id", inv.id).Warn("SSO invite acceptance failed to materialize user")
		return uuid.Nil, "", false
	}
	return userID, role, true
}

// --- small helpers ---------------------------------------------------------

func policyForbidsPassword(db *sql.DB, tenantID uuid.UUID) bool {
	var policy string
	_ = db.QueryRow(`SELECT COALESCE(authentication_policy, 'password_only') FROM tenants WHERE id = $1`, tenantID).Scan(&policy)
	return policy == "sso_only"
}

// requireCallerTenant resolves and validates the caller's tenant from the path +
// token, mirroring the InviteTenantMember guard. Writes the error response and
// returns ok=false on failure.
func requireCallerTenant(c *gin.Context) (uuid.UUID, bool) {
	pathTenant, err := uuid.Parse(c.Param("tenantId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return uuid.Nil, false
	}
	tokTenantStr := c.GetString("tenantID")
	tokTenant, err := uuid.Parse(tokTenantStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found in token"})
		return uuid.Nil, false
	}
	if tokTenant != pathTenant {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to this tenant"})
		return uuid.Nil, false
	}
	return pathTenant, true
}

// invitation sentinel errors mapped to HTTP responses by respondInvitationError.
var (
	errInvitationInvalid    = fmt.Errorf("invitation invalid")
	errInvitationUsed       = fmt.Errorf("invitation used")
	errInvitationExpired    = fmt.Errorf("invitation expired")
	errInvitationEmailTaken = fmt.Errorf("invitation email taken")
)

func respondInvitationError(c *gin.Context, err error) {
	switch err {
	case errInvitationInvalid:
		c.JSON(http.StatusNotFound, gin.H{"error": "This invitation is not valid."})
	case errInvitationUsed:
		c.JSON(http.StatusGone, gin.H{"error": "This invitation has already been used or was revoked."})
	case errInvitationExpired:
		c.JSON(http.StatusGone, gin.H{"error": "This invitation has expired. Ask an administrator to resend it."})
	case errInvitationEmailTaken:
		c.JSON(http.StatusConflict, gin.H{"error": "An account with this email already exists. Sign in with your existing method instead."})
	default:
		if writeRoleGrantError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to accept invitation"})
	}
}
