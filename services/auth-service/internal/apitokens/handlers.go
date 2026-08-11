package apitokens

import (
	"errors"
	"net/http"
	"time"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/shared/api"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// ExchangeTokenTTL is the lifetime of the short-lived user JWT minted for a
// valid PAT. Consumers (the MCP service) re-exchange on expiry; keeping it
// short bounds the blast radius of an intercepted JWT to minutes.
const ExchangeTokenTTL = 15 * time.Minute

// Handlers wires the apitokens service into Gin.
type Handlers struct {
	svc  *Service
	auth *auth.AuthService
	jwt  *auth.JWTService
}

func NewHandlers(svc *Service, authService *auth.AuthService, jwtService *auth.JWTService) *Handlers {
	return &Handlers{svc: svc, auth: authService, jwt: jwtService}
}

func callerIDs(c *gin.Context) (tenantID, userID uuid.UUID, ok bool) {
	tenantID, err1 := uuid.Parse(c.GetString("tenantID"))
	userID, err2 := uuid.Parse(c.GetString("userID"))
	if err1 != nil || err2 != nil || tenantID == uuid.Nil || userID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant context not found"})
		return uuid.Nil, uuid.Nil, false
	}
	return tenantID, userID, true
}

type createTokenRequest struct {
	Name          string   `json:"name" binding:"required"`
	Permissions   []string `json:"permissions"`
	ExpiresInDays int      `json:"expires_in_days"`
}

// CreateToken handles POST /api-tokens. The plaintext token appears in the
// response exactly once and is never retrievable again.
func (h *Handlers) CreateToken(c *gin.Context) {
	tenantID, userID, ok := callerIDs(c)
	if !ok {
		return
	}

	var req createTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	token, plaintext, err := h.svc.Create(tenantID, userID, req.Name, req.Permissions, req.ExpiresInDays)
	if err != nil {
		switch {
		case errors.Is(err, ErrEmptyName), errors.Is(err, ErrInvalidExpiry), errors.Is(err, ErrInvalidPerm):
			api.BadRequest(c, err.Error())
		case errors.Is(err, ErrTooManyTokens):
			api.ErrorResponse(c, http.StatusConflict, err.Error(), nil)
		default:
			logrus.WithError(err).Error("Failed to create api token")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create api token"})
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"token":           token,
		"plaintext_token": plaintext,
	})
}

// ListTokens handles GET /api-tokens — the caller's own tokens only.
func (h *Handlers) ListTokens(c *gin.Context) {
	tenantID, userID, ok := callerIDs(c)
	if !ok {
		return
	}

	tokens, err := h.svc.List(tenantID, userID)
	if err != nil {
		logrus.WithError(err).Error("Failed to list api tokens")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list api tokens"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

// RevokeToken handles DELETE /api-tokens/:id — owner-only.
func (h *Handlers) RevokeToken(c *gin.Context) {
	tenantID, userID, ok := callerIDs(c)
	if !ok {
		return
	}

	tokenID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token ID"})
		return
	}

	switch err := h.svc.Revoke(tenantID, userID, tokenID); {
	case err == nil:
		c.JSON(http.StatusOK, gin.H{"status": "revoked"})
	case errors.Is(err, ErrTokenRevoked):
		c.JSON(http.StatusConflict, gin.H{"error": "Token already revoked"})
	case errors.Is(err, ErrTokenNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Token not found"})
	default:
		logrus.WithError(err).Error("Failed to revoke api token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke api token"})
	}
}

type exchangeRequest struct {
	Token string `json:"token" binding:"required"`
}

// Exchange handles POST /internal/api-tokens/exchange. HMAC-guarded
// (service-to-service only — never exposed to end users): resolves a valid
// PAT to a short-lived access JWT for the owning user, so the consuming
// service can call platform APIs through the standard JWT middleware
// without any data service changing.
func (h *Handlers) Exchange(c *gin.Context) {
	var req exchangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	token, err := h.svc.Validate(req.Token)
	if err != nil {
		// One generic 401 for all invalid-credential shapes — don't give a
		// probing caller an oracle for "exists but expired" vs "revoked".
		logrus.WithError(err).Debug("api token exchange rejected")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid api token"})
		return
	}

	user, err := h.auth.GetUserByID(token.UserID)
	if err != nil || user == nil || !user.IsActive || user.DeletedAt != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid api token"})
		return
	}
	// Token tenancy must still match the user's tenancy (defends against a
	// user moved between tenants after minting).
	if user.TenantID != token.TenantID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid api token"})
		return
	}

	// Mint a SCOPE-NARROWED access token: it carries the PAT's permission
	// set (token.Permissions) as JWT scopes + token_type "pat", so every service
	// authorizes the request against intersect(role permissions, PAT scopes) —
	// a read-only PAT can no longer act as a full-role bearer at the JWT level.
	accessToken, expiresAt, _, err := h.jwt.GenerateScopedAccessTokenWithTTL(
		user.ID, user.TenantID, user.Email, user.Role, token.Permissions, ExchangeTokenTTL)
	if err != nil {
		logrus.WithError(err).Error("Failed to mint exchange JWT")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mint access token"})
		return
	}

	h.svc.TouchLastUsed(token.ID)

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"expires_at":   expiresAt.UTC().Format(time.RFC3339),
		"tenant_id":    token.TenantID,
		"user_id":      token.UserID,
		"email":        user.Email,
		"role":         user.Role,
		"permissions":  token.Permissions,
	})
}
