package api

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"
)

// impersonationService is the narrow surface of *auth.AuthService the
// impersonation handlers use. Depending on the interface (the concrete service
// satisfies it — see auth/impersonation.go) lets the real gin handlers run over
// an in-memory stub in the spec-first contract test (ADR-0001). Production wiring
// sets the concrete *auth.AuthService into the gin context unchanged.
type impersonationService interface {
	GetUserByID(userID uuid.UUID) (*models.User, error)
	GenerateImpersonationToken(targetUserID, targetTenantID uuid.UUID, targetEmail, targetRole, actorID, actorEmail, reason, actorIP, actorUA string, ttl time.Duration) (string, time.Time, string, error)
	RecordImpersonationStart(ctx context.Context, p auth.ImpersonationStartParams) error
	RevokeJTI(ctx context.Context, jti string, ttl time.Duration) error
	RemainingImpersonationTTL(ctx context.Context, jti string) (time.Duration, bool, error)
	RecordImpersonationStop(ctx context.Context, actorID, jti, ip, ua string) error
	ListImpersonationEvents(ctx context.Context) ([]auth.ImpersonationEvent, error)
}

// impersonationSvc pulls the impersonation service from the gin context (set by
// the route middleware). Returns nil when absent or of an unexpected type.
func impersonationSvc(c *gin.Context) impersonationService {
	v, exists := c.Get("authService")
	if !exists || v == nil {
		return nil
	}
	svc, ok := v.(impersonationService)
	if !ok {
		return nil
	}
	return svc
}

// impersonationConfig holds feature flags for impersonation
type impersonationConfig struct {
	RequireMFA bool
}

// getImpersonationConfig reads impersonation feature flags from environment
func getImpersonationConfig() impersonationConfig {
	return impersonationConfig{
		RequireMFA: os.Getenv("IMPERSONATION_REQUIRE_MFA") == "true",
	}
}

// AdminImpersonationRequest represents the initiation payload
type AdminImpersonationRequest struct {
	TenantID   string `json:"tenant_id" binding:"required,uuid4"`
	UserID     string `json:"user_id" binding:"required,uuid4"`
	Reason     string `json:"reason" binding:"required,min=5,max=500"`
	TTLSeconds int    `json:"ttl_seconds" binding:"omitempty,min=60,max=3600"`
}

// InitiateAdminImpersonation handles POST /admin/impersonations
func InitiateAdminImpersonation(c *gin.Context) {
	var req AdminImpersonationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Parse IDs
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant_id"})
		return
	}
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id"})
		return
	}

	// Access services from context
	svc := impersonationSvc(c)
	if svc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Auth service unavailable"})
		return
	}

	// Validate target user exists and belongs to tenant
	targetUser, err := svc.GetUserByID(userID)
	if err != nil {
		if err == auth.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to lookup user"})
		return
	}
	if targetUser.TenantID != tenantID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User does not belong to tenant"})
		return
	}
	if !targetUser.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Target user is inactive"})
		return
	}

	// Check MFA requirement (feature-flagged)
	cfg := getImpersonationConfig()
	if cfg.RequireMFA {
		mfaVerified, _ := c.Get("mfa_verified")
		if mfaVerified != true {
			c.JSON(http.StatusForbidden, gin.H{
				"error":        "MFA verification required for impersonation",
				"mfa_required": true,
				"message":      "Please complete multi-factor authentication to proceed with impersonation",
			})
			return
		}
	}

	// Determine TTL
	ttl := time.Duration(15) * time.Minute
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
		if ttl > 30*time.Minute {
			ttl = 30 * time.Minute
		}
		if ttl < time.Minute {
			ttl = time.Minute
		}
	}

	// Get actor (admin) context from JWT
	actorIDVal, _ := c.Get("userID")
	actorID, _ := actorIDVal.(string)
	actorEmailVal, _ := c.Get("email")
	actorEmail := ""
	if actorEmailVal != nil {
		actorEmail, _ = actorEmailVal.(string)
	}
	ip := c.ClientIP()
	ua := c.Request.UserAgent()

	// Mint impersonation token with actor claims
	token, expiresAt, jti, err := svc.GenerateImpersonationToken(
		targetUser.ID, tenantID, targetUser.Email, targetUser.Role,
		actorID, actorEmail, req.Reason, ip, ua, ttl,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Audit log entry (actor, target, reason). Best-effort — the token is already
	// minted, so a failed audit write must not 500 the caller — but it is NOT
	// discarded: a silent `_ =` here is what hid two SQL parse errors that left
	// the impersonation trail permanently empty.
	if auditErr := svc.RecordImpersonationStart(c.Request.Context(), auth.ImpersonationStartParams{
		TenantID:     tenantID,
		TargetUserID: targetUser.ID,
		TargetEmail:  targetUser.Email,
		ActorID:      actorID,
		ActorEmail:   actorEmail,
		Reason:       req.Reason,
		JTI:          jti,
		IP:           ip,
		UA:           ua,
		TTLSeconds:   int(ttl.Seconds()),
	}); auditErr != nil {
		logrus.WithError(auditErr).WithFields(logrus.Fields{
			"actor_id":       actorID,
			"target_user_id": targetUser.ID.String(),
			"jti":            jti,
		}).Error("Failed to record impersonation_start audit entry")
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": token,
		"expires_at":   expiresAt.UTC().Format(time.RFC3339),
		"token_type":   "Bearer",
		"jti":          jti,
		"target_user": gin.H{
			"id":    targetUser.ID.String(),
			"email": targetUser.Email,
		},
		"actor": gin.H{
			"id":    actorID,
			"email": actorEmail,
		},
	})
}

// StopImpersonationRequest represents the stop impersonation payload
type StopImpersonationRequest struct {
	JTI string `json:"jti" binding:"required"`
}

// StopAdminImpersonation handles POST /admin/impersonations/stop
func StopAdminImpersonation(c *gin.Context) {
	var req StopImpersonationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request - jti is required"})
		return
	}

	jti := req.JTI
	if jti == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token id"})
		return
	}

	svc := impersonationSvc(c)
	if svc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Auth service unavailable"})
		return
	}

	// Add to the denylist with a TTL equal to the token's REAL remaining
	// lifetime, derived from the impersonation-start audit record. Fall
	// back to the maximum impersonation lifetime (30m, the cap enforced at
	// mint time) when the exact remaining can't be determined, so the denylist
	// entry never expires before the token it revokes.
	const maxImpersonationTTL = 30 * time.Minute
	ttl := maxImpersonationTTL
	if remaining, ok, err := svc.RemainingImpersonationTTL(c.Request.Context(), jti); err == nil && ok {
		if remaining <= 0 {
			// Token already expired — nothing to revoke, but record the stop.
			ttl = 0
		} else if remaining < maxImpersonationTTL {
			ttl = remaining
		}
	}
	if ttl > 0 {
		if revokeErr := svc.RevokeJTI(c.Request.Context(), jti, ttl); revokeErr != nil {
			logrus.WithError(revokeErr).WithField("jti", jti).Error("Failed to add impersonation token to the revocation denylist")
		}
	}

	// Audit stop. Best-effort (the token is already denylisted), but logged
	// rather than discarded — see RecordImpersonationStart above.
	actorIDVal, _ := c.Get("userID")
	actorID, _ := actorIDVal.(string)
	if auditErr := svc.RecordImpersonationStop(c.Request.Context(), actorID, jti, c.ClientIP(), c.Request.UserAgent()); auditErr != nil {
		logrus.WithError(auditErr).WithFields(logrus.Fields{
			"actor_id": actorID,
			"jti":      jti,
		}).Error("Failed to record impersonation_stop audit entry")
	}

	c.Status(http.StatusNoContent)
}

// ListImpersonationAudit handles GET /admin/impersonations/audit
func ListImpersonationAudit(c *gin.Context) {
	svc := impersonationSvc(c)
	if svc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Auth service unavailable"})
		return
	}
	events, err := svc.ListImpersonationEvents(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load audit"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events})
}
