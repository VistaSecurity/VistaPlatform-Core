package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Context key constants used by the shared auth middleware.
// All services should use the Get*FromContext helpers below rather than
// accessing these keys directly, to ensure consistent type handling.
const (
	CtxKeyUserID    = "userID"
	CtxKeyTenantID  = "tenantID"
	CtxKeyEmail     = "email"
	CtxKeyRole      = "role"
	CtxKeyUserType  = "userType"
	CtxKeyTokenType = "tokenType"
	// CtxKeyTokenScopes holds a []string of PAT scopes when the request's token
	// is scope-narrowed; absent on normal tokens.
	CtxKeyTokenScopes         = "tokenScopes"
	CtxKeyIsInternalCall      = "isInternalCall"
	CtxKeyActorID             = "actorID"
	CtxKeyActorEmail          = "actorEmail"
	CtxKeyImpersonationReason = "impersonationReason"
	// CtxKeyTokenID holds the jti (string) of the access token RequireJWTAuth
	// verified for this request; absent when the token carries no jti.
	CtxKeyTokenID = "tokenID"
	// CtxKeyTokenExpiresAt holds the exp (time.Time) of that verified token;
	// absent when the token carries no exp.
	CtxKeyTokenExpiresAt = "tokenExpiresAt"

	UserTypePlatform = "platform"
	UserTypeTenant   = "tenant"
)

// InternalUserIDSentinel is the context userID value for HMAC-verified internal service calls.
const InternalUserIDSentinel = "system"

// GetUserIDFromContext retrieves the authenticated user's UUID from the Gin context.
func GetUserIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	val, exists := c.Get(CtxKeyUserID)
	if !exists {
		return uuid.Nil, false
	}
	switch v := val.(type) {
	case uuid.UUID:
		return v, true
	case string:
		if v == InternalUserIDSentinel {
			return uuid.Nil, false
		}
		if parsed, err := uuid.Parse(v); err == nil {
			return parsed, true
		}
	}
	return uuid.Nil, false
}

// StringifyContextIDs copies uuid.UUID userID and tenantID from context to string values for
// handlers that still use c.Get with string type assertions. Preserves InternalUserIDSentinel for internal calls.
func StringifyContextIDs() gin.HandlerFunc {
	return func(c *gin.Context) {
		if IsInternalCall(c) {
			c.Set(CtxKeyUserID, InternalUserIDSentinel)
		} else if uid, ok := GetUserIDFromContext(c); ok {
			c.Set(CtxKeyUserID, uid.String())
		}
		if tid, ok := GetTenantIDFromContext(c); ok {
			c.Set(CtxKeyTenantID, tid.String())
		}
		c.Next()
	}
}

// GetTenantIDFromContext retrieves the tenant UUID from the Gin context.
func GetTenantIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	val, exists := c.Get(CtxKeyTenantID)
	if !exists {
		return uuid.Nil, false
	}
	switch v := val.(type) {
	case uuid.UUID:
		if v == uuid.Nil {
			return uuid.Nil, false
		}
		return v, true
	case string:
		if parsed, err := uuid.Parse(v); err == nil && parsed != uuid.Nil {
			return parsed, true
		}
	}
	return uuid.Nil, false
}

// GetRoleFromContext retrieves the user's role string from the Gin context.
func GetRoleFromContext(c *gin.Context) string {
	if val, exists := c.Get(CtxKeyRole); exists {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

// GetUserType retrieves whether the authenticated identity is a platform or tenant user.
func GetUserType(c *gin.Context) string {
	if val, exists := c.Get(CtxKeyUserType); exists {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

// GetEmailFromContext retrieves the user's email from the Gin context.
func GetEmailFromContext(c *gin.Context) string {
	if val, exists := c.Get(CtxKeyEmail); exists {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

// IsInternalCall returns true if the request was made by an internal service.
func IsInternalCall(c *gin.Context) bool {
	if val, exists := c.Get(CtxKeyIsInternalCall); exists {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

// GetTokenIDFromContext returns the jti of the access token the auth middleware
// verified for this request. It is never read from the request itself, so it is
// always the jti of a signature-checked token.
func GetTokenIDFromContext(c *gin.Context) (string, bool) {
	if val, exists := c.Get(CtxKeyTokenID); exists {
		if s, ok := val.(string); ok && s != "" {
			return s, true
		}
	}
	return "", false
}

// GetTokenExpiresAtFromContext returns the exp of the access token the auth
// middleware verified for this request.
func GetTokenExpiresAtFromContext(c *gin.Context) (time.Time, bool) {
	if val, exists := c.Get(CtxKeyTokenExpiresAt); exists {
		if t, ok := val.(time.Time); ok && !t.IsZero() {
			return t, true
		}
	}
	return time.Time{}, false
}
