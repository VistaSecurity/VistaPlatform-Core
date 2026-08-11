package models

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTClaims represents the standard claims in a JWT token issued by auth-service.
// All services must use this canonical definition to avoid type drift.
// UserID and TenantID are uuid.UUID to match the auth-service that generates tokens.
type JWTClaims struct {
	UserID   uuid.UUID `json:"user_id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Email    string    `json:"email"`
	Role     string    `json:"role"`
	Type     string    `json:"type"` // "access", "refresh", or "impersonation"

	// TokenType marks a narrowed token. "pat" means this access token was minted
	// from a Personal Access Token and is constrained to Scopes. Empty on
	// normal login tokens. Type stays "access" so existing token-type checks pass.
	TokenType string `json:"token_type,omitempty"`
	// Scopes is the PAT's permission set. When non-empty, the request is
	// authorized against the INTERSECTION of the user's role permissions and
	// these scopes — so a read-only PAT can never act as a full-role bearer.
	Scopes []string `json:"scopes,omitempty"`

	// PasswordChangeRequired marks a LIMITED session issued to a user whose
	// force_password_change flag was set at login ( — e.g. the seeded
	// default platform admin, or an admin-forced reset). The shared auth
	// middleware rejects every request carrying this claim except the
	// change-password / me / logout endpoints, so the flag is enforced
	// server-side rather than merely echoed for the UI to honor. Cleared by
	// re-issuing tokens after a successful password change.
	PasswordChangeRequired bool `json:"pwd_change_required,omitempty"`

	jwt.RegisteredClaims
}

// ActorClaims represents the acting admin context for impersonation tokens.
// Per RFC 8693 (OAuth 2.0 Token Exchange), the "act" claim identifies the acting party.
type ActorClaims struct {
	Sub    string `json:"sub"`    // Admin user ID
	Email  string `json:"email"`  // Admin email
	Reason string `json:"reason"` // Impersonation reason
	IP     string `json:"ip"`     // Admin IP address
	UA     string `json:"ua"`     // Admin user agent (truncated)
}

// ImpersonationClaims extends JWTClaims with actor context for impersonation tokens.
type ImpersonationClaims struct {
	UserID   uuid.UUID    `json:"user_id"`
	TenantID uuid.UUID    `json:"tenant_id"`
	Email    string       `json:"email"`
	Role     string       `json:"role"`
	Type     string       `json:"type"`
	Actor    *ActorClaims `json:"act,omitempty"`
	jwt.RegisteredClaims
}
