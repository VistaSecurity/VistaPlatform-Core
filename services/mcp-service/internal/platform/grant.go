package platform

import (
	"context"
	"time"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/auditlog"
)

// Grant is the resolved identity behind an API token: the short-lived user
// JWT minted by auth-service's exchange endpoint plus the token's declared
// permission subset. It is what flows from the HTTP auth middleware into
// tool handlers via context.
type Grant struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	TenantID    string    `json:"tenant_id"`
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	Permissions []string  `json:"permissions"`
}

// HasPermission reports whether the API token granted the named permission.
// This is the MCP-layer authorization gate: even though the exchanged JWT
// carries the user's full role, a tool only runs if the token itself was
// minted with the permission the tool declares.
func (g *Grant) HasPermission(perm string) bool {
	for _, p := range g.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

// Identity flattens the grant into the actor fields an audit record carries.
// Deliberately excludes AccessToken: the JWT is a credential, and an audit
// trail that stores credentials is a second place to steal them from.
func (g *Grant) Identity() auditlog.Identity {
	if g == nil {
		return auditlog.Identity{}
	}
	return auditlog.Identity{
		TenantID: g.TenantID,
		UserID:   g.UserID,
		Email:    g.Email,
		Role:     g.Role,
	}
}

type grantCtxKey struct{}

// WithGrant returns a context carrying the grant.
func WithGrant(ctx context.Context, g *Grant) context.Context {
	return context.WithValue(ctx, grantCtxKey{}, g)
}

// GrantFromContext extracts the grant placed by the auth middleware.
func GrantFromContext(ctx context.Context) (*Grant, bool) {
	g, ok := ctx.Value(grantCtxKey{}).(*Grant)
	return g, ok
}
