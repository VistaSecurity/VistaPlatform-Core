package api

// Core/Enterprise seam for auth-service.
//
// The open-core split for authentication is *who vouches for the user*:
//
//	Core       — local username/password login, the email-first login
//	             dispatcher, invitations, RBAC, and the OAuth 2.0 authorization
//	             server that issues Personal Access Tokens / MCP credentials
//	             (internal/oauth — despite the name that is Vista *issuing*
//	             tokens, not Vista consuming an external IdP, and it is Core).
//	Enterprise — federated identity: tenant OIDC/SAML login, the social-signup
//	             IdP used at registration, and the tenant-side SSO config
//	             surface. All of it lives in services/auth-service/ee/sso/ and
//	             is absent from the open-source tree.
//
// Two things cross the seam, and only two:
//
//  1. SSOMethodEnumerator — the login dispatcher (auth_flow.go) has to answer
//     "what can this email sign in with?". Core answers "password"; Enterprise
//     answers "password plus whatever the tenant federated". This is the only
//     interface Core calls into.
//  2. EditionHooks.RegisterSSORoutes — route registration. Nil in Core, so the
//     SSO routes simply do not exist rather than existing and failing.
//
// Everything else flows the other way: CoreSSOSupport hands the Enterprise
// package the Core helpers it must NOT re-implement (callback base URL,
// auth-cookie shape, invitation consumption, the legal-acceptance gate). A
// second copy of any of those would drift, and every one of them is on a
// security-relevant path.
//
// See docsv4/internal/operations/OPEN_SOURCE_CARVE_TRACKER.md §5.5 for the
// repo-wide pattern.

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
)

// SSOMethodEnumerator supplies the SSO half of the email-first login
// dispatcher. Implemented by the Enterprise build; Core uses noSSOMethods,
// which reports no SSO of any kind.
//
// Returning slices (rather than writing the response) keeps the ordering,
// shape, and error handling of /auth/methods in Core where the contract lives.
// Implementations must never return an error path to the caller: an SSO lookup
// failure degrades to "no SSO methods", exactly as the pre-carve code did when
// its `_ = wrapErr` swallowed the query error. Login must not break because
// provider enumeration hiccuped.
type SSOMethodEnumerator interface {
	// TenantMethods returns the login methods contributed by the tenant's own
	// configured (federated) SSO providers.
	TenantMethods(ctx context.Context, tenantID uuid.UUID) []map[string]interface{}

	// PlatformMethods returns the social-signup ("platform SSO") login methods
	// available to this user. Only consulted when the tenant configured no SSO
	// of its own; the implementation additionally applies the tenant's
	// authentication policy.
	PlatformMethods(ctx context.Context, userID, tenantID uuid.UUID) []map[string]interface{}

	// AuthorizeRedirect resolves the in-app URL that starts the SSO authorize
	// flow for a provider id, or false when no such provider exists for the
	// tenant. Core always returns false.
	AuthorizeRedirect(ctx context.Context, tenantID uuid.UUID, providerID string) (string, bool)
}

// noSSOMethods is the Core edition's enumerator: no federated identity of any
// kind. Deliberately a value type, not a nil pointer — a nil *T stored in an
// interface is itself non-nil, and every `!= nil` guard downstream would
// wrongly pass and then panic on the first call.
type noSSOMethods struct{}

func (noSSOMethods) TenantMethods(context.Context, uuid.UUID) []map[string]interface{} { return nil }
func (noSSOMethods) PlatformMethods(context.Context, uuid.UUID, uuid.UUID) []map[string]interface{} {
	return nil
}
func (noSSOMethods) AuthorizeRedirect(context.Context, uuid.UUID, string) (string, bool) {
	return "", false
}

// EditionHooks are the extension points the Enterprise build fills in. The
// zero value is the Core edition: every hook nil, meaning the SSO routes are
// never mounted and the login dispatcher enumerates password only.
//
// The Enterprise build supplies real implementations from cmd/edition_ee.go,
// which is guarded by `//go:build ee` and is the only file that imports
// services/auth-service/ee/. Neither that file nor the ee/ tree exists in the
// open-source repository, so a Core checkout cannot accidentally link
// Enterprise code — there is nothing to link.
type EditionHooks struct {
	// NewSSOMethodEnumerator builds the enumerator consulted by
	// /auth/initiate, /auth/methods, and /auth/authenticate. Nil in Core.
	NewSSOMethodEnumerator func(db, bypassDB *sql.DB) SSOMethodEnumerator

	// RegisterSSORoutes mounts the tenant-SSO login routes, the social-signup
	// IdP routes, and the tenant SSO configuration surface. Nil in Core, so
	// none of those routes exist.
	RegisterSSORoutes func(deps SSORouteDeps)
}

// resolveSSOMethods picks the enumerator for this build. It never returns nil,
// and it defends against a hook that hands back a nil interface value.
func resolveSSOMethods(hooks EditionHooks, db, bypassDB *sql.DB) SSOMethodEnumerator {
	if hooks.NewSSOMethodEnumerator == nil {
		return noSSOMethods{}
	}
	e := hooks.NewSSOMethodEnumerator(db, bypassDB)
	if e == nil {
		return noSSOMethods{}
	}
	return e
}

// SSORouteDeps is everything the Enterprise SSO package needs to mount its
// routes. Assembled by SetupRouter so that route paths, middleware, and the
// permission gate on the config surface stay defined in one place — the
// Enterprise package chooses handlers, not policy.
type SSORouteDeps struct {
	// ServiceGroup is /api/v1/auth-service.
	ServiceGroup *gin.RouterGroup
	// AuthGroup is /api/v1/auth-service/auth.
	AuthGroup *gin.RouterGroup

	Cfg         *config.Config
	DB          *sql.DB
	BypassDB    *sql.DB
	Redis       *redis.Client
	JWTService  *auth.JWTService
	AuthService *auth.AuthService

	// RequireAuth is the standard authenticated-user middleware.
	RequireAuth gin.HandlerFunc
	// RequireSettingsUpdate gates the tenant SSO configuration surface. SSO
	// config is sensitive tenant auth infrastructure; the gate is Core policy
	// and is passed in rather than re-derived.
	RequireSettingsUpdate gin.HandlerFunc

	// Core is the set of Core helpers the Enterprise package must reuse.
	Core CoreSSOSupport
}

// CoreSSOSupport hands the Enterprise SSO package the Core behavior it must
// not duplicate. Every entry here is either security-relevant (cookie flags,
// redirect base, invitation consumption, legal-acceptance evidence) or shared
// with a Core caller, so a divergent second copy would be a real bug.
type CoreSSOSupport struct {
	// BaseURL is the public origin the service hands an IdP as redirect_uri.
	BaseURL func(cfg *config.Config) string
	// WebUIBaseURL is the public origin of the tenant app, used for the
	// post-callback landing redirect.
	WebUIBaseURL func(cfg *config.Config) string
	// SetAuthCookies writes the httpOnly access/refresh cookie pair with the
	// same flags the password login path uses.
	SetAuthCookies func(w http.ResponseWriter, cfg *config.Config, accessExpirySeconds int, accessToken, refreshToken string)

	// InvitationTenantID resolves the tenant a still-pending invitation token
	// belongs to, so an SSO authorize can start without an explicit tenant_id
	//. Returns false when the token is absent, expired, or consumed.
	InvitationTenantID func(bypassDB *sql.DB, rawToken string) (uuid.UUID, bool)
	// ConsumeInvitationForSSO binds an IdP identity to an invited account:
	// materializes the user with the invited role and marks the invite
	// accepted. Returns the user id and false when the invite is not
	// consumable for this (email, tenant) pair.
	ConsumeInvitationForSSO func(db, bypassDB *sql.DB, rawToken, idpEmail string, tenantID uuid.UUID) (uuid.UUID, string, bool)

	// RejectIfSignupDisabled writes the 403 and reports whether it did, so the
	// social-signup path honors `platform_settings.registration_enabled` exactly
	// like the password paths. Lending it rather than letting Enterprise
	// re-implement it is the point: existed because the social path was
	// the one registration route that never called this, so an operator who had
	// switched self-service sign-up off could still have tenants created
	// through Google.
	RejectIfSignupDisabled func(c *gin.Context, db *sql.DB) bool

	// FetchCurrentLegalDocs reads the currently published legal documents, so
	// social signup enforces the same acceptance gate as password signup.
	FetchCurrentLegalDocs func(ctx context.Context, db *sql.DB) (LegalDocSnapshot, error)
	// RecordLegalAcceptances writes the append-only acceptance evidence rows
	// for a snapshot previously read by FetchCurrentLegalDocs.
	RecordLegalAcceptances func(ctx context.Context, db *sql.DB, tenantID, userID uuid.UUID, ip, ua string, snapshot LegalDocSnapshot) (int, error)
}

// LegalDocSnapshot is an opaque handle to the set of currently published legal
// documents. It exists so the Enterprise signup path can run the same
// check-then-record sequence as password signup without the internal
// legalDocument shape becoming part of the exported surface.
type LegalDocSnapshot struct {
	docs []legalDocument
}

// Required reports whether any legal document must be accepted.
func (s LegalDocSnapshot) Required() bool { return len(s.docs) > 0 }

// NewCoreSSOSupport returns the production Core support bundle. Exported so the
// Enterprise package's own tests can drive handlers through the *real* Core
// helpers rather than hand-rolled stand-ins — a stub here would defeat the
// point of lending the logic in the first place.
func NewCoreSSOSupport() CoreSSOSupport { return coreSSOSupport() }

// coreSSOSupport is the production wiring of CoreSSOSupport. Every field is a
// thin adapter over an existing unexported Core helper — no logic lives here.
func coreSSOSupport() CoreSSOSupport {
	return CoreSSOSupport{
		BaseURL:        getBaseURL,
		WebUIBaseURL:   getWebUIBaseURL,
		SetAuthCookies: setAuthCookiesResponseWriter,

		InvitationTenantID: func(bypassDB *sql.DB, rawToken string) (uuid.UUID, bool) {
			inv, err := lockPendingInvitation(bypassDB, rawToken)
			if err != nil || inv == nil {
				return uuid.Nil, false
			}
			return inv.tenantID, true
		},
		ConsumeInvitationForSSO: consumeInvitationForSSO,

		RejectIfSignupDisabled: rejectIfSignupDisabled,

		FetchCurrentLegalDocs: func(ctx context.Context, db *sql.DB) (LegalDocSnapshot, error) {
			docs, err := fetchCurrentLegalDocuments(ctx, db)
			if err != nil {
				return LegalDocSnapshot{}, err
			}
			return LegalDocSnapshot{docs: docs}, nil
		},
		RecordLegalAcceptances: func(ctx context.Context, db *sql.DB, tenantID, userID uuid.UUID, ip, ua string, snapshot LegalDocSnapshot) (int, error) {
			return recordLegalAcceptances(ctx, db, tenantID, userID, ip, ua, snapshot.docs)
		},
	}
}
