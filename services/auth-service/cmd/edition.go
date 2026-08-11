package main

import (
	"database/sql"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/api"
)

// editionHooks are the extension points the Enterprise build fills in.
//
// The zero value is the Core edition: every hook nil, meaning auth-service
// serves local username/password login, invitations, RBAC, and the OAuth 2.0
// authorization server for Personal Access Tokens / MCP — and no federated
// identity at all. That is a supported product configuration, not a degraded
// one: Core's promise is that a self-hosted install can authenticate its
// users without buying anything.
//
// The Enterprise build supplies real implementations from cmd/edition_ee.go,
// which is guarded by `//go:build ee` and imports services/auth-service/ee/.
// Neither that file nor the ee/ tree exists in the open-source repository, so
// a Core checkout cannot accidentally link Enterprise code — there is nothing
// to link. See docsv4/internal/operations/OPEN_SOURCE_CARVE_TRACKER.md §5.5.
//
// Hooks are wired at process start (init) rather than resolved per request:
// this boundary decides which *code* is present, while shared/entitlements
// decides which *tenant* may use it. Both gates apply in an Enterprise build.
type editionHooks struct {
	// SeedPlatformSSOProviders upserts the social-signup IdP configuration
	// (Google/Microsoft) from environment variables at startup. Nil in Core,
	// where there is no social signup to configure.
	SeedPlatformSSOProviders func(db *sql.DB)

	// Router carries the hooks SetupRouter consumes: SSO route registration
	// and the login dispatcher's SSO enumerator. Its zero value is Core.
	Router api.EditionHooks
}

// hooks is the active edition. Core leaves it zero; the Enterprise build
// replaces it from an init() in cmd/edition_ee.go.
var hooks editionHooks

// edition reports the build's edition for startup logging, so an operator can
// tell from the first log line which binary is running.
func edition() string {
	if hooks.Router.RegisterSSORoutes == nil {
		return "core"
	}
	return "enterprise"
}
