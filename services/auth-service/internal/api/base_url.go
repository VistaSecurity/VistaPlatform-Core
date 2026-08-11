package api

// Public base-URL resolution.
//
// Lived in sso.go, but it is not an SSO concern: invitation emails
// (getWebUIBaseURL in invitations.go) build their accept links from it too, so
// it stays in Core. The Enterprise SSO package reaches it through the exported
// wrapper in edition.go rather than re-deriving the rule — a second copy of
// "which host do we hand to an IdP as redirect_uri" is exactly the kind of
// drift that produces a callback mismatch nobody notices until login breaks.

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
)

func getBaseURL(cfg *config.Config) string {
	// Prefer the explicitly-pinned callback base URL. CORSOrigins[0] is
	// only a fallback for dev/back-compat — it is an allow-list, not a single
	// canonical callback host.
	if base := strings.TrimSpace(cfg.OAuthCallbackBaseURL); base != "" {
		return strings.TrimRight(base, "/")
	}
	if len(cfg.CORSOrigins) > 0 {
		return cfg.CORSOrigins[0]
	}
	return "http://localhost:8080"
}
