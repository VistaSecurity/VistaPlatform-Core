package api

// Every path auth-service's spec documents has a route, and every route its
// `ee/sso` tree registers is tagged `x-edition: enterprise`.
//
// The check itself, and the reasoning behind suffix matching and the inertness
// floors, lives in shared/api/spectest. for the bug in
// inventory-service that started it.

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/api/spectest"
)

func TestContract_SpecRoutesAndEditionTags(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	serviceRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	repoRoot := filepath.Join(serviceRoot, "..", "..")

	spectest.Run(t, spectest.Service{
		Name: "auth-service",
		Root: serviceRoot,
		Spec: filepath.Join(repoRoot, "api", "openapi", "auth-service.openapi.yaml"),
		// Below the CORE count, not the full one: ee/sso's routes are gone from
		// an export, and a floor above what Core has fails the export.
		MinRoutes: 40,
		MinOps:    60,

		// The browser-redirect half of the OAuth dance. These are not API
		// operations a typed client calls — the browser is sent to
		// /authorize and the IdP sends it back to /callback — so they were
		// never specified, and specifying them would document a 302 nobody
		// invokes programmatically. `/sso/link` is the one genuine gap of the
		// five. Recorded rather than silently tolerated, with the reason
		// attached; the spec backlog is.
		UndocumentedEERoutes: map[string]string{
			"GET /sso/:provider/authorize":          "OAuth browser redirect, not a typed API operation",
			"GET /sso/:provider/callback":           "OAuth browser redirect, not a typed API operation",
			"GET /sso/platform/:provider/authorize": "OAuth browser redirect, not a typed API operation",
			"GET /sso/platform/:provider/callback":  "OAuth browser redirect, not a typed API operation",
			"POST /sso/link":                        "unspecified — spec backlog (#257)",
		},
	})
}
