package handlers

// Every path audit-service's spec documents has a route, and every route its
// `ee/` trees register is tagged `x-edition: enterprise`.
//
// audit-service registers `ee/siemexport` and `ee/scheduledreports` routes and
// had no guard of either kind. The public-tree export deletes `ee/`, so a Core
// build shipped a spec documenting SIEM-export and scheduled-report operations
// with nothing behind them — and nothing said so.
//
// The check itself, and the reasoning behind suffix matching and the inertness
// floors, lives in shared/api/spectest. Three services share it; for
// the bug in inventory-service that started it.

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
		Name: "audit-service",
		Root: serviceRoot,
		Spec: filepath.Join(repoRoot, "api", "openapi", "audit-service.openapi.yaml"),
		// Below the CORE count, not the full one: ee/siemexport and
		// ee/scheduledreports are gone from an export.
		MinRoutes: 15,
		MinOps:    20,

		// ee/scheduledreports is not in the spec at all. That is a documentation
		// gap, not an edition bug — the six routes exist, they are Enterprise,
		// and nobody has written them down. Recorded rather than silently
		// tolerated so the gap is a visible line of code; seeded for the spec
		// backlog (api/README.md's pre-spec slice queue).
		UndocumentedEERoutes: map[string]string{
			"GET /scheduled-reports":                "ee/scheduledreports is unspecified — spec backlog",
			"POST /scheduled-reports":               "ee/scheduledreports is unspecified — spec backlog",
			"PUT /scheduled-reports/:id":            "ee/scheduledreports is unspecified — spec backlog",
			"DELETE /scheduled-reports/:id":         "ee/scheduledreports is unspecified — spec backlog",
			"GET /scheduled-reports/:id/executions": "ee/scheduledreports is unspecified — spec backlog",
			"POST /scheduled-reports/:id/trigger":   "ee/scheduledreports is unspecified — spec backlog",
		},
	})
}
