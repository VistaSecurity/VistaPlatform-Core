package main

// Every path maintenance-service's spec documents has a route ( class: a
// documented path no handler serves is invisible to the schema-validating
// contract tests, which only see requests that reached a handler). The check is
// shared/api/spectest's, as for every service with a spec. Core service, no
// `ee/` tree, so no `x-edition` tags.

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/api/spectest"
)

func TestContract_SpecRoutesMatch(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	serviceRoot := filepath.Join(filepath.Dir(thisFile), "..")
	repoRoot := filepath.Join(serviceRoot, "..", "..")

	spectest.Run(t, spectest.Service{
		Name:      "maintenance-service",
		Root:      serviceRoot,
		Spec:      filepath.Join(repoRoot, "api", "openapi", "maintenance-service.openapi.yaml"),
		MinRoutes: 13,
		MinOps:    13,
	})
}
