package handlers

// Every path the spec documents must have a route behind it, and every route the
// `ee/` trees register must be tagged `x-edition: enterprise`.
//
// `POST /discovery/jobs/{id}` was documented (operationId `rerunDiscoveryJob`)
// and the real route is `POST /discovery/jobs/{id}/rerun`. Nothing caught it:
// the contract tests validate response BODIES against schemas, and a body is
// only validated once a request has reached a handler — so a documented path
// that reaches no handler is invisible to all of them. A client following the
// spec got a 404, and the spec was the only thing that said otherwise.
//
// The check used to live here in full, and three other services with `ee/` trees
// had nothing like it — the case that matters most, because the public-tree
// export deletes `ee/` and a Core build can therefore ship a spec documenting
// routes it does not serve. It now lives in shared/api/spectest, which
// admin-service, auth-service and audit-service call the same way; the exemption
// logic and the route scanner are pinned there in both polarities against
// synthetic trees, because the x-edition exemption can never fire in a checkout
// that HAS ee/.
//
// The 17/17 enterprise-tag match this service was carrying had only ever been
// verified by hand. It is machine-checked now, in both directions: an `ee/` route
// whose spec operation is untagged fails, and an operation tagged enterprise
// whose handler is NOT under `ee/` fails too.

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
		Name:      "inventory-service",
		Root:      serviceRoot,
		Spec:      filepath.Join(repoRoot, "api", "openapi", "inventory-service.openapi.yaml"),
		MinRoutes: 50,
		MinOps:    50,
	})
}
