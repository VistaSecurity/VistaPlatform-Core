package api

// Every path admin-service's spec documents has a route, and every route its
// `ee/msp` and `ee/billingapi` trees register is tagged `x-edition: enterprise`.
//
// This is the service with the most to lose: MSP tenant lifecycle and the whole
// self-service billing surface are registered from `ee/`, which the public-tree
// export deletes, and the spec shipped with the Core export documented them
// anyway.
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
		Name: "admin-service",
		Root: serviceRoot,
		Spec: filepath.Join(repoRoot, "api", "openapi", "admin-service.openapi.yaml"),
		// The floor has to hold in a CORE export too, where ee/ is gone: this
		// service loses ~80 routes with it (85 remain of 165). A floor above the
		// Core count fails the export rather than the tree.
		MinRoutes: 60,
		MinOps:    100,

		// `ee/` routes with no spec operation at all. Every one is a
		// documentation gap rather than an edition bug: the capability exists,
		// it is Enterprise, and nobody has written it down. Two are not
		// OpenAPI-shaped at all and never will be — the Stripe webhook
		// receiver (the PROVIDER calls it; no client does) and the dashboard
		// WebSocket upgrade.
		//
		// Recorded as a list with reasons rather than a blanket skip, so the
		// backlog is countable and a NEW undocumented ee route still fails.
		// Spec backlog:.
		UndocumentedEERoutes: map[string]string{
			"DELETE /billing/trials/tenants/:tenant_id":        "trial lifecycle (ee/billingapi) is unspecified — spec backlog (#257)",
			"DELETE /tenants/:id/integrations/:integrationId":  "per-tenant integration CRUD (ee/msp) is unspecified — spec backlog (#257)",
			"GET /billing/dunning/status":                      "dunning (ee/billingapi) is unspecified — spec backlog (#257)",
			"GET /billing/events":                              "provider webhook event log (ee/billingapi) is unspecified — spec backlog (#257)",
			"GET /billing/invoices/:id/download":               "invoice PDF generate/send/download (ee/billingapi) is unspecified — spec backlog (#257)",
			"GET /billing/trials":                              "trial lifecycle (ee/billingapi) is unspecified — spec backlog (#257)",
			"GET /billing/trials/tenants/:tenant_id":           "trial lifecycle (ee/billingapi) is unspecified — spec backlog (#257)",
			"GET /dashboard/health":                            "platform dashboard/stats read (ee/msp) is unspecified — spec backlog (#257)",
			"GET /dashboard/metrics":                           "platform dashboard/stats read (ee/msp) is unspecified — spec backlog (#257)",
			"GET /dashboard/ws":                                "WebSocket upgrade, not an OpenAPI operation",
			"GET /stats/platform":                              "platform dashboard/stats read (ee/msp) is unspecified — spec backlog (#257)",
			"GET /stats/sensors":                               "platform dashboard/stats read (ee/msp) is unspecified — spec backlog (#257)",
			"GET /tenants/:id/billing":                         "per-tenant billing read/write (ee/billingapi) is unspecified — spec backlog (#257)",
			"GET /tenants/:id/integrations":                    "per-tenant integration CRUD (ee/msp) is unspecified — spec backlog (#257)",
			"GET /tenants/:id/integrations/:integrationId":     "per-tenant integration CRUD (ee/msp) is unspecified — spec backlog (#257)",
			"POST /admin/billing/webhook/:provider":            "Stripe webhook receiver: called by the provider, not by any client",
			"POST /billing/dunning/tenants/:tenant_id/resume":  "dunning (ee/billingapi) is unspecified — spec backlog (#257)",
			"POST /billing/dunning/tenants/:tenant_id/retry":   "dunning (ee/billingapi) is unspecified — spec backlog (#257)",
			"POST /billing/dunning/tenants/:tenant_id/suspend": "dunning (ee/billingapi) is unspecified — spec backlog (#257)",
			"POST /billing/events/:id/retry":                   "provider webhook event log (ee/billingapi) is unspecified — spec backlog (#257)",
			"POST /billing/invoices/:id/generate-pdf":          "invoice PDF generate/send/download (ee/billingapi) is unspecified — spec backlog (#257)",
			"POST /billing/invoices/:id/send":                  "invoice PDF generate/send/download (ee/billingapi) is unspecified — spec backlog (#257)",
			"POST /billing/trials":                             "trial lifecycle (ee/billingapi) is unspecified — spec backlog (#257)",
			"POST /billing/trials/tenants/:tenant_id/convert":  "trial lifecycle (ee/billingapi) is unspecified — spec backlog (#257)",
			"POST /billing/trials/tenants/:tenant_id/extend":   "trial lifecycle (ee/billingapi) is unspecified — spec backlog (#257)",
			"POST /tenants/:id/integrations":                   "per-tenant integration CRUD (ee/msp) is unspecified — spec backlog (#257)",
			"PUT /tenants/:id/billing":                         "per-tenant billing read/write (ee/billingapi) is unspecified — spec backlog (#257)",
			"PUT /tenants/:id/integrations/:integrationId":     "per-tenant integration CRUD (ee/msp) is unspecified — spec backlog (#257)",
		},
	})
}
