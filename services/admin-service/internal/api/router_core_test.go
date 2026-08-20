package api

// Core-edition router test.
//
// This file has NO build tag and imports nothing from ee/, so it survives the
// open-source repo cut and keeps proving the Core invariant in a public
// checkout: the Core router builds without a gin panic, mounts the whole Core
// operator console, and mounts NONE of the MSP management plane.
//
// The mirror test that builds BOTH editions lives at
// ee/msp/routes_edition_test.go — it needs to import ee/msp, which would be an
// import cycle from here (ee/msp imports this package for MSPDeps).
//
// Why a route-set assertion at all: gin builds a radix tree per method and
// panics at STARTUP on a conflict. Splitting registration across three packages
// (Core here, ee/msp, ee/billingapi) makes that a real risk, and no other test
// in the service would notice.

import (
	"database/sql"
	"sort"
	"strings"
	"testing"

	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
)

// coreRouteSet builds the Core-edition router (zero hooks) and returns its
// mounted routes as "METHOD path" strings.
//
// The pools are real *sql.DB handles pointing nowhere: sql.Open is lazy, so
// nothing dials, but any code that does reach for a connection errors instead of
// nil-panicking. Any panic here — including a gin tree conflict — fails the test.
func coreRouteSet(t *testing.T) map[string]bool {
	t.Helper()
	db, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	srv := NewServerWithConnections(&config.Config{Environment: "test"}, db, db, EditionHooks{})
	out := map[string]bool{}
	for _, r := range srv.Router().Routes() {
		out[r.Method+" "+r.Path] = true
	}
	return out
}

// mspRoutePrefixes are the URL prefixes the MSP management plane owns. A Core
// build must not mount anything under them.
//
// /admin/tenants is the one prefix with a documented Core exception:
// GET /admin/tenants/:id/limits, the effective-entitlement read-out. It is
// listed in coreTenantExceptions below rather than being silently tolerated.
var mspRoutePrefixes = []string{
	"/api/v1/admin-service/admin/tenants",
	"/api/v1/admin-service/admin/stats",
	"/api/v1/admin-service/admin/dashboard",
	"/api/v1/admin-service/admin/costs",
	"/api/v1/admin-service/admin/announcements",
	"/api/v1/admin-service/admin/maintenance-windows",
	"/api/v1/admin-service/admin/support-tickets",
}

// coreTenantExceptions are the only /admin/tenants routes a Core build may
// mount. Keeping this an explicit allow-list means adding a tenant route to
// Core is a deliberate, reviewed act rather than an accident.
var coreTenantExceptions = map[string]bool{
	"GET /api/v1/admin-service/admin/tenants/:id/limits": true,
}

func TestCoreRouter_BuildsAndMountsTheOperatorConsole(t *testing.T) {
	routes := coreRouteSet(t)

	// The Core console: platform-admin auth + RBAC, platform configuration, the
	// tier/entitlement catalog, and System Health. If any of these disappear,
	// Core has stopped being a usable operator console.
	want := []string{
		// auth + operator identity
		"POST /api/v1/admin-service/auth/login",
		"POST /api/v1/admin-service/auth/refresh",
		"POST /api/v1/admin-service/auth/reset-password",
		"POST /api/v1/admin-service/auth/forgot-password",
		"POST /api/v1/admin-service/admin/auth/logout",
		"GET /api/v1/admin-service/admin/auth/me",
		"POST /api/v1/admin-service/admin/auth/change-password",
		"GET /api/v1/admin-service/admin/user/permissions",
		// Edition read-out — Core MUST mount it, because it is how the admin
		// console learns to stop rendering MSP/Enterprise navigation here.
		"GET /api/v1/admin-service/admin/platform/edition",
		// staff SSO
		"GET /api/v1/admin-service/admin/sso/providers",
		"GET /api/v1/admin-service/admin/sso/:provider/authorize",
		"GET /api/v1/admin-service/admin/sso/:provider/callback",
		// platform users + RBAC
		"GET /api/v1/admin-service/admin/users",
		"POST /api/v1/admin-service/admin/users",
		"POST /api/v1/admin-service/admin/users/invite",
		"DELETE /api/v1/admin-service/admin/users/:id",
		"GET /api/v1/admin-service/admin/roles",
		"POST /api/v1/admin-service/admin/roles",
		"PUT /api/v1/admin-service/admin/roles/:id/permissions",
		"GET /api/v1/admin-service/admin/permissions",
		// tiers + entitlement catalog: the reason Core can still make
		// shared/entitlements resolve to something real.
		"GET /api/v1/admin-service/admin/tiers",
		"POST /api/v1/admin-service/admin/tiers",
		"PUT /api/v1/admin-service/admin/tiers/:id",
		"POST /api/v1/admin-service/admin/tiers/:id/assign",
		"GET /api/v1/admin-service/admin/tiers/:id/entitlements",
		"PUT /api/v1/admin-service/admin/tiers/:id/entitlements",
		"GET /api/v1/admin-service/admin/billable-items",
		"POST /api/v1/admin-service/admin/billable-items",
		"GET /api/v1/admin-service/admin/tenants/:id/limits",
		// platform configuration
		"GET /api/v1/admin-service/admin/settings",
		"PUT /api/v1/admin-service/admin/settings",
		"POST /api/v1/admin-service/admin/settings/test-email",
		"GET /api/v1/admin-service/admin/legal/documents",
		"POST /api/v1/admin-service/admin/legal/documents",
		"POST /api/v1/admin-service/admin/branding/upload",
		"DELETE /api/v1/admin-service/admin/branding/:type",
		"GET /api/v1/admin-service/admin/identity-providers",
		"POST /api/v1/admin-service/admin/identity-providers",
		"GET /api/v1/admin-service/admin/storage/config",
		"PUT /api/v1/admin-service/admin/storage/config",
		"POST /api/v1/admin-service/admin/storage/test",
		"GET /api/v1/admin-service/admin/integrations",
		"POST /api/v1/admin-service/admin/integrations",
		// security + System Health
		"GET /api/v1/admin-service/admin/security/events",
		"GET /api/v1/admin-service/admin/security/dashboard-stats",
		"GET /api/v1/admin-service/admin/monitoring/health",
		"GET /api/v1/admin-service/admin/monitoring/logs",
		// liveness
		"GET /health",
	}
	for _, r := range want {
		if !routes[r] {
			t.Errorf("Core router is missing %q", r)
		}
	}
}

// The compliance-framework routes read public.compliance_framework_status, a
// table with no writer anywhere in the product — no Go INSERT, no seed, no chart
// job. They served an empty table behind a 200 on every deployment forever, so
// they were removed rather than left as a permanently blank panel. This is the
// ratchet: re-adding a route without a producer fails here.
//
// If a real producer is ever built, delete this test in the same commit that
// adds the writer — do not weaken it.
func TestCoreRouter_MountsNoProducerlessComplianceRoutes(t *testing.T) {
	routes := coreRouteSet(t)
	for _, r := range []string{
		"GET /api/v1/admin-service/admin/security/compliance",
		"GET /api/v1/admin-service/admin/security/compliance/:framework",
	} {
		if routes[r] {
			t.Errorf("router mounts %q — that route reads a table nothing writes to", r)
		}
	}
}

func TestCoreRouter_MountsNoMSPRoutes(t *testing.T) {
	routes := coreRouteSet(t)

	var leaked []string
	for route := range routes {
		method, path, ok := strings.Cut(route, " ")
		if !ok {
			continue
		}
		_ = method
		for _, prefix := range mspRoutePrefixes {
			if !strings.HasPrefix(path, prefix) {
				continue
			}
			if coreTenantExceptions[route] {
				continue
			}
			leaked = append(leaked, route)
		}
	}
	sort.Strings(leaked)
	if len(leaked) > 0 {
		t.Fatalf("Core router mounts %d MSP route(s) — the carve leaked:\n  %s",
			len(leaked), strings.Join(leaked, "\n  "))
	}
}

func TestCoreRouter_MountsNoBillingRoutes(t *testing.T) {
	routes := coreRouteSet(t)
	for _, r := range []string{
		"GET /api/v1/admin-service/admin/billing/invoices",
		"GET /api/v1/admin-service/my-billing/invoices",
		"GET /api/v1/admin-service/admin/tenants/:id/billing",
		"POST /api/v1/admin-service/admin/billing/webhook/:provider",
	} {
		if routes[r] {
			t.Errorf("Core router mounts Enterprise billing route %q", r)
		}
	}
}

func TestCoreEdition_ReportsCore(t *testing.T) {
	if got := (EditionHooks{}).Edition(); got != "core" {
		t.Fatalf("zero hooks Edition() = %q, want %q", got, "core")
	}
	// A single populated hook is enough to make it an Enterprise build.
	if got := (EditionHooks{RegisterMSP: func(MSPDeps) MSPRuntime { return nil }}).Edition(); got != "enterprise" {
		t.Fatalf("RegisterMSP-only Edition() = %q, want %q", got, "enterprise")
	}
}
