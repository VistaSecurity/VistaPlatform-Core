package api

// Admin-plane classification test — Core edition.
//
// admin-service holds the cross-tenant control plane. The chart keeps that
// surface off the public tenant host by generating deny/allow route pairs from
// `admin_plane.prefixes` in standards/service-registry.yaml. The chart can only
// deny what the registry declares, so a route mounted OUTSIDE every declared
// prefix rides the /api/v1/admin-service/ catch-all straight onto the public
// host — where its platform-admin role check is the only thing between a caller
// and every tenant's data.
//
// This test makes that impossible to do by accident: every route the real
// router mounts must be either
//
//   - under a declared admin-plane prefix, or
//   - in publicByDesign below — an explicit, justified allow-list.
//
// Anything else fails. The registry is read from disk rather than restated
// here, so deleting a prefix from the registry surfaces as a test failure in
// the service that owns the routes, not just as chart drift.
//
// This file has NO build tag and imports nothing from ee/, so it survives the
// open-source cut and keeps guarding the Core route set in a public checkout.
// The mirror covering the Enterprise route set (ee/msp + ee/billingapi, ~180
// routes) is ee/billingapi/admin_plane_edition_test.go.

import (
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	_ "github.com/lib/pq"
	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
)

// registryPath is the repo-root service registry, four levels up from
// services/admin-service/internal/api.
const registryPath = "../../../../standards/service-registry.yaml"

// publicByDesign lists the admin-service paths that must remain reachable on
// the public tenant host, each with the reason something outside the operator's
// network has to reach it. Adding an entry here is a deliberate decision to
// widen the public API surface — it should be as hard to do quietly as adding a
// route to the admin plane.
//
// Entries are matched as path prefixes against the gin route path.
var publicByDesign = map[string]string{
	"/health":                     "liveness/readiness probe; no data, no auth",
	"/uploads/platform-branding/": "white-label logo and favicon rendered on the tenant login page, before any session exists",
}

// adminPlaneRegistry is the subset of standards/service-registry.yaml this test
// needs.
type adminPlaneRegistry struct {
	AdminPlane struct {
		Prefixes         []string `yaml:"prefixes"`
		PublicExceptions []string `yaml:"public_exceptions"`
	} `yaml:"admin_plane"`
}

func loadAdminPlane(t *testing.T) adminPlaneRegistry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(registryPath))
	if err != nil {
		t.Fatalf("read service registry: %v", err)
	}
	var reg adminPlaneRegistry
	if err := yaml.Unmarshal(raw, &reg); err != nil {
		t.Fatalf("parse service registry: %v", err)
	}
	if len(reg.AdminPlane.Prefixes) == 0 {
		t.Fatal("service registry declares no admin_plane.prefixes — the chart has nothing to deny on the public host")
	}
	return reg
}

// classify reports whether a mounted route is accounted for, and how.
//
// Registry prefixes are version-agnostic (the generator emits both /api/v1 and
// /api/v2 rules), so the version segment is stripped before comparing.
func classify(routePath string, reg adminPlaneRegistry) (kind string, ok bool) {
	for prefix, reason := range publicByDesign {
		if strings.HasPrefix(routePath, prefix) {
			return "public by design (" + reason + ")", true
		}
	}

	stripped := routePath
	for _, v := range []string{"/api/v1", "/api/v2"} {
		if strings.HasPrefix(stripped, v) {
			stripped = strings.TrimPrefix(stripped, v)
			break
		}
	}

	// Declared public exceptions are checked BEFORE the enclosing admin-plane
	// prefix, since they sit inside one.
	for _, ex := range reg.AdminPlane.PublicExceptions {
		if strings.HasPrefix(stripped, ex) {
			return "declared public exception", true
		}
	}
	for _, p := range reg.AdminPlane.Prefixes {
		if strings.HasPrefix(stripped, p) {
			return "admin plane", true
		}
	}
	return "", false
}

func TestCoreRouter_EveryRouteIsClassified(t *testing.T) {
	reg := loadAdminPlane(t)

	db, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	srv := NewServerWithConnections(&config.Config{Environment: "test"}, db, db, EditionHooks{})

	var unclassified []string
	adminPlane := 0
	for _, r := range srv.Router().Routes() {
		if _, ok := classify(r.Path, reg); ok {
			if kind, _ := classify(r.Path, reg); kind == "admin plane" {
				adminPlane++
			}
			continue
		}
		unclassified = append(unclassified, r.Method+" "+r.Path)
	}

	if len(unclassified) > 0 {
		sort.Strings(unclassified)
		t.Errorf(`%d admin-service route(s) are neither declared admin-plane nor public by design.

They will be served on the PUBLIC tenant host through the
/api/v1/admin-service/ catch-all, protected only by their role check:

  %s

Fix one of two ways:
  - cross-tenant/platform-admin? add its prefix to admin_plane.prefixes in
    standards/service-registry.yaml, then run 'make generate-k8s-ingress'
  - genuinely tenant-facing or anonymous? add it to publicByDesign in this
    file WITH the reason it must be publicly reachable`,
			len(unclassified), strings.Join(unclassified, "\n  "))
	}

	// A test that classifies zero admin-plane routes would pass vacuously — for
	// instance if the router failed to mount the console at all.
	if adminPlane == 0 {
		t.Fatal("no routes classified as admin plane; the classification is not actually exercising anything")
	}
	t.Logf("Core router: %d admin-plane routes, all routes classified", adminPlane)
}

// The classifier itself has to be able to fail, or the test above proves
// nothing. Pin both polarities.
func TestClassify_RejectsAnUndeclaredRoute(t *testing.T) {
	reg := loadAdminPlane(t)

	if _, ok := classify("/api/v1/admin-service/admin/users", reg); !ok {
		t.Error("a declared admin-plane route was not classified")
	}
	if _, ok := classify("/api/v1/admin-service/admin/billing/webhook/stripe", reg); !ok {
		t.Error("a declared public exception was not classified")
	}
	if _, ok := classify("/health", reg); !ok {
		t.Error("a publicByDesign route was not classified")
	}
	if kind, ok := classify("/api/v1/admin-service/totally-new-surface", reg); ok {
		t.Errorf("an undeclared route classified as %q — the guard cannot fail", kind)
	}
}
