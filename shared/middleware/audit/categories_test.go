package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The Go category set and the database CHECK must be the same set.
//
// `event_category` is constrained in schema.sql, and an INSERT carrying a
// category outside it is REJECTED (SQLSTATE 23514) — silently, from the
// caller's point of view, because LogActivity appends to a batch and returns
// nil and the flush happens on a background goroutine. Three of the
// asset-inventory build's own audit events were written this way and never
// landed.
//
// So the guard is derived from the schema rather than restated: this test reads
// the CHECK out of scripts/database/schema.sql and compares it to the constants
// in this package, both directions.
//
// To mutation-test: remove a category from validEventCategories, or add one
// that is not in the CHECK. Either fails. Changing the CHECK in schema.sql
// without changing this package fails too, which is the direction that matters
// — the schema is where the rule actually lives.
func TestEventCategories_MatchTheSchemaCheck(t *testing.T) {
	schema := readSchema(t)

	// The CHECK renders as an ARRAY[...]::text[] of quoted literals. Take the
	// first `valid_event_category` constraint; every partition repeats it.
	idx := strings.Index(schema, "CONSTRAINT valid_event_category CHECK")
	if idx < 0 {
		t.Fatal("schema.sql has no valid_event_category CHECK — if the constraint was dropped, " +
			"this guard is what is left saying which categories are meaningful, and it needs rewriting deliberately")
	}
	line := schema[idx:]
	if end := strings.Index(line, "\n"); end > 0 {
		line = line[:end]
	}

	literal := regexp.MustCompile(`'([a-z_]+)'::character varying`)
	fromSchema := map[string]bool{}
	for _, m := range literal.FindAllStringSubmatch(line, -1) {
		fromSchema[m[1]] = true
	}
	if len(fromSchema) == 0 {
		t.Fatalf("no categories parsed out of the CHECK; the guard would pass vacuously: %s", line)
	}

	for c := range fromSchema {
		if !ValidEventCategory(c) {
			t.Errorf("schema.sql accepts event_category %q and this package does not — a caller reading "+
				"the constants would not know it may use it", c)
		}
	}
	for _, c := range EventCategories() {
		if !fromSchema[c] {
			t.Errorf("this package offers event_category %q and the database CHECK rejects it — every "+
				"audit entry written with it is discarded on INSERT", c)
		}
	}
}

// The categories the SHARED middleware derives from a request path must be
// acceptable, and they must be the RIGHT ones. determineEventType picks one for
// every audited request in all sixteen services, so a category it can produce
// and the database cannot store would discard the global audit trail for a
// whole family of paths — and a wrong one files that trail where nobody
// filtering it would look.
//
// The second half is not hypothetical. Until request_category.go existed the
// function read the VERSION segment as the service name, matched nothing, and
// recorded every request as "system"; the older form of this test checked only
// validity, which "system" satisfied by accident.
//
// To mutation-test: point the service lookup back at segment 1, delete the
// certificates override, or drop the /api/vN strip in splitServicePath — each
// fails at least one row below.
func TestDeterminedEventCategoriesAreAllValid(t *testing.T) {
	m := &Middleware{config: DefaultConfig()}

	cases := []struct {
		path string
		want string
	}{
		{"/api/v1/inventory-service/assets", EventCategoryAsset},
		{"/api/v1/inventory-service/assets/2f1c/relationships", EventCategoryAsset},
		{"/api/v1/inventory-service/certificates", EventCategoryCertificate},
		{"/api/v1/inventory-service/settings/identification", EventCategoryConfig},
		{"/api/v1/discovery-processor-service/jobs", EventCategoryDiscovery},
		{"/api/v1/sensor-manager/sensors/register", EventCategoryDiscovery},
		{"/api/v1/sensor-manager/admin/sensors", EventCategoryDiscovery},
		{"/api/v1/cluster-sensor-service/jobs", EventCategoryDiscovery},
		{"/api/v1/device-interrogation-service/jobs", EventCategoryDiscovery},
		{"/api/v1/pcap-processor/upload", EventCategoryDiscovery},
		{"/api/v1/compliance-engine/frameworks", EventCategoryCompliance},
		{"/api/v1/cbom-service/cbom/generate", EventCategoryReport},
		{"/api/v1/cbom-service/scopes", EventCategoryReport},
		{"/api/v1/auth-service/users", EventCategoryUser},
		{"/api/v1/auth-service/tenant/features", EventCategoryUser},
		{"/api/v1/auth-service/auth/login", EventCategoryAuth},
		{"/api/v1/auth-service/auth/refresh", EventCategoryAuth},
		{"/api/v1/auth-service/api-tokens", EventCategoryAuth},
		{"/api/v1/admin-service/auth/login", EventCategoryAuth},
		{"/api/v1/admin-service/admin/tenants", EventCategoryTenant},
		{"/api/v1/admin-service/admin/users", EventCategoryUser},
		{"/api/v1/admin-service/admin/settings", EventCategoryConfig},
		{"/api/v1/admin-service/admin/tiers", EventCategorySystem},
		{"/api/v1/tenant-health-service/score", EventCategoryTenant},
		{"/api/v1/monitoring-service/status", EventCategorySystem},
		{"/api/v1/monitoring-service/platform/metrics", EventCategorySystem},
		{"/api/v1/notification-service/tenant/notifications", EventCategorySystem},
		{"/api/v1/audit-service/activity-logs", EventCategorySystem},
		{"/api/v1/resource-tracker-service/usage", EventCategorySystem},
		{"/api/v1/mcp-service/mcp", EventCategoryData},
		// v2 and prefix-less mounts are the same service.
		{"/api/v2/inventory-service/assets", EventCategoryAsset},
		{"/inventory-service/certificates", EventCategoryCertificate},
		// Nothing to go on.
		{"/health-ish-single-segment", EventCategorySystem},
		{"/api/v1", EventCategorySystem},
		{"/", EventCategorySystem},
	}

	for _, tc := range cases {
		for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"} {
			_, category, _ := m.determineEventType(method, tc.path)
			if !ValidEventCategory(category) {
				t.Errorf("%s %s derives event_category %q, which audit.activity_logs rejects; valid: %v",
					method, tc.path, category, EventCategories())
				continue
			}
			if category != tc.want {
				t.Errorf("%s %s derives event_category %q, want %q", method, tc.path, category, tc.want)
			}
		}
	}
}

// The event type names the RESOURCE — asset.assets.create, not
// system.inventory-service.create — and the admin-plane markers are stepped
// over so the resource is the noun after them.
func TestDeterminedEventType_NamesTheResource(t *testing.T) {
	m := &Middleware{config: DefaultConfig()}
	for _, tc := range []struct{ method, path, want string }{
		{"POST", "/api/v1/inventory-service/assets", "asset.assets.create"},
		{"GET", "/api/v1/inventory-service/certificates/2f1c", "certificate.certificates.read"},
		{"DELETE", "/api/v1/admin-service/admin/tenants/2f1c", "tenant.tenants.delete"},
		{"POST", "/api/v1/auth-service/auth/login", "authentication.auth.create"},
		{"PUT", "/api/v1/monitoring-service/platform/alerting/rules/1", "system.alerting.update"},
		{"HEAD", "/api/v1/compliance-engine/frameworks", "compliance.frameworks.unknown"},
		{"GET", "/health-ish-single-segment", "system.read"},
		{"GET", "/", "system.read"},
	} {
		got, _, _ := m.determineEventType(tc.method, tc.path)
		if got != tc.want {
			t.Errorf("%s %s → event_type %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

// A route mounted without the /api/vN prefix, or under v2, is the same service.
// The derivation must not depend on the prefix being there — that dependence
// is the shape of the original bug, pointed the other way.
func TestDeterminedEventType_IsIndependentOfTheAPIPrefix(t *testing.T) {
	m := &Middleware{config: DefaultConfig()}
	for _, rest := range []string{
		"inventory-service/certificates/2f1c",
		"admin-service/admin/tenants",
		"auth-service/auth/login",
		"monitoring-service/status",
	} {
		wantType, wantCat, _ := m.determineEventType("POST", "/api/v1/"+rest)
		for _, prefix := range []string{"/api/v2/", "/api/v10/", "/"} {
			gotType, gotCat, _ := m.determineEventType("POST", prefix+rest)
			if gotType != wantType || gotCat != wantCat {
				t.Errorf("%s%s → (%q, %q), but /api/v1/%s → (%q, %q)",
					prefix, rest, gotType, gotCat, rest, wantType, wantCat)
			}
		}
	}
}

// Every service in the registry has a deliberate category, and the table names
// no service the registry does not have. An unlisted service falls back to
// "system" — the silent default the table replaced — so a new service must not
// be able to ship without a decision in request_category.go.
//
// To mutation-test: delete any one entry from serviceEventCategory, or rename
// one to a service that does not exist.
func TestEveryRegistryServiceHasAnEventCategory(t *testing.T) {
	path := filepath.Join("..", "..", "..", "standards", "service-registry.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	// Every backend service declares `route_prefix: /<name>`; the frontends do
	// not. A structural change to the registry that stops this matching should
	// fail here, not pass vacuously.
	matches := regexp.MustCompile(`(?m)^\s+route_prefix:\s*/([a-z0-9-]+)\s*$`).FindAllStringSubmatch(string(raw), -1)
	if len(matches) < 10 {
		t.Fatalf("parsed only %d route_prefix entries out of %s; the registry shape changed and this guard needs updating", len(matches), path)
	}

	inRegistry := map[string]bool{}
	for _, m := range matches {
		svc := m[1]
		inRegistry[svc] = true
		if _, ok := serviceEventCategory[svc]; !ok {
			t.Errorf("registry service %q has no entry in serviceEventCategory — every request it audits would be filed under %q by default", svc, EventCategorySystem)
		}
	}
	for svc, c := range serviceEventCategory {
		if !inRegistry[svc] {
			t.Errorf("serviceEventCategory names %q, which is not a registry service (renamed or removed?)", svc)
		}
		if !ValidEventCategory(c) {
			t.Errorf("serviceEventCategory[%q] = %q, which audit.activity_logs rejects", svc, c)
		}
	}
	for res, c := range resourceEventCategory {
		if !ValidEventCategory(c) {
			t.Errorf("resourceEventCategory[%q] = %q, which audit.activity_logs rejects", res, c)
		}
	}
}

func readSchema(t *testing.T) string {
	t.Helper()
	// shared/middleware/audit -> shared/middleware -> shared -> repo root.
	path := filepath.Join("..", "..", "..", "scripts", "database", "schema.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}
