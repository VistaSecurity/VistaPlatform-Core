package spectest

// Both polarities of every claim, against synthetic inputs.
//
// The comparisons in this package are what four services rely on, and each of
// them has an exemption branch that the real repo can never exercise: the
// x-edition exemption only fires when `ee/` is ABSENT, which is never true in
// this tree. An unexercised exemption branch can be deleted without anything
// going red — and deleting it silently reintroduces the Core-export failure the
// whole file exists to prevent. So every branch is driven here, in both
// directions, with no filesystem and no spec.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func route(key string, ee bool) Route { return Route{Key: key, EE: ee, File: "synthetic.go"} }

func routes(rs ...Route) map[string]Route {
	out := map[string]Route{}
	for _, r := range rs {
		out[r.Key] = r
	}
	return out
}

func op(key string, enterprise bool) Operation {
	return Operation{Key: key, Enterprise: enterprise, ID: "syntheticOp"}
}

func ops(os ...Operation) map[string]Operation {
	out := map[string]Operation{}
	for _, o := range os {
		out[o.Key] = o
	}
	return out
}

// --------------------------------------------------------------- missing ----

func TestMissingRoutes_EnterpriseOpIsExemptInACoreTree(t *testing.T) {
	// No ee/: the enterprise-tagged op genuinely has no handler, and Core mounts
	// at most a 402 stub via gin's `.Any()`, which this scanner does not credit.
	got := MissingRoutes(
		routes(route("GET /connectors", false)),
		ops(op("GET /connectors/netbox/connections", true)),
		false, nil,
	)
	if len(got) != 0 {
		t.Fatalf("expected the enterprise op to be exempt in a Core tree, got %v", got)
	}
}

func TestMissingRoutes_EnterpriseOpIsRequiredWhenEEIsPresent(t *testing.T) {
	// ee/ present and the route is still gone: a real bug (the ee routes.go was
	// deleted, or the path typo'd) and it must be reported.
	got := MissingRoutes(
		routes(route("GET /connectors", false)),
		ops(op("GET /connectors/netbox/connections", true)),
		true, nil,
	)
	if len(got) != 1 {
		t.Fatalf("expected the enterprise op to be required when ee/ is present, got %v", got)
	}
}

func TestMissingRoutes_PlainOpIsRequiredInEitherTree(t *testing.T) {
	for _, ee := range []bool{true, false} {
		got := MissingRoutes(routes(), ops(op("GET /assets", false)), ee, nil)
		if len(got) != 1 {
			t.Fatalf("ee=%v: a non-enterprise op with no route must be reported, got %v", ee, got)
		}
	}
}

func TestMissingRoutes_DocumentedElsewhereIsExempt(t *testing.T) {
	got := MissingRoutes(routes(), ops(op("GET /assets", false)), true,
		map[string]string{"GET /assets": "served by the gateway"})
	if len(got) != 0 {
		t.Fatalf("expected the recorded exemption to apply, got %v", got)
	}
}

// ------------------------------------------------------------ edition tag ----

func TestUntaggedEERoutes_ReportsAnEERouteWhoseOpIsNotTagged(t *testing.T) {
	got := UntaggedEERoutes(
		routes(route("GET /siem/types", true)),
		ops(op("GET /siem/types", false)),
	)
	if len(got) != 1 || got[0].Route.Key != "GET /siem/types" {
		t.Fatalf("expected the untagged ee route to be reported, got %+v", got)
	}
}

func TestUntaggedEERoutes_AcceptsATaggedOp(t *testing.T) {
	if got := UntaggedEERoutes(
		routes(route("GET /siem/types", true)),
		ops(op("GET /siem/types", true)),
	); len(got) != 0 {
		t.Fatalf("expected a tagged ee route to pass, got %+v", got)
	}
}

func TestUntaggedEERoutes_IgnoresNonEERoutes(t *testing.T) {
	// A Core route whose op is untagged is CORRECT — that is the normal case,
	// and reporting it would make this check fire on every route in the repo.
	if got := UntaggedEERoutes(
		routes(route("GET /assets", false)),
		ops(op("GET /assets", false)),
	); len(got) != 0 {
		t.Fatalf("expected a Core route to be ignored, got %+v", got)
	}
}

func TestEnterpriseOpsOutsideEE_ReportsAMisplacedTag(t *testing.T) {
	// The tag claims a Core build has no handler; this build's handler is not
	// under ee/, so the claim is false. A false tag is worse than none: it
	// exempts the op from the missing-route check in every Core build.
	got := EnterpriseOpsOutsideEE(
		routes(route("GET /assets", false)),
		ops(op("GET /assets", true)),
	)
	if len(got) != 1 {
		t.Fatalf("expected the misplaced enterprise tag to be reported, got %+v", got)
	}
}

func TestEnterpriseOpsOutsideEE_AcceptsAnEEHandler(t *testing.T) {
	if got := EnterpriseOpsOutsideEE(
		routes(route("GET /siem/types", true)),
		ops(op("GET /siem/types", true)),
	); len(got) != 0 {
		t.Fatalf("expected an ee-hosted enterprise op to pass, got %+v", got)
	}
}

func TestUndocumentedEE_ReportsAndRespectsTheAllowList(t *testing.T) {
	r := routes(route("GET /dashboard/ws", true))
	if got := UndocumentedEE(r, ops(), nil); len(got) != 1 {
		t.Fatalf("expected the undocumented ee route to be reported, got %+v", got)
	}
	if got := UndocumentedEE(r, ops(), map[string]string{"GET /dashboard/ws": "WebSocket"}); len(got) != 0 {
		t.Fatalf("expected the recorded gap to be exempt, got %+v", got)
	}
}

// ---------------------------------------------------------- normalisation ----

func TestNormalizePath_TrimsWholeSegmentsOnly(t *testing.T) {
	cases := []struct{ in, service, want string }{
		{"/api/v1/admin-service/admin/tiers", "admin-service", "/admin/tiers"},
		{"/api/v2/inventory-service/assets", "inventory-service", "/assets"},
		{"/admin/tiers", "admin-service", "/admin/tiers"},
		// The bug this exists for: TrimPrefix("/api-tokens", "/api") is
		// "-tokens", which reported three auth-service ops as unrouted while
		// their routes were right there.
		{"/api-tokens", "auth-service", "/api-tokens"},
		{"/api-tokens/:id", "auth-service", "/api-tokens/:id"},
		// A trailing slash is the same route to gin and the same path to a
		// reader, and both spellings appear in the specs.
		{"/assets/", "inventory-service", "/assets"},
		{"/", "inventory-service", "/"},
	}
	for _, c := range cases {
		if got := NormalizePath(c.in, c.service); got != c.want {
			t.Errorf("NormalizePath(%q, %q) = %q, want %q", c.in, c.service, got, c.want)
		}
	}
}

func TestSamePathModuloPrefix_BothDirectionsAndNoMidSegmentMatch(t *testing.T) {
	// A group arriving as a function parameter loses its prefix, which makes the
	// ROUTE shorter than the spec path; a fully-written registration makes it
	// longer. Both are the same unknown.
	if _, ok := samePathModuloPrefix("/sso/unlink", "/auth/sso/unlink"); !ok {
		t.Error("a route missing its resolved group prefix must still match its spec path")
	}
	if _, ok := samePathModuloPrefix("/platform/admin/tiers", "/admin/tiers"); !ok {
		t.Error("a route carrying an extra unstripped prefix must still match")
	}
	// And the boundary: a suffix must start at a segment.
	if _, ok := samePathModuloPrefix("/custom-tiers", "/tiers"); ok {
		t.Error("/custom-tiers must not match /tiers — that is a different route")
	}
	if _, ok := samePathModuloPrefix("/a/xtiers", "/tiers"); ok {
		t.Error("/a/xtiers must not match /tiers")
	}
	// A bare root matches nothing but itself, or every route would "match".
	if _, ok := samePathModuloPrefix("/anything/at/all", "/"); ok {
		t.Error(`"/" must not match an arbitrary path`)
	}
}

func TestCollapseParams_IgnoresTheParameterName(t *testing.T) {
	if got, want := CollapseParams("GET /assets/:assetId/endpoints"), "GET /assets/:x/endpoints"; got != want {
		t.Errorf("CollapseParams = %q, want %q", got, want)
	}
}

// ------------------------------------------------------------- ee detection --

func TestHasEE(t *testing.T) {
	with := t.TempDir()
	if err := os.Mkdir(filepath.Join(with, "ee"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !HasEE(with) {
		t.Error("expected HasEE to report true when ee/ exists")
	}
	if HasEE(t.TempDir()) {
		t.Error("expected HasEE to report false when ee/ is absent")
	}
}

// ------------------------------------------------------------ route scanner --

// The scanner resolves a group chain within a file, and does NOT mistake a
// `.Get(` header read for a route registration — which is how `GET
// /Stripe-Signature` appeared in admin-service's route table.
func TestScanRoutes_ResolvesGroupsAndIgnoresLookalikes(t *testing.T) {
	dir := t.TempDir()
	src := `package x

func register(root, mounted Router) {
	api := root.Group("/api/v1")
	svc := api.Group("/demo-service")
	svc.GET("/things", nil)
	inner := svc.Group("/things")
	inner.POST("/:id/act", nil)

	// A group this file cannot resolve: the prefix comes from the caller.
	mounted.DELETE("/unresolved", nil)

	// Not registrations.
	_ = c.Request.Header.Get("Stripe-Signature")
	_ = other.Any("/stub", nil)
}
`
	if err := os.WriteFile(filepath.Join(dir, "routes.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	// The scanner strips "/"+filepath.Base(root), so name the dir accordingly.
	got := ScanRoutes(t, dir)

	for _, want := range []string{"POST /demo-service/things/:id/act", "DELETE /unresolved"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected %q in the route table, got:\n%s", want, Describe(got))
		}
	}
	// `/api/v1` is stripped; the service segment is the temp dir's name, which
	// is not "demo-service", so it survives — assert the resolved shape rather
	// than a spelling that depends on the temp directory.
	if _, ok := got["GET /demo-service/things"]; !ok {
		t.Errorf("expected the resolved group chain in the route table, got:\n%s", Describe(got))
	}
	// Matched on the PATH, not on a `<METHOD> <path>` key. Keying on the method
	// spelling too made this inert against the one-line form of the bug: fold
	// the name only at the match site (`httpMethods[strings.ToUpper(...)]`) and
	// the header read is admitted as `Get /Stripe-Signature`, which is not the
	// key the test looked for, so it passed while a bogus route sat in the
	// table.
	for _, unwanted := range []string{"/Stripe-Signature", "/stub"} {
		for key := range got {
			if strings.HasSuffix(key, " "+unwanted) {
				t.Errorf("%q must not be read as a route registration (matched %q):\n%s",
					unwanted, key, Describe(got))
			}
		}
	}
}

// A Core registration of the same key wins over an ee one, so a capability that
// Core really does serve is not reported as an export hazard.
func TestScanRoutes_CoreRegistrationWinsOverEE(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "ee", "thing"), 0o755); err != nil {
		t.Fatal(err)
	}
	core := "package x\n\nfunc a(g Router) { g.GET(\"/shared\", nil) }\n"
	ee := "package thing\n\nfunc b(g Router) { g.GET(\"/shared\", nil) }\n"
	if err := os.WriteFile(filepath.Join(dir, "core.go"), []byte(core), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ee", "thing", "ee.go"), []byte(ee), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ScanRoutes(t, dir)
	r, ok := got["GET /shared"]
	if !ok {
		t.Fatalf("expected GET /shared in the table:\n%s", Describe(got))
	}
	if r.EE {
		t.Errorf("a key registered in BOTH trees must be recorded as Core, got ee=%v (%s)", r.EE, r.File)
	}
}
