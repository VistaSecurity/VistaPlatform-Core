package main

// Admin-plane classification test for inventory-service (split from).
//
// inventory-service is a TENANT service with two platform-admin writes bolted
// on: the algorithm-catalogue create/update, which maintain global crypto
// grading data. Those used to be platform-gated *methods* on
// /inventory-service/algorithms — a path whose GETs the tenant UI reads. The
// chart splits the admin plane off the public host by PATH, so a gated method
// on a tenant-facing path could not be split, and the writes stayed reachable
// on the public tenant host with their RBAC check as the only control.
//
// They now live under /inventory-service/admin/, a declared
// admin_plane.prefixes entry. This test pins both halves of that arrangement:
//
//   - every platform-gated route this service mounts is under a declared
//     admin-plane prefix (so it is DENIED on the tenant host), and
//   - the tenant-facing algorithm reads are NOT under one (so they are not
//     swallowed by the deny — the mirror-image bug that 404'd platform
//     branding on Kubernetes).
//
// It then evaluates the GENERATED Traefik rules rather than trusting that the
// registry entry produced them, because Traefik's PathPrefix(`/x/y/`) does not
// match `/x/y` and the generator has to emit both forms.
//
// The router is built inline in main(), so route discovery is a source scan of
// main.go rather than a real-router walk (the admin-service equivalent,
// services/admin-service/internal/api/admin_plane_test.go, can build its
// router and does). A source scan is enough here: the registrations are plain
// literal calls, and the test fails closed if it finds none.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	registryPath = "../../../standards/service-registry.yaml"
	mainPath     = "main.go"
	ingressPath  = "../../../charts/vistaplatform/templates/ingress/ingressroutes.yaml"
)

// A platform gate, in any of the spellings shared/middleware/rbac offers.
var platformGate = regexp.MustCompile(`RequirePlatformAuth|RequirePlatformAdmin|RequirePlatformPermission|RequireAnyPlatformPermission`)

// `api.POST("/inventory-service/…"` — the only registration shape main.go uses.
var routeReg = regexp.MustCompile(`^\s*(api|apiv2)\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\(\s*"([^"]+)"`)

type route struct {
	method string
	path   string // registry-relative, e.g. /inventory-service/admin/algorithms
	gated  bool
}

// scanRoutes reads main.go and returns every /api/v{1,2} route registration,
// flagged with whether a platform gate appears in that call's own argument
// list. The argument list is gathered by parenthesis balance, not a fixed line
// window: a window overruns into the next registration, which would let a
// gated neighbour make an ungated route look protected.
func scanRoutes(t *testing.T) []route {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	lines := strings.Split(string(raw), "\n")

	var out []route
	for i, line := range lines {
		m := routeReg.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, route{
			method: m[2],
			path:   m[3],
			gated:  platformGate.MatchString(callArgs(lines, i)),
		})
	}
	return out
}

func callArgs(lines []string, i int) string {
	depth := 0
	started := false
	var b strings.Builder
	for j := i; j < len(lines) && j < i+12; j++ {
		b.WriteString(lines[j])
		b.WriteByte('\n')
		for _, ch := range lines[j] {
			switch ch {
			case '(':
				depth++
				started = true
			case ')':
				depth--
			}
		}
		if started && depth <= 0 {
			break
		}
	}
	return b.String()
}

type adminPlaneRegistry struct {
	AdminPlane struct {
		Prefixes []string `yaml:"prefixes"`
	} `yaml:"admin_plane"`
}

func loadPrefixes(t *testing.T) []string {
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
	return reg.AdminPlane.Prefixes
}

// deniedOnTenantHost reports whether a path falls under a declared admin-plane
// prefix, i.e. whether the generated deny answers it on the tenant host.
func deniedOnTenantHost(urlPath string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(urlPath, p) {
			return true
		}
	}
	return false
}

func TestAdminPlane_EveryPlatformGatedRouteIsDeclared(t *testing.T) {
	prefixes := loadPrefixes(t)
	routes := scanRoutes(t)
	if len(routes) == 0 {
		t.Fatal("scanned no routes out of main.go — the scan is not exercising anything")
	}

	gated := 0
	var undeclared []string
	for _, r := range routes {
		if !r.gated {
			continue
		}
		gated++
		if !deniedOnTenantHost(r.path, prefixes) {
			undeclared = append(undeclared, r.method+" "+r.path)
		}
	}

	// A run that classifies zero gated routes would pass vacuously — for
	// instance if the gate spelling changed and the regex stopped matching.
	if gated == 0 {
		t.Fatal("no platform-gated routes found in main.go; the scan is not actually exercising anything")
	}
	if len(undeclared) > 0 {
		t.Errorf(`%d platform-gated inventory-service route(s) are not under a declared admin-plane prefix:

  %s

They ride the /api/v1/inventory-service/ catch-all onto the PUBLIC tenant host,
where the RBAC check is the only control. Move them under an admin-only path
and add that prefix to admin_plane.prefixes in standards/service-registry.yaml,
then run 'make generate'.`, len(undeclared), strings.Join(undeclared, "\n  "))
	}
}

// The inverse. The tenant UI's Algorithm Reference surface reads the catalogue,
// so those GETs must stay OFF the admin plane — a deny covering them would 404
// on the tenant host with nothing logged anywhere.
func TestAdminPlane_TenantFacingAlgorithmReadsStayPublic(t *testing.T) {
	prefixes := loadPrefixes(t)
	for _, r := range scanRoutes(t) {
		if r.method != "GET" || !strings.HasPrefix(r.path, "/inventory-service/algorithms") {
			continue
		}
		if deniedOnTenantHost(r.path, prefixes) {
			t.Errorf("GET %s is under a denied admin-plane prefix; the tenant UI reads it and would get a 404", r.path)
		}
	}
}

// ─── The generated rules ───────────────────────────────────────────────────

type chartRoute struct {
	match string
	body  string
}

var (
	matchLine  = regexp.MustCompile(`^\s*- match: (.+)$`)
	priorityRe = regexp.MustCompile(`priority: (\d+)`)
)

func loadChartRoutes(t *testing.T) []chartRoute {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(ingressPath))
	if err != nil {
		t.Fatalf("read generated ingressroutes: %v", err)
	}
	lines := strings.Split(string(raw), "\n")
	var out []chartRoute
	for i, line := range lines {
		m := matchLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		var body []string
		for j := i + 1; j < len(lines) && !matchLine.MatchString(lines[j]); j++ {
			body = append(body, lines[j])
		}
		out = append(out, chartRoute{match: m[1], body: strings.Join(body, "\n")})
	}
	return out
}

// ruleMatches evaluates the small subset of Traefik matcher syntax the
// generator emits: Host(`h`) && PathPrefix(`p`), optionally with a
// `|| Path(`bare`)` alternative. Implemented rather than string-compared so
// the bare-path case is genuinely exercised: PathPrefix(`/x/y/`) does NOT
// match `/x/y`, which is why the generator emits the Path() alternative at all.
func ruleMatches(rule, host, urlPath string) bool {
	// `{{ $apiHost }}` is the template's both-hosts matcher — it renders to
	// Host(tenant) when no admin host is configured and to
	// (Host(tenant) || Host(admin)) when one is. The per-service catch-alls
	// use it, which is exactly why the admin-plane deny/allow pair has to
	// outrank them.
	if !strings.Contains(rule, "Host(`"+host+"`)") && !strings.Contains(rule, "{{ $apiHost }}") {
		return false
	}
	// Rules that AND in a PathRegexp are narrow per-route carve-outs; this
	// evaluator does not model the conjunction, so it declines to guess rather
	// than over-matching. None of the paths asserted below live under one.
	if strings.Contains(rule, "PathRegexp(") {
		return false
	}
	for _, m := range regexp.MustCompile("PathPrefix\\(`([^`]+)`\\)").FindAllStringSubmatch(rule, -1) {
		if strings.HasPrefix(urlPath, m[1]) {
			return true
		}
	}
	// "Path(`…`)" cannot match inside "PathPrefix(`…`)": the literal "(" has to
	// follow "Path" immediately, and there it is followed by "Prefix".
	for _, m := range regexp.MustCompile("Path\\(`([^`]+)`\\)").FindAllStringSubmatch(rule, -1) {
		if urlPath == m[1] {
			return true
		}
	}
	return false
}

// The hosts as they appear in the Helm template, unrendered.
const (
	tenantHost = "{{ $dnsName }}"
	adminHost  = "{{ $adminDnsName }}"
)

// bestMatch returns the highest-priority route matching host+path. Traefik
// resolves overlaps by priority, and the admin-plane rules are emitted at 900
// precisely so they outrank the per-service catch-all.
func bestMatch(t *testing.T, routes []chartRoute, host, urlPath string) *chartRoute {
	t.Helper()
	var best *chartRoute
	bestPri := -1
	for i := range routes {
		if !ruleMatches(routes[i].match, host, urlPath) {
			continue
		}
		pri := 0
		if m := priorityRe.FindStringSubmatch(routes[i].body); m != nil {
			pri = atoi(m[1])
		}
		if pri > bestPri {
			bestPri = pri
			best = &routes[i]
		}
	}
	return best
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func TestGeneratedRules_AlgorithmWritesDeniedOnTenantHostAllowedOnAdminHost(t *testing.T) {
	routes := loadChartRoutes(t)
	if len(routes) == 0 {
		t.Fatal("parsed no routes out of the generated ingressroutes template")
	}

	// Both the subtree and the BARE prefix path. The bare form is the one a
	// trailing-slash-only rule silently misses.
	for _, version := range []string{"v1", "v2"} {
		for _, urlPath := range []string{
			"/api/" + version + "/inventory-service/admin",
			"/api/" + version + "/inventory-service/admin/algorithms",
			"/api/" + version + "/inventory-service/admin/algorithms/AES-256-GCM",
		} {
			deny := bestMatch(t, routes, tenantHost, urlPath)
			if deny == nil {
				t.Errorf("%s: no tenant-host route matches at all", urlPath)
			} else if !strings.Contains(deny.body, "name: deny-admin-plane") {
				t.Errorf("%s: highest-priority tenant-host route does not carry deny-admin-plane:\n%s", urlPath, deny.match)
			}

			allow := bestMatch(t, routes, adminHost, urlPath)
			if allow == nil {
				t.Errorf("%s: no admin-host route matches — the writes would be unreachable from the admin UI", urlPath)
			} else if strings.Contains(allow.body, "name: deny-admin-plane") {
				t.Errorf("%s: admin-host route carries deny-admin-plane", urlPath)
			} else if !strings.Contains(allow.body, "name: inventory-service") {
				t.Errorf("%s: admin-host route does not reach inventory-service:\n%s", urlPath, allow.body)
			}
		}
	}

	// And the tenant-facing read is NOT denied.
	for _, version := range []string{"v1", "v2"} {
		urlPath := "/api/" + version + "/inventory-service/algorithms"
		r := bestMatch(t, routes, tenantHost, urlPath)
		if r == nil {
			t.Errorf("%s: no tenant-host route matches; the tenant UI cannot read the catalogue", urlPath)
		} else if strings.Contains(r.body, "name: deny-admin-plane") {
			t.Errorf("%s: tenant-host read is DENIED — the deny is too wide", urlPath)
		}
	}
}

// The rule evaluator has to be able to say no, or the assertions above prove
// nothing. Pin both polarities, including the trailing-slash trap itself.
func TestRuleMatches_BothPolarities(t *testing.T) {
	withBare := "Host(`" + tenantHost + "`) && (PathPrefix(`/api/v1/inventory-service/admin/`) || Path(`/api/v1/inventory-service/admin`))"
	prefixOnly := "Host(`" + tenantHost + "`) && PathPrefix(`/api/v1/inventory-service/admin/`)"

	if !ruleMatches(withBare, tenantHost, "/api/v1/inventory-service/admin/algorithms") {
		t.Error("subtree path did not match the generated rule")
	}
	if !ruleMatches(withBare, tenantHost, "/api/v1/inventory-service/admin") {
		t.Error("bare path did not match the rule that carries the Path() alternative")
	}
	if ruleMatches(prefixOnly, tenantHost, "/api/v1/inventory-service/admin") {
		t.Error("bare path matched a PathPrefix-only rule — the evaluator does not reproduce Traefik's trailing-slash behaviour, so the tests above cannot detect that bug")
	}
	if ruleMatches(withBare, adminHost, "/api/v1/inventory-service/admin/algorithms") {
		t.Error("a tenant-host rule matched the admin host")
	}
	if ruleMatches(withBare, tenantHost, "/api/v1/inventory-service/algorithms") {
		t.Error("the admin-plane rule matched a tenant-facing path")
	}
}
