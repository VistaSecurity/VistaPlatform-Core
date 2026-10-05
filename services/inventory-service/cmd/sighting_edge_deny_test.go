package main

// The sightings route is internal-only at the EDGE as well as at the gate:
// every generated ingress — the three Traefik file-provider configs `make
// generate-gateway` writes and the chart's IngressRoutes `make
// generate-k8s-ingress` writes — must route
// /api/v1/inventory-service/internal/sightings to a router carrying the
// deny-internal-plane middleware, and nothing of higher priority may reach the
// backend first. It reads the GENERATED files, so it fails if the registry's
// internal_prefixes entry is dropped and `make generate` is re-run, and if a
// generator stops emitting the deny.
//
// Path matching only: every router compared serves the same host set, and a
// Host() clause cannot make a deny router lose to an allow router on the same
// path.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/shared/identity/sightingclient"
)

const sightingsEdgePath = "/api/v1/inventory-service/internal/sightings"

var (
	rulePathPrefix = regexp.MustCompile("PathPrefix\\(`([^`]+)`\\)")
	rulePath       = regexp.MustCompile("Path\\(`([^`]+)`\\)")
)

// ruleCovers reports whether a router rule's path literals match path.
func ruleCovers(rule, path string) bool {
	for _, m := range rulePathPrefix.FindAllStringSubmatch(rule, -1) {
		if strings.HasPrefix(path, m[1]) {
			return true
		}
	}
	for _, m := range rulePath.FindAllStringSubmatch(rule, -1) {
		if m[1] == path {
			return true
		}
	}
	return false
}

type edgeRouter struct {
	name     string
	rule     string
	priority int
	deny     bool
}

// internalEdgePaths are the internal routes device-interrogation-service
// calls: the sightings route and, after an interrogation's claims settle, the
// gateway-links route.
var internalEdgePaths = []string{sightingsEdgePath, sightingclient.GatewayLinksPath}

// assertEdgeDenies checks that, for each internal path, the highest-priority
// router covering it denies it.
func assertEdgeDenies(t *testing.T, where string, routers []edgeRouter) {
	t.Helper()
	for _, path := range internalEdgePaths {
		var winner *edgeRouter
		for i := range routers {
			r := &routers[i]
			if !ruleCovers(r.rule, path) {
				continue
			}
			if winner == nil || r.priority > winner.priority || (r.priority == winner.priority && !r.deny) {
				winner = r
			}
		}
		switch {
		case winner == nil:
			t.Errorf("%s: no router covers %s at all", where, path)
		case !winner.deny:
			t.Errorf("%s: %s is served by %q (priority %d) without deny-internal-plane", where, path, winner.name, winner.priority)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestSightingRoute_DeniedAtTheEdgeByTheGeneratedTraefikConfig(t *testing.T) {
	for _, name := range []string{"dynamic-development.yaml", "dynamic-production.yaml", "dynamic-ec2-smoke.yaml"} {
		body, err := os.ReadFile(filepath.Join(repoRoot(t), "config", "traefik", name))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			HTTP struct {
				Routers map[string]struct {
					Rule        string   `yaml:"rule"`
					Priority    int      `yaml:"priority"`
					Middlewares []string `yaml:"middlewares"`
				} `yaml:"routers"`
			} `yaml:"http"`
		}
		if err := yaml.Unmarshal(body, &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var routers []edgeRouter
		for rn, r := range doc.HTTP.Routers {
			p := r.Priority
			if p == 0 {
				// Traefik's default priority is the rule's length.
				p = len(r.Rule)
			}
			deny := false
			for _, m := range r.Middlewares {
				deny = deny || m == "deny-internal-plane"
			}
			routers = append(routers, edgeRouter{name: rn, rule: r.Rule, priority: p, deny: deny})
		}
		assertEdgeDenies(t, name, routers)
	}
}

func TestSightingRoute_DeniedAtTheEdgeByTheChartIngressRoutes(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "charts", "vistaplatform", "templates", "ingress", "ingressroutes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The template is not YAML until Helm renders it, so each `- match:` entry
	// is read as the text up to the next one.
	parts := strings.Split(string(body), "- match:")
	priority := regexp.MustCompile(`(?m)^\s*priority:\s*(\d+)`)
	var routers []edgeRouter
	for i, part := range parts[1:] {
		rule := strings.SplitN(part, "\n", 2)[0]
		p := len(rule)
		if m := priority.FindStringSubmatch(part); m != nil {
			p, _ = strconv.Atoi(m[1])
		}
		routers = append(routers, edgeRouter{name: "match #" + strconv.Itoa(i+1), rule: rule, priority: p,
			deny: strings.Contains(part, "name: deny-internal-plane")})
	}
	assertEdgeDenies(t, "ingressroutes.yaml", routers)
}
