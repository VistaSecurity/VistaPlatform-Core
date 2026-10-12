package config

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

// The peer-map guard.
//
// Load() hand-maintains the map of services monitoring-service health-checks
// and reports on System Health. Nothing tied it to standards/service-registry.yaml,
// so an Enterprise-only service shipped in every commercial deployment and never
// appeared there: the check did not break, it just silently covered less than
// it claimed to.
//
// The rule, derived from the registry's own fields:
//
//   - A registry entry under `services:` is a health-checked peer when its
//     docker.type is "go-service". Every Go service mounts the shared /health
//     route; the registry has no per-service health field. Frontends live under
//     `ui:` and infrastructure under `infrastructure:`, so neither is in
//     `services:` at all. monitoring-service itself is excluded (it does not
//     probe itself).
//   - Every peer must have a map entry, and every map entry must be either a
//     registry service or listed in the registry's `infrastructure.exceptions`
//     (postgres, redis, nats, api-gateway ... which are probed but are not
//     registry services).
//
// Enterprise-only services are fenced with `# edition:enterprise` in the
// registry and `// edition:enterprise` in config.go. The export strips both, so
// this same test holds on the public tree.

type peerRegistry struct {
	Infrastructure struct {
		Exceptions []string `yaml:"exceptions"`
	} `yaml:"infrastructure"`
	Services []struct {
		Key    string `yaml:"key"`
		Docker struct {
			Type string `yaml:"type"`
		} `yaml:"docker"`
	} `yaml:"services"`
}

func peerRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("go.work not found above the test directory")
	return ""
}

func diffNames(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// comparePeerMap returns peers absent from the map and map names the registry
// does not know.
func comparePeerMap(mapNames, peers, known map[string]bool) (missing, extra []string) {
	return diffNames(peers, mapNames), diffNames(mapNames, known)
}

func TestPeerMapMatchesServiceRegistry(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(peerRepoRoot(t), "standards", "service-registry.yaml"))
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	var reg peerRegistry
	if err := yaml.Unmarshal(raw, &reg); err != nil {
		t.Fatalf("parse registry: %v", err)
	}

	peers := map[string]bool{}
	known := map[string]bool{}
	for _, s := range reg.Services {
		known[s.Key] = true
		if s.Docker.Type == "go-service" && s.Key != "monitoring-service" {
			peers[s.Key] = true
		}
	}
	for _, e := range reg.Infrastructure.Exceptions {
		known[e] = true
	}
	if len(peers) < 10 {
		t.Fatalf("registry parse found only %d peer services; the guard is not reading the registry", len(peers))
	}

	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")
	t.Setenv("SYNTHETIC_CHECKS_JSON", "")
	mapNames := map[string]bool{}
	for name := range Load().Services {
		mapNames[name] = true
	}

	missing, extra := comparePeerMap(mapNames, peers, known)
	if len(missing) > 0 {
		t.Errorf("registry services with no entry in the monitoring-service peer map (config.go Load, Services): %v\n"+
			"add each one, fenced with // edition:enterprise if the registry fences it", missing)
	}
	if len(extra) > 0 {
		t.Errorf("peer map entries that are neither registry services nor infrastructure.exceptions: %v", extra)
	}
}
