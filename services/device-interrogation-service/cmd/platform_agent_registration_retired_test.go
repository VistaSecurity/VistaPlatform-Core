package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The production process used to construct two background mechanisms for a
// platform device_agents row that no deployment created: auto-registration and
// a two-minute heartbeat updater. This reads the real startup entry point so a
// future reintroduction cannot pass by testing an unused helper in isolation.
func TestStartupDoesNotMaintainPlatformDeviceAgentFleetRows(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse production startup: %v", err)
	}

	retired := map[string]bool{
		"NewAutoRegisterService":       true,
		"RegisterForAllTenants":        true,
		"MonitorCertificateExpiration": true,
		"NewPlatformAgentHeartbeat":    true,
		"TouchPlatformAgentHeartbeat":  true,
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			if retired[node.Name] {
				t.Errorf("production startup references retired platform device-agent mechanism %s", node.Name)
			}
		case *ast.BasicLit:
			if node.Kind == token.STRING && node.Value == `"DEVICE_INTERROGATION_SERVICE_TOKEN"` {
				t.Error("production startup still reads the retired platform auto-registration token")
			}
		}
		return true
	})
}

func TestComposeConfigurationSourcesOmitRetiredPlatformRegistration(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..", "..")
	paths := []struct {
		path               string
		internalOnlyExport bool
	}{
		{path: "standards/service-registry.yaml"},
		{path: "scripts/generate-docker-compose.mjs"},
		{path: "docker-compose.yml"},
		// The public-tree exporter deliberately removes these two private
		// deployment definitions. Check them whenever they are present without
		// making the exported Core Go suite depend on private files.
		{path: "docker-compose.prod.yml", internalOnlyExport: true},
		{path: "docker-compose.ec2-smoke.yml", internalOnlyExport: true},
	}
	retired := []string{
		"DEVICE_INTERROGATION_SERVICE_TOKEN",
		"PLATFORM_DEVICE_INTERROGATION_AGENT_ID",
		"device-interrogation-service-cert.pem",
		"device-interrogation-service-key.pem",
	}

	for _, source := range paths {
		source := source
		t.Run(source.path, func(t *testing.T) {
			contents, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(source.path)))
			if err != nil && source.internalOnlyExport && os.IsNotExist(err) {
				return
			}
			if err != nil {
				t.Fatalf("read %s: %v", source.path, err)
			}
			for _, marker := range retired {
				if strings.Contains(string(contents), marker) {
					t.Errorf("%s still contains retired platform-agent setting %q", source.path, marker)
				}
			}
		})
	}
}
