package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"gopkg.in/yaml.v3"
)

func TestSaveConfigFilePersistsMTLSPathsIdempotently(t *testing.T) {
	tests := []struct {
		name               string
		initialConfig      string
		disallowedContents []string
	}{
		{
			name: "updates existing security block",
			initialConfig: `sensorId: "old-sensor"
controlPlaneUrl: "https://platform.example.test"
registrationKey: ""
reportingIntervalSeconds: 30

security:
  clientCertPath: "/old/client.crt"
  clientKeyPath: "/old/client.key"
  serverCACertPath: "/old/ca.crt"
  useTLS: false

storage:
  dataPath: "/var/lib/crypto-sensor"
`,
			disallowedContents: []string{"/old/client.crt", "/old/client.key", "/old/ca.crt", "useTLS: false"},
		},
		{
			name: "adds missing security block once",
			initialConfig: `sensorId: "old-sensor"
controlPlaneUrl: "https://platform.example.test"
registrationKey: ""
reportingIntervalSeconds: 30

storage:
  dataPath: "/var/lib/crypto-sensor"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "sensor-config.yaml")
			if err := os.WriteFile(configPath, []byte(tt.initialConfig), 0644); err != nil {
				t.Fatalf("write initial config: %v", err)
			}

			s := &Sensor{
				configPath: configPath,
				config: &config.Config{
					SensorID:          "new-sensor",
					ReportingInterval: 45 * time.Second,
					Security: config.SecurityConfig{
						ClientCertPath:   "/new/client.crt",
						ClientKeyPath:    "/new/client.key",
						ServerCACertPath: "/new/ca.crt",
					},
				},
			}

			if err := s.saveConfigFile(); err != nil {
				t.Fatalf("save config first time: %v", err)
			}
			firstSave, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatalf("read first save: %v", err)
			}

			if err := s.saveConfigFile(); err != nil {
				t.Fatalf("save config second time: %v", err)
			}
			secondSave, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatalf("read second save: %v", err)
			}

			if string(firstSave) != string(secondSave) {
				t.Fatalf("second save changed config; first:\n%s\nsecond:\n%s", firstSave, secondSave)
			}
			if count := strings.Count(string(secondSave), "\nsecurity:\n"); count != 1 {
				t.Fatalf("security block count = %d, want 1; config:\n%s", count, secondSave)
			}
			for _, disallowed := range tt.disallowedContents {
				if strings.Contains(string(secondSave), disallowed) {
					t.Fatalf("config still contains stale value %q:\n%s", disallowed, secondSave)
				}
			}

			var parsed struct {
				SensorID                 string `yaml:"sensorId"`
				ReportingIntervalSeconds int    `yaml:"reportingIntervalSeconds"`
				Security                 struct {
					ClientCertPath   string `yaml:"clientCertPath"`
					ClientKeyPath    string `yaml:"clientKeyPath"`
					ServerCACertPath string `yaml:"serverCACertPath"`
					UseTLS           bool   `yaml:"useTLS"`
				} `yaml:"security"`
			}
			if err := yaml.Unmarshal(secondSave, &parsed); err != nil {
				t.Fatalf("parse saved YAML: %v\n%s", err, secondSave)
			}
			if parsed.SensorID != "new-sensor" {
				t.Fatalf("sensorId = %q, want new-sensor", parsed.SensorID)
			}
			if parsed.ReportingIntervalSeconds != 45 {
				t.Fatalf("reportingIntervalSeconds = %d, want 45", parsed.ReportingIntervalSeconds)
			}
			if parsed.Security.ClientCertPath != "/new/client.crt" {
				t.Fatalf("clientCertPath = %q, want /new/client.crt", parsed.Security.ClientCertPath)
			}
			if parsed.Security.ClientKeyPath != "/new/client.key" {
				t.Fatalf("clientKeyPath = %q, want /new/client.key", parsed.Security.ClientKeyPath)
			}
			if parsed.Security.ServerCACertPath != "/new/ca.crt" {
				t.Fatalf("serverCACertPath = %q, want /new/ca.crt", parsed.Security.ServerCACertPath)
			}
			if !parsed.Security.UseTLS {
				t.Fatal("useTLS = false, want true")
			}
		})
	}
}
