package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/api"
	"github.com/vistasecurity/vistaplatform/sensor/internal/capture"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
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

// TestShouldRunInteractive pins the install default and every reason to step
// aside from it. The dialogue being ON by default is what makes a bare
// `./sensor` on a fresh host walk the operator through setup, so a regression
// here is either a silent non-starting install or a service-manager start that
// hangs on a prompt nobody can answer.
func TestShouldRunInteractive(t *testing.T) {
	tests := []struct {
		name       string
		want       bool
		explicit   bool
		configPath string
		register   bool
		tty        bool
		env        string
		expect     bool
	}{
		{name: "fresh host, no arguments", want: true, tty: true, expect: true},
		{name: "-interactive=false", want: false, tty: true, expect: false},
		{name: "existing config file", want: true, tty: true, configPath: "/etc/sensor.yaml", expect: false},
		{name: "explicit -interactive beats an existing config", want: true, explicit: true, configPath: "/etc/sensor.yaml", expect: true},
		{name: "environment-configured deployment", want: true, tty: true, env: "https://platform.example", expect: false},
		{name: "scripted -register", want: true, tty: true, register: true, expect: false},
		{name: "piped stdin (systemd, docker without -it)", want: true, expect: false},
		{name: "explicit -interactive still needs no terminal check", want: true, explicit: true, expect: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CONTROL_PLANE_URL", tt.env)
			if got := shouldRunInteractive(tt.want, tt.explicit, tt.configPath, tt.register, tt.tty); got != tt.expect {
				t.Errorf("shouldRunInteractive() = %v, want %v", got, tt.expect)
			}
		})
	}
}

// TestVerboseConfigOverride pins the three-state verbose semantics: an absent
// `verbose:` key must leave the command-line default (on) alone, and only an
// explicit key may turn it down.
func TestVerboseConfigOverride(t *testing.T) {
	dir := t.TempDir()

	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}

	base := "controlPlaneUrl: https://platform.example\n"

	silent := mustLoadConfig(t, write("silent.yaml", base))
	if silent.Verbose != nil {
		t.Errorf("absent verbose key parsed as %v; want nil so the default stands", *silent.Verbose)
	}

	off := mustLoadConfig(t, write("off.yaml", base+"verbose: false\n"))
	if off.Verbose == nil || *off.Verbose {
		t.Errorf("verbose: false parsed as %v; want an explicit false", off.Verbose)
	}
}

func TestRestartCommandFlushesBufferedDiscoveriesAfterAck(t *testing.T) {
	const sensorID = "11111111-1111-1111-1111-111111111111"

	var acked atomic.Bool
	submitted := make(chan models.DiscoveryBatch, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/commands/cmd-1/ack"):
			acked.Store(true)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/discoveries"):
			var batch models.DiscoveryBatch
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			submitted <- batch
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := &config.Config{SensorID: sensorID, ControlPlaneURL: server.URL}
	s := &Sensor{
		config:       cfg,
		apiClient:    api.NewOutboundClient(cfg),
		discoveries:  []*models.CryptoDiscovery{{ID: "disc-1", SensorID: sensorID, Protocol: "TLS", DestIP: "203.0.113.10", Port: 443}},
		restartChan:  make(chan struct{}, 1),
		restartDelay: time.Nanosecond,
	}

	s.processCommand(models.Command{ID: "cmd-1", Type: "restart", Payload: map[string]interface{}{}})

	if !acked.Load() {
		t.Fatal("restart command was not acknowledged before shutdown")
	}
	select {
	case <-s.restartChan:
	case <-time.After(time.Second):
		t.Fatal("restart command did not signal the main loop to shut down")
	}

	s.shutdownForRestart()

	select {
	case batch := <-submitted:
		if batch.SensorID != sensorID {
			t.Fatalf("submitted sensor ID = %q, want %q", batch.SensorID, sensorID)
		}
		if batch.Count != 1 || len(batch.Discoveries) != 1 || batch.Discoveries[0].ID != "disc-1" {
			t.Fatalf("submitted batch = %+v, want the buffered discovery", batch)
		}
	case <-time.After(time.Second):
		t.Fatal("restart cleanup did not submit buffered discoveries")
	}
}

func TestCleanupSubmitsPendingRetryQueue(t *testing.T) {
	const sensorID = "00000000-0000-0000-0000-000000000001"

	received := make(chan models.DiscoveryBatch, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		wantPath := fmt.Sprintf("/api/v1/sensor-manager/sensors/%s/discoveries", sensorID)
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}

		var batch models.DiscoveryBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode request body: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received <- batch
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{
		SensorID:        sensorID,
		ControlPlaneURL: server.URL,
	}
	s := &Sensor{
		config:    cfg,
		apiClient: api.NewOutboundClient(cfg),
		pendingRetry: []*models.CryptoDiscovery{
			{ID: "retry-1", SensorID: sensorID, Protocol: "TLS", DestIP: "192.0.2.10", Port: 443},
			{ID: "retry-2", SensorID: sensorID, Protocol: "SSH", DestIP: "192.0.2.11", Port: 22},
		},
		discoveries: make([]*models.CryptoDiscovery, 0),
	}

	s.cleanup()

	select {
	case batch := <-received:
		if batch.SensorID != sensorID {
			t.Fatalf("batch.SensorID = %q, want %q", batch.SensorID, sensorID)
		}
		if batch.Count != 2 {
			t.Fatalf("batch.Count = %d, want 2", batch.Count)
		}
		if len(batch.Discoveries) != 2 {
			t.Fatalf("len(batch.Discoveries) = %d, want 2", len(batch.Discoveries))
		}
		if got := []string{batch.Discoveries[0].ID, batch.Discoveries[1].ID}; got[0] != "retry-1" || got[1] != "retry-2" {
			t.Fatalf("submitted discovery IDs = %v, want [retry-1 retry-2]", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not submit the pending retry queue")
	}
}

func TestCleanupSubmitsDiscoveriesLeftInCaptureChannel(t *testing.T) {
	const sensorID = "00000000-0000-0000-0000-000000000002"

	received := make(chan models.DiscoveryBatch, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch models.DiscoveryBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode request body: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received <- batch
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{
		SensorID:        sensorID,
		ControlPlaneURL: server.URL,
	}
	packetCapture := capture.NewPacketCapture(cfg)
	packetCapture.GetDiscoveriesWritable() <- &models.CryptoDiscovery{
		ID:       "flushed-1",
		SensorID: sensorID,
		Protocol: "TLS",
		DestIP:   "192.0.2.20",
		Port:     443,
	}

	s := &Sensor{
		config:        cfg,
		apiClient:     api.NewOutboundClient(cfg),
		packetCapture: packetCapture,
		discoveries:   make([]*models.CryptoDiscovery, 0),
	}

	s.cleanup()

	select {
	case batch := <-received:
		if batch.Count != 1 {
			t.Fatalf("batch.Count = %d, want 1", batch.Count)
		}
		if len(batch.Discoveries) != 1 || batch.Discoveries[0].ID != "flushed-1" {
			t.Fatalf("submitted batch = %+v, want discovery flushed from capture channel", batch)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not submit discovery left in the capture channel")
	}
}

func TestReinitCaptureBuffersDiscoveriesLeftInStoppedCaptureChannel(t *testing.T) {
	const sensorID = "00000000-0000-0000-0000-000000000003"

	cfg := &config.Config{SensorID: sensorID}
	packetCapture := capture.NewPacketCapture(cfg)
	packetCapture.GetDiscoveriesWritable() <- &models.CryptoDiscovery{
		ID:       "reinit-flushed-1",
		SensorID: sensorID,
		Protocol: "TLS",
		DestIP:   "192.0.2.30",
		Port:     443,
	}

	s := &Sensor{
		config:        cfg,
		packetCapture: packetCapture,
		discoveries:   make([]*models.CryptoDiscovery, 0),
	}

	if err := s.reinitCapture(); err == nil {
		t.Fatal("reinitCapture succeeded with no configured interfaces; test requires Start to stop before replacing packetCapture")
	}

	if len(s.discoveries) != 1 || s.discoveries[0].ID != "reinit-flushed-1" {
		t.Fatalf("discoveries buffered after reinit = %+v, want flushed discovery", s.discoveries)
	}
}

func mustLoadConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile(%s): %v", path, err)
	}
	return cfg
}

// TestSensorConfigFilesAreOwnerOnly is the C3 regression guard.
//
// The sensor config carries `registrationKey:` in plaintext, and that key is the
// agentSecret input to agentcreds.DeriveKey — the AES key that unwraps every
// credential envelope carrying the tenant's device administrator passwords. It
// was written 0644, so any unprivileged local user on the sensor host could read
// it.
//
// This stats a file the real code path actually produced rather than reading the
// mode constant back, and it covers all three writers: the interactive installer
// that CREATES the file, and the two rewriters that run afterwards over a file an
// older build may have left world-readable (os.WriteFile does not change the mode
// of a file that already exists — only the explicit Chmod does).
func TestSensorConfigFilesAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "sensor-config.yaml")

	const key = "reg-key-super-secret-value"
	if err := createConfigFile(configPath, "https://platform.example", key, 60, dir, []string{"eth0"}, ""); err != nil {
		t.Fatalf("createConfigFile: %v", err)
	}

	assertOwnerOnly := func(stage string) {
		t.Helper()
		info, err := os.Stat(configPath)
		if err != nil {
			t.Fatalf("%s: stat: %v", stage, err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Fatalf("%s: config mode = %#o, want 0600 — the registration key is the "+
				"AES key for every device credential envelope", stage, perm)
		}
	}
	assertOwnerOnly("createConfigFile")

	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	// The live value belongs in `registrationKey:`. The footer used to repeat it
	// in a comment, so the credential appeared twice in one file.
	if n := strings.Count(string(body), key); n != 1 {
		t.Fatalf("registration key appears %d time(s) in the generated config, want exactly 1 "+
			"(the live `registrationKey:` value); the footer comment must not repeat it:\n%s", n, body)
	}

	// Simulate an upgrade over a config an older build left world-readable, then
	// drive each rewriter and confirm it tightens the mode rather than preserving it.
	s := &Sensor{
		configPath: configPath,
		config: &config.Config{
			SensorID:          "sensor-123",
			ReportingInterval: 45 * time.Second,
		},
	}
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"saveConfigFile", s.saveConfigFile},
		{"persistMonitoredInterfaces", func() error { return s.persistMonitoredInterfaces([]string{"eth1"}) }},
	} {
		if err := os.Chmod(configPath, 0644); err != nil {
			t.Fatalf("%s: chmod to legacy mode: %v", tc.name, err)
		}
		if err := tc.run(); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		assertOwnerOnly(tc.name)
	}
}
