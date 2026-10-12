package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/atomicfile"
)

type fakeCertificateRotator struct {
	expiresAt    time.Time
	expiringSoon bool
	checkErr     error
	rotateErr    error
	checks       int
	rotations    int
}

func (f *fakeCertificateRotator) CheckCertificateExpiration() (time.Time, bool, error) {
	f.checks++
	return f.expiresAt, f.expiringSoon, f.checkErr
}

func (f *fakeCertificateRotator) RotateCertificate() error {
	f.rotations++
	return f.rotateErr
}

func TestCheckAndRotateAgentCertificate_RotatesAndPersistsExpiringCert(t *testing.T) {
	rotator := &fakeCertificateRotator{
		expiresAt:    time.Now().Add(7 * 24 * time.Hour),
		expiringSoon: true,
	}
	var pending atomicfile.Pending
	var persisted int

	rotated := checkAndRotateAgentCertificate(rotator, &config.Config{}, func() error {
		persisted++
		return nil
	}, &pending)

	if !rotated {
		t.Fatal("expected expiring certificate to rotate")
	}
	if rotator.checks != 1 || rotator.rotations != 1 {
		t.Fatalf("checks=%d rotations=%d, want 1/1", rotator.checks, rotator.rotations)
	}
	if persisted != 1 || pending.Err() != nil {
		t.Fatalf("persisted=%d pending=%v, want 1/nil", persisted, pending.Err())
	}
}

func TestCheckAndRotateAgentCertificate_SkipsValidCert(t *testing.T) {
	rotator := &fakeCertificateRotator{expiresAt: time.Now().Add(90 * 24 * time.Hour)}
	var persisted int

	rotated := checkAndRotateAgentCertificate(rotator, &config.Config{}, func() error {
		persisted++
		return nil
	}, &atomicfile.Pending{})

	if rotated {
		t.Fatal("did not expect valid certificate to rotate")
	}
	if rotator.rotations != 0 || persisted != 0 {
		t.Fatalf("rotations=%d persisted=%d, want 0/0", rotator.rotations, persisted)
	}
}

func TestCheckAndRotateAgentCertificate_DoesNotPersistFailedRotation(t *testing.T) {
	rotator := &fakeCertificateRotator{
		expiresAt:    time.Now().Add(7 * 24 * time.Hour),
		expiringSoon: true,
		rotateErr:    errors.New("rotation failed"),
	}
	var persisted int
	var pending atomicfile.Pending

	rotated := checkAndRotateAgentCertificate(rotator, &config.Config{}, func() error {
		persisted++
		return nil
	}, &pending)

	if rotated {
		t.Fatal("did not expect failed rotation to report success")
	}
	if rotator.rotations != 1 || persisted != 0 || pending.Err() != nil {
		t.Fatalf("rotations=%d persisted=%d pending=%v", rotator.rotations, persisted, pending.Err())
	}
}

// The platform revokes the old certificate on rotation, so a failed save must
// be retried, remembered, and never reported as a successful rotation.
func TestCheckAndRotateAgentCertificate_PersistFailureIsRetriedAndRemembered(t *testing.T) {
	oldAttempts, oldDelay := rotationPersistAttempts, rotationPersistDelay
	rotationPersistAttempts, rotationPersistDelay = 3, 0
	t.Cleanup(func() { rotationPersistAttempts, rotationPersistDelay = oldAttempts, oldDelay })

	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	rotator := &fakeCertificateRotator{expiresAt: time.Now().Add(time.Hour), expiringSoon: true}
	var pending atomicfile.Pending
	calls := 0
	rotated := checkAndRotateAgentCertificate(rotator, &config.Config{DataPath: "/data"}, func() error {
		calls++
		return errors.New("disk full")
	}, &pending)

	if !rotated {
		t.Fatal("the platform did rotate; the return value reports that")
	}
	if calls != 3 {
		t.Fatalf("persist attempted %d times, want 3", calls)
	}
	if pending.Err() == nil {
		t.Fatal("unpersisted state not recorded")
	}
	if strings.Contains(logs.String(), "rotated successfully") {
		t.Fatalf("claimed success although the certificate was not saved:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "could NOT be saved") {
		t.Fatalf("failure not logged:\n%s", logs.String())
	}
}

func TestRetryUnpersistedCredentials_ClearsOnceSaved(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataPath: dir, PlatformURL: "https://p.example", Security: config.SecurityConfig{ClientCert: "C", ClientKey: "K"}}
	a := &DeviceAgent{config: cfg, configPath: filepath.Join(dir, "agent.yaml")}
	a.unpersistedCredentials.Set(errors.New("earlier failure"))

	a.retryUnpersistedCredentials()

	if err := a.unpersistedCredentials.Err(); err != nil {
		t.Fatalf("still pending after a successful save: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "certs", "client.key")); err != nil || string(b) != "K" {
		t.Fatalf("key not written: %q %v", b, err)
	}
}

// Values with YAML syntax characters, and every field of the config struct,
// must survive a save and a reload; comments an operator added must survive a
// rewrite.
func TestSaveConfigFileRoundTripsAndPreservesComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	verbose := true
	cfg := &config.Config{
		PlatformURL:                     "https://platform.example/path#frag",
		AgentID:                         "3f2b8c1e-9a7d-4e65-b0c4-2d1e8f7a6b59",
		RegistrationKey:                 "key: with # hash and \"quotes\"",
		PollInterval:                    45 * time.Second,
		HeartbeatInterval:               90 * time.Second,
		DataPath:                        `C:\Data: x # y`,
		Verbose:                         &verbose,
		HostInventoryEnabled:            true,
		HostInventoryInterval:           6 * time.Hour,
		HostInventoryConnectionsEnabled: true,
		Security: config.SecurityConfig{
			ClientCertPath: "/d/certs/client.crt", ClientKeyPath: "/d/certs/client.key", ServerCACertPath: "/d/certs/ca.crt",
		},
	}
	if err := os.WriteFile(path, []byte("# operator note: keep this\nplatform_url: old\ncustom_key: kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveConfigFile(path, cfg); err != nil {
		t.Fatalf("saveConfigFile: %v", err)
	}

	got, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	want := *cfg
	if got.PlatformURL != want.PlatformURL || got.AgentID != want.AgentID || got.RegistrationKey != want.RegistrationKey ||
		got.PollInterval != want.PollInterval || got.HeartbeatInterval != want.HeartbeatInterval || got.DataPath != want.DataPath ||
		got.Verbose == nil || !*got.Verbose || !got.HostInventoryEnabled || got.HostInventoryInterval != want.HostInventoryInterval ||
		!got.HostInventoryConnectionsEnabled || got.Security.ClientCertPath != want.Security.ClientCertPath ||
		got.Security.ClientKeyPath != want.Security.ClientKeyPath || got.Security.ServerCACertPath != want.Security.ServerCACertPath {
		t.Fatalf("round trip lost data:\n got %+v\nwant %+v", got, want)
	}
	body, _ := os.ReadFile(path)
	for _, frag := range []string{"operator note: keep this", "custom_key: kept", "heartbeat_interval"} {
		if !strings.Contains(string(body), frag) {
			t.Errorf("rewrite dropped %q:\n%s", frag, body)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
	if strings.Contains(string(body), "client_key:") || strings.Contains(string(body), "PRIVATE KEY") {
		t.Errorf("config file must not carry key material:\n%s", body)
	}
}

func TestSaveConfigFileDropsSettingsNoLongerSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	on := &config.Config{PlatformURL: "u", DataPath: "d", HostInventoryEnabled: true, HostInventoryInterval: 2 * time.Hour}
	if err := saveConfigFile(path, on); err != nil {
		t.Fatal(err)
	}
	off := &config.Config{PlatformURL: "u", DataPath: "d"}
	if err := saveConfigFile(path, off); err != nil {
		t.Fatal(err)
	}
	got, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.HostInventoryEnabled {
		t.Fatal("host inventory stayed enabled after the agent turned it off")
	}
}

// TestShouldRunInteractive pins the install default and every reason to step
// aside from it. The dialogue being ON by default is what makes a bare
// `./device-agent` on a fresh host walk the operator through setup and then
// start polling — the same install experience as the sensor.
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
		{name: "existing config file", want: true, tty: true, configPath: "/etc/agent.yaml", expect: false},
		{name: "explicit -interactive beats an existing config", want: true, explicit: true, configPath: "/etc/agent.yaml", expect: true},
		{name: "environment-configured deployment", want: true, tty: true, env: "https://platform.example", expect: false},
		{name: "scripted -register", want: true, tty: true, register: true, expect: false},
		{name: "piped stdin (systemd, docker without -it)", want: true, expect: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PLATFORM_URL", tt.env)
			if got := shouldRunInteractive(tt.want, tt.explicit, tt.configPath, tt.register, tt.tty); got != tt.expect {
				t.Errorf("shouldRunInteractive() = %v, want %v", got, tt.expect)
			}
		})
	}
}

// TestSaveConfigFileOmitsUnsetVerbose guards the three-state verbose value:
// writing the resolved default into the generated config would freeze it there
// and make a later default change invisible to already-installed agents.
func TestSaveConfigFileOmitsUnsetVerbose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-config.yaml")
	cfg := &config.Config{PlatformURL: "https://platform.example", DataPath: t.TempDir()}

	if err := saveConfigFile(path, cfg); err != nil {
		t.Fatalf("saveConfigFile: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if strings.Contains(string(body), "verbose:") {
		t.Errorf("generated config pinned a verbose value the operator never set:\n%s", body)
	}

	off := false
	cfg.Verbose = &off
	if err := saveConfigFile(path, cfg); err != nil {
		t.Fatalf("saveConfigFile (explicit verbose): %v", err)
	}
	body, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(body), "verbose: false") {
		t.Errorf("explicit verbose: false was not persisted:\n%s", body)
	}
}

// TestAgentConfigFileIsOwnerOnly is the C3 regression guard.
//
// The generated agent config carries `registration_key:` in plaintext, and that
// key is the agentSecret input to agentcreds.DeriveKey — the AES key that unwraps
// every credential envelope carrying the tenant's F5, Cisco, Fortinet, Palo Alto
// and UniFi administrator passwords. It was written 0644, so any unprivileged
// local user on the agent host could read it and decrypt them.
//
// This stats a file saveConfigFile actually produced rather than reading the mode
// constant back, and it re-runs the save over a file left world-readable by an
// older build: os.WriteFile does not change the mode of a file that already
// exists, so only the explicit Chmod tightens an upgraded install.
func TestAgentConfigFileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}

	path := filepath.Join(t.TempDir(), "agent-config.yaml")
	cfg := &config.Config{
		PlatformURL:     "https://platform.example",
		RegistrationKey: "reg-key-super-secret-value",
		DataPath:        t.TempDir(),
	}

	assertOwnerOnly := func(stage string) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: stat: %v", stage, err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Fatalf("%s: config mode = %#o, want 0600 — the registration key is the "+
				"AES key for every device credential envelope", stage, perm)
		}
	}

	if err := saveConfigFile(path, cfg); err != nil {
		t.Fatalf("saveConfigFile: %v", err)
	}
	assertOwnerOnly("fresh write")

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(body), cfg.RegistrationKey) {
		t.Fatalf("test is vacuous: the config does not contain the registration key:\n%s", body)
	}

	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("chmod to legacy mode: %v", err)
	}
	if err := saveConfigFile(path, cfg); err != nil {
		t.Fatalf("saveConfigFile (rewrite): %v", err)
	}
	assertOwnerOnly("rewrite over a legacy 0644 config")
}
