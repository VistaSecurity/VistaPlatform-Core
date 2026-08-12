package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
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
	cfg := &config.Config{}
	var savedCerts, savedConfig int

	rotated := checkAndRotateAgentCertificate(
		rotator,
		cfg,
		func(got *config.Config) error {
			savedCerts++
			if got != cfg {
				t.Fatalf("saveCerts received unexpected config pointer")
			}
			return nil
		},
		func() error {
			savedConfig++
			return nil
		},
	)

	if !rotated {
		t.Fatal("expected expiring certificate to rotate")
	}
	if rotator.checks != 1 || rotator.rotations != 1 {
		t.Fatalf("checks=%d rotations=%d, want 1/1", rotator.checks, rotator.rotations)
	}
	if savedCerts != 1 || savedConfig != 1 {
		t.Fatalf("savedCerts=%d savedConfig=%d, want 1/1", savedCerts, savedConfig)
	}
}

func TestCheckAndRotateAgentCertificate_SkipsValidCert(t *testing.T) {
	rotator := &fakeCertificateRotator{
		expiresAt: time.Now().Add(90 * 24 * time.Hour),
	}
	var savedCerts, savedConfig int

	rotated := checkAndRotateAgentCertificate(
		rotator,
		&config.Config{},
		func(*config.Config) error {
			savedCerts++
			return nil
		},
		func() error {
			savedConfig++
			return nil
		},
	)

	if rotated {
		t.Fatal("did not expect valid certificate to rotate")
	}
	if rotator.rotations != 0 {
		t.Fatalf("rotations=%d, want 0", rotator.rotations)
	}
	if savedCerts != 0 || savedConfig != 0 {
		t.Fatalf("savedCerts=%d savedConfig=%d, want 0/0", savedCerts, savedConfig)
	}
}

func TestCheckAndRotateAgentCertificate_DoesNotPersistFailedRotation(t *testing.T) {
	rotator := &fakeCertificateRotator{
		expiresAt:    time.Now().Add(7 * 24 * time.Hour),
		expiringSoon: true,
		rotateErr:    errors.New("rotation failed"),
	}
	var savedCerts, savedConfig int

	rotated := checkAndRotateAgentCertificate(
		rotator,
		&config.Config{},
		func(*config.Config) error {
			savedCerts++
			return nil
		},
		func() error {
			savedConfig++
			return nil
		},
	)

	if rotated {
		t.Fatal("did not expect failed rotation to report success")
	}
	if rotator.rotations != 1 {
		t.Fatalf("rotations=%d, want 1", rotator.rotations)
	}
	if savedCerts != 0 || savedConfig != 0 {
		t.Fatalf("savedCerts=%d savedConfig=%d, want 0/0", savedCerts, savedConfig)
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
