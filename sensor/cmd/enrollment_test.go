package main

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/api"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// The registration key is single use. If the sensor cannot keep the result it
// must refuse BEFORE the request is sent, leaving the key unspent.
func TestRegister_PreflightRefusesBeforeSpendingTheKey(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "should not be reached", http.StatusInternalServerError)
	}))
	defer server.Close()

	// A data path beneath a regular file can never hold a certs directory.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ControlPlaneURL: server.URL, RegistrationKey: "REG-fresh"}
	cfg.Storage.DataPath = filepath.Join(blocker, "data")
	s := &Sensor{config: cfg, sensorManager: api.NewSensorManagerClient(cfg)}

	err := s.register()
	if err == nil {
		t.Fatal("register() succeeded although nothing could be stored")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("control plane was contacted %d time(s); the key would have been spent", got)
	}
	if !strings.Contains(err.Error(), "registration key is still unused") {
		t.Errorf("error does not tell the operator the key is unspent: %v", err)
	}
}

func TestPersistEnrollment_FailureNamesPathAndSpentKey(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{SensorID: "3f2b8c1e-9a7d-4e65-b0c4-2d1e8f7a6b59"}
	cfg.Storage.DataPath = filepath.Join(blocker, "data")
	cfg.Security.ClientCert, cfg.Security.ClientKey = "C", "K"
	s := &Sensor{config: cfg}

	err := s.persistEnrollment()
	if err == nil {
		t.Fatal("persistEnrollment reported success although the certificates could not be written")
	}
	for _, want := range []string{filepath.Join(cfg.Storage.DataPath, "certs"), "SPENT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestPersistEnrollment_WritesCertsAndConfig(t *testing.T) {
	s := testSensor(t)
	s.config.Storage.DataPath = t.TempDir()
	s.config.SensorID = "3f2b8c1e-9a7d-4e65-b0c4-2d1e8f7a6b59"
	s.config.Security.ClientCert, s.config.Security.ClientKey, s.config.Security.ServerCACert = "C", "K", "A"
	if err := s.persistEnrollment(); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFromFile(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SensorID != s.config.SensorID || cfg.Security.ClientKey != "K" {
		t.Fatalf("enrollment not recoverable from disk: %+v", cfg.Security)
	}
}

type fakeRotator struct {
	soon      bool
	rotateErr error
	rotations int
}

func (f *fakeRotator) CheckCertificateExpiration() (time.Time, bool, error) {
	return time.Now().Add(time.Hour), f.soon, nil
}
func (f *fakeRotator) RotateCertificate() error { f.rotations++; return f.rotateErr }

func fastRotationRetries(t *testing.T) {
	t.Helper()
	a, d := rotationPersistAttempts, rotationPersistDelay
	rotationPersistAttempts, rotationPersistDelay = 3, 0
	t.Cleanup(func() { rotationPersistAttempts, rotationPersistDelay = a, d })
}

// The platform revokes the old certificate on rotation. A failed save must be
// retried, remembered and reported at error level, never logged as success.
func TestRotation_PersistFailureIsNotReportedAsSuccess(t *testing.T) {
	fastRotationRetries(t)
	logs := captureLog(t)
	s := testSensor(t)
	blocker := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(blocker, nil, 0o600)
	s.config.Storage.DataPath = filepath.Join(blocker, "data")
	s.config.Security.ClientCert, s.config.Security.ClientKey = "C2", "K2"

	s.rotateCertificateIfNeeded(&fakeRotator{soon: true})

	if s.unpersistedCredentials.Err() == nil {
		t.Fatal("unpersisted credentials were not remembered")
	}
	out := logs.String()
	if strings.Contains(out, "rotated successfully") {
		t.Fatalf("claimed success although nothing reached disk:\n%s", out)
	}
	if !strings.Contains(out, "could NOT be saved") {
		t.Fatalf("failure not logged:\n%s", out)
	}
	if s.config.Security.ClientKey != "K2" {
		t.Fatal("new key material must stay in memory")
	}

	// Heartbeat retry: once the disk problem clears, the next beat saves it.
	s.config.Storage.DataPath = t.TempDir()
	s.retryUnpersistedCredentials()
	if err := s.unpersistedCredentials.Err(); err != nil {
		t.Fatalf("still pending after the disk recovered: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(s.config.Storage.DataPath, "certs", "client.key")); err != nil || string(b) != "K2" {
		t.Fatalf("key not saved by the retry: %q %v", b, err)
	}
}

func TestRotation_PersistSuccessReportsSuccess(t *testing.T) {
	fastRotationRetries(t)
	logs := captureLog(t)
	s := testSensor(t)
	s.config.Storage.DataPath = t.TempDir()
	s.config.Security.ClientCert, s.config.Security.ClientKey = "C2", "K2"

	s.rotateCertificateIfNeeded(&fakeRotator{soon: true})

	if err := s.unpersistedCredentials.Err(); err != nil {
		t.Fatalf("unexpected pending state: %v", err)
	}
	if !strings.Contains(logs.String(), "rotated successfully") {
		t.Fatalf("success not reported:\n%s", logs.String())
	}
}

func TestRotation_FailedRotationPersistsNothing(t *testing.T) {
	fastRotationRetries(t)
	s := testSensor(t)
	s.config.Storage.DataPath = t.TempDir()
	s.rotateCertificateIfNeeded(&fakeRotator{soon: true, rotateErr: errors.New("nope")})
	if _, err := os.Stat(filepath.Join(s.config.Storage.DataPath, "certs")); err == nil {
		t.Fatal("certs written for a rotation that failed")
	}
}

// Interface names arrive in a platform-controlled payload.
func TestPersistMonitoredInterfaces_RejectsControlCharacters(t *testing.T) {
	s := testSensor(t)
	before := "capture:\n  interfaces:\n    - eth0\n  hostObservation: true\n"
	if err := os.WriteFile(s.configPath, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"eth0\ncontrolPlaneUrl: https://evil.example", "eth\r1", "eth\x001", ""} {
		if err := s.persistMonitoredInterfaces([]string{bad}); err == nil {
			t.Errorf("interface %q was accepted", bad)
		}
	}
	after, _ := os.ReadFile(s.configPath)
	if string(after) != before {
		t.Fatalf("config modified by a rejected name:\n%s", after)
	}
}

func TestPersistMonitoredInterfaces_QuotesNames(t *testing.T) {
	s := testSensor(t)
	if err := os.WriteFile(s.configPath, []byte("capture:\n  interfaces:\n    - eth0\n  hostObservation: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	names := []string{`Ethernet #2: lab`, `{braces}`, `- dash`}
	if err := s.persistMonitoredInterfaces(names); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFromFile(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.Capture.Interfaces, "|") != strings.Join(names, "|") {
		t.Fatalf("interfaces = %q, want %q", cfg.Capture.Interfaces, names)
	}
	if !cfg.Capture.HostObservation {
		t.Fatal("neighbouring setting lost")
	}
}

func TestWriteSecretConfigFile_IsAtomicAndOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sensor-config.yaml")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeSecretConfigFile(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %#o", st.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
}

// A stray ./config.yaml must not shadow the enrolled config in the data dir.
func TestPickDefaultConfigFile_PrefersDataDirectory(t *testing.T) {
	logs := captureLog(t)
	data := t.TempDir()
	enrolled := filepath.Join(data, "sensor-config.yaml")
	stray := filepath.Join(t.TempDir(), "config.yaml")
	for _, p := range []string{enrolled, stray} {
		if err := os.WriteFile(p, []byte("x: 1"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cands := defaultConfigCandidates(data)
	if cands[0] != enrolled || cands[len(cands)-1] != "config.yaml" {
		t.Fatalf("candidate order = %v", cands)
	}
	// Substitute the stray file for the relative last-resort entry.
	if got := pickDefaultConfigFile(cands[0], stray); got != enrolled {
		t.Fatalf("picked %q, want the data-dir file", got)
	}
	if !strings.Contains(logs.String(), "Using config file "+enrolled) || !strings.Contains(logs.String(), "Ignoring config file "+stray) {
		t.Fatalf("choice not logged:\n%s", logs.String())
	}
	if got := pickDefaultConfigFile(filepath.Join(data, "missing.yaml"), stray); got != stray {
		t.Fatalf("last resort not used: %q", got)
	}
}
