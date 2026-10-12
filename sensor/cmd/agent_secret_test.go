package main

//: the sensor is issued a per-sensor secret at enrolment and a fresh one at
// every certificate rotation, keeps it 0600 beside its certificate, and no longer
// keeps the single-use registration key once the secret is on disk. These run the
// REAL client against a fake platform, then the real persistence and the real
// config loader — and the installer's own text, because the installer decides
// "already enrolled with this key" from what the sensor leaves in the file.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/api"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
)

const (
	testSensorRegKey = "REG-0123456789abcdef0123456789abcdef"
	testSensorID     = "3f2b8c1e-9a7d-4e65-b0c4-2d1e8f7a6b59"
)

type fakeSensorPlatform struct {
	t          *testing.T
	srv        *httptest.Server
	caKey      *rsa.PrivateKey
	caCert     *x509.Certificate
	mu         sync.Mutex
	secrets    []string
	issued     int
	issue      bool
	sawRequest []map[string]any
}

func newFakeSensorPlatform(t *testing.T, issue bool, secrets ...string) *fakeSensorPlatform {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(der)
	f := &fakeSensorPlatform{t: t, caKey: caKey, caCert: caCert, secrets: secrets, issue: issue}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSensorPlatform) sign(csrPEM string) string {
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		f.t.Fatalf("csr: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: csr.Subject,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (f *fakeSensorPlatform) serve(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	f.sawRequest = append(f.sawRequest, body)
	resp := map[string]any{"sensor_id": testSensorID, "client_cert": f.sign(body["csr"].(string)), "reporting_interval": 60}
	if f.issue && f.issued < len(f.secrets) {
		f.issued++
		resp["agent_secret"] = f.secrets[f.issued-1]
		resp["agent_secret_version"] = f.issued
	}
	f.mu.Unlock()
	if !strings.HasSuffix(r.URL.Path, "/sensors/register") && !strings.HasSuffix(r.URL.Path, "/certificates/rotate") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func enrollingSensor(t *testing.T, p *fakeSensorPlatform) (*Sensor, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sensor-config.yaml")
	body := "# Vista sensor\nsensorId: \"\"\ncontrolPlaneUrl: " + p.srv.URL + "\nregistrationKey: \"" + testSensorRegKey + "\"\nreportingIntervalSeconds: 60\nstorage:\n  dataPath: \"" + dir + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return &Sensor{config: cfg, configPath: path, sensorManager: api.NewSensorManagerClient(cfg)}, path
}

func TestSensorSecret_EnrolmentDropsTheRegistrationKey(t *testing.T) {
	p := newFakeSensorPlatform(t, true, "sensor-secret-one")
	s, path := enrollingSensor(t, p)
	if err := s.register(); err != nil {
		t.Fatalf("register: %v", err)
	}
	if got := p.sawRequest[0]["supports_agent_secret"]; got != true {
		t.Fatalf("registration request supports_agent_secret = %v, want true", got)
	}

	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), testSensorRegKey) || strings.Contains(string(body), "registrationKey:") {
		t.Fatalf("the config still holds the registration key:\n%s", body)
	}
	for _, want := range []string{"registrationKeySha256:", "agentSecretPath:", "sensorId: \"" + testSensorID + "\""} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("config lacks %q:\n%s", want, body)
		}
	}
	secretFile := filepath.Join(s.config.Storage.DataPath, "certs", agentcreds.SecretFileName)
	data, err := os.ReadFile(secretFile)
	if err != nil || !strings.Contains(string(data), "sensor-secret-one") || strings.Contains(string(data), testSensorRegKey) {
		t.Fatalf("secret file: %v %q", err, data)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(secretFile); fi.Mode().Perm() != 0o600 {
			t.Fatalf("secret file mode = %v, want 0600", fi.Mode().Perm())
		}
	}

	re, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if re.RegistrationKey != "" {
		t.Fatalf("reloaded RegistrationKey = %q, want none", re.RegistrationKey)
	}
	if st := re.AgentSecretState(); st.Secret != "sensor-secret-one" || st.Version != 1 {
		t.Fatalf("reloaded secret state = %+v", st)
	}
	if !isRegistered(re) {
		t.Fatal("the reloaded sensor does not read as registered — it would try to enrol again with no key")
	}

	// The installer recognises the host from the fingerprint, not the key.
	if runtime.GOOS != "windows" {
		assertInstallerRecognisesKey(t, path, testSensorRegKey, true)
		assertInstallerRecognisesKey(t, path, "REG-some-other-key", false)
	}
}

// assertInstallerRecognisesKey runs install-sensor.sh's own enrolled_with_key.
func assertInstallerRecognisesKey(t *testing.T, cfgPath, key string, want bool) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	raw, err := os.ReadFile(installerPath)
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	readConfigValue := installerSection(t, script, `^read_config_value\(\) \{`, `^\}`)
	sha := installerSection(t, script, `^sha256_of\(\) \{`, `^\}`)
	enrolled := installerSection(t, script, `^enrolled_with_key\(\) \{`, `^\}`)
	out := strings.TrimSpace(runBash(t, readConfigValue+"\n"+sha+"\n"+enrolled+
		"\nif enrolled_with_key "+cfgPath+" "+key+"; then echo yes; else echo no; fi"))
	if (out == "yes") != want {
		t.Fatalf("installer enrolled_with_key(%q) = %s, want %v — a re-run would %s", key, out, want,
			map[bool]string{true: "discard a working enrolment", false: "keep another host's enrolment"}[want])
	}
}

// An older platform issues no secret: the sensor must keep the registration key.
func TestSensorSecret_OlderPlatformKeepsTheRegistrationKey(t *testing.T) {
	p := newFakeSensorPlatform(t, false)
	s, path := enrollingSensor(t, p)
	if err := s.register(); err != nil {
		t.Fatalf("register: %v", err)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), testSensorRegKey) {
		t.Fatalf("the registration key was dropped though no secret was issued:\n%s", body)
	}
	if _, err := os.Stat(filepath.Join(s.config.Storage.DataPath, "certs", agentcreds.SecretFileName)); err == nil {
		t.Fatal("a secret file was written though none was issued")
	}
	if runtime.GOOS != "windows" {
		assertInstallerRecognisesKey(t, path, testSensorRegKey, true)
	}
}

// Rotation replaces the secret; the replaced one is honoured for the window and
// then dropped from disk. A sensor enrolled before secrets existed receives its
// first at rotation and drops the registration key then.
func TestSensorSecret_RotationAndMigration(t *testing.T) {
	fastRotationRetries(t)

	// Migration: enrolled by an older platform (no secret, key kept).
	p := newFakeSensorPlatform(t, false)
	s, path := enrollingSensor(t, p)
	if err := s.register(); err != nil {
		t.Fatalf("register: %v", err)
	}
	p.mu.Lock()
	p.issue, p.secrets = true, []string{"first-secret", "second-secret"}
	p.mu.Unlock()

	reloaded, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rs := &Sensor{config: reloaded, configPath: path, sensorManager: api.NewSensorManagerClient(reloaded)}
	rs.rotateCertificateIfNeeded(rs.sensorManager)
	if got := p.sawRequest[1]["supports_agent_secret"]; got != true {
		t.Fatalf("rotation request supports_agent_secret = %v, want true", got)
	}

	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), testSensorRegKey) || strings.Contains(string(body), "registrationKey:") {
		t.Fatalf("the registration key is still in the config after migration:\n%s", body)
	}
	after, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st := after.AgentSecretState()
	if st.Secret != "first-secret" || st.Previous != testSensorRegKey {
		t.Fatalf("after migration state = %+v, want first-secret with the registration key as the previous", st)
	}

	// Second rotation: replaced again, previous is now the first secret.
	as := &Sensor{config: after, configPath: path, sensorManager: api.NewSensorManagerClient(after)}
	as.rotateCertificateIfNeeded(as.sensorManager)
	again, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st = again.AgentSecretState()
	if st.Secret != "second-secret" || st.Version != 2 || st.Previous != "first-secret" {
		t.Fatalf("after second rotation state = %+v", st)
	}

	// Past the window the replaced secret is dropped from disk.
	st.PreviousUntil = time.Now().Add(-time.Second)
	again.SetAgentSecretState(st)
	ps := &Sensor{config: again, configPath: path}
	ps.pruneAgentSecrets()
	data, _ := os.ReadFile(filepath.Join(again.Storage.DataPath, "certs", agentcreds.SecretFileName))
	if strings.Contains(string(data), "first-secret") {
		t.Fatalf("the replaced secret is still on disk after its window:\n%s", data)
	}
	if !strings.Contains(string(data), "second-secret") {
		t.Fatalf("pruning lost the current secret:\n%s", data)
	}
}
