package main

//: the agent's credential key is rooted in a per-agent secret the platform
// issues at enrolment and at each certificate rotation, and the single-use
// registration key is no longer kept once that secret is on disk. These tests run
// the REAL client against a fake platform, then the real persistence
// (saveCertificates + saveConfigFile) and the real config loader, and open
// envelopes sealed the way the platform seals them (shared/agentcreds).

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

	"github.com/vistasecurity/vistaplatform/device-agent/internal/api"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/security"
	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
)

const testRegKey = "REG-0123456789abcdef0123456789abcdef"

// fakePlatform signs the CSRs it is sent and hands out the agent secrets it is
// told to, the way the real registration and rotation routes do.
type fakePlatform struct {
	t       *testing.T
	srv     *httptest.Server
	caKey   *rsa.PrivateKey
	caCert  *x509.Certificate
	mu      sync.Mutex
	secrets []string // issued in order: enrolment first, then one per rotation
	issued  int
	// issue controls whether a secret is returned at all (false: an older platform).
	issue      bool
	sawRequest []map[string]any
}

func newFakePlatform(t *testing.T, issue bool, secrets ...string) *fakePlatform {
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
	f := &fakePlatform{t: t, caKey: caKey, caCert: caCert, secrets: secrets, issue: issue}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePlatform) signCSR(csrPEM string) string {
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

func (f *fakePlatform) serve(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	f.sawRequest = append(f.sawRequest, body)
	resp := map[string]any{"client_cert": f.signCSR(body["csr"].(string))}
	if f.issue && f.issued < len(f.secrets) {
		f.issued++
		resp["agent_secret"] = f.secrets[f.issued-1]
		resp["agent_secret_version"] = f.issued
	}
	f.mu.Unlock()
	switch {
	case strings.HasSuffix(r.URL.Path, "/agents/register"):
		resp["agent_id"] = "6f1f0a7e-1d3c-4f0e-9a52-0c3b6f3d2a11"
		w.WriteHeader(http.StatusCreated)
	case strings.HasSuffix(r.URL.Path, "/certificates/rotate"):
		resp["agent_id"] = "6f1f0a7e-1d3c-4f0e-9a52-0c3b6f3d2a11"
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func persist(t *testing.T, cfg *config.Config, path string) {
	t.Helper()
	if err := saveCertificates(cfg); err != nil {
		t.Fatalf("saveCertificates: %v", err)
	}
	if err := saveConfigFile(path, cfg); err != nil {
		t.Fatalf("saveConfigFile: %v", err)
	}
}

func sealedFor(t *testing.T, secret string) (map[string]interface{}, string) {
	t.Helper()
	jobID := "5f2b1c7a-9c3e-4a1f-8b6d-2e7c1a4d9f30"
	env, err := agentcreds.Seal(map[string]interface{}{"username": "admin", "password": "device-pw"}, jobID, secret)
	if err != nil {
		t.Fatal(err)
	}
	return env, jobID
}

func opens(cfg *config.Config, env map[string]interface{}, jobID string) bool {
	creds, err := security.DecryptCredentials(env, jobID, cfg.CredentialSecrets()...)
	return err == nil && creds["password"] == "device-pw"
}

func reload(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	return cfg
}

func newEnrolling(t *testing.T, p *fakePlatform) (*config.Config, *api.OutboundClient, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{PlatformURL: p.srv.URL, RegistrationKey: testRegKey, DataPath: dir,
		PollInterval: 30 * time.Second, HeartbeatInterval: time.Minute}
	return cfg, api.NewOutboundClient(cfg), filepath.Join(dir, "agent-config.yaml")
}

// Enrolment: the secret is returned, kept 0600 beside the certificate, the
// registration key is gone from the config, and credentials sealed under the
// secret open on the reloaded agent while the spent key opens nothing.
func TestAgentSecret_EnrolmentDropsTheRegistrationKey(t *testing.T) {
	p := newFakePlatform(t, true, "agent-secret-one")
	cfg, client, path := newEnrolling(t, p)

	if err := client.Register("test"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got := p.sawRequest[0]["supports_agent_secret"]; got != true {
		t.Fatalf("registration request supports_agent_secret = %v, want true", got)
	}
	persist(t, cfg, path)

	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), testRegKey) || strings.Contains(string(body), "registration_key:") {
		t.Fatalf("the config still holds the registration key:\n%s", body)
	}
	if !strings.Contains(string(body), "registration_key_sha256:") || !strings.Contains(string(body), "agent_secret_path:") {
		t.Fatalf("config lacks the fingerprint / secret path:\n%s", body)
	}
	secretFile := filepath.Join(cfg.DataPath, "certs", agentcreds.SecretFileName)
	data, err := os.ReadFile(secretFile)
	if err != nil || !strings.Contains(string(data), "agent-secret-one") {
		t.Fatalf("secret file: %v %q", err, data)
	}
	if strings.Contains(string(data), testRegKey) {
		t.Fatal("the secret file carries the registration key")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(secretFile); fi.Mode().Perm() != 0o600 {
			t.Fatalf("secret file mode = %v, want 0600", fi.Mode().Perm())
		}
	}

	re := reload(t, path)
	if re.RegistrationKey != "" {
		t.Fatalf("reloaded RegistrationKey = %q, want none", re.RegistrationKey)
	}
	env, jobID := sealedFor(t, "agent-secret-one")
	if !opens(re, env, jobID) {
		t.Fatal("credentials sealed under the agent secret do not open on the reloaded agent")
	}
	spent, _ := sealedFor(t, testRegKey)
	if opens(re, spent, jobID) {
		t.Fatal("an envelope sealed under the spent registration key opened")
	}
}

// An older platform issues no secret: the agent must keep the registration key,
// because it is still what opens the platform's envelopes.
func TestAgentSecret_OlderPlatformKeepsTheRegistrationKey(t *testing.T) {
	p := newFakePlatform(t, false)
	cfg, client, path := newEnrolling(t, p)
	if err := client.Register("test"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	persist(t, cfg, path)

	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), testRegKey) {
		t.Fatalf("the registration key was dropped though no agent secret exists:\n%s", body)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataPath, "certs", agentcreds.SecretFileName)); err == nil {
		t.Fatal("a secret file was written though none was issued")
	}
	env, jobID := sealedFor(t, testRegKey)
	if !opens(reload(t, path), env, jobID) {
		t.Fatal("registration-key envelope does not open")
	}
}

// A config written by a build that predates agent secrets (registration key, no
// secret) still opens envelopes sealed under the registration key.
func TestAgentSecret_PreChangeConfigStillDecrypts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent-config.yaml")
	if err := os.WriteFile(path, []byte("agent_id: \"6f1f0a7e-1d3c-4f0e-9a52-0c3b6f3d2a11\"\nplatform_url: \"https://p.example.test\"\nregistration_key: \""+testRegKey+"\"\ndata_path: \""+dir+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := reload(t, path)
	env, jobID := sealedFor(t, testRegKey)
	if !opens(cfg, env, jobID) {
		t.Fatal("a pre-change config can no longer open registration-key envelopes")
	}
}

// Rotation issues a new secret; the replaced one keeps working for the window
// and then does not. Survives a restart (the window is on disk).
func TestAgentSecret_RotationWindow(t *testing.T) {
	p := newFakePlatform(t, true, "agent-secret-one", "agent-secret-two")
	cfg, client, path := newEnrolling(t, p)
	if err := client.Register("test"); err != nil {
		t.Fatal(err)
	}
	persist(t, cfg, path)

	if err := client.RotateCertificate(); err != nil {
		t.Fatalf("RotateCertificate: %v", err)
	}
	if got := p.sawRequest[1]["supports_agent_secret"]; got != true {
		t.Fatalf("rotation request supports_agent_secret = %v, want true", got)
	}
	persist(t, cfg, path)

	oldEnv, jobID := sealedFor(t, "agent-secret-one")
	newEnv, _ := sealedFor(t, "agent-secret-two")
	re := reload(t, path)
	if !opens(re, newEnv, jobID) {
		t.Fatal("the new secret does not open")
	}
	if !opens(re, oldEnv, jobID) {
		t.Fatal("an in-flight envelope sealed under the replaced secret no longer opens inside the window")
	}

	// Past the window the replaced secret is dead, in memory and on disk.
	st := re.AgentSecretState()
	st.PreviousUntil = time.Now().Add(-time.Second)
	re.SetAgentSecretState(st)
	if opens(re, oldEnv, jobID) {
		t.Fatal("the replaced secret still opens after the window")
	}
	if !opens(re, newEnv, jobID) {
		t.Fatal("the current secret stopped opening after the window")
	}
	if !re.PruneAgentSecrets(time.Now()) {
		t.Fatal("PruneAgentSecrets reported nothing to drop")
	}
	if err := saveCertificates(re); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(cfg.DataPath, "certs", agentcreds.SecretFileName))
	if strings.Contains(string(data), "agent-secret-one") {
		t.Fatalf("the replaced secret is still on disk after its window:\n%s", data)
	}
}

// The migration: an agent enrolled before agent secrets existed receives its
// first secret at certificate rotation and switches, with no re-enrolment. The
// registration key it held is dropped from the config but keeps opening
// in-flight envelopes for the window.
func TestAgentSecret_MigrationAtFirstRotation(t *testing.T) {
	p := newFakePlatform(t, false) // enrolled before secrets existed
	cfg, client, path := newEnrolling(t, p)
	if err := client.Register("test"); err != nil {
		t.Fatal(err)
	}
	persist(t, cfg, path)
	if body, _ := os.ReadFile(path); !strings.Contains(string(body), testRegKey) {
		t.Fatal("setup: the pre-change agent should hold its registration key")
	}

	p.mu.Lock()
	p.issue, p.secrets = true, []string{"first-secret"}
	p.mu.Unlock()
	re := reload(t, path)
	rc := api.NewOutboundClient(re)
	rc.SetAgentVersion("test")
	if err := rc.RotateCertificate(); err != nil {
		t.Fatalf("RotateCertificate: %v", err)
	}
	persist(t, re, path)

	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), testRegKey) || strings.Contains(string(body), "registration_key:") {
		t.Fatalf("the registration key is still in the config after migration:\n%s", body)
	}
	after := reload(t, path)
	regEnv, jobID := sealedFor(t, testRegKey)
	newEnv, _ := sealedFor(t, "first-secret")
	if !opens(after, newEnv, jobID) {
		t.Fatal("the issued secret does not open")
	}
	if !opens(after, regEnv, jobID) {
		t.Fatal("an in-flight envelope sealed under the registration key no longer opens inside the migration window")
	}
	st := after.AgentSecretState()
	st.PreviousUntil = time.Now().Add(-time.Second)
	after.SetAgentSecretState(st)
	if opens(after, regEnv, jobID) {
		t.Fatal("the registration key still opens envelopes after the migration window")
	}
}

// The installer decides "this host already enrolled with this key" from what the
// agent leaves in the config. With the key no longer kept, it must recognise the
// fingerprint — and only the fingerprint of THIS key — or a re-run of the same
// install command would discard a working enrolment.
func TestAgentSecret_InstallerRecognisesTheFingerprint(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	p := newFakePlatform(t, true, "agent-secret-one")
	cfg, client, path := newEnrolling(t, p)
	if err := client.Register("test"); err != nil {
		t.Fatal(err)
	}
	persist(t, cfg, path)

	raw, err := os.ReadFile(deviceAgentInstaller)
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	sections := installerSection(t, script, `^read_config_value\(\) \{`, `^\}`) + "\n" +
		installerSection(t, script, `^sha256_of\(\) \{`, `^\}`) + "\n" +
		installerSection(t, script, `^enrolled_with_key\(\) \{`, `^\}`)
	check := func(key string) string {
		return strings.TrimSpace(runInstallerBash(t, sections+"\nif enrolled_with_key "+path+" "+key+"; then echo yes; else echo no; fi"))
	}
	if got := check(testRegKey); got != "yes" {
		t.Fatalf("installer does not recognise the key this host enrolled with (%s) — a re-run would discard the enrolment", got)
	}
	if got := check("REG-another-hosts-key"); got != "no" {
		t.Fatalf("installer recognises a different key (%s)", got)
	}
}

// The agent's own daily check drops a replaced secret from disk once its window
// has passed, through the real method the rotation monitor calls.
func TestAgentSecret_DailyCheckDropsAnExpiredPreviousSecret(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataPath: dir, PlatformURL: "https://p.example.test", AgentID: "6f1f0a7e-1d3c-4f0e-9a52-0c3b6f3d2a11",
		PollInterval: time.Minute, HeartbeatInterval: time.Minute}
	cfg.Security.ClientCert, cfg.Security.ClientKey = "CERT", "KEY"
	cfg.SetAgentSecretState(agentcreds.SecretState{Secret: "current", Version: 2, Previous: "replaced", PreviousUntil: time.Now().Add(-time.Minute)})
	a := &DeviceAgent{config: cfg, configPath: filepath.Join(dir, "agent-config.yaml")}

	a.pruneAgentSecrets()

	data, err := os.ReadFile(filepath.Join(dir, "certs", agentcreds.SecretFileName))
	if err != nil {
		t.Fatalf("secret file not written: %v", err)
	}
	if strings.Contains(string(data), "replaced") || !strings.Contains(string(data), "current") {
		t.Fatalf("secret file after the daily check:\n%s", data)
	}
}
