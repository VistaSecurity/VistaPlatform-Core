package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writeCfg(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "agent-config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A key that exists but cannot be read (root-owned, read by the service user)
// must fail the load, not leave the sensor running without mTLS.
func TestLoadFromFile_UnreadableKeyIsAnError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	_ = os.WriteFile(crt, []byte("CERT"), 0o644)
	_ = os.WriteFile(key, []byte("KEY"), 0o000)
	p := writeCfg(t, dir, "security:\n  client_cert_path: "+crt+"\n  client_key_path: "+key+"\n")

	_, err := LoadFromFile(p)
	var certErr *CertificateReadError
	if !errors.As(err, &certErr) {
		t.Fatalf("err = %v, want *CertificateReadError", err)
	}
	if certErr.Path != key {
		t.Fatalf("error names %q, want %q", certErr.Path, key)
	}
}

func TestLoadFromFile_MissingCertificateFileIsTolerated(t *testing.T) {
	dir := t.TempDir()
	p := writeCfg(t, dir, "security:\n  client_cert_path: "+filepath.Join(dir, "gone.crt")+"\n")
	cfg, err := LoadFromFile(p)
	if err != nil {
		t.Fatalf("a not-yet-enrolled host must still load: %v", err)
	}
	if cfg.Security.UseTLS {
		t.Fatal("TLS enabled without certificates")
	}
}

func TestSaveCertificatesToFiles_ReplacesAtomicallyWithKeyMode(t *testing.T) {
	cfg := &Config{}
	dataPath := t.TempDir()
	certs := filepath.Join(dataPath, "certs")
	_ = os.MkdirAll(certs, 0o700)
	_ = os.WriteFile(filepath.Join(certs, "client.crt"), []byte("old-cert"), 0o644)
	// Make the key unreplaceable: a non-empty directory sits at its path.
	_ = os.MkdirAll(filepath.Join(certs, "client.key", "x"), 0o700)

	if err := SaveCertificatesToFiles(cfg, "new-cert", "new-key", "", dataPath); err == nil {
		t.Fatal("expected failure")
	}
	if b, _ := os.ReadFile(filepath.Join(certs, "client.crt")); string(b) != "old-cert" {
		t.Fatalf("cert replaced although the key could not be: %q — pair mismatched", b)
	}
	if cfg.Security.ClientCert != "" || cfg.Security.UseTLS {
		t.Fatalf("in-memory config changed by a failed save: %+v", cfg.Security)
	}

	// Success path: key file is 0600, no temp files remain.
	_ = os.RemoveAll(filepath.Join(certs, "client.key"))
	if err := SaveCertificatesToFiles(cfg, "new-cert", "new-key", "ca", dataPath); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(certs, "client.key"))
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("key mode %#o", st.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(certs)
	if len(entries) != 3 {
		t.Fatalf("unexpected files in certs dir: %v", entries)
	}
}
