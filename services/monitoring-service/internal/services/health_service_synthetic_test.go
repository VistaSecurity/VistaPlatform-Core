package services

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/config"
)

func TestCheckSyntheticHealth_hostHeader(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	hs := &HealthService{
		config: &config.Config{ServiceTimeout: 5 * time.Second},
	}

	result := hs.checkSyntheticHealth(config.SyntheticCheck{
		Name:       "edge-tenant",
		URL:        srv.URL + "/api/v1/auth-service/health",
		HostHeader: "portal.example.com",
	})
	if result.Status != "healthy" {
		t.Fatalf("status=%q error=%v", result.Status, result.Error)
	}
	if gotHost != "portal.example.com" {
		t.Fatalf("Host header=%q, want portal.example.com", gotHost)
	}
}

func TestBuildSyntheticRootCAs_EmptyPath(t *testing.T) {
	if pool := buildSyntheticRootCAs(""); pool != nil {
		t.Fatalf("expected nil pool for empty path, got %v", pool)
	}
}

func TestBuildSyntheticRootCAs_UnreadableFile(t *testing.T) {
	if pool := buildSyntheticRootCAs(filepath.Join(t.TempDir(), "does-not-exist.pem")); pool != nil {
		t.Fatalf("expected nil pool for unreadable file, got %v", pool)
	}
}

func TestBuildSyntheticRootCAs_GarbagePEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pool := buildSyntheticRootCAs(path); pool != nil {
		t.Fatalf("expected nil pool for garbage PEM, got %v", pool)
	}
}

// TestCheckSyntheticHealth_extraTrustedCA proves the fix for a real bug seen
// on a self-hosted deployment: a synthetic check against an edge cert signed
// by a private CA fails
// TLS verification by default (the container's CA bundle doesn't include a
// CA the *host* OS trusts — those are different trust stores), reporting
// "down" even though nothing is actually broken. Handing the check that CA
// via ExtraTrustedCACertPath must make it verify — not silently skip
// verification like InsecureSkipVerify would.
func TestCheckSyntheticHealth_extraTrustedCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	check := config.SyntheticCheck{Name: "edge-tenant", URL: srv.URL}

	// Without the CA: verification fails against the default system pool, so
	// this must report "down", never "healthy" — proves the test server's
	// cert genuinely isn't trusted by default (i.e. this is a real check,
	// not a tautology).
	hsNoTrust := &HealthService{config: &config.Config{ServiceTimeout: 5 * time.Second}}
	untrusted := hsNoTrust.checkSyntheticHealth(check)
	if untrusted.Status != "down" {
		t.Fatalf("expected down without extra CA (proves the test is meaningful), got status=%q error=%v", untrusted.Status, untrusted.Error)
	}

	// With the CA: real verification succeeds.
	certPath := filepath.Join(t.TempDir(), "test-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	hsTrusted := &HealthService{
		config:           &config.Config{ServiceTimeout: 5 * time.Second},
		syntheticRootCAs: buildSyntheticRootCAs(certPath),
	}
	trusted := hsTrusted.checkSyntheticHealth(check)
	if trusted.Status != "healthy" {
		t.Fatalf("expected healthy with extra CA trusted, got status=%q error=%v", trusted.Status, trusted.Error)
	}
}
