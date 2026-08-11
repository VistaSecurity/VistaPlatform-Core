package services

import (
	"net/http"
	"net/http/httptest"
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
