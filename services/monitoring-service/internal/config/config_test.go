package config

import (
	"testing"
)

func TestLoad_apiGatewayURLOptOut(t *testing.T) {
	t.Setenv("API_GATEWAY_URL", "")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")
	t.Setenv("SYNTHETIC_CHECKS_JSON", "")

	cfg := Load()
	if cfg.Services["api-gateway"].URL != "" {
		t.Fatalf("api-gateway URL=%q, want empty (disabled probe)", cfg.Services["api-gateway"].URL)
	}
}
