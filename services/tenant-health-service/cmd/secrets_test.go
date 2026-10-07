package main

import (
	"os"
	"strings"
	"testing"
)

const strongSecret = "0123456789abcdef0123456789abcdef0123456789abcdef"

func setProduction(t *testing.T, vars map[string]string) {
	t.Helper()
	for _, name := range []string{"INTERNAL_AUTH_SECRET", "ENCRYPTION_MASTER_KEY", "JWT_SECRET", "JWT_JWKS_URL", "JWT_PUBLIC_KEYS"} {
		t.Setenv(name, "") // register restore
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("ENV", "production")
	for k, v := range vars {
		t.Setenv(k, v)
	}
}

func TestEnforceStartupSecrets(t *testing.T) {
	full := map[string]string{"INTERNAL_AUTH_SECRET": strongSecret, "ENCRYPTION_MASTER_KEY": strongSecret, "JWT_SECRET": strongSecret}
	with := func(over map[string]string, drop ...string) map[string]string {
		m := map[string]string{}
		for k, v := range full {
			m[k] = v
		}
		for k, v := range over {
			m[k] = v
		}
		for _, d := range drop {
			delete(m, d)
		}
		return m
	}
	tests := []struct {
		name string
		vars map[string]string
		want string // "" = starts
	}{
		{"strong secrets start", full, ""},
		{"missing INTERNAL_AUTH_SECRET", with(nil, "INTERNAL_AUTH_SECRET"), "INTERNAL_AUTH_SECRET"},
		{"short INTERNAL_AUTH_SECRET", with(map[string]string{"INTERNAL_AUTH_SECRET": "short"}), "INTERNAL_AUTH_SECRET"},
		{"short JWT_SECRET", with(map[string]string{"JWT_SECRET": "short"}), "JWT_SECRET"},
		{"absent JWT_SECRET with ES256 starts", with(map[string]string{"JWT_JWKS_URL": "http://auth-service:8080/.well-known/jwks.json"}, "JWT_SECRET"), ""},
		{"absent JWT_SECRET without ES256", with(nil, "JWT_SECRET"), "JWT_SECRET"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setProduction(t, tt.vars)
			err := enforceStartupSecrets()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected refusal: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want a refusal naming %s, got %v", tt.want, err)
			}
		})
	}
}
