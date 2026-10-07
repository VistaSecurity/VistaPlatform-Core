package config

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestFirstInsecureDefault(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		secrets map[string]string
		want    string
	}{
		{
			name:    "non-production is a no-op even with dev defaults",
			env:     "development",
			secrets: map[string]string{"JWT_SECRET": "dev-secret-key-change-in-production"},
			want:    "",
		},
		{
			name:    "production with strong secrets passes",
			env:     "production",
			secrets: map[string]string{"JWT_SECRET": "a-real-strong-secret", "INTERNAL_AUTH_SECRET": "another-strong-one"},
			want:    "",
		},
		{
			name:    "production rejects the dev JWT default",
			env:     "production",
			secrets: map[string]string{"JWT_SECRET": "dev-secret-key-change-in-production"},
			want:    "JWT_SECRET",
		},
		{
			name:    "production catches the your-secret-key variant",
			env:     "production",
			secrets: map[string]string{"JWT_SECRET": "your-secret-key"},
			want:    "JWT_SECRET",
		},
		{
			name:    "production catches the master-key dev default",
			env:     "production",
			secrets: map[string]string{"ENCRYPTION_MASTER_KEY": "dev-master-key-change-in-production"},
			want:    "ENCRYPTION_MASTER_KEY",
		},
		{
			name:    "production catches the internal-auth dev default",
			env:     "production",
			secrets: map[string]string{"INTERNAL_AUTH_SECRET": "dev-internal-auth-secret-change-in-production"},
			want:    "INTERNAL_AUTH_SECRET",
		},
		{
			name:    "empty secret is not treated as a dev default",
			env:     "production",
			secrets: map[string]string{"INTERNAL_AUTH_SECRET": ""},
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstInsecureDefault(tt.env, tt.secrets); got != tt.want {
				t.Fatalf("firstInsecureDefault(%q, %v) = %q, want %q", tt.env, tt.secrets, got, tt.want)
			}
		})
	}
}

func TestJWTSecretEnvironmentFallback(t *testing.T) {
	t.Run("development keeps local fallback", func(t *testing.T) {
		t.Setenv("ENV", "development")
		t.Setenv("JWT_SECRET", "")
		// Setenv marks the value explicitly present, and explicit empty means
		// disabled. Unset it to exercise the absent-variable fallback.
		if err := os.Unsetenv("JWT_SECRET"); err != nil {
			t.Fatal(err)
		}
		if got := JWTSecret(); got != "dev-secret-key-change-in-production" {
			t.Fatalf("JWTSecret() = %q, want development fallback", got)
		}
	})

	t.Run("production absence disables legacy hmac", func(t *testing.T) {
		t.Setenv("ENV", "production")
		if err := os.Unsetenv("JWT_SECRET"); err != nil {
			t.Fatal(err)
		}
		if got := JWTSecret(); got != "" {
			t.Fatalf("JWTSecret() = %q, want empty production secret", got)
		}
	})

	t.Run("explicit value is preserved", func(t *testing.T) {
		t.Setenv("ENV", "production")
		t.Setenv("JWT_SECRET", "migration-window-secret")
		if got := JWTSecret(); got != "migration-window-secret" {
			t.Fatalf("JWTSecret() = %q, want configured secret", got)
		}
	})
}

func envMap(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

const strong32 = "0123456789abcdef0123456789abcdef" // exactly 32 bytes

func TestCheckProductionSecrets(t *testing.T) {
	both := SecretSpec{Required: []string{"INTERNAL_AUTH_SECRET", "ENCRYPTION_MASTER_KEY"}, VerifiesJWT: true}
	tests := []struct {
		name    string
		env     string
		spec    SecretSpec
		vars    map[string]string
		wantErr []string // substrings; nil = must pass
	}{
		{"strong secrets pass", "production", both,
			map[string]string{"INTERNAL_AUTH_SECRET": strong32, "ENCRYPTION_MASTER_KEY": strong32, "JWT_SECRET": strong32}, nil},
		{"31 bytes fails, 32 passes (boundary)", "production", SecretSpec{Required: []string{"INTERNAL_AUTH_SECRET"}},
			map[string]string{"INTERNAL_AUTH_SECRET": strong32[:31]}, []string{"INTERNAL_AUTH_SECRET", "31 bytes"}},
		{"missing INTERNAL_AUTH_SECRET names it", "production", both,
			map[string]string{"ENCRYPTION_MASTER_KEY": strong32, "JWT_SECRET": strong32}, []string{"INTERNAL_AUTH_SECRET is not set"}},
		{"missing ENCRYPTION_MASTER_KEY says credentials would be unencrypted", "production", both,
			map[string]string{"INTERNAL_AUTH_SECRET": strong32, "JWT_SECRET": strong32}, []string{"ENCRYPTION_MASTER_KEY is not set", "unencrypted"}},
		{"explicitly empty counts as missing", "production", both,
			map[string]string{"INTERNAL_AUTH_SECRET": "", "ENCRYPTION_MASTER_KEY": strong32, "JWT_SECRET": strong32}, []string{"INTERNAL_AUTH_SECRET is not set"}},
		{"short ENCRYPTION_MASTER_KEY", "production", both,
			map[string]string{"INTERNAL_AUTH_SECRET": strong32, "ENCRYPTION_MASTER_KEY": "short", "JWT_SECRET": strong32}, []string{"ENCRYPTION_MASTER_KEY is 5 bytes"}},
		{"every offender is named at once", "production", both,
			map[string]string{"INTERNAL_AUTH_SECRET": "a", "JWT_SECRET": "b"}, []string{"ENCRYPTION_MASTER_KEY", "INTERNAL_AUTH_SECRET", "JWT_SECRET"}},
		{"present short JWT_SECRET fails even with ES256 configured", "production", both,
			map[string]string{"INTERNAL_AUTH_SECRET": strong32, "ENCRYPTION_MASTER_KEY": strong32, "JWT_SECRET": "short", "JWT_JWKS_URL": "http://auth-service:8080/.well-known/jwks.json"}, []string{"JWT_SECRET is 5 bytes"}},
		{"absent JWT_SECRET passes with a JWKS URL (ES256-only final step)", "production", both,
			map[string]string{"INTERNAL_AUTH_SECRET": strong32, "ENCRYPTION_MASTER_KEY": strong32, "JWT_JWKS_URL": "http://auth-service:8080/.well-known/jwks.json"}, nil},
		{"absent JWT_SECRET passes with inline public keys", "production", both,
			map[string]string{"INTERNAL_AUTH_SECRET": strong32, "ENCRYPTION_MASTER_KEY": strong32, "JWT_PUBLIC_KEYS": `{"keys":[]}`}, nil},
		{"empty-string JWT_SECRET (explicit disable) passes with ES256", "production", both,
			map[string]string{"INTERNAL_AUTH_SECRET": strong32, "ENCRYPTION_MASTER_KEY": strong32, "JWT_SECRET": "", "JWT_JWKS_URL": "http://x/jwks"}, nil},
		{"absent JWT_SECRET and no ES256 source fails clearly", "production", both,
			map[string]string{"INTERNAL_AUTH_SECRET": strong32, "ENCRYPTION_MASTER_KEY": strong32}, []string{"JWT_SECRET is not set", "JWT_JWKS_URL"}},
		{"a service that does not verify JWTs is not asked for JWT_SECRET", "production", SecretSpec{Required: []string{"INTERNAL_AUTH_SECRET"}},
			map[string]string{"INTERNAL_AUTH_SECRET": strong32}, nil},
		{"issuer lists JWT_SECRET as Required: absent fails even with ES256", "production", SecretSpec{Required: []string{"JWT_SECRET"}},
			map[string]string{"JWT_JWKS_URL": "http://x/jwks"}, []string{"JWT_SECRET is not set"}},
		{"dev literal is reported as a dev literal", "production", both,
			map[string]string{"INTERNAL_AUTH_SECRET": strong32, "ENCRYPTION_MASTER_KEY": "dev-master-key-change-in-production", "JWT_SECRET": strong32}, []string{"ENCRYPTION_MASTER_KEY", "insecure default"}},
		{"non-production tolerates everything", "development", both,
			map[string]string{"INTERNAL_AUTH_SECRET": "a"}, nil},
		{"staging is not production", "staging", both, map[string]string{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkProductionSecrets(tt.env, tt.spec, envMap(tt.vars))
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error mentioning %v, got nil", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q should contain %q", err, want)
				}
			}
			for _, v := range tt.vars {
				if len(v) >= 8 && strings.Contains(err.Error(), v) {
					t.Fatalf("error leaks a secret value: %q", err)
				}
			}
		})
	}
}

func TestEnforceOutsideProductionWarnsAndContinues(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	spec := SecretSpec{Required: []string{"INTERNAL_AUTH_SECRET", "ENCRYPTION_MASTER_KEY"}, VerifiesJWT: true}
	err := enforceProductionSecrets("development", spec, envMap(map[string]string{"INTERNAL_AUTH_SECRET": "short", "JWT_SECRET": "tiny"}))
	if err != nil {
		t.Fatalf("development must keep running, got %v", err)
	}
	out := buf.String()
	for _, want := range []string{"INTERNAL_AUTH_SECRET is 5 bytes", "ENCRYPTION_MASTER_KEY is not set", "unencrypted", "JWT_SECRET is 4 bytes", "WARNING"} {
		if !strings.Contains(out, want) {
			t.Fatalf("warning output %q should contain %q", out, want)
		}
	}
	if strings.Contains(out, "short") && strings.Contains(out, "=short") {
		t.Fatalf("warning leaks a value: %q", out)
	}

	// Dev with no JWT_SECRET and no ES256 is NOT a finding: JWTSecret() supplies the dev fallback.
	buf.Reset()
	if err := enforceProductionSecrets("development", SecretSpec{VerifiesJWT: true}, envMap(nil)); err != nil || buf.Len() != 0 {
		t.Fatalf("dev, absent JWT_SECRET: err=%v log=%q, want silence", err, buf.String())
	}
}

func TestIsProduction(t *testing.T) {
	for env, want := range map[string]bool{"production": true, "development": false, "staging": false, "": false, "Production": false} {
		if got := IsProduction(env); got != want {
			t.Errorf("IsProduction(%q) = %v, want %v", env, got, want)
		}
	}
}
