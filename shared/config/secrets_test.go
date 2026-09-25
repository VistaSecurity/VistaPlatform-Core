package config

import (
	"os"
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
