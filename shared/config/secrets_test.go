package config

import "testing"

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
