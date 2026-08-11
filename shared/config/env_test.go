package config

import (
	"os"
	"testing"
)

func TestGetEnvIfPresent(t *testing.T) {
	const key = "TEST_GET_ENV_IF_PRESENT"

	t.Run("unset uses fallback", func(t *testing.T) {
		os.Unsetenv(key)
		if got := GetEnvIfPresent(key, "fallback"); got != "fallback" {
			t.Fatalf("got %q, want fallback", got)
		}
	})

	t.Run("empty string is preserved", func(t *testing.T) {
		t.Setenv(key, "")
		if got := GetEnvIfPresent(key, "fallback"); got != "" {
			t.Fatalf("got %q, want empty string", got)
		}
	})

	t.Run("non-empty value is returned", func(t *testing.T) {
		t.Setenv(key, "http://example:8080")
		if got := GetEnvIfPresent(key, "fallback"); got != "http://example:8080" {
			t.Fatalf("got %q, want explicit value", got)
		}
	})
}
