package config

import (
	"os"
	"testing"
)

func TestResolveEnforceSecureCookies(t *testing.T) {
	cases := []struct {
		name        string
		environment string
		enforce     string // ENFORCE_SECURE_COOKIES ("" = unset)
		cookieSec   string // COOKIE_SECURE ("" = unset)
		want        bool
	}{
		// The regression this test exists for. Every shipped deployment — the
		// Helm chart and docker-compose.ec2-smoke — sets
		// COOKIE_SECURE and none of them set ENFORCE_SECURE_COOKIES. Before the
		// fix this combination resolved to false, so admin-service never forced
		// Secure anywhere, in any environment.
		{
			name:        "chart deployment with TLS: COOKIE_SECURE=true, no override",
			environment: "production",
			cookieSec:   "true",
			want:        true,
		},
		{
			name:        "COOKIE_SECURE=true honoured even when ENV is not production",
			environment: "development",
			cookieSec:   "true",
			want:        true,
		},

		// The dev carve-out must keep working: tls.mode=none renders
		// COOKIE_SECURE=false, and a Secure cookie over plain HTTP is dropped by
		// the browser, which would lock an operator out of a local stack.
		{
			name:        "tls.mode=none renders COOKIE_SECURE=false",
			environment: "development",
			cookieSec:   "false",
			want:        false,
		},
		{
			name:        "local dev with nothing set at all",
			environment: "development",
			want:        false,
		},

		// Matches auth-service's default so the two services agree.
		{
			name:        "production floor applies when COOKIE_SECURE is unset",
			environment: "production",
			want:        true,
		},

		// The explicit override wins in both directions.
		{
			name:        "override forces on despite COOKIE_SECURE=false",
			environment: "development",
			enforce:     "true",
			cookieSec:   "false",
			want:        true,
		},
		{
			name:        "override forces off despite COOKIE_SECURE=true",
			environment: "production",
			enforce:     "false",
			cookieSec:   "true",
			want:        false,
		},
		{
			name:        "unparseable override falls through rather than defaulting to off",
			environment: "production",
			enforce:     "yes-please",
			cookieSec:   "true",
			want:        true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv registers the restore-on-cleanup, then os.Unsetenv makes
			// the "" cases genuinely unset rather than set-to-empty. The
			// distinction does not currently change the outcome (both readers
			// treat empty as absent) but testing the real shape means this stays
			// true if either reader is ever tightened.
			setOrUnset(t, "ENFORCE_SECURE_COOKIES", tc.enforce)
			setOrUnset(t, "COOKIE_SECURE", tc.cookieSec)

			if got := resolveEnforceSecureCookies(tc.environment); got != tc.want {
				t.Errorf("resolveEnforceSecureCookies(%q) = %v, want %v (ENFORCE_SECURE_COOKIES=%q COOKIE_SECURE=%q)",
					tc.environment, got, tc.want, tc.enforce, tc.cookieSec)
			}
		})
	}
}

// setOrUnset sets key to value, or removes it entirely when value is "".
// t.Setenv is called first in both branches so the original value is restored
// when the test finishes.
func setOrUnset(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv(key, value)
	if value == "" {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
}
