package database

import (
	"strings"
	"testing"
)

// secret is the password every case below plants. Each test asserts it does not
// survive redaction, so a regression shows up as the literal appearing in output
// rather than as a subtle formatting diff.
const secret = "sup3r-s3cret-pw"

func TestRedactDSN_RemovesPassword(t *testing.T) {
	cases := []struct {
		name string
		dsn  string
		want string
	}{
		{
			name: "url form (DATABASE_URL)",
			dsn:  "postgres://crypto_user:" + secret + "@postgres:5432/crypto_inventory?sslmode=disable",
			want: "postgres://crypto_user:" + redactedPlaceholder + "@postgres:5432/crypto_inventory?sslmode=disable",
		},
		{
			name: "postgresql:// scheme",
			dsn:  "postgresql://u:" + secret + "@h:5432/d",
			want: "postgresql://u:" + redactedPlaceholder + "@h:5432/d",
		},
		{
			name: "keyword form built from individual config",
			dsn:  "host=postgres port=5432 user=crypto_user password=" + secret + " dbname=crypto_inventory sslmode=verify-full",
			want: "host=postgres port=5432 user=crypto_user password=" + redactedPlaceholder + " dbname=crypto_inventory sslmode=verify-full",
		},
		{
			name: "keyword form, password is the last field",
			dsn:  "host=postgres dbname=crypto_inventory password=" + secret,
			want: "host=postgres dbname=crypto_inventory password=" + redactedPlaceholder,
		},
		{
			name: "keyword form with a quoted password containing spaces",
			dsn:  "host=postgres password='" + secret + " with spaces' sslmode=require",
			want: "host=postgres password=" + redactedPlaceholder + " sslmode=require",
		},
		{
			name: "sslpassword (client key passphrase) is also a credential",
			dsn:  "host=postgres sslkey=/certs/tls.key sslpassword=" + secret + " sslmode=verify-full",
			want: "host=postgres sslkey=/certs/tls.key sslpassword=" + redactedPlaceholder + " sslmode=verify-full",
		},
		{
			name: "password as a url query parameter",
			dsn:  "postgres://u@h:5432/d?password=" + secret,
			want: "postgres://u@h:5432/d?password=" + redactedPlaceholder,
		},
		{
			name: "no password at all is left intact",
			dsn:  "host=postgres port=5432 user=crypto_user dbname=crypto_inventory sslmode=disable",
			want: "host=postgres port=5432 user=crypto_user dbname=crypto_inventory sslmode=disable",
		},
		{
			name: "empty dsn",
			dsn:  "",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactDSN(tc.dsn)

			// The load-bearing assertion: the credential is gone. Checked
			// separately from the exact-shape assertion so a formatting change
			// can never be mistaken for a leak, or vice versa.
			if strings.Contains(got, secret) {
				t.Fatalf("redactDSN leaked the password\n  dsn:  %q\n  got:  %q", tc.dsn, got)
			}
			if got != tc.want {
				t.Errorf("redactDSN shape mismatch\n  dsn:  %q\n  got:  %q\n  want: %q", tc.dsn, got, tc.want)
			}
		})
	}
}

// A DSN we cannot parse must be redacted wholesale. Returning it verbatim would
// be the "check that cannot fail" shape: the call site reads as safe while the
// credential still reaches the log.
func TestRedactDSN_UnparseableURLIsFullyRedacted(t *testing.T) {
	// A control character in the host makes url.Parse fail.
	dsn := "postgres://u:" + secret + "@ho\x7fst:5432/d"
	got := redactDSN(dsn)
	if strings.Contains(got, secret) {
		t.Fatalf("unparseable DSN leaked the password: %q", got)
	}
	if got != redactedPlaceholder {
		t.Errorf("unparseable DSN should be redacted wholesale, got %q", got)
	}
}

// The password must not survive even when it contains characters that look like
// DSN structure ('@', '=', ' ', ':').
func TestRedactDSN_PasswordContainingDelimiters(t *testing.T) {
	t.Run("url form with encoded delimiters", func(t *testing.T) {
		got := redactDSN("postgres://u:p%40ss%3Dword@h:5432/d")
		for _, leak := range []string{"p%40ss", "pass=word", "p@ss"} {
			if strings.Contains(got, leak) {
				t.Fatalf("leaked %q in %q", leak, got)
			}
		}
	})
	t.Run("keyword form with equals in password", func(t *testing.T) {
		got := redactDSN("host=h password=a=b=c dbname=d")
		if strings.Contains(got, "a=b=c") {
			t.Fatalf("leaked password with embedded '=': %q", got)
		}
		if got != "host=h password="+redactedPlaceholder+" dbname=d" {
			t.Errorf("unexpected shape: %q", got)
		}
	})
}
