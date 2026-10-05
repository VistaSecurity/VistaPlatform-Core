package database

import "testing"

func TestApplyServerDefaults(t *testing.T) {
	t.Setenv(DBJITEnvVar, "")
	cases := []struct{ name, in, want string }{
		{"url no query", "postgres://u:p@h:5432/db", "postgres://u:p@h:5432/db?jit=off"},
		{"url with query", "postgres://u:p@h/db?sslmode=disable", "postgres://u:p@h/db?jit=off&sslmode=disable"},
		{"postgresql scheme", "postgresql://u@h/db", "postgresql://u@h/db?jit=off"},
		{"url with options kept", "postgres://u@h/db?options=-c%20statement_timeout%3D5s", "postgres://u@h/db?jit=off&options=-c+statement_timeout%3D5s"},
		{"url already jit on", "postgres://u@h/db?jit=on", "postgres://u@h/db?jit=on"},
		{"kv", "host=h user=u dbname=d", "host=h user=u dbname=d jit=off"},
		{"kv with options kept", "host=h options='-c statement_timeout=5s'", "host=h options='-c statement_timeout=5s' jit=off"},
		{"kv already jit", "host=h jit=on", "host=h jit=on"},
		{"kv already jit spaced", "host=h JIT = on", "host=h JIT = on"},
		{"kv dbname containing jit is not jit", "host=h dbname=jitdb", "host=h dbname=jitdb jit=off"},
		{"empty", "", "jit=off"},
		{"unparseable url passes through", "postgres://u@h:badport/db", "postgres://u@h:badport/db"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ApplyServerDefaults(c.in)
			if got != c.want {
				t.Fatalf("ApplyServerDefaults(%q) = %q, want %q", c.in, got, c.want)
			}
			if again := ApplyServerDefaults(got); again != got {
				t.Fatalf("not idempotent: %q -> %q", got, again)
			}
		})
	}
}

func TestApplyServerDefaults_KillSwitch(t *testing.T) {
	for _, v := range []string{"on", "ON", "true", "1"} {
		t.Setenv(DBJITEnvVar, v)
		in := "postgres://u@h/db"
		if got := ApplyServerDefaults(in); got != in {
			t.Fatalf("%s=%s: DSN changed to %q", DBJITEnvVar, v, got)
		}
	}
	t.Setenv(DBJITEnvVar, "off")
	if got := ApplyServerDefaults("host=h"); got != "host=h jit=off" {
		t.Fatalf("DB_JIT=off should keep the default (jit off), got %q", got)
	}
}
