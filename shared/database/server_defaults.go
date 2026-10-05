package database

import (
	"net/url"
	"os"
	"regexp"
	"strings"
)

// DBJITEnvVar is the kill-switch for ApplyServerDefaults. "on", "true" or "1"
// leaves the server's own JIT setting alone; anything else (including unset)
// makes every platform connection ask for jit=off.
const DBJITEnvVar = "DB_JIT"

// jitKeyValue finds an existing jit setting in a key=value DSN, so a DSN that
// already says what it wants (jit=on included) is never overridden.
var jitKeyValue = regexp.MustCompile(`(?i)(^|\s)jit\s*=`)

// jitKeptByOperator reports whether the operator asked to keep the server's
// JIT default.
func jitKeptByOperator() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(DBJITEnvVar))) {
	case "on", "true", "1":
		return true
	}
	return false
}

// ApplyServerDefaults returns dsn with the platform's run-time parameters added
// for every connection it opens. Today that is one: jit=off.
//
// Why: PostgreSQL's JIT compiler pays off on long analytical queries and hurts
// short OLTP ones. Our tables are hash-partitioned, so even a simple lookup
// plans a large tree and JIT compile time dominates it (a per-target
// authorization query took 21-38 s with jit=on and 112 ms with jit=off). It is
// set per connection, not only in the chart, so it also holds for customers
// who run their own Postgres.
//
// The parameter travels as a startup parameter (lib/pq sends any unrecognised
// DSN key that way), not through the `options` key, so a DSN that already sets
// options=... keeps them untouched. A DSN that already names jit is returned
// as is. Both URL (postgres://...?x=y) and key=value forms are handled.
//
// Failure mode to know about: a connection pooler between the platform and
// Postgres (pgbouncer) rejects startup parameters it does not know with
// "unsupported startup parameter: jit" unless told to ignore them
// (ignore_startup_parameters = jit in pgbouncer.ini). Customers behind such a
// pooler either add that line or set DB_JIT=on here.
//
// The result is idempotent, so applying it twice is harmless.
func ApplyServerDefaults(dsn string) string {
	if jitKeptByOperator() {
		return dsn
	}
	return withJITOff(dsn)
}

func withJITOff(dsn string) string {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			// Leave a DSN we cannot parse for the driver to reject with its own
			// error; guessing at it here would only change the message.
			return dsn
		}
		q := u.Query()
		if _, ok := q["jit"]; ok {
			return dsn
		}
		q.Set("jit", "off")
		u.RawQuery = q.Encode()
		return u.String()
	}
	if jitKeyValue.MatchString(dsn) {
		return dsn
	}
	if strings.TrimSpace(dsn) == "" {
		return "jit=off"
	}
	return dsn + " jit=off"
}
