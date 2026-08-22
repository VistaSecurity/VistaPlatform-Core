package database

import (
	"net/url"
	"strings"
)

// redactedPlaceholder is what a password is replaced with once redacted. It is
// deliberately not empty — an operator reading the log needs to be able to tell
// "no password was configured" apart from "a password was configured and we hid
// it", because the two produce very different connection failures.
const redactedPlaceholder = "REDACTED"

// redactDSN returns dsn with any password removed, so a connection string can be
// logged for operator diagnostics without leaking the database credential.
//
// Both Postgres DSN spellings carry the password and both are reachable here:
// the URL form (DATABASE_URL, "postgres://user:pass@host/db") and the keyword
// form this package builds from the individual config fields
// ("host=… password=… sslmode=…"). A redactor that only understands one of them
// is worse than none, because it reads as safe at the call site while still
// printing the credential for the other spelling.
//
// An unparseable DSN is redacted wholesale rather than returned verbatim: if we
// cannot prove where the password ends, we must not guess.
func redactDSN(dsn string) string {
	if dsn == "" {
		return ""
	}

	if isURLDSN(dsn) {
		return redactURLDSN(dsn)
	}
	return redactKeywordDSN(dsn)
}

func isURLDSN(dsn string) bool {
	lower := strings.ToLower(dsn)
	return strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://")
}

func redactURLDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		// Cannot locate the credential boundary — redact everything rather than
		// emit a string that might still contain it.
		return redactedPlaceholder
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			u.User = url.UserPassword(u.User.Username(), redactedPlaceholder)
		}
	}
	// A password can also arrive as a query parameter on the URL form.
	if q := u.Query(); q.Has("password") {
		q.Set("password", redactedPlaceholder)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// redactKeywordDSN masks the value of any password-bearing keyword in a libpq
// keyword/value DSN ("host=… password=… sslmode=…").
//
// This scans rather than using strings.Fields because libpq permits a
// single-quoted value, and a password containing a space would then span two
// "fields" — masking only the first leaks the rest of the credential.
func redactKeywordDSN(dsn string) string {
	var out strings.Builder
	i := 0
	for i < len(dsn) {
		// Preserve inter-pair whitespace verbatim.
		if isSpace(dsn[i]) {
			out.WriteByte(dsn[i])
			i++
			continue
		}

		keyStart := i
		for i < len(dsn) && dsn[i] != '=' && !isSpace(dsn[i]) {
			i++
		}
		key := dsn[keyStart:i]
		out.WriteString(key)

		if i >= len(dsn) || dsn[i] != '=' {
			continue // bare token, no value to mask
		}
		out.WriteByte('=')
		i++

		valStart := i
		i = skipDSNValue(dsn, i)
		if isSecretDSNKeyword(key) {
			out.WriteString(redactedPlaceholder)
		} else {
			out.WriteString(dsn[valStart:i])
		}
	}
	return out.String()
}

// skipDSNValue returns the index just past the libpq value starting at i,
// honouring single-quoted values and backslash escapes within them.
func skipDSNValue(dsn string, i int) int {
	if i < len(dsn) && dsn[i] == '\'' {
		i++ // opening quote
		for i < len(dsn) {
			if dsn[i] == '\\' && i+1 < len(dsn) {
				i += 2
				continue
			}
			if dsn[i] == '\'' {
				return i + 1 // closing quote
			}
			i++
		}
		return i // unterminated quote — value runs to end of string
	}
	for i < len(dsn) && !isSpace(dsn[i]) {
		i++
	}
	return i
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// isSecretDSNKeyword reports whether a libpq keyword's value is a credential.
// sslkey/sslpassword are included because a DSN may carry a client-key
// passphrase alongside the database password.
func isSecretDSNKeyword(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "password", "sslpassword":
		return true
	default:
		return false
	}
}
