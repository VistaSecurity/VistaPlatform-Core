package redact

import (
	"regexp"
	"strings"
)

// The value-shaped half of this package, for strings that reach a boundary with
// no field name of their own.
//
// [TextPEM] (in redact.go) is the first such rule. This file adds the second,
// and [Text] is the pair applied together — what a caller persisting an error
// message wants, because an error string has no key to judge it by.

// urlSecretParam matches one `name=value` pair as it appears inside free text —
// a query string, a stringified *url.Error, a curl command an operator pasted.
//
// The value stops at the first `&`, whitespace, quote or angle bracket, which is
// exactly where a query parameter ends in every one of those contexts. The name
// is bounded to the characters a parameter name is made of, so ordinary prose
// ("status = 401") cannot be read as a parameter.
var urlSecretParam = regexp.MustCompile(`([A-Za-z0-9_.\-]{1,64})=([^&\s"'<>]+)`)

// TextURLSecrets replaces the VALUE of every `name=value` pair in s whose name
// [IsSecretName] recognises, leaving the name and the surrounding text alone.
//
// It is here for the same reason as [TextPEM]: a credential that travelled in a
// URL has no field name at the boundary that stores it. PAN-OS takes its API
// key as `key=` in the query string, and Go stringifies a transport failure as a
// *url.Error carrying the WHOLE URL — so a firewall that stopped answering
// mid-interrogation wrote a live API key into device_jobs.error_message, the one
// field the job-results projection never touches.
//
// The rule is still NAME-based: the parameter name IS the field name, judged by
// the same list as every map key. So `key_size=2048` and `public_key=…` survive
// (safeFieldNames says they are posture) while `key=`, `password=`, `api_key=`
// and `token=` do not. Moving a credential out of the URL is the real fix; this
// is the backstop for the next vendor nobody has checked.
//
// It deliberately does not try to recognise a credential by shape. "This looks
// like a token" is the heuristic this package refuses everywhere else, and it
// would redact the fingerprints and public keys the inventory exists to record.
func TextURLSecrets(s string) string {
	if !strings.Contains(s, "=") {
		return s
	}
	return urlSecretParam.ReplaceAllStringFunc(s, func(pair string) string {
		eq := strings.IndexByte(pair, '=')
		if eq < 0 || !IsSecretName(pair[:eq]) {
			return pair
		}
		return pair[:eq+1] + Marker
	})
}

// Text is the redaction for a free-text string with no field name of its own —
// an error message, a log line, a job's failure reason. It runs both value
// rules: PEM private-key blocks by shape, and credential query parameters by
// parameter name.
//
// Use it wherever a string built from arbitrary runtime material is PERSISTED or
// returned to a client. A map has keys to judge and goes through [Map]; an error
// string has nothing but itself.
func Text(s string) string {
	return TextPEM(TextURLSecrets(s))
}
