package redact

import (
	"regexp"
	"strings"
)

// The structured shapes a credential takes inside free text.
//
// [Text] is applied to strings that reach a boundary with no field name of
// their own — an error message, a collection warning's detail. Those strings
// are built from whatever a device, a vendor API or a transport said, and a
// credential inside them is usually still WEARING its name: a JSON error body
// quoting `"password": "…"`, a header echoed as `X-F5-Auth-Token: …`, a Cisco
// configuration line `crypto isakmp key …`. Each rule below reads the NAME and
// masks the value, judged by the same [IsSecretName] list as every map key —
// the package stays name-based. The one exception is URL userinfo, which is a
// credential by its position in a URL rather than by a name.
//
// Every rule masks the value only; the name and the text around it survive,
// because an operator reading a failure needs to see what failed.

// urlUserinfo matches a URL's scheme and the rest of its token. The userinfo
// is found by [maskUserinfo], not by the pattern: a password may itself contain
// `@` or `/`, so the only safe cut is at the LAST `@` before the path's query.
var urlUserinfo = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]{0,31}://)([^\s"'<>]+)`)

// maskUserinfo replaces everything between `scheme://` and the last `@` of the
// authority-and-path part of the URL. A `?` or `#` ends the search, so an email
// address in a query string is not mistaken for userinfo.
func maskUserinfo(s string) string {
	if !strings.Contains(s, "@") {
		return s
	}
	return urlUserinfo.ReplaceAllStringFunc(s, func(m string) string {
		sub := urlUserinfo.FindStringSubmatch(m)
		scheme, rest := sub[1], sub[2]
		search := rest
		if i := strings.IndexAny(search, "?#"); i >= 0 {
			search = search[:i]
		}
		at := strings.LastIndexByte(search, '@')
		if at <= 0 {
			return m
		}
		return scheme + Marker + rest[at:]
	})
}

// authorizationHeader matches an Authorization header or field and its whole
// value: the scheme (Bearer, Basic, …) and the credential after it. The scheme
// is masked too — it is one token of the value, and leaving it would let the
// generic name/value rule below stop at the scheme and leave the credential.
var authorizationHeader = regexp.MustCompile(
	`(?i)(\b(?:proxy-)?authorization"?\s*[:=]\s*"?)((?:bearer|basic|digest|negotiate|token)\s+)?[^\s",;}]+`)

// ciscoSecretLines are Cisco IOS/ASA configuration lines whose last argument is
// a credential. The optional digit is the encryption type (0, 5, 7, 8, 9); the
// value after it is masked whether or not it is encrypted, because a type-7
// "encrypted" password is reversible and a type-5 hash is crackable.
var ciscoSecretLines = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(\benable\s+(?:secret|password)(?:\s+level\s+\d+)?\s+(?:\d{1,2}\s+)?)\S+`),
	regexp.MustCompile(`(?i)(\busername\s+\S+(?:\s+privilege\s+\d+)?\s+(?:secret|password)\s+(?:\d{1,2}\s+)?)\S+`),
	regexp.MustCompile(`(?i)(\bcrypto\s+isakmp\s+key\s+(?:\d\s+)?)\S+`),
	regexp.MustCompile(`(?i)(\bpre-shared-key\s+(?:(?:local|remote)\s+)?(?:\d\s+)?)\S+`),
	regexp.MustCompile(`(?i)(\bsnmp-server\s+community\s+)\S+`),
	regexp.MustCompile(`(?i)(\bkey-string\s+(?:\d\s+)?)\S+`),
	// tunnel-group … ikev1 pre-shared-key is covered above; ASA's
	// `tunnel-group … general-attributes` password lines use "password".
	regexp.MustCompile(`(?i)(\b(?:tacacs-server|radius-server)\s+(?:host\s+\S+\s+)?key\s+(?:\d\s+)?)\S+`),
}

// jsonPair matches one `"name": value` member. The value is a string
// (optionally backslash-escaped, as it is inside a %q-formatted error), or any
// run up to the next delimiter — which also covers a string cut off by a byte
// bound before its closing quote, and a nested object, whose opening is masked.
var jsonPair = regexp.MustCompile(
	`(\\?"([^"\\]{1,64})\\?"\s*:\s*)(\\?"(?:[^"\\]|\\[^"])*\\?"|[^,}\]\s]+)`)

// namedValue matches `name: value` where the name starts a line or follows a
// delimiter — `{`, `,`, `;`, `(`, `[`, or another `: `. That position rule is
// what keeps prose alone: "failed to get API key: request timed out" has the
// word "key" before a colon, but it is the end of a sentence, not a field.
var namedValue = regexp.MustCompile(
	`(?m)((?:^|[\n{,;(\[]|:[ \t])[ \t]*)([A-Za-z][A-Za-z0-9_.\-]{0,63})([ \t]*:[ \t]*)([^\s,;}\]]+)`)

// TextStructuredSecrets masks credentials that appear in free text with their
// name still attached: URL userinfo, Authorization headers, Cisco secret
// configuration lines, JSON members and `name: value` pairs whose name
// [IsSecretName] recognises. Names that are posture (key_size, public_key)
// keep their values.
func TextStructuredSecrets(s string) string {
	s = maskUserinfo(s)
	s = authorizationHeader.ReplaceAllString(s, "${1}"+Marker)
	for _, line := range ciscoSecretLines {
		s = line.ReplaceAllString(s, "${1}"+Marker)
	}
	if strings.Contains(s, `"`) {
		s = jsonPair.ReplaceAllStringFunc(s, func(m string) string {
			sub := jsonPair.FindStringSubmatch(m)
			if !IsSecretName(sub[2]) || strings.Contains(sub[3], Marker) {
				return m
			}
			return sub[1] + `"` + Marker + `"`
		})
	}
	if strings.Contains(s, ":") {
		s = namedValue.ReplaceAllStringFunc(s, func(m string) string {
			sub := namedValue.FindStringSubmatch(m)
			if !IsSecretName(sub[2]) || strings.HasPrefix(sub[4], Marker) {
				return m
			}
			return sub[1] + sub[2] + sub[3] + Marker
		})
	}
	return s
}
