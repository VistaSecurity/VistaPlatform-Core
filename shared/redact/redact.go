// Package redact is the platform's single name-based secret redactor.
//
// Secret material must never leave the system that holds it.
//
// We inventory cryptographic POSTURE — which algorithms, key sizes, protocol
// versions and certificates a thing uses. We have no need for the key material
// itself, and storing it would make our database a more attractive target than
// the devices it describes. A UniFi interrogation was persisting the
// controller's mesh PSK, per-device auth keys and syslog keys verbatim into
// device_jobs.results and discovery_findings.details, because collectors
// assigned whole vendor API response objects into Metadata.
//
// Two independent defences, deliberately:
//
//  1. Collectors project vendor responses onto an explicit allowlist of fields
//     we actually use, so secrets are never collected in the first place. That
//     is the real fix — see unifiDeviceMetadata in shared/deviceinterrogation.
//  2. This package walks everything a collector emitted and redacts anything
//     whose field name still looks like a secret. It is the backstop for the
//     next collector someone writes, and for vendor fields we have not seen
//     yet.
//
// Defence 2 exists BECAUSE defence 1 depends on a human remembering. A redacted
// value is replaced with [Marker] rather than dropped, so that when the
// backstop fires it is visible in the payload and in tests — a scrubber whose
// effect you cannot observe is a scrubber you cannot trust.
//
// # Why this is its own package
//
// The rule started life inside shared/deviceinterrogation, where the
// interrogator Registry wraps every interrogator so no collector can skip it.
// It is now called from four more boundaries — the host agent, the SBOM parser
// (SBOMs carry credentials in properties), the CMDB connectors, and the AI
// provider boundary — and every one of them has to make the same decisions
// about the same field names. One list, one set of mutation-tested guards
// (ADR-0004 D4, ADR-0008 D4.5).
//
// The matching is name-based, with exactly one exception: [TextPEM] masks PEM
// PRIVATE KEY blocks by shape, and [Any] applies it to every string it walks.
// That exception is here rather than at one caller because a pasted key has no
// field name to catch it by, and an interrogator banner, an SBOM property, a
// CMDB description and a prompt all have the same problem — one rule beats four
// copies of it, three of which would be missing.
//
// Rules that read a value for anything else (entropy heuristics, "this looks
// like a token") stay out: they cannot be reasoned about, and they would redact
// the fingerprints and public keys the inventory exists to record.
package redact

import (
	"regexp"
	"sort"
	"strings"
)

// Marker replaces any value whose field name indicates secret material.
const Marker = "[redacted]"

// pemPrivateKey matches a PEM private-key block of any flavour: RSA, EC,
// OPENSSH, ENCRYPTED, or the bare PKCS#8 form. Non-greedy, so two blocks in one
// string are redacted as two blocks rather than as everything between them.
//
// RE2 has no backtracking, so the non-greedy `.*?` is linear in the length of
// the input and cannot be made to blow up by a crafted value.
var pemPrivateKey = regexp.MustCompile(
	`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

// pemPrivateKeyHeadless matches a BEGIN header with no END line after it —
// what is left of a key when the text it sat in was cut at a line or a length
// bound before it reached this function (an SSH identification string is read
// one line at a time; a banner is truncated). The block regex above cannot
// match a fragment with no END, so without this rule the header and whatever
// follows it shipped. Everything from the header to the end of the string is
// the key's territory and is redacted as one.
var pemPrivateKeyHeadless = regexp.MustCompile(
	`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*$`)

// TextPEM replaces every PEM private-key block in s with [Marker], leaving the
// text around it — and every public artefact — alone.
//
// This is the one VALUE-shaped rule in a package that is otherwise strictly
// name-based, and it is here rather than at a single caller because a pasted
// key has no field name to catch it by, and every boundary has the same
// problem. An interrogator banner, an SBOM property, a CMDB description field
// and a prompt are all places a private key has actually turned up inside a
// string whose name is innocent. [Any] applies it to every string it walks, so
// all four are covered by one rule instead of four copies of it.
//
// It is deliberately narrow: "PRIVATE KEY" in the header is the whole test.
// CERTIFICATE, PUBLIC KEY and CERTIFICATE REQUEST blocks are posture — they are
// what we are in business to inventory — and pass through untouched.
func TextPEM(s string) string {
	// The header text is the cheap pre-filter: the overwhelming majority of
	// strings walked here are hostnames and version numbers, and running a
	// regex over every one of them earns nothing.
	if !strings.Contains(s, "PRIVATE KEY") {
		return s
	}
	s = pemPrivateKey.ReplaceAllString(s, Marker)
	return pemPrivateKeyHeadless.ReplaceAllString(s, Marker)
}

// secretNameFragments mark a field as secret material wherever they appear in
// the field name. Matched case-insensitively against the whole name.
var secretNameFragments = []string{
	"password", "passwd", "passphrase",
	"secret", "credential",
	"psk", "preshared", "pre_shared",
	"token", "bearer", "cookie",
	// `passcode` is a password by another name, and "passwd"/"password"/
	// "passphrase" do not cover it. Same for the bare `pin`, which is why that
	// one is an exact name rather than a fragment: "pin" appears inside
	// `pinning`, `pinned_cert` and `spinlock`.
	//
	// (X.5 originally added a bare `community` fragment here for the SNMP case.
	// Gate 4 rejected it — Azure returns `communityGalleryImageId`, an image
	// identifier and posture — and shipped the suffix rule below plus the two
	// `community_string` spellings instead. That is the better shape and it is
	// what stands; this comment exists so the bare fragment is not re-added.)
	"passcode",
	// An `authorization` field is a header value — "Bearer …", "Basic …" — and
	// is the single likeliest key name for an integration whose auth_type is a
	// header. Deliberately NOT the bare fragment "auth": that would swallow
	// authentication_algorithm / authmethod, which are crypto posture and are
	// exactly what we are in business to collect. A bare field named `auth` is
	// handled by exactSecretNames instead.
	"authorization",
	// Webhook URLs (Slack, Teams, generic SIEM sinks) carry their credential
	// inside the URL path, so the URL IS the secret. Redacted whole rather than
	// split: there is no vendor-independent way to say which path segment is the
	// token, and a half-shown URL invites the reader to believe the rest is safe
	// to display. Matches webhook_url, webhook_uri, slack_webhook, ….
	"webhook",
	"apikey", "api_key",
	// An SNMP v1/v2c community string IS the credential — a GET authenticates
	// with nothing else, and it travels in the clear, which is why the
	// plaintext_management finding exists. The interrogators carry one as
	// Credentials.Custom["community"], and the suffix rule below is what catches
	// that bare spelling along with snmp_community, read_community,
	// ro_community and trap_community. These two fragments are the one shape the
	// suffix cannot reach, in both the folded and the camelCase spelling —
	// exactly as privatekey/private_key and apikey/api_key are listed twice.
	//
	// Deliberately NOT the bare fragment "community": Azure returns
	// communityGalleryImageId, which is an image identifier and is posture. The
	// same reasoning as "auth", one line up.
	"community_string", "communitystring",
	"privatekey", "private_key",
	"x_authkey", "authkey", "auth_key",
	"sessionkey", "session_key",
	"masterkey", "master_key",
	"sharedkey", "shared_key",
	"signingkey", "signing_key",
	"encryptionkey", "encryption_key",
}

// exactSecretNames are field names that carry secret material as the WHOLE name
// but whose text is too common to use as a fragment. `auth` is the case that
// forced this: an integration's auth block is often stored under a bare `auth`
// key, while "auth" as a substring appears throughout legitimate crypto posture
// (authentication_algorithm, authmethod, authenticated). Matched after
// safeFieldNames, on the normalized whole name only.
var exactSecretNames = map[string]bool{
	"auth": true,
	// `pin` as the WHOLE name is a credential (a device PIN, a SIM PIN). As a
	// fragment it would swallow `pinning`, `pinned_certificate` and `spinlock`,
	// none of which is a secret and the first two of which are posture.
	"pin": true,
}

// safeFieldNames are the cryptographic-posture fields whose names contain "key"
// but which carry no secret material — they are exactly what we are in business
// to inventory. Checked before the "ends in key" rule below, so describing a key
// stays possible while storing one does not.
var safeFieldNames = map[string]bool{
	"key_algorithm":          true,
	"key_size":               true,
	"key_length":             true,
	"key_strength":           true,
	"key_exchange":           true,
	"key_exchange_algorithm": true,
	"key_types":              true,
	"key_usage":              true,
	"extended_key_usage":     true,
	"key_agreement":          true,
	"key_id":                 true,
	"keyid":                  true,
	"public_key":             true,
	"public_key_algorithm":   true,
	"host_key_type":          true,
	"host_key_fingerprint":   true,
}

// normalizeFieldName lowercases and folds separators so one fragment matches
// every spelling a vendor might use. FortiOS returns `private-key`, PAN-OS
// returns `private_key`, and some APIs return `privateKey` — without folding,
// a fragment list would have to enumerate all three and would silently miss the
// fourth.
var fieldNameSeparators = strings.NewReplacer("-", "_", " ", "_", ".", "_")

func normalizeFieldName(name string) string {
	return fieldNameSeparators.Replace(strings.ToLower(strings.TrimSpace(name)))
}

// IsSecretName reports whether a field name indicates secret material.
//
// It is the single predicate behind every other function here, and the one a
// caller building its own projection allowlist should consult (ADR-0004 D4:
// every allowlist widening reviews the new field names against this).
func IsSecretName(name string) bool {
	lower := normalizeFieldName(name)
	if lower == "" {
		return false
	}
	if safeFieldNames[lower] {
		return false
	}
	if explicitSecretName(lower) {
		return true
	}
	// Catch-all for the vendor-specific key fields we cannot enumerate ahead of
	// time (x_vwirekey, syslog_key, x_mesh_key, …). Anything whose name ends in
	// "key" and is not an explicitly safe posture field is treated as material.
	return strings.HasSuffix(lower, "key")
}

// explicitSecretName is every NAMED rule — the exact names and the fragments —
// without the "ends in key" catch-all. It takes an already-normalized name.
//
// Split out so [IsExplicitSecretName] and [IsSecretName] cannot disagree about
// what the list says: a fragment added to the list is picked up by both.
func explicitSecretName(lower string) bool {
	if exactSecretNames[lower] {
		return true
	}
	for _, frag := range secretNameFragments {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	// …and the same rule for SNMP community strings, which cannot be enumerated
	// either: `community`, `snmp_community`, `read_community`, `write_community`,
	// `ro_community`, `rw_community`, `trap_community`. A SUFFIX rather than a
	// fragment, because a name that merely CONTAINS the word — Azure's
	// communityGalleryImageId — is an identifier and is posture. Over-redacting
	// an image id would be the same bug pointed the other way.
	//
	// It lives HERE rather than beside the "ends in key" catch-all because the
	// two are different kinds of rule: this one NAMES a credential we speak
	// (deviceinterrogation carries one as Credentials.Custom["community"]),
	// while "ends in key" guesses at vendor field names we have not seen. Only
	// the guess is dropped by [IsExplicitSecretName].
	return strings.HasSuffix(lower, "community")
}

// IsExplicitSecretName is [IsSecretName] without the "ends in key" catch-all:
// true only for a name this package has actually NAMED as a credential.
//
// It exists for one caller shape — a rail whose keys are PLATFORM-chosen
// identifiers rather than vendor field names, where the catch-all is the wrong
// rule rather than a cautious one. The findings evidence map is that shape: its
// keys are written by producers in this repository, and two of them
// (`observation_key`, `class_key`) end in "key" while being the finding's own
// identity rather than material. Redacting those would break the drift producer
// silently — the over-strict polarity of the same bug the catch-all prevents.
//
// Use IsSecretName anywhere the names come from a VENDOR. The catch-all is
// there because we cannot enumerate what a vendor will call a key, and that
// reasoning is untouched.
func IsExplicitSecretName(name string) bool {
	lower := normalizeFieldName(name)
	if lower == "" || safeFieldNames[lower] {
		return false
	}
	return explicitSecretName(lower)
}

// String returns value, or [Marker] when fieldName names secret material. Use
// it where a single field is being copied by name and there is no map to walk.
// A surviving value still has its PEM private-key blocks masked, exactly as it
// would inside [Map].
func String(fieldName, value string) string {
	if IsSecretName(fieldName) {
		return Marker
	}
	return TextPEM(value)
}

// Any recursively sanitizes an arbitrary decoded-JSON value: maps are walked by
// key, slices element-wise, and strings have their PEM private-key blocks
// masked by [TextPEM]. Any other value is returned unchanged — a scalar reached
// without a field name has no name to judge, which is why the caller's entry
// point should be a map wherever one exists.
func Any(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		return Map(typed)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = Any(item)
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(typed))
		for i, item := range typed {
			out[i] = Map(item)
		}
		return out
	case []string:
		// A []string is the one other slice type collectors build by hand
		// (banner lines, cipher lists, command output). Without this case it
		// was returned as the SAME slice header, so a caller mutating the copy
		// mutated the input, and its elements never reached TextPEM.
		//
		// There is deliberately no reflect-based fallback for the general slice
		// case: a redactor that walks arbitrary types by reflection is a
		// redactor nobody can reason about, and the two shapes that actually
		// occur are enumerated here instead.
		out := make([]string, len(typed))
		for i, item := range typed {
			out[i] = TextPEM(item)
		}
		return out
	case string:
		return TextPEM(typed)
	default:
		return v
	}
}

// Map returns a copy of m with every secret-looking field replaced by [Marker],
// recursing through nested maps and slices. The input is not mutated. A nil map
// returns nil.
func Map(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if IsSecretName(k) {
			out[k] = Marker
			continue
		}
		out[k] = Any(v)
	}
	return out
}

// MustNotRedact returns the crypto-posture allowlist: the field names that
// contain "key" but carry no secret material and must survive redaction. The
// slice is a sorted copy; mutating it changes nothing.
//
// The inverse polarity matters as much as the forward one. An over-strict
// scrubber that eats key_size and public_key is the same bug pointed the other
// way — it destroys the inventory we exist to produce, and does it silently.
// A caller adding a posture field to its own projection checks it against this
// list.
func MustNotRedact() []string {
	out := make([]string, 0, len(safeFieldNames))
	for name := range safeFieldNames {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// IsMustNotRedact reports whether name is on the crypto-posture allowlist.
// Note this is NOT the negation of IsSecretName: the overwhelming majority of
// field names are on neither list — they are simply not secret-shaped.
func IsMustNotRedact(name string) bool {
	return safeFieldNames[normalizeFieldName(name)]
}

// SecretNameFragments returns the substrings that mark a field name as secret
// wherever they appear in it. The slice is a sorted copy.
//
// Exported for the review workflow ADR-0004 D4 requires: when a collector's
// projection allowlist is widened, the new field names are reviewed against
// these fragments before the widening lands.
func SecretNameFragments() []string {
	out := append([]string(nil), secretNameFragments...)
	sort.Strings(out)
	return out
}

// ExactSecretNames returns the field names treated as secret only when they are
// the WHOLE name. The slice is a sorted copy.
func ExactSecretNames() []string {
	out := make([]string, 0, len(exactSecretNames))
	for name := range exactSecretNames {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
