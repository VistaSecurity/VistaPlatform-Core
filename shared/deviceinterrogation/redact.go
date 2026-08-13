package deviceinterrogation

import (
	"context"
	"strings"
)

// Secret material must never leave the interrogated device.
//
// We inventory cryptographic POSTURE — which algorithms, key sizes, protocol
// versions and certificates a device uses. We have no need for the key material
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
//     is the real fix — see unifiDeviceMetadata in unifi.go.
//  2. Sanitize walks everything a collector emitted and redacts anything whose
//     field name still looks like a secret. This is the backstop for the next
//     collector someone writes, and for vendor fields we have not seen yet.
//
// Defence 2 exists BECAUSE defence 1 depends on a human remembering. A redacted
// value is replaced with redactedMarker rather than dropped, so that when the
// backstop fires it is visible in the payload and in tests — a scrubber whose
// effect you cannot observe is a scrubber you cannot trust.

// redactedMarker replaces any value whose field name indicates secret material.
const redactedMarker = "[redacted]"

// secretNameFragments mark a field as secret material wherever they appear in
// the field name. Matched case-insensitively against the whole name.
var secretNameFragments = []string{
	"password", "passwd", "passphrase",
	"secret", "credential",
	"psk", "preshared", "pre_shared",
	"token", "bearer", "cookie",
	"apikey", "api_key",
	"privatekey", "private_key",
	"x_authkey", "authkey", "auth_key",
	"sessionkey", "session_key",
	"masterkey", "master_key",
	"sharedkey", "shared_key",
	"signingkey", "signing_key",
	"encryptionkey", "encryption_key",
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

// isSecretFieldName reports whether a field name indicates secret material.
func isSecretFieldName(name string) bool {
	lower := normalizeFieldName(name)
	if lower == "" {
		return false
	}
	if safeFieldNames[lower] {
		return false
	}
	for _, frag := range secretNameFragments {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	// Catch-all for the vendor-specific key fields we cannot enumerate ahead of
	// time (x_vwirekey, syslog_key, x_mesh_key, …). Anything whose name ends in
	// "key" and is not an explicitly safe posture field is treated as material.
	return strings.HasSuffix(lower, "key")
}

// redactValue recursively sanitizes an arbitrary decoded-JSON value.
func redactValue(v interface{}) interface{} {
	switch typed := v.(type) {
	case map[string]interface{}:
		return RedactMap(typed)
	case []interface{}:
		out := make([]interface{}, len(typed))
		for i, item := range typed {
			out[i] = redactValue(item)
		}
		return out
	case []map[string]interface{}:
		out := make([]map[string]interface{}, len(typed))
		for i, item := range typed {
			out[i] = RedactMap(item)
		}
		return out
	default:
		return v
	}
}

// RedactMap returns a copy of m with every secret-looking field replaced by
// redactedMarker, recursing through nested maps and slices. The input is not
// mutated. A nil map returns nil.
func RedactMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if isSecretFieldName(k) {
			out[k] = redactedMarker
			continue
		}
		out[k] = redactValue(v)
	}
	return out
}

// Sanitize scrubs secret material from an interrogation result in place. It is
// applied by the Registry to every interrogator's output, so no collector can
// skip it and no new collector has to remember it.
func Sanitize(result *InterrogateResult) {
	if result == nil {
		return
	}
	result.DeviceInfo = RedactMap(result.DeviceInfo)
	for i := range result.Assets {
		result.Assets[i].Metadata = RedactMap(result.Assets[i].Metadata)
	}
}

// sanitizingInterrogator decorates a DeviceInterrogator so its result is
// scrubbed before any caller sees it. Registry.Get returns these, which is what
// makes redaction structural rather than a convention.
type sanitizingInterrogator struct {
	inner DeviceInterrogator
}

func (s sanitizingInterrogator) Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error) {
	result, err := s.inner.Interrogate(ctx, device, creds)
	Sanitize(result)
	return result, err
}

func (s sanitizingInterrogator) SupportedDeviceTypes() []string {
	return s.inner.SupportedDeviceTypes()
}
