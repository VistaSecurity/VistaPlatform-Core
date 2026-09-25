package deviceinterrogation

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// cipherStringSuiteField is the CipherSuite value a collector reports for a
// device's OpenSSL-style cipher string (F5 profiles, ASA `ssl cipher` lines,
// FortiOS custom lists).
//
// Resolved completely, it is the enabled suites as one colon-separated list of
// OpenSSL names — the whole set, so a weak suite later in the list is not
// hidden behind the first (SupportedCiphers is not yet linked to the catalogue,
// W2.5).
//
// Not resolved completely — DEFAULT, HIGH, an ASA level, a vendor keyword, an
// RC4 keyword addition — it is the cipher string itself. Inventory evaluates
// cipher strings with the same parser: it never counts an excluded cipher,
// still counts what the string may enable, and records the configuration as
// partially assessed. Dropping the string here instead would have left
// inventory nothing to evaluate: an unknown cipher set would have read as a
// configuration with no weak cipher (review of, B1).
//
// "" means there is nothing to report.
func cipherStringSuiteField(raw string, parsed *cryptoparse.CipherStringResult) string {
	if parsed.Complete {
		return strings.Join(parsed.EnabledNames(), ":")
	}
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(raw), `"'`))
}

// recordCipherString writes the cipher string, what it excludes, what could
// not be expanded and whether it resolved completely into asset metadata.
func recordCipherString(meta map[string]interface{}, raw string, parsed *cryptoparse.CipherStringResult) {
	meta["cipher_string"] = raw
	if len(parsed.Excluded) > 0 {
		meta["cipher_string_excluded"] = parsed.Excluded
	}
	if len(parsed.Unexpanded) > 0 {
		meta["cipher_string_unexpanded"] = parsed.Unexpanded
	}
	meta["cipher_string_complete"] = parsed.Complete
}
