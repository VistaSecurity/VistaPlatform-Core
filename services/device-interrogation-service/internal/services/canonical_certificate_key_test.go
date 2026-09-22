package services

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The canonical-certificate-key guard.
//
// CLAUDE.md, *Single certificate format*: every discovery path emits
// certificates as a `"certificates"` JSON array using the canonical field
// names, and "alternative naming conventions" must not be introduced. That rule
// held for years and then quietly stopped: the ACM record for a CloudFront
// distribution's viewer certificate was written under `acm_certificates`, a key
// no materializer reads, so a real certificate with a real expiry existed in
// the database and in no certificate inventory.
//
// The rule was already written down. What was missing was something that FAILS
// when it is broken, so this walks the discovery producers and consumers and
// rejects two spellings:
//
//	<something>_certificates   a certificate array parked under its own key
//	cert_<canonical field>     a certificate flattened into per-field keys
//
// Both are matched as bare string literals, because a key is a string literal
// at the point it is introduced, and because an AST walk would miss the same
// name appearing in a SQL fragment or a JSON tag — where it is just as wrong.
//
// Known exceptions are listed below WITH REASONS, and an exception that matches
// nothing is itself a failure: a stale allowlist is how a guard stops guarding.

// certKeyScanRoots are the trees that produce or consume discovery metadata,
// relative to the repository root.
var certKeyScanRoots = []string{
	"services/device-interrogation-service",
	"services/discovery-processor-service",
	"services/inventory-service/internal/services",
	"sensor",
}

// canonicalCertFields are the certificate field names of
// shared/certificates.CertificateInfo plus the spellings the ingest path also
// accepts. A `cert_`-prefixed version of any of them is a certificate taken
// apart into loose keys — the flat form the rule forbids. Names NOT on this
// list (cert_has_sct, cert_validation_status, cert_known_bad_ca …) are
// assessments ABOUT a certificate rather than fields OF one, and are fine.
var canonicalCertFields = []string{
	"subject", "subject_dn", "issuer", "issuer_dn", "serial", "serial_number",
	"not_before", "not_after", "fingerprint_sha256", "fingerprint_sha1",
	"key_algorithm", "public_key_algorithm", "key_size", "public_key_size",
	"signature_alg", "signature_algorithm", "certificate_pem", "pem",
	"chain_order", "subject_alternative_names", "san", "is_ca", "common_name",
	"key_usage", "extended_key_usage",
}

// certKeyAllowlist maps an allowed literal to why it is allowed. Every entry
// must still be found by the scan.
var certKeyAllowlist = map[string]string{
	// Same canonical ENTRY shape, deliberately a different key: these are the
	// certificates the CLIENT presented during mTLS, not the server's. Folding
	// them into "certificates" would materialize a peer's certificate as the
	// asset's own.
	"client_certificates": "mTLS client certificates — a different role, not a different format",

	// Counts and table names, not payload keys.
	"with_certificates":                  "a COUNT field in the job-results summary",
	"total_certificates":                 "a COUNT field in the certificate statistics response",
	"crypto_implementation_certificates": "a database TABLE name, in the merge-preview table list",

	// Known debt, deliberately not fixed here — see the notes on each.
	//
	// The sensor's passive TLS parser flattens the leaf certificate into
	// cert_* keys instead of emitting a canonical "certificates" array. It
	// predates this guard, the ingest path reads the flat spelling, and
	// changing it is a sensor-protocol change with its own blast radius. It is
	// listed so that it is a KNOWN exception rather than an unnoticed one.
	"cert_fingerprint_sha256":  "sensor passive TLS parser, pre-existing flat form (packet_capture.go)",
	"cert_subject":             "sensor passive TLS parser + external_connections column name",
	"cert_issuer":              "sensor passive TLS parser, pre-existing flat form",
	"cert_not_before":          "sensor passive TLS parser, pre-existing flat form",
	"cert_not_after":           "sensor passive TLS parser, pre-existing flat form",
	"cert_key_algorithm":       "sensor passive TLS parser, pre-existing flat form",
	"cert_signature_algorithm": "sensor passive TLS parser, pre-existing flat form",
	"cert_public_key_size":     "sensor passive TLS parser, pre-existing flat form",
	"cert_san":                 "sensor passive TLS parser, pre-existing flat form",
}

func TestCanonicalCertificateMetadataKey(t *testing.T) {
	root := repoRootForCertKeyScan(t)

	arrayKey := regexp.MustCompile(`"([a-z][a-z0-9]*(?:_[a-z0-9]+)*_certificates)"`)
	flatKey := regexp.MustCompile(`"(cert_(?:` + strings.Join(canonicalCertFields, "|") + `))"`)

	type hit struct{ key, where string }
	var violations []hit
	used := map[string]bool{}

	for _, rel := range certKeyScanRoots {
		dir := filepath.Join(root, rel)
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("scan root %s is missing — the guard would scan nothing: %v", rel, err)
		}
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			body, readErr := os.ReadFile(path) //nolint:gosec // walking a known repo subtree
			if readErr != nil {
				return readErr
			}
			// This file names the forbidden spellings in order to hunt for
			// them, exactly like the two "quanta"+"view" guards CLAUDE.md
			// describes. Scanning itself would always fail.
			if strings.HasSuffix(path, "canonical_certificate_key_test.go") {
				return nil
			}
			where, _ := filepath.Rel(root, path)
			for _, re := range []*regexp.Regexp{arrayKey, flatKey} {
				for _, m := range re.FindAllStringSubmatch(string(body), -1) {
					key := m[1]
					if _, ok := certKeyAllowlist[key]; ok {
						used[key] = true
						continue
					}
					violations = append(violations, hit{key: key, where: where})
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", rel, err)
		}
	}

	if len(violations) > 0 {
		seen := map[string]bool{}
		var lines []string
		for _, v := range violations {
			line := fmt.Sprintf("  %-34s %s", v.key, v.where)
			if seen[line] {
				continue
			}
			seen[line] = true
			lines = append(lines, line)
		}
		sort.Strings(lines)
		t.Errorf("non-canonical certificate metadata key(s):\n%s\n\n"+
			"CLAUDE.md, *Single certificate format*: certificates travel as a %q array whose\n"+
			"entries use the canonical field names (subject_dn, issuer_dn, fingerprint_sha256,\n"+
			"not_before, not_after, key_algorithm, signature_alg, certificate_pem, chain_order …).\n"+
			"A certificate array under its own key reaches no materializer — that is how a live\n"+
			"ACM certificate sat in the database and in no certificate inventory.\n"+
			"Emit it under %q (see mergeProviderCertificates), or, if it genuinely is not the\n"+
			"same thing, add it to certKeyAllowlist with the reason.",
			strings.Join(lines, "\n"), "certificates", "certificates")
	}

	for key, reason := range certKeyAllowlist {
		if !used[key] {
			t.Errorf("certKeyAllowlist entry %q (%s) matched nothing — the code it excused is gone.\n"+
				"Delete the entry. An allowlist that outlives its subject is how a guard stops guarding.", key, reason)
		}
	}
}

// repoRootForCertKeyScan walks up from the test's working directory to the
// directory holding go.work.
func repoRootForCertKeyScan(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the repository root (no go.work above the test's working directory)")
	return ""
}
