package formatters

// The CBOM's canonical bytes, pinned byte-for-byte.
//
// WHY A GOLDEN AND NOT A REPRODUCIBILITY CHECK
//
// `TestCanonicalJSON_IsCompactAndStable` proves the formatter agrees with
// itself across two calls in one process. It cannot notice the formatter
// agreeing with itself about something NEW — and the xBOM work (ADR-0005 D6)
// added six fields to these structs: `services` and `vulnerabilities` on the
// document, `cpe`, `group`, `licenses` and `evidence` on the component. Every
// one is `omitempty` and left unset on the crypto path, and every one was
// appended rather than inserted, because encoding/json emits struct fields in
// declaration order. Both of those facts were asserted in a comment and by
// nothing else.
//
// They have to hold. These bytes ARE the content hash, and every CBOM artifact
// a customer has already stored carries a hash and (on Enterprise) an HMAC
// signature over the bytes the formatter produced at the time. A field that
// moved, or one that stopped being omitted when empty, would make every stored
// artifact fail `POST /cbom/artifacts/:id/verify` — the endpoint whose whole
// purpose is to say the evidence was not tampered with. The failure would be
// silent until an auditor ran it.
//
// The golden file was generated from the formatter as it stood BEFORE the xBOM
// fields were added and committed unchanged, so this is a real before/after
// comparison rather than a record of whatever the code does today. Regenerate
// it with -update ONLY when the CBOM document is deliberately changing shape,
// and understand when you do that every artifact stored under the old shape
// keeps verifying against bytes this file no longer describes.

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateCanonicalGolden = flag.Bool("update-cbom-golden", false,
	"rewrite testdata/cbom-canonical.golden.json — see the file comment before you do")

const canonicalGoldenPath = "testdata/cbom-canonical.golden.json"

func TestCanonicalJSON_BytesHaveNotMoved(t *testing.T) {
	got, err := NewCycloneDXFormatter().FormatCBOMAsCanonicalJSON(representativeCBOM())
	if err != nil {
		t.Fatalf("FormatCBOMAsCanonicalJSON: %v", err)
	}

	if *updateCanonicalGolden {
		if err := os.MkdirAll(filepath.Dir(canonicalGoldenPath), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(canonicalGoldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("rewrote %s (%d bytes)", canonicalGoldenPath, len(got))
		return
	}

	want, err := os.ReadFile(canonicalGoldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf(`the CBOM's canonical bytes changed.

These bytes are the content_hash and the signature payload of every CBOM
artifact already stored. If this change is deliberate, say so in the PR and
regenerate with -update-cbom-golden; if it is not, a field was inserted rather
than appended, or one stopped being omitempty.

--- want (%d bytes) ---
%s
--- got (%d bytes) ---
%s`, len(want), want, len(got), got)
	}
}

// TestCanonicalJSON_XBOMFieldsAreAbsentFromACBOM names the specific keys the
// xBOM kinds introduced, so a failure says WHICH one leaked rather than only
// that the bytes moved.
//
// Absent, not empty: `"services":[]` in the document would be a new key in the
// hashed bytes just as surely as a populated one, and it would also assert that
// this snapshot looked for network services and found none.
//
// `group` is NOT in the list. `CDXComponent.Group` is one of the six new
// fields, but `metadata.tools.components[].group` has always carried
// "io.vistasecurity", so a substring search for it reports a key that was
// there before the change — the guard would fail on correct code, which is the
// same defect as one that cannot fail, pointed the other way. The golden above
// covers `group` exactly, by position.
func TestCanonicalJSON_XBOMFieldsAreAbsentFromACBOM(t *testing.T) {
	got, err := NewCycloneDXFormatter().FormatCBOMAsCanonicalJSON(representativeCBOM())
	if err != nil {
		t.Fatalf("FormatCBOMAsCanonicalJSON: %v", err)
	}
	for _, key := range []string{
		`"services"`, `"vulnerabilities"`, `"cpe"`, `"licenses"`, `"evidence"`,
	} {
		if bytes.Contains(got, []byte(key)) {
			t.Errorf("an xBOM-only key %s reached a CBOM document; it must stay omitempty on this path", key)
		}
	}
}
