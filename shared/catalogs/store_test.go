package catalogs

// The gap-list bound, which is the one part of the SQL store that is pure Go
// and therefore testable without a database. The rest of the store's behaviour
// (the LIKE prefilter, the ON CONFLICT count) needs real rows and is covered by
// the integration tests.

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The gap list is written on the UNANSWERABLE path, so nothing upstream has
// vouched for the subject string. Bounding it is what stops one caller passing
// prose from growing a table whose whole purpose is to be read by a person and
// sorted by a count.
func TestClipSubject(t *testing.T) {
	if got := ClipSubject("  Cisco IOS-XE  "); got != "Cisco IOS-XE" {
		t.Errorf("ClipSubject trimmed to %q", got)
	}
	long := strings.Repeat("a", MaxSubjectField+500)
	if got := ClipSubject(long); len(got) != MaxSubjectField {
		t.Errorf("ClipSubject(%d bytes) = %d bytes, want %d", len(long), len(got), MaxSubjectField)
	}
	// Cut on a RUNE boundary. Half a UTF-8 sequence is a broken string in the
	// console, in the prompt the gap pass later builds from this row, and in
	// anything that logs it.
	multi := strings.Repeat("é", MaxSubjectField) // two bytes each
	got := ClipSubject(multi)
	if len(got) > MaxSubjectField {
		t.Errorf("ClipSubject kept %d bytes, past the %d-byte cap", len(got), MaxSubjectField)
	}
	if !utf8.ValidString(got) {
		t.Errorf("ClipSubject cut mid-rune: %q", got)
	}
	// A subject at or under the cap is untouched — the inverse polarity, since
	// a clip that always returned "" would satisfy every bound above and empty
	// the gap list instead of bounding it.
	if got := ClipSubject("nginx"); got != "nginx" {
		t.Errorf("ClipSubject(%q) = %q", "nginx", got)
	}
}
